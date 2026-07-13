#!/usr/bin/env python3
"""
ShardKeep Node Agent — role-driven (Warden / Bastion / Sentry)

Sends periodic heartbeats to the ShardKeep aggregator, reports system
health metrics, manages API key authentication, and handles the
node lifecycle pipeline:

    PENDING → EVALUATING → AUTHENTICATED → QUALIFIED → ACTIVE

v0.3.0: Added WebSocket client for real-time challenge responses.

Usage:
    python3 sentry.py [--aggregator URL] [--interval SECONDS] [--type TYPE] [--network NETWORK]
"""

from __future__ import annotations  # PEP 563: lazy annotations (Python 3.7+ compat)

AGENT_VERSION = "0.6.3"

# Role identity — populated in main() once args.type is known. Defaults match
# the legacy 'sentry' shape so module-level imports (e.g. tests) don't crash
# before main() runs. After main(), ROLE/ROLE_LABEL/SERVICE_NAME/INSTALL_DIR
# reflect the actual role this process was started for (warden/bastion/sentry).
ROLE = "sentry"
ROLE_LABEL = "Sentry"
SERVICE_NAME = "shardkeep-sentry"
INSTALL_DIR_STR = "/opt/shardkeep/sentry"

import asyncio
import base64
import json
import os
import sys
import time
import uuid
import hashlib
import hmac as hmac_mod
import platform
import socket
import signal
import argparse
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    print("ERROR: Python 3.6+ required")
    sys.exit(1)


def _ensure_websockets():
    """Install the websockets package if missing. Called before first import.

    Nodes installed from older install.sh scripts (pre v0.3.0) may be missing
    websockets. This lets the agent self-heal without an install.sh re-run.
    Returns True if websockets is importable afterwards, else False.
    """
    try:
        import websockets  # noqa: F401
        return True
    except ImportError:
        pass

    # Agent may run as root or as a non-root service user, with or without
    # pip available, and the host may or may not enforce PEP 668.
    # Prefer the apt-provided python3-websockets package when running as
    # root (most reliable on Debian/Ubuntu nodes without pip installed).
    install_variants = []
    if hasattr(os, "getuid") and os.getuid() == 0:
        install_variants.extend([
            ["apt-get", "install", "-y", "-q", "python3-websockets"],
            ["apt-get", "update", "-q"],  # refresh then retry below
            ["apt-get", "install", "-y", "-q", "python3-websockets"],
            ["apt-get", "install", "-y", "-q", "python3-pip"],
        ])
    install_variants.extend([
        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--quiet", "websockets"],
        [sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", "--quiet", "websockets"],
        [sys.executable, "-m", "pip", "install", "--user", "--quiet", "websockets"],
        [sys.executable, "-m", "pip", "install", "--quiet", "websockets"],
    ])
    log_path = Path.home() / ".shardkeep" / "bootstrap.log"
    log_lines = []
    for cmd in install_variants:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            log_lines.append(
                f"cmd: {' '.join(cmd)}\nexit: {result.returncode}\nstderr: {result.stderr[:200]}\n"
            )
            if result.returncode != 0:
                continue
        except Exception as e:
            log_lines.append(f"cmd: {' '.join(cmd)}\nexception: {e}\n")
            continue
        # Force re-scan of site-packages so --user installs are visible
        try:
            import site, importlib
            importlib.reload(site)
        except Exception:
            pass
        try:
            import websockets  # noqa: F401
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text("SUCCESS via: " + " ".join(cmd) + "\n\n" + "\n".join(log_lines))
            except Exception:
                pass
            return True
        except ImportError:
            continue
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("FAILED all variants\n\n" + "\n".join(log_lines))
    except Exception:
        pass
    return False


HAS_WEBSOCKETS = _ensure_websockets()
if HAS_WEBSOCKETS:
    import websockets

# Collect bootstrap diagnostics
def _collect_bootstrap_info():
    info = {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "user": os.environ.get("USER", "?"),
        "uid": os.getuid() if hasattr(os, "getuid") else -1,
        "home": str(Path.home()),
        "pid": os.getpid(),
        "process_start": int(time.time()),
    }
    # Read previous exit reason (written by atexit handler on previous run)
    exit_file = Path.home() / ".shardkeep" / "last_exit.txt"
    if exit_file.exists():
        try:
            info["prev_exit"] = exit_file.read_text()[:400]
        except Exception:
            pass
    # Persistent startup counter to detect restart loops
    counter_file = Path.home() / ".shardkeep" / "startup_counter"
    try:
        counter = int(counter_file.read_text().strip()) if counter_file.exists() else 0
    except Exception:
        counter = 0
    counter += 1
    try:
        counter_file.parent.mkdir(parents=True, exist_ok=True)
        counter_file.write_text(str(counter))
    except Exception:
        pass
    info["startup_count"] = counter
    try:
        if HAS_WEBSOCKETS:
            info["ws_version"] = getattr(websockets, "__version__", "unknown")
    except Exception as e:
        info["ws_version_err"] = str(e)
    # Has api_key / challenge_secret files on disk
    info["api_key_file"] = (Path.home() / ".shardkeep" / "api_key").exists()
    info["secret_file"] = (Path.home() / ".shardkeep" / "challenge_secret").exists()
    # Read bootstrap log written by _ensure_websockets
    log_path = Path.home() / ".shardkeep" / "bootstrap.log"
    if log_path.exists():
        try:
            info["bootstrap_log"] = log_path.read_text()[:1000]
        except Exception as e:
            info["bootstrap_log_err"] = str(e)
    else:
        info["bootstrap_log"] = "(not written)"
    return info

BOOTSTRAP_INFO = _collect_bootstrap_info()

# Shared WSS state for heartbeat diagnostics
def _count_shards_on_disk() -> int:
    try:
        d = Path.home() / ".shardkeep" / "shards"
        if not d.exists():
            return 0
        return len([p for p in d.iterdir() if p.suffix == ".bin"])
    except Exception:
        return 0

WSS_STATE = {
    "has_websockets": HAS_WEBSOCKETS,
    "has_secret": False,
    "connected": False,
    "last_event": "init",
    "last_error": None,
    "connect_attempts": 0,
    "challenges_handled": 0,
    "shards_held": _count_shards_on_disk(),
    "bootstrap": BOOTSTRAP_INFO,
}

# ─── Configuration ───
DEFAULT_AGGREGATOR = "https://master.shardkeep.io/shardkeep/operator/api/heartbeat.php"
DEFAULT_WS_URL = "wss://master.shardkeep.io/shardkeep/operator/ws"
DEFAULT_INTERVAL = 30  # seconds
CONFIG_DIR = Path.home() / ".shardkeep"
NODE_ID_FILE = CONFIG_DIR / "node_id"
API_KEY_FILE = CONFIG_DIR / "api_key"
CHALLENGE_SECRET_FILE = CONFIG_DIR / "challenge_secret"
CLAIM_CODE_FILE = CONFIG_DIR / "claim_code"   # raw claim code written by the installer


def load_claim_code_hash():
    """sha256 of the raw claim code the installer wrote, or None. The raw code stays
    local (and in the install summary the operator pastes at claim time); only this
    hash is ever sent to the server, so the DB/heartbeat never carry the usable token."""
    try:
        if CLAIM_CODE_FILE.exists():
            raw = CLAIM_CODE_FILE.read_text().strip()
            if raw:
                return hashlib.sha256(raw.encode()).hexdigest()
    except Exception:
        pass
    return None
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_FILE = CONFIG_DIR / "sentry.log"
SHARDS_DIR = CONFIG_DIR / "shards"

# ─── Logging ───
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [" + ROLE_LABEL + "] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE) if CONFIG_DIR.exists() else logging.StreamHandler()
    ]
)
logger = logging.getLogger("sentry")

# ─── Node Identity ───
def get_or_create_node_id():
    """Get existing node ID or generate a new one."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if NODE_ID_FILE.exists():
        node_id = NODE_ID_FILE.read_text().strip()
        logger.info(f"Loaded node ID: {node_id}")
        return node_id

    # Generate a unique node ID from hardware fingerprint
    fingerprint_parts = [
        platform.node(),
        platform.machine(),
        str(uuid.getnode()),  # MAC address as int
    ]
    fingerprint = hashlib.sha256("|".join(fingerprint_parts).encode()).hexdigest()[:16]
    # Role-prefixed ID — self-documents the node's role in admin views.
    # Reads --type from CLI args via the global ARGS captured in main().
    # Falls back to 'sentry' if unavailable (matches pre-0.5.8 behaviour).
    role = (globals().get('ARGS').type if globals().get('ARGS') is not None else None) or 'sentry'
    if role not in ('warden', 'bastion', 'sentry'):
        role = 'sentry'
    node_id = f"{role}-{fingerprint}"

    NODE_ID_FILE.write_text(node_id)
    logger.info(f"Generated new node ID: {node_id}")
    return node_id


def load_api_key():
    """Load API key from file if it exists."""
    if API_KEY_FILE.exists():
        key = API_KEY_FILE.read_text().strip()
        if key:
            return key
    return None


def save_api_key(key):
    """Save API key to file with restricted permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    API_KEY_FILE.write_text(key)
    os.chmod(str(API_KEY_FILE), 0o600)
    logger.info("API key saved to %s", API_KEY_FILE)


def load_challenge_secret():
    """Load challenge secret from file if it exists."""
    if CHALLENGE_SECRET_FILE.exists():
        secret = CHALLENGE_SECRET_FILE.read_text().strip()
        if secret:
            return secret
    return None


def save_challenge_secret(secret):
    """Save challenge secret to file with restricted permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CHALLENGE_SECRET_FILE.write_text(secret)
    os.chmod(str(CHALLENGE_SECRET_FILE), 0o600)
    logger.info("Challenge secret saved to %s", CHALLENGE_SECRET_FILE)


# ─── System Metrics ───
def get_display_hostname():
    """
    Hostname the warden/bastion/sentry reports to the aggregator.

    A single physical host may run multiple ShardKeep roles AND non-ShardKeep
    services, in which case the OS-level hostname (e.g. master.chillxand.com)
    isn't the right name to surface in the warden settings UI. Operators can
    override by writing the desired name to `$CONFIG_DIR/hostname` (one line,
    no trailing newline required). Falls back to platform.node() when absent
    or empty — preserves existing behaviour for nodes that don't set it.
    """
    try:
        override = (CONFIG_DIR / 'hostname').read_text().strip()
        if override:
            return override
    except Exception:
        pass
    return platform.node()


def get_system_info():
    """Collect system health metrics."""
    info = {
        "hostname": get_display_hostname(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
    }

    # CPU info
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
        info["cpu_model"] = next(
            (line.split(":")[1].strip() for line in cpuinfo.split("\n")
             if "model name" in line.lower()), "unknown"
        )
        info["cpu_cores"] = cpuinfo.count("processor")
    except Exception:
        info["cpu_model"] = platform.processor() or "unknown"
        info["cpu_cores"] = os.cpu_count() or 0

    # Memory
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        total = int(next(l for l in meminfo.split("\n") if "MemTotal" in l).split()[1])
        available = int(next(l for l in meminfo.split("\n") if "MemAvailable" in l).split()[1])
        info["memory_total_mb"] = total // 1024
        info["memory_available_mb"] = available // 1024
        info["memory_used_pct"] = round((1 - available / total) * 100, 1)
    except Exception:
        info["memory_total_mb"] = 0
        info["memory_available_mb"] = 0
        info["memory_used_pct"] = 0

    # Disk
    try:
        stat = os.statvfs("/")
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        info["disk_total_gb"] = round(total / (1024**3), 1)
        info["disk_free_gb"] = round(free / (1024**3), 1)
        info["disk_used_pct"] = round((1 - free / total) * 100, 1)
    except Exception:
        info["disk_total_gb"] = 0
        info["disk_free_gb"] = 0
        info["disk_used_pct"] = 0

    # Uptime
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
        info["uptime_hours"] = round(uptime_seconds / 3600, 1)
    except Exception:
        info["uptime_hours"] = 0

    # Load average
    try:
        load = os.getloadavg()
        info["load_1m"] = round(load[0], 2)
        info["load_5m"] = round(load[1], 2)
        info["load_15m"] = round(load[2], 2)
    except Exception:
        info["load_1m"] = 0

    # IP address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip_address"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["ip_address"] = "unknown"

    return info


# ─── Command Handling ───
def handle_commands(commands):
    """Process commands received from the aggregator."""
    results = []
    for cmd in commands:
        cmd_type = cmd.get('type', '')
        if cmd_type == 'system_verify':
            results.append({
                'type': 'system_verify',
                'status': 'ok',
                'message': 'System info included in heartbeat payload'
            })
            logger.info("Processed command: system_verify (acknowledged)")
        elif cmd_type == 'update':
            target_version = cmd.get('target_version', '?')
            update_url = cmd.get('update_url', '')
            logger.info(f"Update command received: target v{target_version}")
            if update_url:
                perform_update(update_url, target_version)
            results.append({
                'type': 'update',
                'status': 'initiated',
                'target_version': target_version
            })
        elif cmd_type == 'reconfigure':
            new_type = cmd.get('node_type', '')
            new_network = cmd.get('network', '')
            logger.info(f"Reconfigure command: type={new_type}, network={new_network}")
            perform_reconfigure(new_type, new_network)
            results.append({
                'type': 'reconfigure',
                'status': 'initiated',
                'node_type': new_type,
                'network': new_network
            })
        elif cmd_type == 'config_change':
            updates = cmd.get('updates', {})
            logger.info(f"Config-change command: {len(updates)} key(s)")
            applied = perform_config_change(updates)
            results.append({
                'type': 'config_change',
                'status': 'applied' if applied else 'noop',
                'keys': list(updates.keys()),
            })
        elif cmd_type == 'install_cert':
            # Backend-issued TLS cert (heartbeat-delivered). Pipe the fullchain to
            # the pinned root helper, which validates it matches our local key,
            # installs it, and reloads apache. Agent stays unprivileged; the only
            # new privilege is `sudo /opt/shardkeep/bin/sk-cert-install` (no args).
            fullchain = cmd.get('fullchain', '') or ''
            if 'BEGIN CERTIFICATE' not in fullchain:
                results.append({'type': 'install_cert', 'status': 'failed', 'error': 'no certificate in payload'})
                logger.warning("install_cert: payload had no certificate")
            else:
                try:
                    r = subprocess.run(
                        ['sudo', '/opt/shardkeep/bin/sk-cert-install'],
                        input=fullchain, text=True, capture_output=True, timeout=30,
                    )
                    if r.returncode == 0:
                        results.append({'type': 'install_cert', 'status': 'installed'})
                        logger.info("install_cert: TLS cert installed + apache reloaded")
                    else:
                        err = (r.stderr or r.stdout or 'helper failed').strip()[:200]
                        results.append({'type': 'install_cert', 'status': 'failed', 'error': err})
                        logger.error("install_cert helper failed: %s", err)
                except Exception as e:
                    results.append({'type': 'install_cert', 'status': 'failed', 'error': str(e)[:200]})
                    logger.error("install_cert error: %s", e)
        elif cmd_type == 'provision_web':
            # Second warden lifecycle (separate from the agent): stand up / refresh
            # the WEB-serving stack via the pinned root rail. Non-destructive.
            logger.info("provision_web command received — running install-web via run-update.sh")
            try:
                r = subprocess.run(
                    ['sudo', '/opt/shardkeep/bin/run-update.sh', 'install-web'],
                    capture_output=True, text=True, timeout=1200,
                )
                if r.returncode == 0:
                    results.append({'type': 'provision_web', 'status': 'ok'})
                    logger.info("provision_web: web-serving stack provisioned/refreshed")
                else:
                    err = (r.stderr or r.stdout or 'install-web failed').strip()[-300:]
                    results.append({'type': 'provision_web', 'status': 'failed', 'error': err})
                    logger.error("provision_web failed: %s", err)
            except Exception as e:
                results.append({'type': 'provision_web', 'status': 'failed', 'error': str(e)[:200]})
                logger.error("provision_web error: %s", e)
        else:
            results.append({
                'type': cmd_type,
                'status': 'unknown_command'
            })
            logger.warning(f"Unknown command type: {cmd_type}")
    return results


def report_update_stage(aggregator_url, node_id, node_type, network, stage, api_key=None):
    """Send a quick status update to the aggregator about the update process."""
    payload = {
        "node_id": node_id,
        "node_type": node_type,
        "network": network,
        "version": AGENT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "update_stage": stage,
        "system": get_system_info(),
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(aggregator_url, data=data, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Best effort — don't block the update


def perform_update(update_url, target_version):
    """Download updated agent and restart the service."""
    import shutil
    # Self-update writes to the file we're currently executing from — that's
    # the binary systemd's ExecStart references. Hardcoding "sentry.py" would
    # leave the unit running a stale copy after migrate.sh renamed the file.
    agent_path = Path(__file__).resolve()
    install_dir = agent_path.parent
    backup_path = agent_path.with_suffix(agent_path.suffix + ".bak")
    fallback_path = CONFIG_DIR / "agent_update.py"

    try:
        # Download new version
        logger.info(f"Downloading update from {update_url}")
        req = urllib.request.Request(update_url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            new_code = resp.read()

        # Try primary install location first
        try:
            if agent_path.exists():
                shutil.copy2(str(agent_path), str(backup_path))
            with open(str(agent_path), 'wb') as f:
                f.write(new_code)
            os.chmod(str(agent_path), 0o755)
            logger.info(f"Updated agent at {agent_path} ({len(new_code)} bytes)")
        except (PermissionError, OSError) as e:
            # ProtectSystem=strict blocks /opt writes — use fallback in home dir
            logger.warning(f"Cannot write to {agent_path}: {e}")
            with open(str(fallback_path), 'wb') as f:
                f.write(new_code)
            os.chmod(str(fallback_path), 0o755)
            logger.info(f"Saved update to fallback {fallback_path} ({len(new_code)} bytes)")

            # Fix the service file to use fallback path AND add ReadWritePaths
            try:
                svc_file = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
                svc_content = svc_file.read_text()
                # Update ExecStart to use fallback path
                import re
                svc_content = re.sub(
                    r'(ExecStart=/usr/bin/python3 )\S+\.py',
                    r'\g<1>' + str(fallback_path),
                    svc_content
                )
                # Add this role's install dir to ReadWritePaths if not present.
                # Home-agnostic: appends to whatever ReadWritePaths line exists
                # (per-role homes make the base path /var/lib/shardkeep/<role>).
                if INSTALL_DIR_STR not in svc_content:
                    svc_content = re.sub(
                        r'(ReadWritePaths=[^\n]*)',
                        r'\g<1> ' + INSTALL_DIR_STR,
                        svc_content, count=1
                    )
                os.system(f"sudo bash -c 'echo \"{svc_content}\" > {svc_file} && systemctl daemon-reload'")
                logger.info("Updated service file with fallback path + ReadWritePaths fix")
            except Exception as svc_err:
                logger.warning(f"Could not update service file: {svc_err}")

        # Exit to trigger systemd auto-restart with the new code
        logger.info("Update applied — exiting for systemd auto-restart...")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Update failed: {e}")
        if backup_path.exists():
            try:
                shutil.copy2(str(backup_path), str(agent_path))
                logger.info("Restored backup after failed update")
            except (PermissionError, OSError):
                pass


# Whitelist of keys the server is allowed to push via config_change.
# Each maps to a strict validator. New runtime flags get added here.
_CONFIG_CHANGE_VALIDATORS = {
    'AGGREGATOR_URL':    lambda v: isinstance(v, str) and v.startswith('https://') and len(v) <= 256,
    'WS_URL':            lambda v: isinstance(v, str) and v.startswith('wss://')   and len(v) <= 256,
    'NODE_TYPE':         lambda v: v in ('warden', 'bastion', 'sentry'),
    'NETWORK':           lambda v: v in ('testnet', 'devnet', 'mainnet'),
    'HEARTBEAT_INTERVAL': lambda v: isinstance(v, (int, str)) and str(v).isdigit() and 10 <= int(v) <= 300,
}

# Home-relative so per-role homes (/var/lib/shardkeep/<role>) get their own
# runtime.env. Existing shared-user installs keep HOME=/var/lib/shardkeep, so
# CONFIG_DIR resolves to /var/lib/shardkeep/.shardkeep — the exact legacy path.
RUNTIME_ENV_PATH = CONFIG_DIR / "runtime.env"


def perform_config_change(updates):
    """
    Merge server-pushed updates into runtime.env, then restart so systemd
    re-reads the EnvironmentFile and execs with the new flag values.

    `updates` is a dict like {"AGGREGATOR_URL": "...", "NETWORK": "mainnet"}.
    Unknown keys and values that fail validation are skipped + logged. The
    file is rewritten only when at least one valid change is in flight.
    """
    if not isinstance(updates, dict) or not updates:
        return False

    # Validate first; never write a partial/bad file
    valid = {}
    for k, v in updates.items():
        validator = _CONFIG_CHANGE_VALIDATORS.get(k)
        if validator is None:
            logger.warning(f"config_change: rejecting unknown key '{k}'")
            continue
        if not validator(v):
            logger.warning(f"config_change: rejecting invalid value for '{k}': {v!r}")
            continue
        valid[k] = str(v)

    if not valid:
        logger.warning("config_change: no valid updates after validation; nothing to do")
        return False

    if not RUNTIME_ENV_PATH.exists():
        logger.error(f"config_change: {RUNTIME_ENV_PATH} not found — node likely on pre-EnvironmentFile shape; run migrate.sh first")
        return False

    # Read existing → merge → write atomically
    try:
        existing = {}
        for line in RUNTIME_ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            if '=' not in line: continue
            k, _, v = line.partition('=')
            existing[k.strip()] = v.strip()

        for k, v in valid.items():
            existing[k] = v

        # Atomic rewrite via tmp + rename
        tmp = RUNTIME_ENV_PATH.with_suffix('.env.tmp')
        tmp.write_text(''.join(f'{k}={v}\n' for k, v in existing.items()))
        os.replace(str(tmp), str(RUNTIME_ENV_PATH))
        logger.info(f"config_change: updated {list(valid.keys())} — restarting to apply")
    except Exception as e:
        logger.error(f"config_change: failed to write {RUNTIME_ENV_PATH}: {e}")
        return False

    # Restart self via the existing sudoers entry. systemd reloads
    # EnvironmentFile before exec → new values are live in the next process.
    rc = os.system(f'sudo systemctl restart {SERVICE_NAME}')
    if rc != 0:
        logger.error(f"config_change: restart returned {rc}; new values will take effect on next service start")
    return True


def perform_reconfigure(new_type, new_network):
    """Update the systemd service file with new type/network and restart."""
    service_path = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

    if not service_path.exists():
        logger.error("Cannot reconfigure — service file not found")
        return

    try:
        content = service_path.read_text()
        original = content

        # Update --type flag
        if new_type and new_type in ('warden', 'bastion', 'sentry'):
            import re
            content = re.sub(r'--type\s+\w+', f'--type {new_type}', content)
            logger.info(f"Service config: --type set to {new_type}")

        # Update --network flag
        if new_network and new_network in ('testnet', 'devnet', 'mainnet'):
            import re
            content = re.sub(r'--network\s+\w+', f'--network {new_network}', content)
            logger.info(f"Service config: --network set to {new_network}")

        if content != original:
            service_path.write_text(content)
            logger.info("Service file updated — reloading and restarting...")
            # Note: writing the unit file + daemon-reload requires real root.
            # If we're running as the unprivileged shardkeep user, the unit
            # write above fails first — the sudo here is only for the case
            # where this runs from migrate.sh / install.sh as root.
            os.system('sudo systemctl daemon-reload')
            os.system(f'sudo systemctl restart {SERVICE_NAME}')
            sys.exit(0)
        else:
            logger.info("No changes needed in service config")

    except Exception as e:
        logger.error(f"Reconfigure failed: {e}")


# ─── Heartbeat ───
def send_heartbeat(aggregator_url, node_id, node_type, network, system_info, api_key=None, command_results=None):
    """Send a heartbeat to the aggregator."""
    # Always recompute shards_held from disk so the counter stays accurate even
    # if the in-memory state drifted (e.g. after a failed delivery retry).
    WSS_STATE["shards_held"] = _count_shards_on_disk()
    payload = {
        "node_id": node_id,
        "node_type": node_type,
        "network": network,
        "version": AGENT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system_info,
        "wss_state": dict(WSS_STATE),
    }

    # Report the claim-code hash (installer-generated) so an unbound node can be
    # claimed by whoever holds the raw code. Only sent until the node is bound.
    _cch = load_claim_code_hash()
    if _cch:
        payload["claim_code_hash"] = _cch

    # Warden TLS: include our CSR so the backend can (re)issue the node's cert and
    # deliver it back via an install_cert command. The installer writes this file
    # ONLY on nodes provisioned for heartbeat-delivered certs (wardens), so this is
    # a no-op everywhere else. The CSR is public; the private key never leaves here.
    try:
        _csr_path = Path('/etc/shardkeep/tls/node.csr')
        if _csr_path.is_file() and _csr_path.stat().st_size < 8000:
            _csr = _csr_path.read_text()
            if 'CERTIFICATE REQUEST' in _csr:
                payload["tls_csr"] = _csr
    except Exception:
        pass

    if command_results:
        payload["command_results"] = command_results

    # Include Sentry verification result from previous task
    global _pending_verify_result
    if _pending_verify_result:
        payload["verify_result"] = _pending_verify_result
        _pending_verify_result = None

    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    # Include API key if we have one
    if api_key:
        headers["X-API-Key"] = api_key

    req = urllib.request.Request(
        aggregator_url,
        data=data,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            return True, body
    except urllib.error.HTTPError as e:
        try:
            error_body = json.loads(e.read().decode())
            return False, f"HTTP {e.code}: {error_body.get('error', e.reason)}"
        except Exception:
            return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Connection failed: {e.reason}"
    except Exception as e:
        return False, str(e)


# ─── Sentry Verification ───
_pending_verify_result = None

async def execute_verify_task(aggregator_url, task):
    """Execute a shard verification task by calling the API."""
    global _pending_verify_result
    task_id = task.get('task_id')
    shard_id = task.get('shard_id')
    if not task_id or not shard_id:
        return

    logger.info(f"Verify task {task_id[:8]}... for shard {shard_id[:12]}...")

    # Build the verify API URL (same base as aggregator, different endpoint)
    verify_url = aggregator_url.rsplit('/', 1)[0] + '/shards.php'
    payload = json.dumps({'action': 'sentry-verify', 'task_id': task_id, 'shard_id': shard_id}).encode('utf-8')

    try:
        req = urllib.request.Request(verify_url, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            responded = result.get('bastion_responded', False)
            passed = result.get('bastion_passed', False)
            latency = result.get('latency_ms', 0)
            logger.info(f"Verify complete: responded={responded}, passed={passed}, latency={latency}ms")
            _pending_verify_result = {'task_id': task_id, 'passed': passed, 'latency_ms': latency}
    except Exception as e:
        logger.warning(f"Verify task failed: {e}")
        _pending_verify_result = {'task_id': task_id, 'error': str(e)}


# ─── WebSocket Challenge Client ───
async def ws_challenge_client(ws_url, node_id, api_key, challenge_secret, running_event):
    """Maintain a persistent WebSocket connection for challenge responses."""
    WSS_STATE["last_event"] = "ws_client_entered"
    WSS_STATE["has_secret"] = bool(challenge_secret)
    WSS_STATE["secret_len"] = len(challenge_secret) if challenge_secret else 0
    WSS_STATE["api_key_len"] = len(api_key) if api_key else 0
    if not HAS_WEBSOCKETS:
        WSS_STATE["last_event"] = "no_websockets_pkg"
        logger.warning("websockets package not installed — WSS challenges disabled")
        return

    if not challenge_secret:
        WSS_STATE["last_event"] = "no_secret"
        logger.info("No challenge secret yet — WSS will start after authentication")
        return

    backoff = 5
    max_backoff = 120

    while not running_event.is_set():
        try:
            WSS_STATE["connect_attempts"] += 1
            WSS_STATE["last_event"] = "connecting"
            logger.info(f"Connecting to WSS: {ws_url}")
            async with websockets.connect(
                ws_url,
                close_timeout=5,
                ping_interval=30,
                ping_timeout=60,
                max_size=2**20,
            ) as ws:
                # Authenticate
                await ws.send(json.dumps({
                    "type": "auth",
                    "node_id": node_id,
                    "api_key": api_key,
                }))

                # Wait for auth response
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                resp = json.loads(raw)

                if resp.get("type") != "auth_ok":
                    WSS_STATE["last_event"] = "auth_failed"
                    WSS_STATE["last_error"] = str(resp)[:200]
                    logger.error(f"WSS auth failed: {resp}")
                    await asyncio.sleep(30)
                    continue

                WSS_STATE["connected"] = True
                WSS_STATE["last_event"] = "connected"
                WSS_STATE["last_error"] = None
                logger.info(f"WSS connected — Epoch {resp.get('epoch')}, Block {resp.get('block')}")
                backoff = 5  # Reset backoff on successful connect

                # Receive loop — explicit ws.recv() is more portable across
                # websockets versions than `async for raw in ws:`.
                msg_count = 0
                while not running_event.is_set():
                    try:
                        raw = await ws.recv()
                    except Exception as recv_exc:
                        WSS_STATE["last_event"] = "recv_loop_exc"
                        WSS_STATE["last_error"] = f"{type(recv_exc).__name__}: {str(recv_exc)[:200]} (msgs={msg_count})"
                        raise
                    msg_count += 1
                    try:
                        msg = json.loads(raw)
                        await handle_ws_message(ws, msg, challenge_secret)
                    except json.JSONDecodeError:
                        logger.warning("Invalid JSON from WSS server")
                    except Exception as e:
                        logger.error(f"WSS message error: {e}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            WSS_STATE["connected"] = False
            WSS_STATE["last_event"] = "connection_lost"
            WSS_STATE["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
            logger.warning(f"WSS connection lost: {e}")

        WSS_STATE["connected"] = False

        if running_event.is_set():
            break

        # Reconnect with exponential backoff + jitter
        jitter = int.from_bytes(os.urandom(1), 'big') / 255.0 * 5  # 0-5s jitter
        wait = min(backoff + jitter, max_backoff)
        logger.info(f"WSS reconnecting in {wait:.1f}s...")
        await asyncio.sleep(wait)
        backoff = min(backoff * 2, max_backoff)


def shard_path(shard_id_hex: str, ext: str = "bin") -> Path:
    SHARDS_DIR.mkdir(parents=True, exist_ok=True)
    # Validate hex-only to prevent path traversal
    if not all(c in "0123456789abcdefABCDEF" for c in shard_id_hex):
        raise ValueError(f"invalid shard_id_hex: {shard_id_hex}")
    return SHARDS_DIR / f"{shard_id_hex.lower()}.{ext}"


def store_shard_locally(shard_id_hex: str, shard_data: bytes, hmac_key_hex: str) -> int:
    """Write shard bytes + HMAC key to disk. Returns bytes written."""
    p = shard_path(shard_id_hex, "bin")
    p.write_bytes(shard_data)
    os.chmod(str(p), 0o600)
    k = shard_path(shard_id_hex, "key")
    k.write_bytes(bytes.fromhex(hmac_key_hex))
    os.chmod(str(k), 0o600)
    return len(shard_data)


def delete_shard_locally(shard_id_hex: str) -> bool:
    p = shard_path(shard_id_hex, "bin")
    k = shard_path(shard_id_hex, "key")
    removed = False
    for f in (p, k):
        if f.exists():
            f.unlink()
            removed = True
    return removed


def read_shard_locally(shard_id_hex: str) -> tuple[bytes, bytes] | None:
    """Return (shard_bytes, hmac_key) or None if not found."""
    p = shard_path(shard_id_hex, "bin")
    k = shard_path(shard_id_hex, "key")
    if not p.exists() or not k.exists():
        return None
    return p.read_bytes(), k.read_bytes()


async def handle_ws_message(ws, msg, challenge_secret):
    """Handle a message from the WSS server."""
    msg_type = msg.get("type", "")

    if msg_type == "challenge":
        nonce = msg.get("nonce", "")
        challenge_id = msg.get("challenge_id", "")

        if not nonce or not challenge_id:
            return
        WSS_STATE["challenges_handled"] += 1

        # Compute HMAC-SHA256 response
        response_hmac = hmac_mod.new(
            challenge_secret.encode(),
            nonce.encode(),
            hashlib.sha256,
        ).hexdigest()

        await ws.send(json.dumps({
            "type": "challenge_response",
            "challenge_id": challenge_id,
            "hmac": response_hmac,
        }))

        logger.debug(f"Challenge {challenge_id[:8]} responded")

    elif msg_type == "store_shard":
        shard_id = msg.get("shard_id", "")
        try:
            shard_data = base64.b64decode(msg.get("shard_data", ""))
            hmac_key_hex = msg.get("hmac_key", "")
            size = store_shard_locally(shard_id, shard_data, hmac_key_hex)
            WSS_STATE["shards_held"] = WSS_STATE.get("shards_held", 0) + 1
            await ws.send(json.dumps({
                "type": "shard_stored",
                "shard_id": shard_id,
                "ok": True,
                "size": size,
            }))
            logger.info(f"Stored shard {shard_id[:8]} ({size} bytes)")
        except Exception as e:
            await ws.send(json.dumps({
                "type": "shard_stored",
                "shard_id": shard_id,
                "ok": False,
                "error": f"{type(e).__name__}: {str(e)[:120]}",
            }))
            logger.error(f"Failed to store shard {shard_id[:8]}: {e}")

    elif msg_type == "verify_shard":
        shard_id = msg.get("shard_id", "")
        challenge_id = msg.get("challenge_id", "")
        try:
            nonce = base64.b64decode(msg.get("nonce", ""))
            result = read_shard_locally(shard_id)
            if result is None:
                await ws.send(json.dumps({
                    "type": "verify_response",
                    "shard_id": shard_id,
                    "challenge_id": challenge_id,
                    "hmac": "",
                    "error": "not_found",
                }))
                return
            _, hmac_key = result
            resp = hmac_mod.new(hmac_key, nonce, hashlib.sha256).digest()
            await ws.send(json.dumps({
                "type": "verify_response",
                "shard_id": shard_id,
                "challenge_id": challenge_id,
                "hmac": base64.b64encode(resp).decode("ascii"),
            }))
        except Exception as e:
            logger.error(f"verify_shard {shard_id[:8]} handler error: {e}")

    elif msg_type == "fetch_shard":
        shard_id = msg.get("shard_id", "")
        request_id = msg.get("request_id", "")
        try:
            result = read_shard_locally(shard_id)
            if result is None:
                await ws.send(json.dumps({
                    "type": "shard_data",
                    "shard_id": shard_id,
                    "request_id": request_id,
                    "ok": False,
                    "error": "not_found",
                }))
                logger.warning(f"fetch_shard {shard_id[:8]}: not found")
            else:
                shard_bytes, _ = result
                await ws.send(json.dumps({
                    "type": "shard_data",
                    "shard_id": shard_id,
                    "request_id": request_id,
                    "ok": True,
                    "data": base64.b64encode(shard_bytes).decode("ascii"),
                }))
                logger.info(f"fetch_shard {shard_id[:8]} served ({len(shard_bytes)} bytes)")
        except Exception as e:
            await ws.send(json.dumps({
                "type": "shard_data",
                "shard_id": shard_id,
                "request_id": request_id,
                "ok": False,
                "error": f"{type(e).__name__}: {str(e)[:120]}",
            }))

    elif msg_type == "delete_shard":
        shard_id = msg.get("shard_id", "")
        try:
            removed = delete_shard_locally(shard_id)
            if removed and WSS_STATE.get("shards_held", 0) > 0:
                WSS_STATE["shards_held"] = WSS_STATE["shards_held"] - 1
            await ws.send(json.dumps({
                "type": "shard_deleted",
                "shard_id": shard_id,
                "ok": True,
                "existed": removed,
            }))
            logger.info(f"Deleted shard {shard_id[:8]} (existed={removed})")
        except Exception as e:
            await ws.send(json.dumps({
                "type": "shard_deleted",
                "shard_id": shard_id,
                "ok": False,
                "error": f"{type(e).__name__}: {str(e)[:120]}",
            }))
            logger.error(f"Failed to delete shard {shard_id[:8]}: {e}")

    elif msg_type == "purge_stale":
        # Server sends list of valid shard IDs — delete everything else
        valid_ids = set(s.lower() for s in msg.get("valid_shard_ids", []))
        try:
            purged = 0
            kept = 0
            if SHARDS_DIR.exists():
                for f in SHARDS_DIR.iterdir():
                    if f.suffix not in (".bin", ".key"):
                        continue
                    file_shard_id = f.stem.lower()
                    if file_shard_id not in valid_ids:
                        f.unlink()
                        purged += 1
                    else:
                        kept += 1
            WSS_STATE["shards_held"] = _count_shards_on_disk()
            await ws.send(json.dumps({
                "type": "purge_result",
                "ok": True,
                "purged": purged,
                "kept": kept,
                "shards_held": WSS_STATE["shards_held"],
            }))
            logger.info(f"Purge stale: removed {purged} files, kept {kept}, shards_held={WSS_STATE['shards_held']}")
        except Exception as e:
            await ws.send(json.dumps({
                "type": "purge_result",
                "ok": False,
                "error": f"{type(e).__name__}: {str(e)[:120]}",
            }))
            logger.error(f"Purge stale failed: {e}")

    elif msg_type == "ping":
        await ws.send(json.dumps({"type": "pong"}))

    else:
        logger.debug(f"WSS message: {msg_type}")


# ─── Async Heartbeat Loop ───
async def heartbeat_loop(args, node_id, running_event):
    """Async wrapper around the synchronous heartbeat loop."""
    api_key = load_api_key()
    challenge_secret = load_challenge_secret()

    consecutive_failures = 0
    total_heartbeats = 0
    total_successes = 0
    pending_command_results = None
    last_status = None

    # Start WSS client task if we have credentials
    ws_task = None
    WSS_STATE["last_event"] = (
        f"startup: api_key={'yes' if api_key else 'no'}, "
        f"secret={'yes' if challenge_secret else 'no'}, "
        f"ws_pkg={'yes' if HAS_WEBSOCKETS else 'no'}"
    )
    if api_key and HAS_WEBSOCKETS:
        try:
            # ensure_future is more broadly available than create_task on older asyncio
            ws_task = asyncio.ensure_future(
                ws_challenge_client(args.ws_url, node_id, api_key, challenge_secret, running_event)
            )
            WSS_STATE["last_event"] = "task_scheduled"
            # Yield to the event loop so the coroutine starts before the first heartbeat
            await asyncio.sleep(0.1)
            if ws_task.done():
                try:
                    ws_task.result()
                    WSS_STATE["last_event"] = "task_completed_early"
                except Exception as exc:
                    WSS_STATE["last_event"] = "task_crashed_early"
                    WSS_STATE["last_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        except Exception as e:
            WSS_STATE["last_event"] = "task_create_failed"
            WSS_STATE["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
            logger.error(f"Failed to create WSS task: {e}")

    while not running_event.is_set():
        system_info = get_system_info()

        # Run synchronous heartbeat in executor to avoid blocking
        loop = asyncio.get_event_loop()
        success, response = await loop.run_in_executor(
            None, send_heartbeat,
            args.aggregator, node_id, args.type, args.network,
            system_info, api_key, pending_command_results
        )
        pending_command_results = None

        total_heartbeats += 1
        if success:
            total_successes += 1
            consecutive_failures = 0

            # Track qualification status changes
            new_status = response.get('qualification_status')
            if new_status and new_status != last_status:
                logger.info(f"Qualification status: {last_status or '(init)'} -> {new_status}")
                last_status = new_status

            # Handle API key + challenge secret receipt
            # Server-side prefix shim has remapped this heartbeat to a
            # canonical role-prefixed id (warden-* / bastion-* / sentry-*).
            # Overwrite the local node_id file so future heartbeats use the
            # canonical id directly, then exit so systemd restarts the agent
            # — the in-memory `node_id` and api_key are tied to the old id.
            new_id = response.get('adopt_node_id')
            if new_id and new_id != node_id:
                logger.warning("=" * 60)
                logger.warning("ADOPTING canonical node_id: %s -> %s", node_id, new_id)
                logger.warning("=" * 60)
                try:
                    NODE_ID_FILE.write_text(new_id)
                    # Drop API key — it was issued for the OLD id; server
                    # will reissue against the new id on next heartbeat.
                    if API_KEY_FILE.exists():
                        API_KEY_FILE.unlink()
                except Exception as e:
                    logger.error("Could not persist adopted node_id: %s", e)
                logger.info("Restarting to pick up new id...")
                os.system(f'sudo systemctl restart {SERVICE_NAME}')
                return

            if response.get('api_key'):
                raw_key = response['api_key']
                save_api_key(raw_key)
                api_key = raw_key

                # Save challenge secret if provided
                if response.get('challenge_secret'):
                    save_challenge_secret(response['challenge_secret'])
                    challenge_secret = response['challenge_secret']

                # Save WS URL if provided
                if response.get('ws_url'):
                    logger.info(f"WSS URL received: {response['ws_url']}")

                logger.info("API key received and saved — restarting to use authenticated mode...")
                # Set running_event first so the WSS challenge task winds down
                # cleanly via its `while not running_event.is_set()` checks.
                # Without this, sys.exit() / systemd restart kills the loop
                # mid-await and floods journalctl with "Task was destroyed
                # but it is pending!" tracebacks.
                running_event.set()
                # Sudoers grants `sudo systemctl restart shardkeep-sentry` for
                # the shardkeep user — without sudo, polkit refuses with
                # "Interactive authentication required".
                os.system(f'sudo systemctl restart {SERVICE_NAME}')
                return

            # Handle commands from aggregator
            if response.get('commands'):
                pending_command_results = handle_commands(response['commands'])

            # Migration nudge — server detected we're posting via the legacy
            # chillxand reverse-proxy. We can't auto-migrate (running as the
            # unprivileged shardkeep user; migrate.sh requires full root).
            # Surface a loud journal warning every cycle and a marker file so
            # the operator can spot stale nodes at a glance.
            mig = response.get('migration_required')
            if mig:
                logger.warning("=" * 70)
                logger.warning("MIGRATION REQUIRED — %s", mig.get('reason', 'aggregator URL is stale'))
                logger.warning("Observed via: %s", mig.get('observed_via', 'unknown'))
                logger.warning("Canonical:    %s", mig.get('canonical_url', '(see ops)'))
                logger.warning("Run on this host as root:")
                logger.warning("  %s", mig.get('migrate_command', '(contact ShardKeep ops)'))
                logger.warning("=" * 70)
                try:
                    marker = CONFIG_DIR / 'MIGRATION_REQUIRED'
                    marker.write_text(
                        f"{datetime.now(timezone.utc).isoformat()}\n"
                        f"reason: {mig.get('reason','')}\n"
                        f"observed_via: {mig.get('observed_via','')}\n"
                        f"canonical_url: {mig.get('canonical_url','')}\n"
                        f"command: {mig.get('migrate_command','')}\n"
                    )
                except Exception as e:
                    logger.debug(f"Could not write MIGRATION_REQUIRED marker: {e}")

            # Handle Sentry verification task
            if response.get('verify_task'):
                vtask = response['verify_task']
                asyncio.ensure_future(execute_verify_task(args.aggregator, vtask))

            hb_num = response.get('heartbeat', total_heartbeats)
            status_str = f" [{new_status}]" if new_status else ""
            logger.info(f"Heartbeat #{hb_num} sent OK{status_str} ({total_successes}/{total_heartbeats} success)")
        else:
            consecutive_failures += 1
            logger.warning(f"Heartbeat #{total_heartbeats} failed: {response} (failures: {consecutive_failures})")

            # Back off on repeated failures
            if consecutive_failures > 5:
                backoff_time = min(consecutive_failures * args.interval, 300)
                logger.warning(f"Backing off for {backoff_time}s after {consecutive_failures} consecutive failures")
                await asyncio.sleep(backoff_time)
                continue

        # Wait for next interval (interruptible)
        try:
            await asyncio.wait_for(running_event.wait(), timeout=args.interval)
        except asyncio.TimeoutError:
            pass

    # Clean up WSS task
    if ws_task and not ws_task.done():
        ws_task.cancel()
        try:
            await ws_task
        except asyncio.CancelledError:
            pass

    logger.info(f"Sentry stopped. Total heartbeats: {total_heartbeats}, successes: {total_successes}")


# ─── Legacy Migration ───
def migrate_from_legacy():
    """Detect and migrate from exnus-xnode or citadel-sentry to shardkeep-sentry.

    When an OTA update delivers new sentry.py code to an old node, the code
    initially runs from the old path (e.g. /opt/exnus-xnode/xnode.py) under the
    old service (exnus-xnode). This function detects that situation and:

      1. Copies config files from ~/.exnus/ → ~/.shardkeep/ (preserving node_id)
      2. Copies the agent script to /opt/shardkeep-sentry/sentry.py
      3. Creates the shardkeep-sentry.service with correct aggregator/WSS URLs
      4. Enables + starts the new service, disables the old one
      5. Exits so the new service takes over

    If already running on the new paths, this is a no-op.
    """
    import shutil
    import re

    current_script = Path(__file__).resolve()
    new_install_dir = Path("/opt/shardkeep-sentry")
    new_agent_path = new_install_dir / "sentry.py"

    # Legacy service names and their config directories
    legacy_map = {
        "exnus-xnode": Path.home() / ".exnus",
        "citadel-sentry": Path.home() / ".citadel",
    }

    # Detect which legacy service we're running under
    legacy_service = None
    for svc_name, config_dir in legacy_map.items():
        svc_file = Path(f"/etc/systemd/system/{svc_name}.service")
        if svc_file.exists():
            try:
                content = svc_file.read_text()
                # Check if the ExecStart references the current script or its parent dir
                if str(current_script) in content or str(current_script.parent) in content:
                    legacy_service = svc_name
                    break
            except Exception:
                continue

    if not legacy_service:
        # Not running from a legacy service — either already migrated or fresh install
        return

    print(f"[Migration] Detected legacy service: {legacy_service}")
    old_config_dir = legacy_map[legacy_service]

    # Parse current service file to extract --type and --network flags
    svc_file = Path(f"/etc/systemd/system/{legacy_service}.service")
    svc_content = svc_file.read_text()
    node_type = "sentry"
    network = "testnet"
    svc_user = "root"

    type_match = re.search(r'--type\s+(\w+)', svc_content)
    if type_match:
        t = type_match.group(1)
        # Map old type names to new ones
        type_remap = {"operator": "warden", "vault": "bastion", "xnode": "sentry"}
        node_type = type_remap.get(t, t)

    net_match = re.search(r'--network\s+(\w+)', svc_content)
    if net_match:
        network = net_match.group(1)

    user_match = re.search(r'^User=(.+)$', svc_content, re.MULTILINE)
    if user_match:
        svc_user = user_match.group(1).strip()

    home_match = re.search(r'^Environment=HOME=(.+)$', svc_content, re.MULTILINE)
    svc_home = home_match.group(1).strip() if home_match else f"/{'root' if svc_user == 'root' else 'home/' + svc_user}"

    print(f"[Migration] Type: {node_type}, Network: {network}, User: {svc_user}")

    # Step 1: Migrate config directory
    new_config = Path(svc_home) / ".shardkeep"
    new_config.mkdir(parents=True, exist_ok=True)

    if old_config_dir.exists():
        for fname in ["node_id", "api_key", "challenge_secret", "config.json"]:
            old_file = old_config_dir / fname
            new_file = new_config / fname
            if old_file.exists() and not new_file.exists():
                shutil.copy2(str(old_file), str(new_file))
                print(f"[Migration] Copied {fname}")

        # Migrate shards directory
        old_shards = old_config_dir / "shards"
        new_shards = new_config / "shards"
        if old_shards.exists() and not new_shards.exists():
            shutil.copytree(str(old_shards), str(new_shards))
            print(f"[Migration] Copied shards directory")

    # Step 2: Copy agent to new install directory
    new_install_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(current_script), str(new_agent_path))
    os.chmod(str(new_agent_path), 0o755)
    print(f"[Migration] Installed agent to {new_agent_path}")

    # Step 3: Create new systemd service
    new_svc_content = f"""[Unit]
Description=ShardKeep Sentry Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={svc_user}
ExecStart=/usr/bin/python3 {new_agent_path} --aggregator {DEFAULT_AGGREGATOR} --interval 30 --type {node_type} --network {network} --ws-url {DEFAULT_WS_URL}
Restart=always
RestartSec=10
Environment=HOME={svc_home}

[Install]
WantedBy=multi-user.target
"""

    new_svc_path = Path("/etc/systemd/system/shardkeep-sentry.service")
    new_svc_path.write_text(new_svc_content)
    print(f"[Migration] Created {new_svc_path}")

    # Step 4: Reload, enable new, start new, disable old
    os.system("systemctl daemon-reload")
    os.system("systemctl enable shardkeep-sentry")
    os.system("systemctl start shardkeep-sentry")
    print(f"[Migration] Started shardkeep-sentry service")

    # Disable and stop old service (don't delete — keep for rollback)
    os.system(f"systemctl disable {legacy_service}")
    os.system(f"systemctl stop {legacy_service}")
    print(f"[Migration] Disabled {legacy_service} service")

    print("[Migration] Complete — new service running, exiting old process")
    sys.exit(0)


# ─── Main ───
def ensure_sudoers():
    """Create sudoers rule so shardkeep user can restart its own service and set hostname."""
    try:
        sudoers_file = Path("/etc/sudoers.d/shardkeep-sentry")
        if not sudoers_file.exists():
            rule = "shardkeep ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart shardkeep-sentry, /usr/bin/systemctl stop shardkeep-sentry, /usr/bin/systemctl start shardkeep-sentry, /usr/bin/hostnamectl\n"
            sudoers_file.write_text(rule)
            os.chmod(str(sudoers_file), 0o440)
            logger.info("Created sudoers rule for service management")
    except (PermissionError, OSError):
        pass  # Not running as root — skip (migration script handles this)


def sync_hostname():
    """Ensure the live hostname matches /etc/hostname (applies pending renames)."""
    try:
        etc_hostname = Path("/etc/hostname").read_text().strip()
        live_hostname = os.popen("hostname").read().strip()
        if etc_hostname and etc_hostname != live_hostname:
            os.system(f"sudo hostnamectl set-hostname {etc_hostname}")
            logger.info(f"Hostname synced: {live_hostname} → {etc_hostname}")
    except Exception:
        pass  # Non-fatal — hostname will update on next reboot


def main():
    # Ensure sudoers rule exists for service management
    ensure_sudoers()

    # Sync hostname from /etc/hostname if needed
    sync_hostname()

    # Check for legacy service migration before anything else
    migrate_from_legacy()

    parser = argparse.ArgumentParser(description="ShardKeep Sentry Agent")
    parser.add_argument("--aggregator", default=DEFAULT_AGGREGATOR, help="Aggregator URL")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Heartbeat interval (seconds)")
    parser.add_argument("--type", default="sentry", choices=["warden", "bastion", "sentry"], help="Node type (warden/bastion/sentry)")
    parser.add_argument("--network", default="testnet", choices=["testnet", "devnet", "mainnet"], help="Network (testnet/devnet/mainnet)")
    parser.add_argument("--ws-url", default=DEFAULT_WS_URL, help="WebSocket server URL")
    args = parser.parse_args()

    # Expose parsed args at module scope so get_or_create_node_id() (called
    # below) can use args.type to choose the role-prefixed node_id.
    global ARGS, ROLE, ROLE_LABEL, SERVICE_NAME, INSTALL_DIR_STR
    ARGS = args

    # Lock in role-derived identity now that --type is known. Used everywhere
    # downstream (log prefix, install path, service name, sudoers, restarts).
    ROLE = args.type if args.type in ('warden', 'bastion', 'sentry') else 'sentry'
    ROLE_LABEL = ROLE.capitalize()
    SERVICE_NAME = f'shardkeep-{ROLE}'
    INSTALL_DIR_STR = f'/opt/shardkeep/{ROLE}'

    # Update root logger format to use the role label (was hardcoded [Sentry]
    # at module-import time, before --type was known).
    for h in logging.getLogger().handlers + logger.handlers:
        h.setFormatter(logging.Formatter(
            f"%(asctime)s [{ROLE_LABEL}] %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))

    # Ensure config directory exists
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Update file handler now that directory exists
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter(
        f"%(asctime)s [{ROLE_LABEL}] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(file_handler)

    node_id = get_or_create_node_id()
    api_key = load_api_key()
    challenge_secret = load_challenge_secret()

    logger.info("=" * 50)
    logger.info(f"ShardKeep {ROLE_LABEL} Agent v{AGENT_VERSION}")
    logger.info(f"Node ID:     {node_id}")
    logger.info(f"Node Type:   {args.type}")
    logger.info(f"Network:     {args.network}")
    logger.info(f"Aggregator:  {args.aggregator}")
    logger.info(f"WSS URL:     {args.ws_url}")
    logger.info(f"Interval:    {args.interval}s")
    logger.info(f"API Key:     {'loaded' if api_key else 'none (will authenticate)'}")
    logger.info(f"Challenge:   {'loaded' if challenge_secret else 'none'}")
    logger.info(f"WebSockets:  {'available' if HAS_WEBSOCKETS else 'NOT INSTALLED'}")
    logger.info("=" * 50)

    # Create the event loop FIRST and make it current, then create asyncio.Event
    # so it binds to the correct loop (critical for Python 3.7 compat — otherwise
    # "got Future attached to a different loop" RuntimeError crashes the agent).
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    running_event = asyncio.Event()

    def shutdown_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        loop.call_soon_threadsafe(running_event.set)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    exit_file = CONFIG_DIR / "last_exit.txt"
    try:
        loop.run_until_complete(heartbeat_loop(args, node_id, running_event))
        loop.close()
        try:
            exit_file.write_text(f"normal exit at {datetime.now(timezone.utc).isoformat()}")
        except Exception:
            pass
    except BaseException as exc:
        import traceback
        tb = traceback.format_exc()
        try:
            exit_file.write_text(f"crash at {datetime.now(timezone.utc).isoformat()}\n{type(exc).__name__}: {exc}\n\n{tb}")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
