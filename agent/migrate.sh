#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# ShardKeep — Node Migration Script v4 (role-detect + delegate)
#
# Migrates a node to the role-specific layout:
#   /opt/shardkeep/{role}/agent.py
#   /etc/systemd/system/shardkeep-{role}.service
#   /etc/sudoers.d/shardkeep-{role}
#
# Handles three starting states:
#   1. Brand-new host (no existing service)        → fresh install at new layout
#   2. Legacy shardkeep-sentry (any role inside)   → rename to shardkeep-{role}
#   3. Already on new shardkeep-{role} layout      → no-op (idempotent)
#
# Also handles the older exnus-xnode / citadel-sentry layouts via the same
# legacy detection chain.
#
# Run on each node via:
#   curl -sSL https://master.shardkeep.io/shardkeep/operator/agent/migrate.sh | sudo bash
#
# Optional: pass role + network for fresh installs:
#   ... | sudo bash -s bastion devnet
#
# Safe to run multiple times.
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

AGENT_URL_BASE="https://master.shardkeep.io/shardkeep/operator/agent"
AGENT_URL="$AGENT_URL_BASE/agent.py"
RUN_UPDATE_URL="$AGENT_URL_BASE/run-update.sh"
MASTER_KEY_URL="$AGENT_URL_BASE/master-key.pub"
AGGREGATOR_URL="https://master.shardkeep.io/shardkeep/operator/api/heartbeat.php"
WS_URL="wss://master.shardkeep.io/shardkeep/operator/ws"

SVC_USER="shardkeep"
SVC_HOME="/var/lib/shardkeep"
CONFIG_DIR="$SVC_HOME/.shardkeep"
RUNTIME_ENV="$CONFIG_DIR/runtime.env"
SHARED_BIN_DIR="/opt/shardkeep/bin"
RUN_UPDATE_PATH="$SHARED_BIN_DIR/run-update.sh"

echo "═══════════════════════════════════════════════════"
echo "  ShardKeep Node Migration v4"
echo "  (role-specific layout: /opt/shardkeep/{role}/agent.py)"
echo "═══════════════════════════════════════════════════"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Must run as root (use sudo)." >&2
    exit 1
fi

# ── Step 1: Detect current layout ──
echo "[1/3] Detecting role..."

OLD_SERVICE=""
OLD_INSTALL_DIR=""
OLD_SUDOERS=""
NODE_TYPE=""
NETWORK="devnet"

# Always collect legacy service/dir state so we can clean it up post-migration.
for svc in "shardkeep-sentry" "citadel-sentry" "exnus-xnode"; do
    if [ -f "/etc/systemd/system/$svc.service" ]; then
        OLD_SERVICE="$svc"
        break
    fi
done
for d in "/opt/shardkeep-sentry" "/opt/citadel-sentry" "/opt/exnus-xnode"; do
    [ -d "$d" ] && OLD_INSTALL_DIR="$d"
done
for s in "/etc/sudoers.d/shardkeep-sentry" "/etc/sudoers.d/citadel-sentry" "/etc/sudoers.d/exnus-xnode"; do
    [ -f "$s" ] && OLD_SUDOERS="$s"
done

# Apply CLI overrides — these win over everything else, including server lookup.
ARG_NODE_TYPE="${1:-}"
ARG_NETWORK="${2:-}"
case "$ARG_NODE_TYPE" in
    warden|bastion|sentry) NODE_TYPE="$ARG_NODE_TYPE"; ROLE_SOURCE="CLI arg" ;;
esac
case "$ARG_NETWORK" in
    testnet|devnet|mainnet) NETWORK="$ARG_NETWORK" ;;
esac

# Server lookup — if a local node_id exists, ask master what role is canonical.
# Resolves the "exnus-xnode actually became a bastion" case automatically.
if [ -z "$NODE_TYPE" ] && [ -f /var/lib/shardkeep/.shardkeep/node_id ]; then
    LOCAL_NID=$(tr -d '\r\n ' </var/lib/shardkeep/.shardkeep/node_id)
    if [ -n "$LOCAL_NID" ]; then
        RESOLVED=$(curl -sSf -m 8 "https://master.shardkeep.io/shardkeep/operator/api/resolve-role.php?node_id=$LOCAL_NID" 2>/dev/null \
            | grep -oE '"role":"[^"]+"' | cut -d'"' -f4 || true)
        case "$RESOLVED" in
            warden|bastion|sentry) NODE_TYPE="$RESOLVED"; ROLE_SOURCE="server lookup ($LOCAL_NID)" ;;
        esac
    fi
fi

# Check shardkeep-{role} new-layout services — but only as a fallback hint, not
# a hard short-circuit. CLI/server-resolved role must still win.
if [ -z "$NODE_TYPE" ]; then
    for role in warden bastion sentry; do
        if [ -f "/etc/systemd/system/shardkeep-${role}.service" ] \
            && grep -q "/opt/shardkeep/${role}/agent.py" "/etc/systemd/system/shardkeep-${role}.service" 2>/dev/null; then
            NODE_TYPE="$role"
            ROLE_SOURCE="existing shardkeep-${role}.service"
            break
        fi
    done
fi

# Look at legacy EnvironmentFile / ExecStart --type as a last hint
if [ -z "$NODE_TYPE" ] && [ -n "$OLD_SERVICE" ]; then
    SVC_FILE="/etc/systemd/system/$OLD_SERVICE.service"
    if grep -q '^EnvironmentFile=' "$SVC_FILE" 2>/dev/null; then
        ENVF=$(grep '^EnvironmentFile=' "$SVC_FILE" | head -1 | cut -d= -f2-)
        if [ -f "$ENVF" ]; then
            NODE_TYPE=$(grep '^NODE_TYPE=' "$ENVF" 2>/dev/null | cut -d= -f2- | tr -d ' "')
            [ -n "$NODE_TYPE" ] && ROLE_SOURCE="legacy EnvironmentFile NODE_TYPE"
        fi
    fi
    if [ -z "$NODE_TYPE" ]; then
        TYPE_RAW=$(grep -oP -- '--type\s+\K\w+' "$SVC_FILE" 2>/dev/null || echo "")
        case "$TYPE_RAW" in
            operator)              NODE_TYPE="warden";  ROLE_SOURCE="legacy --type operator" ;;
            vault|xnode)           NODE_TYPE="bastion"; ROLE_SOURCE="legacy --type $TYPE_RAW (exnus era, mapped → bastion)" ;;
            warden|bastion|sentry) NODE_TYPE="$TYPE_RAW"; ROLE_SOURCE="legacy --type $TYPE_RAW" ;;
        esac
    fi
fi

# Absolute last resort — default to bastion (most common pNode role)
if [ -z "$NODE_TYPE" ]; then
    NODE_TYPE="bastion"
    ROLE_SOURCE="default (no signals — re-run with: ... | sudo bash -s warden|bastion|sentry to override)"
fi

INSTALL_DIR="/opt/shardkeep/${NODE_TYPE}"
NEW_SERVICE="shardkeep-${NODE_TYPE}"
ROLE_LABEL="$(echo "${NODE_TYPE:0:1}" | tr '[:lower:]' '[:upper:]')${NODE_TYPE:1}"
echo "    Role:    $NODE_TYPE  ($ROLE_LABEL)   [source: ${ROLE_SOURCE:-unknown}]"
echo "    Network: $NETWORK"

# ── Step 2: Retire a legacy GENERIC unit being replaced (never a sibling role) ──
# Only the detected legacy generic service (shardkeep-sentry/citadel-sentry/
# exnus-xnode) is stopped — those ARE what we migrate away from. Per-role sibling
# services (a co-located warden/bastion/sentry) are NEVER touched.
if [ -n "$OLD_SERVICE" ] && [ "$OLD_SERVICE" != "$NEW_SERVICE" ]; then
    echo "[2/3] Retiring legacy unit $OLD_SERVICE (replaced by $NEW_SERVICE)..."
    systemctl stop "$OLD_SERVICE" 2>/dev/null || true
    systemctl disable "$OLD_SERVICE" 2>/dev/null || true
else
    echo "[2/3] No legacy generic unit to retire."
fi

# ── Step 3: Delegate the install to the canonical per-role installer ──
# Single source of truth for the per-role user/home/config layout. Idempotent,
# carries a role-matched identity forward, and refreshes run-update.sh. It never
# touches a sibling role.
echo "[3/3] Delegating to the $NODE_TYPE per-role installer..."
curl -sSfL "https://master.shardkeep.io/shardkeep/operator/${NODE_TYPE}/install.sh" | bash -s "$NETWORK"
