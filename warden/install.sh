#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# ShardKeep — Warden Node Installer
#
# One canonical installer per role. Fully per-role: dedicated service user,
# home, config dir, install dir, systemd unit and sudoers — so Warden,
# Bastion and Sentry can COEXIST on one host without colliding on identity.
#
#   Service:     shardkeep-warden.service
#   User:        shardkeep-warden
#   Home:        /var/lib/shardkeep/warden
#   Config:      /var/lib/shardkeep/warden/.shardkeep   (node_id, api_key, …)
#   Binary:      /opt/shardkeep/warden/agent.py
#   Sudoers:     /etc/sudoers.d/shardkeep-warden
#   Log prefix:  [Warden]
#
# NEVER touches another role. Retiring a sibling role is a deliberate,
# out-of-band action — this installer only ever creates/replaces its OWN role.
#
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/ShardKeep/shardkeep-dist/main/warden/install.sh | sudo bash
#
# Optional network override (defaults to devnet):
#   ... | sudo bash -s mainnet
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

NODE_TYPE="warden"
ROLE_LABEL="Warden"

NETWORK="${1:-devnet}"
case "$NETWORK" in testnet|devnet|mainnet) ;; *) NETWORK="devnet" ;; esac

AGENT_URL="https://raw.githubusercontent.com/ShardKeep/shardkeep-dist/main/agent/agent.py"
RUN_UPDATE_URL="https://raw.githubusercontent.com/ShardKeep/shardkeep-dist/main/agent/run-update.sh"
MASTER_KEY_URL="https://raw.githubusercontent.com/ShardKeep/shardkeep-dist/main/agent/master-key.pub"
AGGREGATOR_URL="https://master.shardkeep.io/shardkeep/operator/api/heartbeat.php"
WS_URL="wss://master.shardkeep.io/shardkeep/operator/ws"

# ── Per-role identity/isolation (the whole point of this installer) ──
SVC_USER="shardkeep-$NODE_TYPE"
SVC_HOME="/var/lib/shardkeep/$NODE_TYPE"
CONFIG_DIR="$SVC_HOME/.shardkeep"
RUNTIME_ENV="$CONFIG_DIR/runtime.env"
INSTALL_DIR="/opt/shardkeep/$NODE_TYPE"
SERVICE_NAME="shardkeep-$NODE_TYPE"
SUDOERS_FILE="/etc/sudoers.d/shardkeep-$NODE_TYPE"

SHARED_BIN_DIR="/opt/shardkeep/bin"
RUN_UPDATE_PATH="$SHARED_BIN_DIR/run-update.sh"

# Legacy shared config from the pre-split installer. We migrate an identity out
# of it ONLY when it belongs to this role (role-matched carry-forward).
LEGACY_DIR="/var/lib/shardkeep/.shardkeep"

echo "═══════════════════════════════════════════════════"
echo "  ShardKeep $ROLE_LABEL Installer (per-role)"
echo "  Role:    $NODE_TYPE  ($ROLE_LABEL)"
echo "  User:    $SVC_USER"
echo "  Home:    $SVC_HOME"
echo "  Network: $NETWORK"
echo "═══════════════════════════════════════════════════"

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Must run as root (use sudo)." >&2; exit 1; }
command -v python3 &>/dev/null || { echo "[ERROR] python3 required: apt-get install python3" >&2; exit 1; }

# ── 1/9: own-role prep — NEVER touches another role ──
# This installer creates or replaces ONLY shardkeep-$NODE_TYPE. It never stops,
# disables or deletes a sibling role. A co-located Warden/Bastion/Sentry keeps
# running untouched.
echo "[1/9] $ROLE_LABEL: preparing (own role only)..."
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    echo "    Stopped existing $SERVICE_NAME for replacement"
else
    echo "    (fresh install)"
fi

# ── 2/9: per-role service user + home ──
echo "[2/9] $ROLE_LABEL: service user..."
if id "$SVC_USER" &>/dev/null; then
    echo "    User '$SVC_USER' exists"
else
    useradd --system --home-dir "$SVC_HOME" --create-home --shell /bin/bash "$SVC_USER"
    echo "    Created '$SVC_USER'"
fi
mkdir -p "$SVC_HOME" "$CONFIG_DIR"
chown "$SVC_USER":"$SVC_USER" "$SVC_HOME"
chmod 755 "$SVC_HOME"
chmod 700 "$CONFIG_DIR"

# ── 2b/9: role-matched identity carry-forward ──
# If this per-role config has no api_key yet, and a legacy shared identity
# exists whose node_id belongs to THIS role, migrate it so the node keeps its
# registration. If the legacy identity is a DIFFERENT role (e.g. a co-located
# bastion's), we do NOT steal it — this role enrols fresh instead.
if [ ! -f "$CONFIG_DIR/api_key" ] && [ -f "$LEGACY_DIR/node_id" ]; then
    LEG_NID=$(tr -d ' \r\n' < "$LEGACY_DIR/node_id" 2>/dev/null || echo "")
    LEG_ROLE="${LEG_NID%%-*}"
    if [ "$LEG_ROLE" = "$NODE_TYPE" ]; then
        echo "    Migrating legacy $NODE_TYPE identity: $LEGACY_DIR → $CONFIG_DIR"
        for f in api_key node_id challenge_secret wallet_keypair.json config.json hostname; do
            [ -f "$LEGACY_DIR/$f" ] && cp -a "$LEGACY_DIR/$f" "$CONFIG_DIR/$f" || true
        done
    elif [ -n "$LEG_ROLE" ]; then
        echo "    Legacy identity is role '$LEG_ROLE' (not $NODE_TYPE) — leaving it; $ROLE_LABEL will enrol fresh."
    fi
fi
chown -R "$SVC_USER":"$SVC_USER" "$CONFIG_DIR"

# Force node_id to canonical {role}-{fingerprint}. Strips any historical prefix
# (sk-, sentry-, xnode-, citadel-, or a wrong-role warden-/bastion-/sentry-) and
# rebuilds with THIS installer's role, so every UI/log/heartbeat shows the right
# prefix from the first second. The server prefix-shim treats variants as equal.
NID_FILE="$CONFIG_DIR/node_id"
if [ -f "$NID_FILE" ]; then
    CUR_NID=$(tr -d ' \r\n' < "$NID_FILE")
    FP=$(echo "$CUR_NID" | sed -E 's/^(sk|sentry|xnode|citadel|warden|bastion)-//')
    if [ -n "$FP" ] && [ "$CUR_NID" != "${NODE_TYPE}-${FP}" ]; then
        echo "    Renaming local node_id: $CUR_NID → ${NODE_TYPE}-${FP}"
        echo "${NODE_TYPE}-${FP}" > "$NID_FILE"
    fi
    chown "$SVC_USER":"$SVC_USER" "$NID_FILE"
    chmod 644 "$NID_FILE"
fi

# ── 3/9: python deps ──
echo "[3/9] $ROLE_LABEL: dependencies..."
if python3 -c "import websockets" &>/dev/null; then
    echo "    websockets: present"
else
    # OS-agnostic install. The old apt-only path failed on Ubuntu without the
    # 'universe' repo and on non-apt (RHEL/CentOS) boxes. Prefer pip (works across
    # distros regardless of OS repos); OS package via 'universe' is the fallback.
    python3 -m ensurepip --upgrade &>/dev/null || true
    if ! python3 -m pip --version &>/dev/null; then
        command -v apt-get &>/dev/null && apt-get install -y -q python3-pip &>/dev/null || true
        command -v dnf &>/dev/null && dnf install -y -q python3-pip &>/dev/null || true
        command -v yum &>/dev/null && yum install -y -q python3-pip &>/dev/null || true
    fi
    python3 -m pip install --break-system-packages -q websockets &>/dev/null         || python3 -m pip install -q websockets &>/dev/null || true
    if ! python3 -c "import websockets" &>/dev/null && command -v apt-get &>/dev/null; then
        apt-get install -y -q software-properties-common &>/dev/null || true
        add-apt-repository -y universe &>/dev/null || true
        apt-get update -q &>/dev/null || true
        apt-get install -y -q python3-websockets &>/dev/null || true
    fi
    if python3 -c "import websockets" &>/dev/null; then
        echo "    websockets: installed"
    else
        echo "    WARNING: could not install websockets automatically — WSS will stay down until it is installed"
    fi
fi

# ── 4/9: agent.py + run-update.sh ──
echo "[4/9] $ROLE_LABEL: downloading agent + helper..."
mkdir -p "$INSTALL_DIR" "$SHARED_BIN_DIR"
chown "$SVC_USER":"$SVC_USER" "$INSTALL_DIR"
curl -sSfL -o "$INSTALL_DIR/agent.py" "$AGENT_URL"
chmod 755 "$INSTALL_DIR/agent.py"
chown "$SVC_USER":"$SVC_USER" "$INSTALL_DIR/agent.py"
VERSION=$(grep -oP 'AGENT_VERSION\s*=\s*"\K[^"]+' "$INSTALL_DIR/agent.py" 2>/dev/null || echo "unknown")
echo "    agent.py v$VERSION → $INSTALL_DIR/agent.py"

curl -sSfL -o "$RUN_UPDATE_PATH" "$RUN_UPDATE_URL"
chmod 755 "$RUN_UPDATE_PATH"
chown root:root "$RUN_UPDATE_PATH"
echo "    run-update.sh → $RUN_UPDATE_PATH"

# ── 5/9: sudoers (scoped to THIS role's user + service only) ──
echo "[5/9] $ROLE_LABEL: sudoers..."
cat > "$SUDOERS_FILE" <<SUDOEOF
$SVC_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart $SERVICE_NAME, /usr/bin/systemctl stop $SERVICE_NAME, /usr/bin/systemctl start $SERVICE_NAME, /usr/bin/hostnamectl, $RUN_UPDATE_PATH
SUDOEOF
chmod 440 "$SUDOERS_FILE"
echo "    $SUDOERS_FILE (440)"

# ── 6/9: runtime.env ──
echo "[6/9] $ROLE_LABEL: runtime.env..."
cat > "$RUNTIME_ENV" <<ENVEOF
AGGREGATOR_URL=$AGGREGATOR_URL
WS_URL=$WS_URL
NODE_TYPE=$NODE_TYPE
NETWORK=$NETWORK
HEARTBEAT_INTERVAL=30
ENVEOF
chown "$SVC_USER":"$SVC_USER" "$RUNTIME_ENV"
chmod 640 "$RUNTIME_ENV"
echo "    NODE_TYPE=$NODE_TYPE  NETWORK=$NETWORK"

# ── 7/9: systemd unit ──
echo "[7/9] $ROLE_LABEL: systemd unit..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=ShardKeep $ROLE_LABEL Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$RUNTIME_ENV
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py --aggregator \${AGGREGATOR_URL} --interval \${HEARTBEAT_INTERVAL} --type \${NODE_TYPE} --network \${NETWORK} --ws-url \${WS_URL}
Restart=always
RestartSec=10
Environment=HOME=$SVC_HOME
Environment=PYTHONUNBUFFERED=1

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$SVC_HOME $INSTALL_DIR
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
echo "    /etc/systemd/system/$SERVICE_NAME.service"

# ── 8/9: master SSH key (lets master push updates via run-update.sh) ──
echo "[8/9] $ROLE_LABEL: master SSH key..."
SSH_DIR="$SVC_HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$SVC_USER":"$SVC_USER" "$SSH_DIR"
MASTER_KEY=$(curl -sSfL "$MASTER_KEY_URL" 2>/dev/null || echo "")
if [ -n "$MASTER_KEY" ]; then
    AUTH="$SSH_DIR/authorized_keys"
    grep -qF "$MASTER_KEY" "$AUTH" 2>/dev/null || echo "$MASTER_KEY" >> "$AUTH"
    chmod 600 "$AUTH"
    chown "$SVC_USER":"$SVC_USER" "$AUTH"
    echo "    installed"
else
    echo "    WARNING: could not fetch master key (non-fatal)"
fi

# ── Claim code — the secret the operator pastes to claim this node ──
# Generated ONCE and kept across re-installs. The agent sends only its SHA-256 hash
# via heartbeat; the raw code appears solely in the summary below + this 0600 file.
# Two-factor claim: the wallet signature proves wallet control, this proves box access.
CLAIM_FILE="$CONFIG_DIR/claim_code"
mkdir -p "$CONFIG_DIR"
if [ ! -s "$CLAIM_FILE" ]; then
    # od reads a FIXED 15 bytes then exits — no `| head` truncation, which races a
    # SIGPIPE that under `set -o pipefail` would abort the whole installer. 30 hex
    # chars, uppercase (0-9A-F has no ambiguous O/I/l).
    CLAIM_CODE="$(od -An -N15 -tx1 /dev/urandom | tr -dc '0-9a-f' | tr 'a-f' 'A-F')"
    printf '%s' "$CLAIM_CODE" > "$CLAIM_FILE"
fi
CLAIM_CODE="$(cat "$CLAIM_FILE")"
chmod 600 "$CLAIM_FILE"
chown -R "$SVC_USER":"$SVC_USER" "$CONFIG_DIR" 2>/dev/null || true

# ── 9/9: enable + start ──
echo "[9/9] $ROLE_LABEL: starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
systemctl restart "$SERVICE_NAME"

# Poll up to 30s; agent may briefly exit/restart on first heartbeat (OTA update).
ACTIVE=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 3
    systemctl is-active --quiet "$SERVICE_NAME" && { ACTIVE=1; break; }
done

if [ $ACTIVE -eq 1 ]; then
    # Wait briefly for the agent to write its node_id (needed for the claim link).
    NODE_ID=""
    for _ in 1 2 3 4 5 6 7 8; do
        NODE_ID=$(cat "$CONFIG_DIR/node_id" 2>/dev/null || echo "")
        [ -n "$NODE_ID" ] && break
        sleep 2
    done
    [ -n "$NODE_ID" ] || NODE_ID="(pending first heartbeat — run: sudo cat $CONFIG_DIR/node_id)"
    CLAIM_URL="https://master.shardkeep.io/shardkeep/operator/claim.php?node=$NODE_ID"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✅  $ROLE_LABEL installed and running."
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Role:      $ROLE_LABEL        Service:  $SERVICE_NAME (active)"
    echo "  Agent:     v$VERSION          Network:  $NETWORK"
    echo ""
    echo "  ────────────────  SAVE THESE TWO VALUES  ────────────────"
    echo "     Node ID:     $NODE_ID"
    echo "     Claim code:  $CLAIM_CODE"
    echo "  ──────────────────────────────────────────────────────────"
    echo ""
    echo "  ➜  NEXT STEP — claim this node so it goes active and earns:"
    echo ""
    echo "      1.  Open:  $CLAIM_URL"
    echo "      2.  Connect your Solana wallet (Phantom)."
    echo "      3.  Paste the Claim code above and sign (free — no transaction)."
    echo ""
    echo "  Until it's claimed, the node stays 'qualified' but inactive."
    echo "  Your claim code is also stored at: $CLAIM_FILE (root-only)."
    echo ""
    echo "  Logs:  journalctl -u $SERVICE_NAME -f"
    echo "═══════════════════════════════════════════════════════════════"
else
    echo ""
    echo "[ERROR] $ROLE_LABEL service failed to start. Last log lines:"
    journalctl -u "$SERVICE_NAME" --no-pager -n 20
    exit 1
fi
