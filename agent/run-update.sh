#!/usr/bin/env bash
# /opt/shardkeep/bin/run-update.sh
#
# Tightly-scoped root helper. The ONLY script the node's `shardkeep*` sudoers
# grants NOPASSWD, so it is the master→node privileged rail. Every action here
# only ever `curl|bash`es from the ShardKeep/shardkeep-dist GitHub repo — the same canonical
# origin migrate.sh already trusts. No local role state is ever destroyed:
# retiring a role is NOT a verb here (that stays a deliberate, out-of-band act).
#
#   run-update.sh                       → agent self-update (pinned migrate.sh)   [default]
#   run-update.sh update                → same as default
#   run-update.sh install-role <role>   → (re)install ONE role from its pinned installer
#   run-update.sh install-web           → (re)provision the Warden WEB-serving stack (separate from the agent)
#
# install-role is NON-DESTRUCTIVE: the per-role installers never stop, disable
# or delete a sibling role, so a stolen master key can use this only to
# (re)install a role from canonical source — never as a fleet role-kill switch.
set -euo pipefail

BASE="https://raw.githubusercontent.com/ShardKeep/shardkeep-dist/main"
cmd="${1:-update}"

case "$cmd" in
    update)
        exec curl -sSfL "$BASE/agent/migrate.sh" | bash
        ;;
    install-role)
        role="${2:-}"
        case "$role" in
            warden|bastion|sentry) ;;
            *) echo "run-update.sh install-role: invalid role '${role:-<empty>}' (want warden|bastion|sentry)" >&2; exit 2 ;;
        esac
        exec curl -sSfL "$BASE/$role/install.sh" | bash
        ;;
    install-web)
        # (re)provision the Warden WEB-serving stack (apache :443 + container + WSS +
        # TLS), a SEPARATE lifecycle from the agent. Non-destructive: only installs /
        # refreshes; never stops or deletes a sibling role. Canonical origin only.
        exec curl -sSfL "$BASE/warden/install-web.sh" | bash
        ;;
    *)
        echo "run-update.sh: unknown command '$cmd' (want: update | install-role <role>)" >&2
        exit 2
        ;;
esac
