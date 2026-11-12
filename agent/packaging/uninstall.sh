#!/usr/bin/env bash
#
# Remove the UbuntuGuard agent.
#
# By default this removes the service and the code and KEEPS the device
# identity and local state, so a reinstall does not need a new enrollment
# token. That is the safe default: deleting a private key is not reversible,
# and re-enrolling a laptop creates a second device row for one machine.
#
# --purge removes the state directory, which includes the device private key
# and the certificate. It requires confirmation.
#
#   sudo ./uninstall.sh                 # remove service and code, keep identity
#   sudo ./uninstall.sh --purge         # also delete keys and state (asks first)
#   sudo ./uninstall.sh --purge --yes   # no prompt, for automation
#        ./uninstall.sh --dry-run       # print every action, change nothing
#
set -euo pipefail

SERVICE_NAME="ubuntuguard-agent"
AGENT_USER="ubuntuguard"
AGENT_GROUP="ubuntuguard"
VENV_PARENT="/opt/ubuntuguard"
CONFIG_DIR="/etc/ubuntuguard"
STATE_DIR="/var/lib/ubuntuguard"
UNIT_DIR="/etc/systemd/system"

PURGE=0
ASSUME_YES=0
DRY_RUN=0

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//;$d'
    exit 0
}

log()  { printf '[uninstall] %s\n' "$*"; }
die()  { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)   PURGE=1; shift ;;
        --yes|-y)  ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *)         die "unknown option: $1 (try --help)" ;;
    esac
done

if [[ "${DRY_RUN}" -eq 0 && "${EUID}" -ne 0 ]]; then
    die "must run as root. Try: sudo $0"
fi

# --- service --------------------------------------------------------------- #
# `|| true` throughout: an already-stopped or already-removed unit must not
# abort the rest of the teardown under `set -e`.

if command -v systemctl >/dev/null 2>&1; then
    log "stopping and disabling ${SERVICE_NAME}"
    run systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
    run systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true

    if [[ -f "${UNIT_DIR}/${SERVICE_NAME}.service" ]]; then
        log "removing the systemd unit"
        run rm -f "${UNIT_DIR}/${SERVICE_NAME}.service"
    fi
    run systemctl daemon-reload || true
    run systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
else
    log "systemctl not found; skipping the service teardown"
fi

# --- code ------------------------------------------------------------------ #

if [[ -d "${VENV_PARENT}" ]]; then
    log "removing ${VENV_PARENT}"
    run rm -rf "${VENV_PARENT}"
fi

# --- state ----------------------------------------------------------------- #

if [[ "${PURGE}" -eq 0 ]]; then
    cat <<EOF

[uninstall] done. The service and the code are gone.

KEPT:
  ${CONFIG_DIR}   configuration
  ${STATE_DIR}    device identity, private key, local state

Reinstalling will pick these up and will not need a new enrollment token.
To remove them as well:  sudo $0 --purge
EOF
    exit 0
fi

if [[ "${ASSUME_YES}" -eq 0 && "${DRY_RUN}" -eq 0 ]]; then
    cat <<EOF

About to permanently delete:
  ${STATE_DIR}    including the device PRIVATE KEY and certificate
  ${CONFIG_DIR}   including agent.yaml

This cannot be undone. Reinstalling afterwards will need a NEW single-use
enrollment token, and the server will show this laptop as a new device.
The old device row is not removed by this script; revoke it in the dashboard.

EOF
    read -r -p "Type 'purge' to continue: " reply
    [[ "${reply}" == "purge" ]] || die "aborted; nothing was deleted"
fi

if [[ -d "${STATE_DIR}" ]]; then
    log "removing ${STATE_DIR} (private key and certificate included)"
    run rm -rf "${STATE_DIR}"
fi

if [[ -d "${CONFIG_DIR}" ]]; then
    log "removing ${CONFIG_DIR}"
    run rm -rf "${CONFIG_DIR}"
fi

# The account goes last, so nothing it owns outlives it as an orphaned uid.
if getent passwd "${AGENT_USER}" >/dev/null 2>&1; then
    log "removing user ${AGENT_USER}"
    run userdel "${AGENT_USER}" 2>/dev/null || true
fi
if getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
    log "removing group ${AGENT_GROUP}"
    run groupdel "${AGENT_GROUP}" 2>/dev/null || true
fi

cat <<EOF

[uninstall] purge complete.

The device row on the server still exists. Revoke it in the dashboard so a
copy of the removed key cannot be used: Devices -> this host -> Revoke.
EOF
