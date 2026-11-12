#!/usr/bin/env bash
#
# Install the UbuntuGuard agent.
#
# What this script deliberately does NOT do: enrol the device. Enrollment
# consumes a single-use token and creates a device identity, so it is an
# operator action with an audit trail, not a side effect of installing a
# package (feature D11). The script finishes by printing what to do next.
#
# It also does not START the service, only enable it. A freshly installed agent
# has no server configured, so starting it would produce a warning loop in the
# journal and nothing else. Enabling it is what satisfies "comes back after a
# reboot"; the operator starts it once the configuration is in place.
#
# Idempotent: safe to re-run to upgrade the code in place.
#
#   sudo ./install.sh                 # install from the directory above this one
#   sudo ./install.sh --source /path  # install from a specific source tree
#        ./install.sh --dry-run       # print every action, change nothing
#
set -euo pipefail

SERVICE_NAME="ubuntuguard-agent"
AGENT_USER="ubuntuguard"
AGENT_GROUP="ubuntuguard"
VENV_DIR="/opt/ubuntuguard/venv"
CONFIG_DIR="/etc/ubuntuguard"
STATE_DIR="/var/lib/ubuntuguard"
UNIT_DIR="/etc/systemd/system"
MIN_PYTHON_MINOR=10

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DRY_RUN=0
DO_ENABLE=1

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//;$d'
    exit 0
}

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARNING: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

# Every mutating action goes through this, so --dry-run is complete by
# construction rather than by remembering to check a flag at each call site.
run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)   SOURCE_DIR="$(cd -- "$2" && pwd)"; shift 2 ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --no-enable) DO_ENABLE=0; shift ;;
        -h|--help)  usage ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
done

# --- preflight ------------------------------------------------------------- #

if [[ "${DRY_RUN}" -eq 0 && "${EUID}" -ne 0 ]]; then
    die "must run as root. Try: sudo $0"
fi

[[ -f "${SOURCE_DIR}/pyproject.toml" ]] \
    || die "no pyproject.toml in ${SOURCE_DIR}; pass --source <agent directory>"

command -v python3 >/dev/null 2>&1 || die "python3 not found"

PY_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])')"
PY_MAJOR="$(python3 -c 'import sys; print(sys.version_info[0])')"
if [[ "${PY_MAJOR}" -ne 3 || "${PY_MINOR}" -lt "${MIN_PYTHON_MINOR}" ]]; then
    die "the agent needs Python 3.${MIN_PYTHON_MINOR} or newer, found ${PY_MAJOR}.${PY_MINOR}"
fi

# python3-venv is a separate package on Debian and Ubuntu, and its absence is
# the single most common reason this script fails. Checked up front so the
# message names the package instead of surfacing a pip traceback.
if ! python3 -c 'import venv' >/dev/null 2>&1; then
    die "the python3 venv module is missing. Install it with: apt-get install python3-venv"
fi

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl not found; this installer targets systemd hosts"
fi

log "source       ${SOURCE_DIR}"
log "python       $(python3 --version 2>&1)"
log "virtualenv   ${VENV_DIR}"

# --- account --------------------------------------------------------------- #
# No login shell, no home directory, no password. The account exists to own a
# process and a state directory, and nothing else.

if getent group "${AGENT_GROUP}" >/dev/null 2>&1; then
    log "group ${AGENT_GROUP} already exists"
else
    log "creating group ${AGENT_GROUP}"
    run groupadd --system "${AGENT_GROUP}"
fi

if getent passwd "${AGENT_USER}" >/dev/null 2>&1; then
    log "user ${AGENT_USER} already exists"
else
    log "creating user ${AGENT_USER}"
    run useradd --system \
        --gid "${AGENT_GROUP}" \
        --home-dir "${STATE_DIR}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "UbuntuGuard agent" \
        "${AGENT_USER}"
fi

# --- directories ----------------------------------------------------------- #
# /var/lib/ubuntuguard is also declared as StateDirectory in the unit, so
# systemd will create it with the right owner if it is absent. Creating it here
# too means `selftest` and `status` work before the service has ever started.

log "creating ${CONFIG_DIR} (0755, root-owned: readable by the agent, writable only by root)"
run install -d -m 0755 -o root -g root "${CONFIG_DIR}"

log "creating ${STATE_DIR} (0750)"
run install -d -m 0750 -o "${AGENT_USER}" -g "${AGENT_GROUP}" "${STATE_DIR}"

log "creating ${STATE_DIR}/pki (0700: private key material, owner only)"
run install -d -m 0700 -o "${AGENT_USER}" -g "${AGENT_GROUP}" "${STATE_DIR}/pki"

# --- code ------------------------------------------------------------------ #
# Its own virtualenv, not the system site-packages. Two reasons: the agent must
# not be broken by an unrelated apt upgrade, and Ubuntu 22.04 ships
# python3-cryptography 3.4.8, which is too old to rely on.

if [[ -x "${VENV_DIR}/bin/python" ]]; then
    log "reusing the existing virtualenv"
else
    log "creating the virtualenv"
    run install -d -m 0755 -o root -g root "$(dirname "${VENV_DIR}")"
    run python3 -m venv "${VENV_DIR}"
fi

log "installing the agent and its dependencies"
run "${VENV_DIR}/bin/python" -m pip install --quiet --upgrade pip
run "${VENV_DIR}/bin/python" -m pip install --quiet "${SOURCE_DIR}"

# Root-owned and not writable by the agent account: the service must not be able
# to rewrite its own code. That is what keeps a compromise of the agent from
# becoming persistence.
log "setting virtualenv ownership to root (the agent cannot modify its own code)"
run chown -R root:root "${VENV_DIR}"

# --- configuration --------------------------------------------------------- #

if [[ -f "${CONFIG_DIR}/agent.yaml" ]]; then
    log "keeping the existing ${CONFIG_DIR}/agent.yaml"
else
    log "installing the example configuration to ${CONFIG_DIR}/agent.yaml"
    run install -m 0644 -o root -g root \
        "${SOURCE_DIR}/packaging/etc/agent.yaml.example" \
        "${CONFIG_DIR}/agent.yaml"
fi

# --- service --------------------------------------------------------------- #

log "installing the systemd unit"
run install -m 0644 -o root -g root \
    "${SOURCE_DIR}/packaging/systemd/${SERVICE_NAME}.service" \
    "${UNIT_DIR}/${SERVICE_NAME}.service"

run systemctl daemon-reload

if [[ "${DO_ENABLE}" -eq 1 ]]; then
    # enable, not enable --now: see the header. This is what brings the agent
    # back after a reboot.
    log "enabling ${SERVICE_NAME} for start at boot"
    run systemctl enable "${SERVICE_NAME}.service"
else
    log "skipping enable (--no-enable)"
fi

cat <<EOF

[install] done.

Next steps, in order:

  1. Edit ${CONFIG_DIR}/agent.yaml
       - server_url        the https URL of the UbuntuGuard API
       - server_ca_bundle  the CA that issued the SERVER's TLS certificate

  2. Check the installation:
       ${VENV_DIR}/bin/ubuntuguard-agent selftest

  3. Start it:
       systemctl start ${SERVICE_NAME}
       systemctl status ${SERVICE_NAME}
       journalctl -u ${SERVICE_NAME} -f

  4. Enrol it. This is a separate, deliberate step - see below:
       # the token comes from the dashboard, and must NOT be an argument
       install -m 0600 /dev/null /run/ubuntuguard-token
       printf '%s' '<token from the dashboard>' > /run/ubuntuguard-token
       ${VENV_DIR}/bin/ubuntuguard-agent enroll --token-file /run/ubuntuguard-token
       shred -u /run/ubuntuguard-token

     or, reading it from a password manager without touching the disk:
       pass show ubuntuguard/token \\
         | ${VENV_DIR}/bin/ubuntuguard-agent enroll --token-stdin

This install does NOT enrol the device. Enrollment consumes a single-use token
and creates an auditable identity, so it is a deliberate operator action with a
person behind it, not a side effect of installing a package.

There is deliberately no --token option. Anything in a command line is readable
by every user on this machine through /proc/<pid>/cmdline and visible in ps, so
an enrollment token passed that way is a credential published to the whole
system.

The device plane needs mutual TLS, which needs the nginx configuration in
deploy/nginx/. The agent presents its client certificate on every device-plane
request, but it cannot verify from here that the proxy is enforcing
ssl_verify_client - so 'status' reports mtls_verified: no regardless, and that
claim belongs to whoever deployed the proxy.
EOF
