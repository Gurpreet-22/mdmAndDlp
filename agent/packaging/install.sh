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
#        ./install.sh --no-instructions  # omit the closing "next steps" text
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
SHOW_INSTRUCTIONS=1

# os-release IDs this installer will proceed on, and the architectures the
# agent has been written for. Reported by the OS rather than assumed; the agent
# makes the same distinction in `osadapter/ubuntu.py`.
SUPPORTED_OS_ID="ubuntu"
SUPPORTED_ARCH="x86_64 aarch64"

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
        # Set by the employee-facing installer, which prints its own
        # confirmation block. The closing text below tells an operator to edit
        # agent.yaml and enrol by hand, which that installer has already done.
        --no-instructions) SHOW_INSTRUCTIONS=0; shift ;;
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

# The operating system and architecture, read rather than assumed. This is a
# refusal and not a warning: there is one OS adapter, it reads Ubuntu's
# interfaces, and installing on anything else would produce a service that runs
# and reports nothing useful.
#
# Parsed rather than sourced - `. /etc/os-release` executes the file, and
# reading it as data costs one sed.
HOST_OS_ID=""
HOST_OS_VERSION=""
for candidate in /etc/os-release /usr/lib/os-release; do
    if [[ -r "${candidate}" ]]; then
        HOST_OS_ID="$(sed -n 's/^ID=//p' "${candidate}" | head -1 | tr -d '"')"
        HOST_OS_VERSION="$(sed -n 's/^VERSION_ID=//p' "${candidate}" | head -1 | tr -d '"')"
        [[ -n "${HOST_OS_ID}" ]] && break
    fi
done

[[ -n "${HOST_OS_ID}" ]] \
    || die "could not read an ID from /etc/os-release, so this host's operating system is unknown"

if [[ "${HOST_OS_ID}" != "${SUPPORTED_OS_ID}" ]]; then
    die "this host reports os-release ID '${HOST_OS_ID}'; the agent supports ${SUPPORTED_OS_ID} only"
fi

HOST_ARCH="$(uname -m)"
arch_ok=0
for candidate in ${SUPPORTED_ARCH}; do
    [[ "${HOST_ARCH}" == "${candidate}" ]] && arch_ok=1
done
[[ "${arch_ok}" -eq 1 ]] \
    || die "architecture '${HOST_ARCH}' is not one the agent targets (${SUPPORTED_ARCH})"

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

# ensurepip is the check that actually matters, and `import venv` does not
# imply it. Debian and Ubuntu split ensurepip out of the standard library into
# python3-venv, so on a machine without that package `import venv` succeeds
# while `python3 -m venv` fails partway through with "You may need to use sudo
# with that command" - having already created a directory. Verified on the
# development host, where venv imports and ensurepip does not.
#
# Reported rather than fatal under --dry-run: a dry run should show the whole
# plan, and this is the one preflight item a developer's machine routinely
# fails while still being able to review what the script would do.
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        warn "the python3 ensurepip module is missing, so '${VENV_DIR}' could not get pip."
        warn "Install it with: apt-get install python3-venv. A real install would stop here."
    else
        die "the python3 ensurepip module is missing, so the virtualenv cannot get pip.
     Install it with: apt-get install python3-venv"
    fi
fi

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl not found; this installer targets systemd hosts"
fi

log "source       ${SOURCE_DIR}"
log "host         ${HOST_OS_ID} ${HOST_OS_VERSION}  ${HOST_ARCH}"
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

if [[ "${SHOW_INSTRUCTIONS}" -eq 0 ]]; then
    log "done (closing instructions omitted at the caller's request)"
    exit 0
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
