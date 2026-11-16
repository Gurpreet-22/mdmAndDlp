#!/usr/bin/env bash
#
# UbuntuGuard agent installer.
#
# Download this file from your company's UbuntuGuard enrollment page and run it:
#
#     ./ubuntuguard-agent-installer.sh
#
# It will ask for your administrator password (to install a system service) and
# then for the one-time enrollment token your administrator sent you. Nothing
# else is required: no repository to clone, no Python to install, no
# certificates to configure.
#
#        --dry-run     print every action and change nothing. Needs no password
#        --token-stdin read the token from standard input instead of asking,
#                      for an unattended install
#        --no-enroll   install and configure, but do not enrol
#   -h | --help        this text
#
# ---------------------------------------------------------------------------
# THIS FILE IS GENERATED. Edit agent/packaging/installer-template.sh instead,
# then rebuild with agent/packaging/build_installer.py.
# ---------------------------------------------------------------------------
#
# What this script does NOT contain, and must never:
#
#   - a private key of any kind
#   - a device certificate
#   - an enrollment token, or any other shared credential
#
# It carries a server URL and, where the server uses an internal CA, that CA's
# public CERTIFICATE. Both are already disclosed by any TLS handshake with the
# server. The device's private key is generated on the laptop during enrollment
# and never leaves it. `tests/test_installer_build.py` asserts the absence of
# the three items above from the built artifact.
#
set -euo pipefail

# Tracing is never enabled in this script, and must not be added: `set -x`
# would echo the enrollment token to the terminal when it is piped to the agent
# in `stage_enroll`.

# --- baked in at build time ------------------------------------------------ #
AGENT_VERSION="@AGENT_VERSION@"
SERVER_URL="@SERVER_URL@"
SERVER_CA_PEM_B64="@SERVER_CA_PEM_B64@"
PAYLOAD_SHA256="@PAYLOAD_SHA256@"
ADMIN_CONTACT="@ADMIN_CONTACT@"
SUPPORTED_OS_ID="@SUPPORTED_OS_ID@"
SUPPORTED_ARCH="@SUPPORTED_ARCH@"
TARGET_OS_VERSIONS="@TARGET_OS_VERSIONS@"
VALIDATED_OS_VERSIONS="@VALIDATED_OS_VERSIONS@"
MINIMUM_PYTHON="@MINIMUM_PYTHON@"

# --- fixed layout, matching install.sh ------------------------------------- #
SERVICE_NAME="ubuntuguard-agent"
AGENT_USER="ubuntuguard"
AGENT_GROUP="ubuntuguard"
VENV_DIR="/opt/ubuntuguard/venv"
CONFIG_DIR="/etc/ubuntuguard"
STATE_DIR="/var/lib/ubuntuguard"
AGENT_BIN="${VENV_DIR}/bin/ubuntuguard-agent"
SERVER_CA_PATH="${CONFIG_DIR}/server-ca.pem"
SYSTEM_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

#: How long to watch the journal for a heartbeat problem after starting the
#: service. The agent's first heartbeat is immediate at start-up
#: (`core/runtime.py`, first_run_immediately), so a few seconds is enough for a
#: failure to appear. It is NOT enough to prove success - see stage_confirm.
HEARTBEAT_OBSERVE_SECONDS=12

DRY_RUN=0
DO_ENROLL=1
TOKEN_FROM_STDIN=0
WORKDIR=""

log()   { printf '[ubuntuguard] %s\n' "$*"; }
warn()  { printf '[ubuntuguard] WARNING: %s\n' "$*" >&2; }
plain() { printf '%s\n' "$*"; }

die() {
    printf '[ubuntuguard] ERROR: %s\n' "$*" >&2
    printf '\nInstallation did not complete. Nothing was enrolled.\n' >&2
    printf 'If you need help, contact %s.\n' "${ADMIN_CONTACT}" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/p' "${SELF}" | sed 's/^# \?//;$d'
    exit 0
}

# Every mutating action goes through this, so --dry-run is complete by
# construction rather than by remembering to check a flag at each call site.
# Copied deliberately from install.sh: one pattern, one thing to audit.
run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

cleanup() {
    # The extracted source tree is removed whatever happened. It holds no
    # secret - it is the same code published on the enrollment page - but
    # leaving a directory under /run after every install is untidy and would
    # eventually be mistaken for something load-bearing.
    if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
        rm -rf -- "${WORKDIR}"
    fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# Stage 0: find ourselves, because the payload lives in this file
# --------------------------------------------------------------------------- #

locate_self() {
    # This file is read twice at run time: to extract the embedded agent, and
    # to print --help. Neither works if the script arrived on a pipe, which is
    # what `curl … | bash` does, so that is refused with the remedy rather than
    # with a confusing "No such file" from tail.
    #
    # `:-` because under `set -u` BASH_SOURCE is simply unset when bash is
    # reading a script from standard input, and an "unbound variable" message
    # is not a useful thing to hand an employee.
    local source="${BASH_SOURCE[0]:-}"
    if [[ -z "${source}" || ! -f "${source}" ]]; then
        printf 'ERROR: this installer must be saved to a file before it is run,\n' >&2
        printf '       because the UbuntuGuard agent is embedded inside it and a\n' >&2
        printf '       pipe cannot be read twice.\n' >&2
        printf '       Download it from your enrollment page and run that file.\n' >&2
        exit 1
    fi
    SELF="$(cd -- "$(dirname -- "${source}")" && pwd)/$(basename -- "${source}")"
}

# --------------------------------------------------------------------------- #
# Stage 1: is this machine one we support
# --------------------------------------------------------------------------- #

os_release_value() {
    # Parsed, not sourced. `. /etc/os-release` is the common idiom and it
    # executes the file; this reads it as data instead. The file is root-owned
    # so that is defence in depth rather than the only thing in the way, but a
    # parser is two lines and executing a file to learn its contents is a habit
    # worth not having in an installer.
    local key="$1" file="$2"
    sed -n "s/^${key}=//p" "${file}" 2>/dev/null | head -1 | sed 's/^"//;s/"$//'
}

detect_platform() {
    # Read, never guessed. The agent reports whatever os-release says
    # (`osadapter/ubuntu.py`), and the installer applies the same discipline so
    # that a refusal names what was actually found.
    OS_ID=""
    OS_VERSION_ID=""
    OS_PRETTY=""
    for candidate in /etc/os-release /usr/lib/os-release; do
        if [[ -r "${candidate}" ]]; then
            OS_ID="$(os_release_value ID "${candidate}")"
            OS_VERSION_ID="$(os_release_value VERSION_ID "${candidate}")"
            OS_PRETTY="$(os_release_value PRETTY_NAME "${candidate}")"
            [[ -n "${OS_ID}" ]] && break
        fi
    done
    ARCH="$(uname -m)"
    KERNEL="$(uname -r)"
    HOSTNAME_NOW="$(hostname 2>/dev/null || printf 'unknown')"
}

check_platform_supported() {
    if [[ -z "${OS_ID}" ]]; then
        die "could not read /etc/os-release, so this machine's operating system is
       unknown. The UbuntuGuard agent supports ${SUPPORTED_OS_ID^} only."
    fi

    if [[ "${OS_ID}" != "${SUPPORTED_OS_ID}" ]]; then
        die "this machine reports itself as '${OS_ID}' (${OS_PRETTY:-no pretty name}).
       The UbuntuGuard agent supports ${SUPPORTED_OS_ID^} only, so it will not be
       installed here. Contact ${ADMIN_CONTACT} if this laptop should be managed."
    fi

    local supported=0
    for candidate in ${SUPPORTED_ARCH}; do
        [[ "${ARCH}" == "${candidate}" ]] && supported=1
    done
    if [[ "${supported}" -eq 0 ]]; then
        die "this machine's processor architecture is '${ARCH}', and the agent
       supports: ${SUPPORTED_ARCH}. Contact ${ADMIN_CONTACT}."
    fi

    # A target is not a test result. `VALIDATED_OS_VERSIONS` is empty until the
    # agent has actually been run on a release and the evidence recorded, which
    # mirrors `osadapter.ubuntu.VALIDATED_OS_VERSION_IDS`. So this warns on
    # every release today and must not be read as a compatibility claim either
    # way - it does not block the install, because refusing every release would
    # make the installer useless.
    local validated=0
    for candidate in ${VALIDATED_OS_VERSIONS}; do
        [[ "${OS_VERSION_ID}" == "${candidate}" ]] && validated=1
    done
    if [[ "${validated}" -eq 0 ]]; then
        warn "the agent has not yet been tested on ${SUPPORTED_OS_ID^} ${OS_VERSION_ID}."
        warn "It is written for ${TARGET_OS_VERSIONS}, but no release has been formally"
        warn "validated. The install will continue; report anything that misbehaves"
        warn "to ${ADMIN_CONTACT}."
    fi
}

# --------------------------------------------------------------------------- #
# Stage 2: does this machine have what the install needs
# --------------------------------------------------------------------------- #

check_dependencies() {
    # Under --dry-run a missing dependency is reported and the plan continues,
    # because the point of a dry run is to show every action; under a real run
    # it stops, because the install would fail anyway and failing here names
    # the package instead of surfacing a pip traceback.
    local missing=0

    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 is not installed.  Fix with: sudo apt-get install -y python3"
        missing=1
    else
        local major minor
        major="$(python3 -c 'import sys; print(sys.version_info[0])')"
        minor="$(python3 -c 'import sys; print(sys.version_info[1])')"
        local want_minor="${MINIMUM_PYTHON#*.}"
        if [[ "${major}" -ne 3 || "${minor}" -lt "${want_minor}" ]]; then
            warn "the agent needs Python ${MINIMUM_PYTHON} or newer; this machine has ${major}.${minor}."
            missing=1
        fi
        # python3-venv is a separate package on Ubuntu and its absence is the
        # single most common reason an install of this shape fails. Named here
        # so the employee sees a package to install rather than a pip traceback.
        if ! python3 -c 'import venv' >/dev/null 2>&1; then
            warn "the python3 venv module is missing."
            warn "  Fix with: sudo apt-get install -y python3-venv"
            missing=1
        fi
        if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
            warn "the python3 ensurepip module is missing, so a virtualenv cannot get pip."
            warn "  Fix with: sudo apt-get install -y python3-venv"
            missing=1
        fi
    fi

    for tool in systemctl runuser sha256sum base64 tar install; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            warn "${tool} is not available, and the install needs it."
            missing=1
        fi
    done

    if [[ "${missing}" -ne 0 ]]; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            warn "a real install would STOP here. Continuing to show the remaining plan."
            return 0
        fi
        die "this machine is missing something the install needs; see the warnings
       above. Each one names the package that provides it."
    fi
}

# --------------------------------------------------------------------------- #
# Stage 3: administrator privileges
# --------------------------------------------------------------------------- #

become_root() {
    # Deliberately AFTER the platform and dependency checks, so an employee on
    # an unsupported machine is told so without first being asked for a
    # password they did not need to type.
    if [[ "${EUID}" -eq 0 ]]; then
        return 0
    fi
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log "not running as root; --dry-run needs no privileges"
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        die "installing a system service needs administrator privileges, and sudo is
       not available. Re-run this installer as root."
    fi

    log "installing a system service needs administrator privileges"
    plain ""
    plain "  You may be asked for your own login password by sudo."
    plain "  This is NOT your UbuntuGuard enrollment token; that comes later."
    plain ""
    # exec, so there is one process and the employee's terminal stays attached
    # to it. The token prompt in stage_enroll reads that terminal, so handing
    # it to a child and waiting would be one more thing to get wrong.
    #
    # The ORIGINAL arguments are replayed, not `$@` as it stands here: main()
    # has already shifted its way through them, so by this point `$@` is empty
    # and the re-executed installer would silently lose --no-enroll. The
    # `+` expansion keeps `set -u` happy when there were none.
    exec sudo -- "${SELF}" ${_ORIGINAL_ARGS[@]+"${_ORIGINAL_ARGS[@]}"}
}

# --------------------------------------------------------------------------- #
# Stage 4: verify, then extract
# --------------------------------------------------------------------------- #

verify_and_extract() {
    local marker_line
    # Matched anchored and whole-line. The marker is substituted in from
    # @PAYLOAD_MARKER@ rather than written literally, because the builder
    # refuses a template that contains the literal string - two occurrences
    # would make this grep find the wrong offset and extract nothing.
    marker_line="$(grep -n "^@PAYLOAD_MARKER@\$" "${SELF}" | head -1 | cut -d: -f1)"
    if [[ -z "${marker_line}" ]]; then
        die "this installer is incomplete: the embedded agent could not be found.
       Download it again from your enrollment page."
    fi

    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ubuntuguard-install.XXXXXXXX")"
    chmod 0700 "${WORKDIR}"
    local archive="${WORKDIR}/agent.tar.gz"

    if ! tail -n +$((marker_line + 1)) "${SELF}" | base64 -d > "${archive}" 2>/dev/null; then
        die "the embedded agent could not be decoded, so this installer is damaged.
       Download it again from your enrollment page."
    fi

    # Verified BEFORE anything is extracted, and certainly before anything is
    # executed. A digest checked after unpacking would be checking a directory
    # that already exists on disk.
    local actual
    actual="$(sha256sum "${archive}" | cut -d' ' -f1)"
    if [[ "${actual}" != "${PAYLOAD_SHA256}" ]]; then
        die "the embedded agent failed its integrity check and will not be used.
         expected  ${PAYLOAD_SHA256}
         found     ${actual}
       The download may have been corrupted, or this file may have been
       altered. Download it again from your enrollment page, and if it fails
       again contact ${ADMIN_CONTACT}."
    fi
    log "integrity check passed (sha256 ${actual:0:16}…)"

    mkdir -p "${WORKDIR}/agent"
    # No -P/--absolute-names, so a crafted archive cannot write outside here;
    # the archive is digest-pinned above in any case.
    tar -xzf "${archive}" -C "${WORKDIR}/agent"
    rm -f -- "${archive}"

    SOURCE_DIR="${WORKDIR}/agent"
    [[ -f "${SOURCE_DIR}/pyproject.toml" ]] \
        || die "the embedded agent is not a complete source tree. Download it again."
}

# --------------------------------------------------------------------------- #
# Stage 5: install the code and the service
# --------------------------------------------------------------------------- #

stage_install() {
    log "installing the agent (this downloads its two Python dependencies)"
    # The existing, tested install script, called unchanged. It creates the
    # unprivileged account, the root-owned virtualenv, /var/lib/ubuntuguard/pki
    # at 0700, and the systemd unit, and it ENABLES the unit without starting
    # it. It deliberately does not enrol - that is feature D11, and it is still
    # true: the enrolling action is stage_enroll below, with the employee
    # typing a single-use token into it.
    local flags=(--source "${SOURCE_DIR}" --no-instructions)
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        flags+=(--dry-run)
    fi
    if ! bash "${SOURCE_DIR}/packaging/install.sh" "${flags[@]}"; then
        die "installing the agent failed. The most common cause is no route to
       the Python package index, which the install needs for the agent's two
       dependencies (cryptography and PyYAML). Check this machine's network
       and proxy settings, then contact ${ADMIN_CONTACT}."
    fi
}

# --------------------------------------------------------------------------- #
# Stage 6: point the agent at this company's server
# --------------------------------------------------------------------------- #

stage_configure() {
    local ca_bundle="${SYSTEM_CA_BUNDLE}"

    if [[ -n "${SERVER_CA_PEM_B64}" ]]; then
        log "installing the server's CA certificate to ${SERVER_CA_PATH}"
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            printf '[dry-run] install -m 0644 -o root -g root <embedded CA> %s\n' \
                "${SERVER_CA_PATH}"
        else
            printf '%s' "${SERVER_CA_PEM_B64}" | base64 -d > "${WORKDIR}/server-ca.pem"
            install -m 0644 -o root -g root "${WORKDIR}/server-ca.pem" "${SERVER_CA_PATH}"
            rm -f -- "${WORKDIR}/server-ca.pem"
        fi
        ca_bundle="${SERVER_CA_PATH}"
    else
        log "the server uses a publicly trusted certificate; using the system trust store"
    fi

    # Exactly the two keys `config.ALLOWED_CONFIG_KEYS` permits. A third would
    # make `load_config` raise and the agent refuse to start, so this file is
    # written rather than templated from anything that could grow a field.
    log "writing ${CONFIG_DIR}/agent.yaml"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] write %s/agent.yaml (server_url: %s, server_ca_bundle: %s)\n' \
            "${CONFIG_DIR}" "${SERVER_URL}" "${ca_bundle}"
        return 0
    fi

    cat > "${WORKDIR}/agent.yaml" <<YAML
# UbuntuGuard agent configuration.
#
# Written by the installer for agent ${AGENT_VERSION}, build ${PAYLOAD_SHA256:0:12}.
#
# Only these two keys are permitted. Every tunable - heartbeat interval,
# backoff, log level - comes from a signed policy from the server, not from
# this file, so editing one here would have no effect and adding a third key
# stops the agent from starting.
#
# server_ca_bundle validates the SERVER to this agent. It is NOT the device CA
# chain, which arrives in the enrollment response and is the issuer of this
# laptop's own client certificate (${STATE_DIR}/pki/ca-chain.pem).
server_url: ${SERVER_URL}
server_ca_bundle: ${ca_bundle}
YAML
    install -m 0644 -o root -g root "${WORKDIR}/agent.yaml" "${CONFIG_DIR}/agent.yaml"
    rm -f -- "${WORKDIR}/agent.yaml"
}

# --------------------------------------------------------------------------- #
# Stage 7: enrol
# --------------------------------------------------------------------------- #

already_enrolled() {
    # The same test `identity.is_enrolled` makes: both halves present. Checked
    # so that re-running the installer to upgrade the code does not ask for a
    # token it would then have to refuse.
    [[ -f "${STATE_DIR}/pki/device.key" && -f "${STATE_DIR}/pki/device.crt" ]]
}

#: Where `read_token_interactively` leaves the token for `stage_enroll`.
#:
#: A global rather than a return value, deliberately. `token="$(read_...)"`
#: would run the reader in a subshell and capture its STDOUT - which is where
#: the instructions to the employee go, so the token variable would end up
#: holding the prompt text as well as the token. It would also push the
#: credential through an extra pipe between two processes for no benefit.
#: Unset by `stage_enroll` as soon as it has been used.
_ENROLLMENT_INPUT=""

read_token_interactively() {
    # Read here, as root, with echo off, and handed to the agent on a pipe.
    #
    # Why not the agent's own `--token-prompt`, which exists and is the tidier
    # answer: enrollment must run as the unprivileged `ubuntuguard` account
    # (see enrol_as_agent_user), and a process that has dropped to another user
    # may not be able to reopen the controlling terminal - the pty is mode 0600
    # and owned by the employee. `getpass` would then fall back to reading
    # stdin WITH ECHO, printing the token to the screen and into the terminal's
    # scrollback. The agent refuses that fallback outright rather than leaking,
    # which would leave the installer dead at its final step.
    #
    # So the privileged process does the reading, where the terminal is
    # certainly readable, and passes the value over a pipe. `--token-prompt`
    # remains the right channel for an administrator running the CLI directly.
    #
    # The value never reaches a command line, a file, the environment or a log:
    # `read` and `printf` are shell builtins, so nothing appears in
    # /proc/*/cmdline, and the variable lives only in this root-owned process.
    plain ""
    plain "Your administrator sent you a one-time enrollment token."
    plain "Paste it below. It will not be shown as you type."
    plain ""

    _ENROLLMENT_INPUT=""
    local attempt
    for attempt in 1 2 3; do
        # `|| true` because `read` returns non-zero on EOF - Ctrl-D at the
        # prompt - which under `set -e` would kill the script with no
        # explanation at all.
        IFS= read -rs -p "Enter your UbuntuGuard enrollment token: " _ENROLLMENT_INPUT || true
        plain ""
        if [[ -n "${_ENROLLMENT_INPUT}" ]]; then
            return 0
        fi
        if [[ "${attempt}" -lt 3 ]]; then
            warn "nothing was entered. Paste the token your administrator sent you."
        fi
    done

    die "no enrollment token was entered, so this device has not been enrolled.
       The agent is installed and will start at boot, but it cannot report to
       the server until it is enrolled. To finish later, run:
         sudo ${AGENT_BIN} enroll --token-prompt
       and then: sudo systemctl start ${SERVICE_NAME}"
}

enrol_as_agent_user() {
    # Enrollment runs as `ubuntuguard`, NOT as root, and that is a correctness
    # fix as much as least privilege.
    #
    # `identity.py` never chowns: it creates the private key at mode 0600 owned
    # by whoever is running. The unit runs `User=ubuntuguard`. So enrolling as
    # root writes a root-owned device.key into a directory the service account
    # owns, and the service then cannot read its own private key - the one file
    # the whole device identity rests on. It survives today only on systemd's
    # recursive StateDirectory ownership fixup, which is not something to rest
    # an identity on.
    #
    # Enrollment needs to write one directory and make one HTTPS request. It
    # has never needed root.
    #
    # Reads `_ENROLLMENT_INPUT` directly rather than taking it as `$1`. A shell
    # function argument never becomes process argv - no process is created -
    # so both are safe, but one fewer place the value is copied is one fewer
    # place to reason about.
    printf '%s' "${_ENROLLMENT_INPUT}" \
        | runuser -u "${AGENT_USER}" -- "${AGENT_BIN}" enroll --token-stdin
}

stage_enroll() {
    if [[ "${DO_ENROLL}" -eq 0 ]]; then
        log "skipping enrollment (--no-enroll)"
        return 0
    fi

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        # Printed as a planned action with no token anywhere in it, which is
        # also what the packaging test asserts.
        printf '[dry-run] prompt for the enrollment token (not echoed, never written to disk)\n'
        printf '[dry-run] runuser -u %s -- %s enroll --token-stdin\n' "${AGENT_USER}" "${AGENT_BIN}"
        return 0
    fi

    if already_enrolled; then
        log "this device already has an identity in ${STATE_DIR}/pki; not re-enrolling"
        log "the agent code and configuration were updated"
        ENROLL_OUTCOME="already enrolled before this run"
        return 0
    fi

    read_token_interactively

    plain ""
    log "enrolling with the server at ${SERVER_URL}"

    # Checked explicitly rather than left to `set -e`, so a refusal is
    # explained in the employee's terms. The agent has already printed the
    # specific reason - expired, already used, revoked - on stderr.
    if ! enrol_as_agent_user; then
        _ENROLLMENT_INPUT=""
        die "enrollment was refused by the server, and the reason is printed above.
       Enrollment tokens are single use and expire, so the most likely causes
       are that it has already been used, that it has expired, or that it was
       copied incompletely.
       Ask ${ADMIN_CONTACT} for a new token, then run:
         sudo ${AGENT_BIN} enroll --token-prompt
         sudo systemctl start ${SERVICE_NAME}"
    fi
    _ENROLLMENT_INPUT=""
    ENROLL_OUTCOME="enrolled during this run"
}

# --------------------------------------------------------------------------- #
# Stage 8: start the service, then report only what was actually checked
# --------------------------------------------------------------------------- #

stage_start() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] systemctl start %s\n' "${SERVICE_NAME}"
        return 0
    fi
    if [[ "${DO_ENROLL}" -eq 0 ]] && ! already_enrolled; then
        log "not starting ${SERVICE_NAME}: the device is not enrolled, so it would idle"
        return 0
    fi

    log "starting ${SERVICE_NAME}"
    START_MARK="$(date '+%Y-%m-%d %H:%M:%S')"
    systemctl start "${SERVICE_NAME}.service" || true
}

heartbeat_observation() {
    # What can honestly be said about the first heartbeat from this machine.
    #
    # It CANNOT be read from the unit's state: an active unit means the process
    # is running, not that it reached the server. Nor can success be read from
    # the journal, because a successful heartbeat is logged at DEBUG
    # (`service.py:HeartbeatTask`) and the default level is info, so there is
    # no line to find. What a failure produces IS visible: `runtime.py` logs
    # "task failed" at warning with the task name, and a skipped heartbeat logs
    # "heartbeat skipped" at info.
    #
    # So this reports the absence of a failure, and says that is what it is.
    # The authoritative answer is server-side, in the dashboard, which is where
    # the confirmation block points.
    if ! command -v journalctl >/dev/null 2>&1; then
        printf 'not checked (journalctl unavailable)'
        return 0
    fi

    local journal
    journal="$(journalctl -u "${SERVICE_NAME}.service" \
                   --since "${START_MARK}" --no-pager -o cat 2>/dev/null || true)"

    if grep -q '"task":"heartbeat"' <<<"${journal}" 2>/dev/null; then
        printf 'FAILING - the agent reported a heartbeat error; see journalctl'
    elif grep -q 'heartbeat skipped' <<<"${journal}" 2>/dev/null; then
        printf 'not sent - the agent skipped it; see journalctl'
    else
        printf 'no error reported in the first %ss (not proof of delivery)' \
            "${HEARTBEAT_OBSERVE_SECONDS}"
    fi
}

stage_confirm() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '[dry-run] report hostname, enrollment status, service status and heartbeat\n'
        plain ""
        plain "[dry-run] complete. Nothing on this machine was changed."
        return 0
    fi

    local service_state device_line heartbeat
    service_state="$(systemctl is-active "${SERVICE_NAME}.service" 2>/dev/null || true)"
    : "${service_state:=unknown}"

    if already_enrolled; then
        # From the agent itself, so the device id shown is the one in the
        # certificate on this disk rather than anything the installer inferred.
        device_line="$("${AGENT_BIN}" status 2>/dev/null \
                        | sed -n 's/^device id *//p' | head -1 || true)"
        : "${device_line:=enrolled (device id unavailable)}"
    else
        device_line="NOT ENROLLED"
    fi

    if [[ -n "${START_MARK:-}" ]]; then
        sleep "${HEARTBEAT_OBSERVE_SECONDS}"
        heartbeat="$(heartbeat_observation)"
    else
        heartbeat="not checked (the service was not started)"
    fi

    plain ""
    if already_enrolled && [[ "${service_state}" == "active" ]]; then
        plain "UbuntuGuard has been successfully installed and enrolled."
    else
        plain "UbuntuGuard was installed, but the result needs attention."
    fi
    plain ""
    plain "  device hostname    ${HOSTNAME_NOW}"
    plain "  operating system   ${OS_PRETTY:-${OS_ID} ${OS_VERSION_ID}}  (${ARCH})"
    plain "  agent version      ${AGENT_VERSION}"
    plain "  server             ${SERVER_URL}"
    plain "  enrollment         ${ENROLL_OUTCOME:-not enrolled}"
    plain "  device identity    ${device_line}"
    plain "  agent service      ${service_state}  (${SERVICE_NAME})"
    plain "  first heartbeat    ${heartbeat}"
    plain ""
    plain "The private key for this device was generated on this machine and has not"
    plain "left it. It is stored at ${STATE_DIR}/pki/device.key, readable only by the"
    plain "agent's own account."
    plain ""

    if already_enrolled && [[ "${service_state}" == "active" ]]; then
        plain "Your administrator will see this laptop in the UbuntuGuard dashboard once"
        plain "it has checked in. That is the authoritative confirmation; this installer"
        plain "can only report that the agent started without erroring."
    else
        plain "Something is not right. Send the lines above to ${ADMIN_CONTACT}, along"
        plain "with the output of:"
        plain "    systemctl status ${SERVICE_NAME}"
        plain "    journalctl -u ${SERVICE_NAME} -n 50"
    fi
    plain ""
    plain "Nothing further is required of you. The agent starts automatically at boot."
}

# --------------------------------------------------------------------------- #

main() {
    locate_self

    # Captured before parsing, because become_root has to replay them verbatim
    # through sudo and the loop below destroys them.
    _ORIGINAL_ARGS=("$@")

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)     DRY_RUN=1; shift ;;
            --no-enroll)   DO_ENROLL=0; shift ;;
            --token-stdin) TOKEN_FROM_STDIN=1; shift ;;
            -h|--help)     usage ;;
            *)             die "unknown option: $1 (try --help)" ;;
        esac
    done

    # The payload digest identifies this build exactly, and unlike a timestamp
    # it is the same for two builds of the same code - see the note on
    # determinism in build_installer.py. It is what to quote in a support
    # request.
    # Checked here, before anything is inspected, because it is a property of
    # how the script was invoked rather than of the machine.
    #
    # Refused rather than handled: with --token-stdin the token is on our
    # standard input, and sudo asked for a password may read its own prompt
    # answer from there - consuming a single-use credential into sudo's
    # authentication path and then failing to authenticate anyway. Something
    # running an unattended install can already be root.
    if [[ "${TOKEN_FROM_STDIN}" -eq 1 && "${EUID}" -ne 0 && "${DRY_RUN}" -eq 0 ]]; then
        die "--token-stdin must be run as root. The token is on standard input, and
       sudo may try to read its password prompt from there. Run:
         sudo ${SELF} --token-stdin < token-file"
    fi

    plain "UbuntuGuard agent installer ${AGENT_VERSION}  (build ${PAYLOAD_SHA256:0:12})"
    plain ""

    detect_platform
    log "detected        ${OS_PRETTY:-${OS_ID} ${OS_VERSION_ID}}  ${KERNEL}  ${ARCH}"
    check_platform_supported
    check_dependencies
    become_root

    verify_and_extract
    stage_install
    stage_configure

    if [[ "${TOKEN_FROM_STDIN}" -eq 1 && "${DRY_RUN}" -eq 0 ]]; then
        # The unattended path: the token is already on our stdin, so it is
        # forwarded without a prompt. Same pipe, same unprivileged account.
        if already_enrolled; then
            log "this device already has an identity in ${STATE_DIR}/pki; not re-enrolling"
            ENROLL_OUTCOME="already enrolled before this run"
        else
            log "reading the enrollment token from standard input"
            if ! runuser -u "${AGENT_USER}" -- "${AGENT_BIN}" enroll --token-stdin; then
                die "enrollment was refused by the server; the reason is printed above."
            fi
            ENROLL_OUTCOME="enrolled during this run"
        fi
    else
        stage_enroll
    fi

    stage_start
    stage_confirm
}

# Run only when executed, so the script can be SOURCED by the test suite to
# call `check_platform_supported`, `check_dependencies` and `os_release_value`
# directly with the globals set to whatever case is under test. That is how an
# "unsupported OS is refused" test is written without either an Ubuntu-less
# machine or an environment variable that changes the behaviour of a real
# install - a test hook that production honours is a liability, and this one
# cannot be reached by any invocation.
#
# Both branches must stop the shell before the payload below, because base64 is
# not shell and the marker line is not a command. `exit` does that when
# executed; `return` is what does it in a sourced file, and is valid only
# there - which is why it sits after a branch that always exits.
# The sourced case is the narrow one and is tested for explicitly: a non-empty
# BASH_SOURCE that differs from $0. Everything else - executed normally, or
# read from standard input where BASH_SOURCE is unset entirely - falls through
# to main, where locate_self gives the piped case a message worth reading.
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "${0}" ]]; then
    return 0
fi

main "$@"
exit 0
