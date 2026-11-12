#!/usr/bin/env bash
# UbuntuGuard Phase 0 - USBGuard enforcement spike
#
# PURPOSE
#   Decide, with evidence, whether usbguard can actually BLOCK unauthorized USB
#   storage for a standard user on Ubuntu 22.04 / 24.04 - before we build a USB
#   feature on top of it. Nothing in this repo may claim "blocks USB storage"
#   until this spike passes on the target release.
#
# SAFETY
#   usbguard with ImplicitPolicyTarget=block CAN LOCK OUT A USB KEYBOARD OR MOUSE.
#   This script therefore:
#     - refuses to arm enforcement unless --i-have-console-access is passed
#     - backs up any existing config and rules first, with a timestamp
#     - generates an allow-policy for everything currently attached BEFORE
#       switching the implicit target to block
#     - aborts if that generated policy contains no HID (keyboard/mouse) rule on
#       a machine that has a USB HID device attached
#     - ships `restore` to put the machine back
#
#   Run this on a SCRATCH machine or VM you can reach over SSH or a non-USB
#   console. Do not run it on your daily driver.
#
# USAGE
#   sudo ./spike.sh env                                 # read-only survey, no changes
#   sudo ./spike.sh install                             # install usbguard (asks first)
#   sudo ./spike.sh arm --i-have-console-access         # back up, allow present, block rest
#   sudo ./spike.sh listen                              # compare D-Bus vs usbguard vs udev
#   sudo ./spike.sh test-block --user alice             # guided insert + block tests
#   sudo ./spike.sh test-allow --user alice --vid 090c --pid 1000
#   sudo ./spike.sh test-ipc-listen --user alice        # unprivileged read-only events
#   sudo ./spike.sh root-bypass                         # demonstrate the known limitation
#   sudo ./spike.sh post-reboot                         # persistence + boot-order evidence
#   sudo ./spike.sh restore                             # undo everything
#
# Every command appends to an evidence log under ./evidence/.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
readonly SPIKE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly EVIDENCE_DIR="${SPIKE_DIR}/evidence"
readonly BACKUP_DIR="${SPIKE_DIR}/backup"
readonly USBGUARD_CONF="/etc/usbguard/usbguard-daemon.conf"
readonly USBGUARD_RULES="/etc/usbguard/rules.conf"
readonly STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

CONSENT_CONSOLE=0
TEST_USER=""
TEST_VID=""
TEST_PID=""
LISTEN_SECONDS=90

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
log()  { printf '\033[36m[spike]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[ ok ]\033[0m %s\n'  "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n'  "$*"; }
err()  { printf '\033[31m[FAIL]\033[0m %s\n'  "$*" >&2; }
die()  { err "$*"; exit 1; }

# Append a line to the evidence log for this run.
record() {
  mkdir -p "${EVIDENCE_DIR}"
  printf '%s | %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" \
    >> "${EVIDENCE_DIR}/spike-${STAMP}.log"
}

# Run a command, echo it, and tee its output into a named evidence file.
capture() {
  local name="$1"; shift
  mkdir -p "${EVIDENCE_DIR}"
  local out="${EVIDENCE_DIR}/${name}.txt"
  {
    printf '### %s\n### command: %s\n### at: %s\n\n' \
      "${name}" "$*" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "$@" 2>&1 || printf '\n### exit status: %s\n' "$?"
  } > "${out}"
  record "captured ${name} -> ${out}"
  printf '  -> %s\n' "${out}"
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "run this with sudo: sudo $0 $*"
}

have() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  local prompt="$1"
  read -r -p "${prompt} [y/N] " reply
  [[ "${reply}" == "y" || "${reply}" == "Y" ]]
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --i-have-console-access) CONSENT_CONSOLE=1; shift ;;
      --user)    TEST_USER="${2:?--user needs a username}"; shift 2 ;;
      --vid)     TEST_VID="${2:?--vid needs a 4-hex vendor id}"; shift 2 ;;
      --pid)     TEST_PID="${2:?--pid needs a 4-hex product id}"; shift 2 ;;
      --seconds) LISTEN_SECONDS="${2:?--seconds needs a number}"; shift 2 ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

resolve_test_user() {
  if [[ -z "${TEST_USER}" ]]; then
    TEST_USER="${SUDO_USER:-}"
  fi
  [[ -n "${TEST_USER}" ]] || die "pass --user <standard-non-root-username>"
  id -u "${TEST_USER}" >/dev/null 2>&1 || die "no such user: ${TEST_USER}"
  [[ "$(id -u "${TEST_USER}")" != "0" ]] || die "--user must NOT be root"
  log "standard user for tests: ${TEST_USER} (uid $(id -u "${TEST_USER}"))"
}

# --------------------------------------------------------------------------- #
# cmd: env - read-only survey
# --------------------------------------------------------------------------- #
cmd_env() {
  log "surveying environment (no changes)"
  mkdir -p "${EVIDENCE_DIR}"

  capture 01-os-release        cat /etc/os-release
  capture 02-kernel            uname -a
  capture 03-lsusb             bash -c 'lsusb || echo "lsusb not installed (usbutils)"'
  capture 04-lsusb-tree        bash -c 'lsusb -t || true'
  capture 05-virtualization    bash -c 'systemd-detect-virt || true'
  capture 06-systemd-version   bash -c 'systemctl --version | head -1'

  if have usbguard; then
    capture 10-usbguard-version  usbguard --version
    capture 11-usbguard-units    bash -c 'systemctl list-unit-files | grep -i usbguard || echo NONE'
    capture 12-usbguard-status   bash -c 'systemctl status usbguard.service --no-pager || true'
    capture 13-usbguard-conf     bash -c "cat '${USBGUARD_CONF}' 2>/dev/null || echo MISSING"
    capture 14-usbguard-rules    bash -c "cat '${USBGUARD_RULES}' 2>/dev/null || echo MISSING-OR-EMPTY"
    capture 15-usbguard-devices  bash -c 'usbguard list-devices 2>&1 || true'
    capture 16-usbguard-rules-live bash -c 'usbguard list-rules 2>&1 || true'
  else
    warn "usbguard is NOT installed - capability would be reported 'unsupported'"
    record "usbguard absent"
  fi

  # Which event sources exist? This decides the agent's USB event source.
  {
    printf 'gdbus:        %s\n' "$(have gdbus        && echo present || echo MISSING)"
    printf 'dbus-monitor: %s\n' "$(have dbus-monitor && echo present || echo MISSING)"
    printf 'udevadm:      %s\n' "$(have udevadm      && echo present || echo MISSING)"
    printf 'udisksctl:    %s\n' "$(have udisksctl    && echo present || echo MISSING)"
    printf 'usbguard:     %s\n' "$(have usbguard     && echo present || echo MISSING)"
  } > "${EVIDENCE_DIR}/20-tooling.txt"
  printf '  -> %s\n' "${EVIDENCE_DIR}/20-tooling.txt"

  # Does a usbguard D-Bus service exist on the system bus?
  if have gdbus; then
    capture 21-dbus-usbguard-introspect bash -c \
      'gdbus introspect --system --dest org.usbguard1 --object-path /org/usbguard1 2>&1 || echo "org.usbguard1 not reachable on the system bus"'
  fi

  ok "survey written to ${EVIDENCE_DIR}"
  log "next: sudo $0 install    (if usbguard is missing)"
}

# --------------------------------------------------------------------------- #
# cmd: install
# --------------------------------------------------------------------------- #
cmd_install() {
  require_root
  if have usbguard; then
    ok "usbguard already installed: $(usbguard --version | head -1)"
    return 0
  fi
  warn "about to install: usbguard usbutils (and enable NO service yet)"
  confirm "proceed with apt-get install?" || die "aborted by operator"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y usbguard usbutils
  # Ubuntu's postinst may enable and start the daemon with an EMPTY rules.conf.
  # With ImplicitPolicyTarget=block that is exactly the lockout scenario, so we
  # stop it immediately and only re-arm from `arm`, which generates a policy first.
  systemctl stop usbguard.service 2>/dev/null || true
  systemctl disable usbguard.service 2>/dev/null || true
  warn "usbguard installed but STOPPED and DISABLED on purpose."
  warn "An empty rules.conf plus the default block target is how people lock"
  warn "themselves out. 'arm' generates an allow-policy before enabling anything."
  record "installed usbguard, left stopped+disabled"
  capture 10-usbguard-version usbguard --version
}

# --------------------------------------------------------------------------- #
# cmd: arm - the dangerous step, hence the guard rails
# --------------------------------------------------------------------------- #
cmd_arm() {
  require_root
  have usbguard || die "usbguard not installed - run: sudo $0 install"
  [[ ${CONSENT_CONSOLE} -eq 1 ]] || die \
    "refusing to arm without --i-have-console-access (this can disable a USB keyboard)"

  mkdir -p "${BACKUP_DIR}"

  # 1. Back up whatever is there now.
  for f in "${USBGUARD_CONF}" "${USBGUARD_RULES}"; do
    if [[ -f "${f}" ]]; then
      cp -a "${f}" "${BACKUP_DIR}/$(basename "${f}").${STAMP}.bak"
      ok "backed up ${f}"
    else
      printf 'ABSENT\n' > "${BACKUP_DIR}/$(basename "${f}").${STAMP}.absent"
      warn "${f} did not exist; recorded as absent for restore"
    fi
  done
  systemctl is-enabled usbguard.service > "${BACKUP_DIR}/usbguard.enabled-state.${STAMP}" 2>&1 || true

  # 2. Generate an allow-policy for everything currently attached.
  local generated="${EVIDENCE_DIR}/30-generated-policy.conf"
  mkdir -p "${EVIDENCE_DIR}"
  log "generating allow-policy for currently attached devices"
  usbguard generate-policy > "${generated}"

  if [[ ! -s "${generated}" ]]; then
    die "generate-policy produced nothing; refusing to continue"
  fi

  # 3. Lockout guard: if a USB HID device is attached, the policy MUST allow it.
  local hid_attached=0 hid_in_policy=0
  # usbutils has printed this class name differently across versions, so match
  # both spellings rather than relying on one.
  if lsusb -t 2>/dev/null | grep -qiE 'Class=(Human Interface Device|HID)'; then
    hid_attached=1
  fi
  if grep -qiE 'with-interface.*03:' "${generated}"; then
    hid_in_policy=1
  fi
  log "USB HID attached: ${hid_attached}, HID present in generated policy: ${hid_in_policy}"
  if [[ ${hid_attached} -eq 1 && ${hid_in_policy} -eq 0 ]]; then
    die "a USB HID device is attached but the generated policy has no HID rule - refusing to arm (this is the lockout case)"
  fi
  if [[ ${hid_attached} -eq 0 ]]; then
    warn "no USB HID detected. If this machine's keyboard is USB and currently"
    warn "unplugged, plug it in and re-run 'arm' so it lands in the allow policy."
    confirm "continue anyway?" || die "aborted by operator"
  fi

  # 4. Install the generated policy and the enforcing config.
  install -m 0600 -o root -g root "${generated}" "${USBGUARD_RULES}"
  ok "installed allow-policy for present devices -> ${USBGUARD_RULES}"

  # Write the config keys the spike depends on, preserving anything else.
  log "setting ImplicitPolicyTarget=block, PresentDevicePolicy=apply-policy, InsertedDevicePolicy=apply-policy"
  set_conf_key ImplicitPolicyTarget  block
  set_conf_key PresentDevicePolicy   apply-policy
  set_conf_key InsertedDevicePolicy  apply-policy

  capture 31-armed-conf  cat "${USBGUARD_CONF}"
  capture 32-armed-rules cat "${USBGUARD_RULES}"

  # 5. Enable and start. Enable is what makes it survive a reboot.
  systemctl enable usbguard.service
  systemctl restart usbguard.service
  sleep 2
  systemctl is-active --quiet usbguard.service \
    || die "usbguard.service failed to start - check: journalctl -u usbguard -n 50"
  ok "usbguard armed and enabled"

  capture 33-armed-devices usbguard list-devices
  capture 34-armed-boot-order bash -c \
    "systemctl show usbguard.service -p After -p Before -p WantedBy -p DefaultDependencies"

  record "armed: implicit=block, present=apply-policy, inserted=apply-policy"
  warn "USB storage that is not in the allow policy should now be blocked."
  log "next: sudo $0 listen   (in a second terminal), then sudo $0 test-block --user <name>"
}

# Set a key in usbguard-daemon.conf, replacing an existing line or appending.
set_conf_key() {
  local key="$1" value="$2"
  [[ -f "${USBGUARD_CONF}" ]] || touch "${USBGUARD_CONF}"
  if grep -qE "^[#[:space:]]*${key}=" "${USBGUARD_CONF}"; then
    sed -i -E "s|^[#[:space:]]*${key}=.*|${key}=${value}|" "${USBGUARD_CONF}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${USBGUARD_CONF}"
  fi
  grep -E "^${key}=" "${USBGUARD_CONF}" >/dev/null \
    || die "failed to set ${key} in ${USBGUARD_CONF}"
}

# --------------------------------------------------------------------------- #
# cmd: listen - compare the three candidate event sources side by side
# --------------------------------------------------------------------------- #
cmd_listen() {
  require_root
  mkdir -p "${EVIDENCE_DIR}"
  log "listening for ${LISTEN_SECONDS}s on all available event sources"
  log "INSERT AND REMOVE THE TEST USB STICK NOW"
  log ""
  log "This answers the question the brief raises: a blocked device may expose no"
  log "interface information to udev, so we need to see what each source reports"
  log "for the SAME blocked insertion."

  local pids=()

  if have gdbus; then
    ( gdbus monitor --system --dest org.usbguard1 \
        > "${EVIDENCE_DIR}/40-events-dbus-gdbus.txt" 2>&1 ) & pids+=($!)
    log "  started: gdbus monitor --system --dest org.usbguard1"
  elif have dbus-monitor; then
    ( dbus-monitor --system \
        "type='signal',interface='org.usbguard.Devices1'" \
        > "${EVIDENCE_DIR}/40-events-dbus-monitor.txt" 2>&1 ) & pids+=($!)
    log "  started: dbus-monitor on org.usbguard.Devices1"
  else
    warn "  no gdbus or dbus-monitor; cannot evaluate the D-Bus event source"
  fi

  if have usbguard; then
    ( usbguard watch > "${EVIDENCE_DIR}/41-events-usbguard-watch.txt" 2>&1 ) & pids+=($!)
    log "  started: usbguard watch (IPC)"
  fi

  if have udevadm; then
    ( udevadm monitor --udev --property \
        --subsystem-match=usb --subsystem-match=block \
        > "${EVIDENCE_DIR}/42-events-udev.txt" 2>&1 ) & pids+=($!)
    log "  started: udevadm monitor (usb + block)"
  fi

  [[ ${#pids[@]} -gt 0 ]] || die "no event source available to listen on"

  sleep "${LISTEN_SECONDS}"
  for p in "${pids[@]}"; do kill "${p}" 2>/dev/null || true; done
  wait 2>/dev/null || true

  ok "event capture complete"
  for f in 40-events-dbus-gdbus 40-events-dbus-monitor 41-events-usbguard-watch 42-events-udev; do
    [[ -s "${EVIDENCE_DIR}/${f}.txt" ]] && printf '  %-34s %s lines\n' \
      "${f}.txt" "$(wc -l < "${EVIDENCE_DIR}/${f}.txt")"
  done
  record "listened ${LISTEN_SECONDS}s on available event sources"
  warn "Compare the files: note whether the UDEV capture contains the vendor/product"
  warn "and interface class of the BLOCKED device, or only a bare bind/unbind."
}

# --------------------------------------------------------------------------- #
# cmd: test-block
# --------------------------------------------------------------------------- #
cmd_test_block() {
  require_root
  resolve_test_user
  have usbguard || die "usbguard not installed"
  systemctl is-active --quiet usbguard.service || die "usbguard.service is not running - run 'arm' first"

  log "snapshot of block devices BEFORE insertion"
  mkdir -p "${EVIDENCE_DIR}"
  lsblk -o NAME,SIZE,TYPE,RM,MOUNTPOINT > "${EVIDENCE_DIR}/50-lsblk-before.txt"
  # Machine-readable list for the diff. The tree format prefixes partitions with
  # box-drawing characters, so it cannot be compared with a plain anchored regex.
  lsblk -nro NAME | sort -u > "${EVIDENCE_DIR}/50-nodes-before.txt"

  log ""
  log "INSERT THE TEST USB STORAGE DEVICE, then press Enter"
  read -r _

  sleep 3
  capture 51-usbguard-devices-after usbguard list-devices
  capture 52-lsblk-after            lsblk -o NAME,SIZE,TYPE,RM,MOUNTPOINT
  capture 53-dmesg-tail             bash -c 'dmesg | tail -40'
  lsblk -nro NAME | sort -u > "${EVIDENCE_DIR}/52-nodes-after.txt"

  # --- Did usbguard record a block? ---
  local blocked_lines
  blocked_lines="$(usbguard list-devices 2>/dev/null | grep -c '^[0-9]*: block' || true)"
  log "usbguard currently reports ${blocked_lines} blocked device(s)"
  record "blocked device count after insertion: ${blocked_lines}"

  # --- Did a block device node appear at all? ---
  # This is the real question. usbguard 'block' deauthorizes the device, so the
  # kernel never binds usb-storage and NO /dev/sd* node appears. If that holds,
  # there is nothing for a user to mount, which is a much stronger result than
  # "mount refused".
  local new_nodes
  new_nodes="$(comm -13 \
      "${EVIDENCE_DIR}/50-nodes-before.txt" \
      "${EVIDENCE_DIR}/52-nodes-after.txt" || true)"
  if [[ -z "${new_nodes}" ]]; then
    ok "NO new block device appeared - the device was deauthorized before usb-storage bound"
    record "RESULT no-block-device-node: PASS"
  else
    warn "new block device(s) appeared: ${new_nodes}"
    record "RESULT no-block-device-node: FAIL (${new_nodes})"
    log "attempting standard-user mount of the new node(s) to see if it is usable"
    local node
    for node in ${new_nodes}; do
      test_user_mount "/dev/${node}"
    done
  fi

  log ""
  log "NOTE ON METHOD: a standard user cannot run mount(8) regardless of usbguard,"
  log "so 'mount failed' proves nothing on its own. The meaningful checks are:"
  log "  (a) no /dev/sd* node appears at all, and"
  log "  (b) udisksctl / the desktop auto-mount path also fails."
  log "Both are recorded above."
}

# Try the realistic desktop mount paths as the standard user.
test_user_mount() {
  local dev="$1"
  log "standard-user mount attempts on ${dev} as ${TEST_USER}"
  {
    printf '### target: %s as user %s\n\n' "${dev}" "${TEST_USER}"
    printf '--- udisksctl mount (the desktop path GNOME actually uses) ---\n'
    sudo -u "${TEST_USER}" -- udisksctl mount -b "${dev}" 2>&1 || printf 'exit=%s\n' "$?"
    printf '\n--- plain mount(8) (expected to fail for any non-root user) ---\n'
    sudo -u "${TEST_USER}" -- mount "${dev}" /mnt 2>&1 || printf 'exit=%s\n' "$?"
    printf '\n--- dd read of the raw device ---\n'
    sudo -u "${TEST_USER}" -- dd if="${dev}" of=/dev/null bs=512 count=1 2>&1 || printf 'exit=%s\n' "$?"
  } > "${EVIDENCE_DIR}/54-user-mount-$(basename "${dev}").txt"
  printf '  -> %s\n' "${EVIDENCE_DIR}/54-user-mount-$(basename "${dev}").txt"
}

# --------------------------------------------------------------------------- #
# cmd: test-allow - confirm the allow path works, i.e. we are testing the right stick
# --------------------------------------------------------------------------- #
cmd_test_allow() {
  require_root
  resolve_test_user
  [[ -n "${TEST_VID}" && -n "${TEST_PID}" ]] || die "pass --vid and --pid (see: usbguard list-devices)"

  log "appending a TEMPORARY allow rule for ${TEST_VID}:${TEST_PID}"
  # --temporary keeps it out of rules.conf, so a reboot drops it.
  usbguard append-rule --temporary "allow id ${TEST_VID}:${TEST_PID}" \
    || die "append-rule failed"
  record "temporary allow rule added for ${TEST_VID}:${TEST_PID}"

  log "re-insert the device, then press Enter"
  read -r _
  sleep 3

  capture 60-allow-usbguard-devices usbguard list-devices
  capture 61-allow-lsblk            lsblk -o NAME,SIZE,TYPE,RM,MOUNTPOINT

  warn "If a node now appears and the standard user CAN mount and write to it,"
  warn "then the earlier block result was real enforcement and not a broken stick."
  log "run: sudo $0 test-block --user ${TEST_USER}  again after 'restore-rules'"
}

# --------------------------------------------------------------------------- #
# cmd: test-ipc-listen - can an unprivileged account get READ-ONLY events?
# --------------------------------------------------------------------------- #
cmd_test_ipc_listen() {
  require_root
  resolve_test_user
  have usbguard || die "usbguard not installed"

  # This validates the agentd/enforcerd split: agentd (unprivileged) only needs to
  # LISTEN for device events, while enforcerd (root) is the only thing that may
  # change policy. If Devices=listen works, agentd never needs policy-write rights.
  log "granting ${TEST_USER} read-only device-event access (Devices=listen)"
  usbguard add-user "${TEST_USER}" --devices=listen \
    || warn "add-user failed - record the error; the agent may need another route"
  record "granted Devices=listen to ${TEST_USER}"

  capture 70-ipc-acl bash -c 'ls -la /etc/usbguard/IPCAccessControl.d/ 2>&1 || echo "no IPCAccessControl.d"'

  log "as ${TEST_USER}, trying to WATCH events (should succeed) for 20s"
  if have timeout; then
    ( sudo -u "${TEST_USER}" -- timeout 20 usbguard watch \
        > "${EVIDENCE_DIR}/71-ipc-listen-watch.txt" 2>&1 || true ) &
    local watch_pid=$!
    log "insert/remove the test stick now"
    wait "${watch_pid}" 2>/dev/null || true
  else
    ( sudo -u "${TEST_USER}" -- usbguard watch \
        > "${EVIDENCE_DIR}/71-ipc-listen-watch.txt" 2>&1 || true ) &
    local watch_pid=$!
    log "insert/remove the test stick now (stopping in 20s)"
    sleep 20
    kill "${watch_pid}" 2>/dev/null || true
    wait "${watch_pid}" 2>/dev/null || true
  fi

  log "as ${TEST_USER}, trying to MODIFY policy (should FAIL - least privilege)"
  {
    printf '### expected: permission denied, because only Devices=listen was granted\n\n'
    sudo -u "${TEST_USER}" -- usbguard append-rule "allow id 1234:5678" 2>&1 \
      || printf '\nexit=%s (a non-zero exit here is the DESIRED result)\n' "$?"
  } > "${EVIDENCE_DIR}/72-ipc-listen-cannot-modify.txt"

  printf '  -> %s\n' "${EVIDENCE_DIR}/71-ipc-listen-watch.txt"
  printf '  -> %s\n' "${EVIDENCE_DIR}/72-ipc-listen-cannot-modify.txt"
  warn "remember: 'restore' removes this grant"
}

# --------------------------------------------------------------------------- #
# cmd: root-bypass - demonstrate the limitation we must document honestly
# --------------------------------------------------------------------------- #
cmd_root_bypass() {
  require_root
  have usbguard || die "usbguard not installed"
  log "demonstrating the KNOWN LIMITATION: local root can bypass enforcement"
  {
    printf '### Known limitation evidence: local root bypasses usbguard.\n'
    printf '### This is why docs say "detection and response", not "prevention".\n\n'
    printf '--- before: device list ---\n'
    usbguard list-devices 2>&1 || true
    printf '\n--- root can stop the daemon ---\n'
    systemctl stop usbguard.service 2>&1 && printf 'stopped: yes\n' || printf 'stopped: no\n'
    systemctl is-active usbguard.service 2>&1 || true
    printf '\n--- root can re-authorize a device directly via sysfs ---\n'
    printf 'sysfs authorized flags (writable by root only):\n'
    for f in /sys/bus/usb/devices/*/authorized; do
      [[ -e "${f}" ]] && printf '%s = %s\n' "${f}" "$(cat "${f}" 2>/dev/null || echo '?')"
    done
    printf '\n--- root can set authorized_default ---\n'
    for f in /sys/bus/usb/devices/usb*/authorized_default; do
      [[ -e "${f}" ]] && printf '%s = %s\n' "${f}" "$(cat "${f}" 2>/dev/null || echo '?')"
    done
    printf '\n### restarting the daemon\n'
    systemctl start usbguard.service 2>&1 || true
    systemctl is-active usbguard.service 2>&1 || true
  } > "${EVIDENCE_DIR}/80-root-bypass.txt"
  printf '  -> %s\n' "${EVIDENCE_DIR}/80-root-bypass.txt"
  record "captured root-bypass evidence"
  ok "daemon restarted"
}

# --------------------------------------------------------------------------- #
# cmd: post-reboot - persistence and boot-order evidence
# --------------------------------------------------------------------------- #
cmd_post_reboot() {
  require_root
  log "checking that enforcement survived the reboot and came up before the network"

  capture 90-enabled-state  bash -c 'systemctl is-enabled usbguard.service 2>&1 || true'
  capture 91-active-state   bash -c 'systemctl is-active  usbguard.service 2>&1 || true'
  capture 92-rules-on-disk  bash -c "cat '${USBGUARD_RULES}' 2>/dev/null || echo MISSING"
  capture 93-conf-on-disk   bash -c "cat '${USBGUARD_CONF}'  2>/dev/null || echo MISSING"
  capture 94-devices        bash -c 'usbguard list-devices 2>&1 || true'

  # Boot ordering: did usbguard become active BEFORE network-online.target?
  # The brief requires USB rules to hold at boot before the network is up.
  capture 95-boot-order bash -c '
    echo "--- usbguard.service activation ---"
    systemctl show usbguard.service -p ActiveEnterTimestampMonotonic -p ActiveEnterTimestamp
    echo "--- network-online.target activation ---"
    systemctl show network-online.target -p ActiveEnterTimestampMonotonic -p ActiveEnterTimestamp
    echo "--- unit ordering ---"
    systemctl show usbguard.service -p After -p Before -p WantedBy
    echo "--- blame (top 15) ---"
    systemd-analyze blame 2>/dev/null | head -15 || true'

  capture 96-journal-boot bash -c 'journalctl -u usbguard.service -b --no-pager | head -60 || true'

  warn "COMPARE the two ActiveEnterTimestampMonotonic values in 95-boot-order.txt."
  warn "usbguard must be the smaller number for 'rules hold before the network' to be true."
  log ""
  log "Also do the physical test: shut down WITH the unauthorized stick inserted,"
  log "boot, log in as the standard user, and check that it is still blocked."
}

# --------------------------------------------------------------------------- #
# cmd: restore
# --------------------------------------------------------------------------- #
cmd_restore() {
  require_root
  log "restoring the machine to its pre-spike state"

  # Drop the IPC grant if we made one.
  if [[ -n "${TEST_USER}" ]] || [[ -n "${SUDO_USER:-}" ]]; then
    local u="${TEST_USER:-${SUDO_USER}}"
    if have usbguard && id -u "${u}" >/dev/null 2>&1; then
      usbguard remove-user "${u}" 2>/dev/null && ok "removed IPC grant for ${u}" || true
    fi
  fi

  # Restore the newest backup of each file, or remove the file if it was absent.
  local newest
  for base in usbguard-daemon.conf rules.conf; do
    local target="/etc/usbguard/${base}"
    newest="$(ls -1t "${BACKUP_DIR}/${base}".*.bak 2>/dev/null | head -1 || true)"
    if [[ -n "${newest}" ]]; then
      cp -a "${newest}" "${target}"
      ok "restored ${target} from $(basename "${newest}")"
    elif ls -1 "${BACKUP_DIR}/${base}".*.absent >/dev/null 2>&1; then
      rm -f "${target}"
      ok "removed ${target} (it did not exist before the spike)"
    else
      warn "no backup found for ${target}; leaving it as is"
    fi
  done

  # Restore the enabled/disabled state.
  newest="$(ls -1t "${BACKUP_DIR}"/usbguard.enabled-state.* 2>/dev/null | head -1 || true)"
  if [[ -n "${newest}" ]] && grep -q '^enabled' "${newest}"; then
    systemctl enable usbguard.service 2>/dev/null || true
    systemctl restart usbguard.service 2>/dev/null || true
    ok "usbguard left enabled (its state before the spike)"
  else
    systemctl stop usbguard.service 2>/dev/null || true
    systemctl disable usbguard.service 2>/dev/null || true
    ok "usbguard stopped and disabled (its state before the spike)"
  fi

  record "restored"
  warn "If you installed usbguard for this spike and want it gone:"
  warn "  sudo apt-get purge usbguard && sudo rm -rf /etc/usbguard"
  warn "Verify your USB keyboard and mouse still work before logging out."
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
main() {
  local cmd="${1:-help}"
  shift || true
  parse_args "$@"

  case "${cmd}" in
    env)              cmd_env ;;
    install)          cmd_install ;;
    arm)              cmd_arm ;;
    listen)           cmd_listen ;;
    test-block)       cmd_test_block ;;
    test-allow)       cmd_test_allow ;;
    test-ipc-listen)  cmd_test_ipc_listen ;;
    root-bypass)      cmd_root_bypass ;;
    post-reboot)      cmd_post_reboot ;;
    restore)          cmd_restore ;;
    help|--help|-h)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      ;;
    *) die "unknown command '${cmd}' - try: $0 help" ;;
  esac
}

main "$@"
