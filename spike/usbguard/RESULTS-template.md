# USBGuard spike results — Ubuntu __._ (__)

Copy to `RESULTS-ubuntu2204.md` or `RESULTS-ubuntu2404.md`, fill in, commit.
Leave a row as `NOT RUN` rather than guessing. An empty row is information; a
guessed row is a bug waiting to ship.

## Environment

| Field | Value |
|---|---|
| Date (UTC) | |
| Operator | |
| Ubuntu version (`/etc/os-release` VERSION) | |
| Kernel (`uname -r`) | |
| Bare metal or VM (`systemd-detect-virt`) | |
| usbguard version (`usbguard --version`) | |
| usbguard units present | |
| `usbguard-dbus` service present and active? | |
| gdbus / dbus-monitor / udisksctl present? | |
| Unauthorized test stick (vendor:product, serial or NONE) | |
| Allowlisted test stick (vendor:product, serial) | |
| Hub / dock model used | |
| Standard (non-root) test user | |

## Results

| Case | Question | Result | Evidence file | Notes |
|---|---|---|---|---|
| A | No `/dev/sd*` node appears for the blocked stick | PASS / FAIL / NOT RUN | `52-nodes-after.txt` | |
| B | Standard user **cannot** mount via `udisksctl` | PASS / FAIL / NOT RUN | `54-user-mount-*.txt` | |
| B2 | Standard user **cannot** raw-read via `dd` | PASS / FAIL / NOT RUN | `54-user-mount-*.txt` | |
| C1 | Still blocked after reboot | PASS / FAIL / NOT RUN | `92-rules-on-disk.txt`, `94-devices.txt` | |
| C2 | usbguard active **before** `network-online.target` | PASS / FAIL / NOT RUN | `95-boot-order.txt` | record both monotonic timestamps |
| C3 | Blocked when inserted *before* boot | PASS / FAIL / NOT RUN | | physical test |
| D | No-serial stick: can it be matched and blocked? | PASS / FAIL / NOT RUN | `51-usbguard-devices-after.txt` | what did `serial` field contain? |
| E1 | Hub itself stays usable | PASS / FAIL / NOT RUN | | |
| E2 | Storage behind a hub is still blocked | PASS / FAIL / NOT RUN | | |
| E3 | Composite device (storage + HID) behaviour | PASS / FAIL / NOT RUN | | did it block the whole device or one interface? |
| F1 | D-Bus reports vendor/product/decision for a **blocked** device | PASS / FAIL / NOT RUN | `40-events-*.txt` | which signal fired? |
| F2 | `usbguard watch` reports the same | PASS / FAIL / NOT RUN | `41-events-usbguard-watch.txt` | |
| F3 | udev reports enough to identify a blocked device | PASS / FAIL / NOT RUN | `42-events-udev.txt` | expected to be thin — that is the finding |
| G1 | USB keyboard keeps working while armed | PASS / FAIL / NOT RUN | | |
| G2 | USB mouse keeps working | PASS / FAIL / NOT RUN | | |
| G3 | USB-C dock keeps working (network, display, audio) | PASS / FAIL / NOT RUN | | |
| H1 | Unprivileged user **can** listen with `Devices=listen` | PASS / FAIL / NOT RUN | `71-ipc-listen-watch.txt` | decides the agentd privilege split |
| H2 | Same user **cannot** modify policy | PASS / FAIL / NOT RUN | `72-ipc-listen-cannot-modify.txt` | non-zero exit is the desired result |
| I | Root can bypass (expected: yes) | CONFIRMED / NOT RUN | `80-root-bypass.txt` | documents the known limitation |
| J | Allowlisted stick **is** usable by the standard user | PASS / FAIL / NOT RUN | `60-*`, `61-*` | proves the block was real, not a dead stick |

## Which signal should the agent consume?

Pick one and say why, citing the evidence files:

- [ ] `org.usbguard.Devices1.DevicePolicyApplied` — documented as a superset of
      `DevicePolicyChanged`, fired on insert, authorise and reject
- [ ] `org.usbguard.Devices1.DevicePolicyChanged`
- [ ] `org.usbguard.Devices1.DevicePresenceChanged`
- [ ] `usbguard watch` over IPC
- [ ] udev

Chosen: ______________  Available in this usbguard version? ______

Reason:

Startup reconciliation: the D-Bus interface documentation warns that
`DevicePresenceChanged` for already-present devices may not reach bus clients,
because connections are handled after devices are processed. Did a `listDevices`
call at startup return the already-attached devices? ______

## Attribute fields actually observed

Record exactly what arrived, so `event.usb.v1` matches reality rather than the docs:

| Attribute | Present? | Example value (redact serials if sharing) |
|---|---|---|
| `id` (vendor:product) | | |
| `name` | | |
| `serial` | | |
| `via-port` | | |
| `hash` | | |
| `parent-hash` | | |
| `with-interface` | | |
| `with-connect-type` | | |

Was `with-interface` **empty** for a device blocked before enumeration? ______
(`event.usb.v1` already permits an empty `interface_classes` array for this reason.)

## Verdict

- [ ] **GO** — all four GO conditions in `README.md` met
- [ ] **PARTIAL** — ship with an explicit supported-release matrix; failing release reports `unsupported`
- [ ] **NO-GO** — fall back to option ___ from `README.md` and spike that instead

Exact sentence the docs are now allowed to use:

> blocks unauthorized USB mass-storage devices for standard (non-root) users on
> Ubuntu ______ with usbguard ______

Surprises, breakage, or anything that should change the Phase 5 design:
