# USBGuard enforcement spike

**Status: NOT YET RUN. Every USB enforcement claim in this repo is UNVALIDATED until it is.**

USBGuard is a *candidate*, not a decision. This spike exists to find out whether it
genuinely blocks unauthorized USB storage for a standard user on Ubuntu 22.04 and
24.04 — before Phase 5 builds a feature on top of it. The decision rule is written
down below *before* the experiment, so the result cannot be argued into a pass.

## Why this has to run on your hardware

I cannot run it from here, and the gaps are not incidental:

| Requirement | This dev box |
|---|---|
| Ubuntu 22.04 or 24.04 | Ubuntu 26.04.1 — not a target release |
| `usbguard` installed | absent, and installing it needs interactive sudo |
| root | no passwordless sudo |
| A physical USB stick to insert and remove | cannot be done remotely at all |

The last row is the real blocker. Enforcement is a physical-world property; it cannot
be asserted from a code review.

## Before you start

- Use a **scratch machine or VM**, not your daily driver.
- Keep a **non-USB route in**: SSH, a VM console, or a laptop's built-in keyboard.
  `ImplicitPolicyTarget=block` can disable a USB keyboard. The script refuses to arm
  without `--i-have-console-access` and aborts if a USB HID device is attached but
  absent from the generated allow-policy, but a way back in is still your safety net.
- Have **two USB sticks**: one to stay unauthorized (the thing being blocked), one to
  allowlist (to prove the allow path works and that the first stick isn't simply dead).
- Prefer a stick **with no serial number** for case D, and a **USB hub or USB-C dock**
  for case E. Those are the cases that break naive implementations.
- Run each step on **both 22.04 and 24.04**. `usbguard` versions differ between them
  and a pass on one is not a pass on the other.

## Run order

```bash
cd spike/usbguard

sudo ./spike.sh env                                   # read-only survey, no changes
sudo ./spike.sh install                               # asks before apt-get
sudo ./spike.sh arm --i-have-console-access           # backs up, allows present, blocks rest

# in a second terminal, while you insert/remove the unauthorized stick:
sudo ./spike.sh listen --seconds 90

sudo ./spike.sh test-block --user <standard-user>     # the core enforcement test
sudo ./spike.sh test-ipc-listen --user <standard-user>
sudo ./spike.sh root-bypass                           # documents the limitation
sudo ./spike.sh test-allow --user <standard-user> --vid 090c --pid 1000

sudo reboot                                           # with the unauthorized stick IN
sudo ./spike.sh post-reboot

sudo ./spike.sh restore                               # put the machine back
```

Everything lands in `evidence/` (gitignored — it is machine-specific and contains
USB serials). Copy `RESULTS-template.md` to `RESULTS-ubuntu2204.md` /
`RESULTS-ubuntu2404.md`, fill it in, and commit those.

## What each case decides

| Case | Question | Why it matters |
|---|---|---|
| **A** | Does a `/dev/sd*` node appear at all for a blocked stick? | The strongest possible result. usbguard deauthorizes the device so `usb-storage` never binds, leaving nothing to mount. Far better than "mount was refused". |
| **B** | Can a standard user mount it via `udisksctl` / the desktop path? | **The only mount test that means anything.** A standard user cannot run `mount(8)` on any Linux box, with or without usbguard, so "mount failed" on its own proves nothing. The desktop auto-mount path through udisks2 is what a real user would actually use. |
| **C** | Does enforcement survive a reboot, and come up before the network? | Policy must hold at boot before the agent can reach the server. The script compares `usbguard.service` and `network-online.target` activation timestamps. |
| **D** | What happens with a stick that reports **no serial**? | Allowlisting by serial is impossible for these, which is exactly why the policy schema has `serial_match: "any"` and why the dashboard must label such rules as weaker. |
| **E** | Hubs and composite devices | A composite device exposes several interface classes at once; a USB-C dock is a hub plus network, audio, video and HID. Getting this wrong locks people out of their docks. USBGuard has open issues in this area. |
| **F** | **D-Bus vs udev as the event source** | The brief flags this: a blocked device may never enumerate its interfaces, so udev may report almost nothing. `listen` captures the same insertion from `gdbus`, `usbguard watch` and `udevadm` side by side so the choice is based on what each actually produced. |
| **G** | Keyboards, mice and docks keep working | A DLP control that locks users out gets switched off, which is worse than not shipping it. |
| **H** | Can an unprivileged account get **read-only** events via `Devices=listen`? | This decides the agent's privilege split. If yes, `agentd` listens with no ability to change policy and only root `enforcerd` may write. If no, we need a different event path. |
| **I** | Root bypass | Captured deliberately so the documented limitation is backed by evidence, not an apology. |

## Decision rule — written before the experiment

**GO** (build Phase 5 on usbguard) requires, on **both** 22.04 and 24.04:

1. Case A or B passes — the standard user cannot read or mount the unauthorized
   stick. A alone is sufficient; B alone is acceptable; neither is a fail.
2. Case C passes — still blocked after a reboot, with usbguard active before
   `network-online.target`.
3. Case G passes — USB keyboard, mouse and dock keep working throughout.
4. Case F yields at least one event source that reports vendor, product and decision
   for a **blocked** device.

**NO-GO** on any of:

- the stick is mountable or readable by a standard user (enforcement is cosmetic);
- enforcement does not survive a reboot;
- any input device or dock is disabled by a policy that allowed it before;
- no event source can identify a blocked device, leaving nothing to report.

**Fallbacks if NO-GO**, in preference order, each needing its own spike:

1. `authorized_default=0` on USB controllers plus a udev rule, managed by `enforcerd`
   directly — removes the usbguard dependency but means we own the hard cases.
2. udev rules that block only `ID_USB_DRIVER=usb-storage` — narrower, and does not
   stop a device that lies about its class.
3. Blacklist the `usb_storage` / `uas` modules — blunt, breaks allowlisting entirely,
   and trivially reversed by root.

Partial result, e.g. 24.04 passes and 22.04 fails: ship the feature with an explicit
supported-release matrix and report `unsupported` on the failing release. The capability
reporting in `inventory.v1` already models that outcome.

## Honest framing for whatever comes out

Even a clean GO supports only this sentence: *"blocks unauthorized USB mass-storage
devices for standard (non-root) users on Ubuntu <version> with usbguard <version>."*
It does not support "prevents data theft". Local root bypasses it (case I), and a user
can still photograph the screen.
