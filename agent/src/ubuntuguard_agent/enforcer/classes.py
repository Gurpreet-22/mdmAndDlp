"""USB interface class vocabulary.

Translates the class *names* used in UbuntuGuard's `usb_control` policy into
the numeric USB interface class codes that USBGuard rules match on.

This mapping is the whole reason the policy protocol can be data-only: the
server says "mass_storage" and "hid", never "08:*:*" or a rule string. The
translation happens here, on the endpoint, where it cannot be influenced by
whatever the server sent.

Codes are from the USB-IF defined class list. Only the classes UbuntuGuard's
schema names are included -- an unknown name is an error, never a guess.
"""

from __future__ import annotations

from types import MappingProxyType

#: Class names the policy may list under `protected_classes`.
#:
#: `image` is USB class 06 (PTP/MTP): phones and cameras. It is a separate
#: protected class rather than part of mass_storage because a phone in MTP
#: mode presents class 06 and is therefore *not* caught by a storage-only
#: policy -- a gap that looks like working enforcement until someone tests it
#: with a phone.
PROTECTED_CLASS_CODES: dict[str, tuple[str, ...]] = {
    "mass_storage": ("08",),
    "image": ("06",),
}

#: Class names the policy may list under `always_allow_classes`.
#:
#: Two entries need comment:
#:
#: `cdc` and `network` both map to the CDC pair (02 control, 0a data), because
#: USB networking *is* CDC -- an Ethernet dongle presents 02 and 0a together.
#: They are distinct names in the schema but not distinct code sets. Harmless
#: here (both are allow-lists, so overlap cannot widen anything beyond what
#: either alone would), but worth confirming with the schema author rather
#: than leaving as a silent assumption.
#:
#: `vendor_specific` (ff) is deliberately available: USB-C docks and
#: fingerprint readers commonly present ff, and a policy that cannot allow
#: them would make docks unusable. It is broad, so the dashboard should show
#: it as such.
ALWAYS_ALLOW_CLASS_CODES: dict[str, tuple[str, ...]] = {
    "audio": ("01",),
    "cdc": ("02", "0a"),
    "hid": ("03",),
    "physical": ("05",),
    "printer": ("07",),
    "hub": ("09",),
    "smartcard": ("0b",),
    "video": ("0e",),
    "billboard": ("11",),
    "network": ("02", "0a"),
    "wireless": ("e0",),
    "vendor_specific": ("ff",),
}

#: Classes that must appear in `always_allow_classes` for a policy to be
#: applied at all.
#:
#: Without HID the policy can deauthorise the keyboard and mouse, leaving a
#: desktop user with no way to undo it. Without hub, every device behind a
#: dock or hub disappears, including that keyboard. The schema already
#: requires both; this is the endpoint re-checking rather than trusting it,
#: because the endpoint is where the lockout would actually happen.
REQUIRED_ALWAYS_ALLOW: frozenset[str] = frozenset({"hid", "hub"})

#: Human-readable names, for operator-facing output only. Never used for
#: matching.
CLASS_DESCRIPTIONS = MappingProxyType(
    {
        "01": "audio",
        "02": "communications (CDC control)",
        "03": "human interface",
        "05": "physical",
        "06": "image (PTP/MTP)",
        "07": "printer",
        "08": "mass storage",
        "09": "hub",
        "0a": "CDC data",
        "0b": "smart card",
        "0e": "video",
        "11": "billboard",
        "e0": "wireless controller",
        "ff": "vendor specific",
    }
)


def protected_codes(names: list[str]) -> tuple[str, ...]:
    """Resolve `protected_classes` names to interface class codes.

    Raises KeyError on an unrecognised name. Refusing is deliberate: silently
    dropping a class the operator asked to protect would produce a policy that
    enforces less than the dashboard claims.
    """
    codes: list[str] = []
    for name in names:
        if name not in PROTECTED_CLASS_CODES:
            raise KeyError(
                f"unknown protected class {name!r}; "
                f"known: {', '.join(sorted(PROTECTED_CLASS_CODES))}"
            )
        for code in PROTECTED_CLASS_CODES[name]:
            if code not in codes:
                codes.append(code)
    return tuple(codes)


def always_allow_codes(names: list[str]) -> tuple[str, ...]:
    """Resolve `always_allow_classes` names to interface class codes."""
    codes: list[str] = []
    for name in names:
        if name not in ALWAYS_ALLOW_CLASS_CODES:
            raise KeyError(
                f"unknown always-allow class {name!r}; "
                f"known: {', '.join(sorted(ALWAYS_ALLOW_CLASS_CODES))}"
            )
        for code in ALWAYS_ALLOW_CLASS_CODES[name]:
            if code not in codes:
                codes.append(code)
    return tuple(codes)


def selector(code: str) -> str:
    """Render a class code as a USBGuard interface selector, e.g. 08:*:*."""
    return f"{code}:*:*"
