#!/usr/bin/env python3
"""Build the UbuntuGuard agent `.deb`.

Produces three files from one source tree:

    ubuntuguard-agent_<version>_<arch>.deb         the artifact an employee downloads
    ubuntuguard-agent_<version>_<arch>.deb.sha256  the digest the enrollment page shows
    deb-manifest.json                              what the server serves as metadata

Why this exists alongside `build_installer.py`
----------------------------------------------
`docs/04-feature-list.md` records that the employee artifact is a script and
not a `.deb`, for one specific reason: `postinst` must not enrol (feature
D11's own constraint), and a `.deb` opened from a browser is handled by GNOME
Software, which gives the employee no terminal in which to type a token. They
would install successfully and then be stuck.

That reasoning is correct about the terminal and wrong only in its conclusion
that the prompt has to be a terminal. This package ships a desktop
application - `ubuntuguard-enroll` - which the employee opens after
installing and pastes their token into. `postinst` still does not enrol, and
the token is still something a person is handed and types once.

What this does NOT do is make enrollment automatic. It cannot, and neither
could any other packaging. Automatic enrollment means a credential the
package already holds, and a package published for every employee to download
holds nothing secret. The alternative - one shared enrollment secret baked
into the artifact - would turn a single-use, auditable, per-device token into
a permanent fleet-wide password sitting in every employee's Downloads folder.

What goes in, and what must never
---------------------------------
In: the agent source (the same allowlist `build_installer.py` uses), the
runtime dependency wheels, the enrollment application, a systemd-less
`agent.yaml` holding the server URL, and optionally the CA certificate that
validates the SERVER's TLS.

Never: a private key, a device certificate, or an enrollment token. The CA
reader is shared with `build_installer.py`, so `--server-ca ca.key` is refused
here for the same reason and by the same code.

Offline by construction
-----------------------
The runtime dependencies are downloaded at BUILD time into a wheelhouse inside
the package, and `postinst` points pip at it with `PIP_NO_INDEX`. An employee
installing with one `apt install` command should not have to read pip
worked but configuring it needed the internet" is a failure mode worth
spending 6 MB to remove.

The wheelhouse carries pip itself, because `install.sh` runs
`pip install --upgrade pip`, which with no index and no local pip wheel would
fail and abort the install.

Determinism
-----------
Two builds of one tree, with the same inputs, produce a byte-identical `.deb`.
Both tars sort their members and pin every mtime, uid, gid, uname, gname and
mode; gzip is given `mtime=0` because it stores a timestamp in its own header
that `tarfile`'s determinism does not reach; and the `ar` headers that wrap
them are written with a fixed mtime too. The build timestamp lives in the
manifest, not in the artifact, so that the digest published on a web page does
not change when the code did not.

The `.deb` is assembled here rather than by `dpkg-deb` for that reason and one
other: `dpkg-deb` is not deterministic across versions, and requiring it would
make the build fail on a machine that can otherwise run every test.

Usage
-----
    python3 agent/packaging/build_deb.py \\
        --server-url https://mdm.company.com \\
        --server-ca /etc/ssl/ubuntuguard/internal-ca.crt \\
        --output-dir server/var/installer
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path

# Shared with the script installer rather than reimplemented. The URL
# validator mirrors the agent's own, and the CA reader refuses a private key;
# both properties matter identically here, and two copies would drift.
from build_installer import (  # type: ignore[import-not-found]
    BuildError,
    _agent_version,
    _payload_members,
    read_server_ca,
    validate_server_url,
)

PACKAGE_NAME = "ubuntuguard-agent"

MANIFEST_FILENAME = "deb-manifest.json"
MANIFEST_SCHEMA = "ubuntuguard.deb.v1"

#: Runtime dependencies resolved from Debian's archive rather than pip.
#:
#: usbguard is what the root enforcer drives. Declared as a hard dependency
#: because it is the entire point of this package on an employee laptop, and
#: because "apt installs it for you" is the behaviour being asked for. It
#: lives in Ubuntu's `universe` component, which is enabled by default on
#: desktop installs.
#:
#: python3-venv carries ensurepip, which install.sh checks for explicitly: it
#: is the single most common reason that script fails.
#:
#: zenity and polkitd are what the enrollment application is built from. Both
#: are present on a default Ubuntu desktop; declaring them means a minimal or
#: server install gets them rather than a package whose enrollment step cannot
#: run. polkitd is named `policykit-1` before Ubuntu 23.04, hence the
#: alternation.
DEB_DEPENDS: tuple[str, ...] = (
    "python3 (>= 3.10)",
    "python3-venv",
    "usbguard",
    "systemd",
    "zenity",
    "polkitd | policykit-1",
    "passwd",
)

DEB_MAINTAINER = "UbuntuGuard <ubuntuguard@localhost>"
DEB_HOMEPAGE = "https://github.com/Gurpreet-22/mdmAndDlp"

#: Architectures this builder will produce, mapped to the manylinux platform
#: tags pip is asked for.
#:
#: Not `all`, even though the agent is pure Python: the vendored wheels for
#: cryptography and PyYAML carry compiled extensions and are architecture
#: specific. Declaring `all` would let apt install this package on armhf and
#: then fail in postinst, leaving a half-configured package. The architecture
#: is a real property of the artifact, so it is declared as one.
ARCH_PLATFORM_TAGS: dict[str, tuple[str, ...]] = {
    "amd64": (
        "manylinux_2_28_x86_64",
        "manylinux_2_17_x86_64",
        "manylinux2014_x86_64",
    ),
    "arm64": (
        "manylinux_2_28_aarch64",
        "manylinux_2_17_aarch64",
        "manylinux2014_aarch64",
    ),
}

#: CPython versions the wheelhouse must satisfy.
#:
#: 3.10 is the agent's floor (Ubuntu 22.04) and 3.12 is Ubuntu 24.04. The two
#: in between and 3.13 are included because cryptography ships one abi3 wheel
#: that covers all of them, while PyYAML and cffi ship one wheel per version -
#: so the cost of covering a version is small and the cost of missing the one
#: an employee's laptop happens to have is a failed install.
TARGET_PYTHONS: tuple[str, ...] = ("3.10", "3.11", "3.12", "3.13")

#: Packages fetched into the wheelhouse.
#:
#: The two runtime dependencies from pyproject.toml, plus three things the
#: install needs rather than the agent:
#:
#:   pip         install.sh runs `pip install --upgrade pip`, which with
#:               PIP_NO_INDEX set and no local pip wheel fails and aborts.
#:
#:   hatchling   the agent's build backend. install.sh installs the agent from
#:               a source DIRECTORY, so pip builds a wheel from it first, in an
#:               isolated environment it populates from the index. With no
#:               index and no local hatchling that build fails with "No
#:               matching distribution found for hatchling" - which is what the
#:               first offline test of this package did. Vendoring the backend
#:               keeps install.sh unmodified, which matters because it is the
#:               script 45 existing packaging tests describe.
#:
#:   wheel       pip's build isolation expects it to be available for some
#:               backends; cheap insurance at 70 KB.
#:
#: Marker-gated transitive dependencies - hatchling's `tomli` and
#: cryptography's `typing-extensions`, both gated on Python < 3.11 - are NOT
#: listed here. They are resolved correctly because each download pass runs
#: under the interpreter it is resolving for; see `_target_interpreter` for
#: why that matters and what went wrong before it did.
#:
#: Versions are NOT pinned here: the floors come from pyproject.toml, and
#: pinning a ceiling in a second place is how the two drift apart.
#: `--only-binary` and the platform tags do the real constraining.
WHEELHOUSE_REQUIREMENTS: tuple[str, ...] = (
    "cryptography>=42.0",
    "PyYAML>=6.0",
    "pip",
    "hatchling",
    "wheel",
)

#: Wheels the install cannot proceed without, checked by name after the
#: download. Asserted rather than assumed because each one's absence produces a
#: failure at `apt install` time on an employee's laptop, which is the worst
#: place to discover it.
#: tomli and typing_extensions are in this list precisely because they are the
#: marker-gated ones. They are the wheels a resolution bug drops silently, and
#: their absence breaks only the oldest supported Ubuntu - the configuration
#: least likely to be the one the package was tested on.
REQUIRED_WHEEL_PREFIXES: tuple[str, ...] = (
    "pip-",
    "hatchling-",
    "tomli-",
    "tomlkit-",
    "trove_classifiers-",
    "packaging-",
    "pathspec-",
    "pluggy-",
    "typing_extensions-",
    "cryptography-",
    "pyyaml-",
    "cffi-",
)

#: Paths inside the package.
SHARE_DIR = "usr/share/ubuntuguard"
SOURCE_SUBDIR = f"{SHARE_DIR}/agent-src"
WHEEL_SUBDIR = f"{SHARE_DIR}/wheels"
CONFIG_DIR = "etc/ubuntuguard"
SERVER_CA_PATH = f"{CONFIG_DIR}/server-ca.pem"
AGENT_YAML_PATH = f"{CONFIG_DIR}/agent.yaml"
HELPER_PATH = "usr/libexec/ubuntuguard/ubuntuguard-enroll-root"
LAUNCHER_PATH = "usr/bin/ubuntuguard-enroll"
DESKTOP_PATH = "usr/share/applications/ubuntuguard-enroll.desktop"
POLICY_PATH = "usr/share/polkit-1/actions/com.ubuntuguard.enroll.policy"

#: The login reminder, shipped INERT here and copied to /etc/xdg/autostart by
#: postinst only when the laptop has no identity.
#:
#: Not shipped straight into /etc/xdg/autostart, which would be simpler and
#: wrong: dpkg would own it, restore it on every upgrade, and an already
#: enrolled laptop would start being asked for a token again. Leaving the copy
#: to postinst and the deletion to the enrollment helper makes the file's
#: presence mean "still needs enrolling", with only root able to change it and
#: nothing to fall out of step with.
AUTOSTART_TEMPLATE_PATH = f"{SHARE_DIR}/ubuntuguard-enroll-autostart.desktop"
AUTOSTART_INSTALLED_PATH = "etc/xdg/autostart/ubuntuguard-enroll.desktop"
DOC_DIR = f"usr/share/doc/{PACKAGE_NAME}"

#: Matches install.sh and installer-template.sh. The agent permits exactly two
#: configuration keys and refuses to start with a third, so this file is
#: written literally rather than templated from a structure that could grow a
#: field.
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

#: Files dpkg must treat as configuration: it will not overwrite local edits on
#: upgrade, and it removes them on purge. agent.yaml holds the server URL, so
#: it is genuinely configuration and not generated state.
CONFFILES: tuple[str, ...] = (AGENT_YAML_PATH, SERVER_CA_PATH)

_FIXED_MTIME = 0
_MODE_FILE = 0o644
_MODE_EXEC = 0o755
_MODE_DIR = 0o755

#: install.sh installs these two units. A `.deb` that shipped the agent source
#: without one of them would install the agent and then fail partway through
#: postinst, so the set is asserted at build time instead.
REQUIRED_UNITS: tuple[str, ...] = (
    "packaging/systemd/ubuntuguard-agent.service",
    "packaging/systemd/ubuntuguard-enforcerd.service",
)


# --------------------------------------------------------------------------- #
# ar, the outer container
# --------------------------------------------------------------------------- #


def _ar_member(name: str, data: bytes) -> bytes:
    """One `ar` member: a 60-byte header, the data, padded to an even length.

    Written by hand because the standard library has no `ar` writer, the format
    is sixty bytes of ASCII, and the alternative is making `dpkg-deb` a build
    dependency for something this small. Every numeric field is fixed, which is
    what makes the artifact reproducible.

    Debian requires the three members in order - `debian-binary`,
    `control.tar.gz`, `data.tar.gz` - and all three names are under the
    sixteen-character limit, so none of `ar`'s long-name extensions are needed.
    """
    if len(name) > 16:
        raise BuildError(f"ar member name {name!r} exceeds 16 characters")
    header = (
        f"{name:<16}"
        f"{_FIXED_MTIME:<12}"
        f"{0:<6}"  # uid
        f"{0:<6}"  # gid
        f"{_MODE_FILE:<8o}"
        f"{len(data):<10}"
        "`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise BuildError(f"built a malformed ar header of {len(header)} bytes for {name!r}")
    # Members are padded to an even offset with a newline, and the padding is
    # not counted in the size field.
    padding = b"\n" if len(data) % 2 else b""
    return header + data + padding


def build_ar(members: Sequence[tuple[str, bytes]]) -> bytes:
    return b"!<arch>\n" + b"".join(_ar_member(name, data) for name, data in members)


# --------------------------------------------------------------------------- #
# tar, the two inner archives
# --------------------------------------------------------------------------- #


class TarBuilder:
    """Collects members, then emits one deterministic gzipped tar.

    Members are buffered rather than streamed so they can be sorted by name:
    the archive's byte layout is then a property of the file set and not of
    whatever order the caller happened to add things in, or of the
    filesystem's directory order, which is not stable across machines.
    """

    def __init__(self) -> None:
        self._files: dict[str, tuple[bytes, int]] = {}
        self._dirs: set[str] = set()

    def add_file(self, name: str, data: bytes, *, mode: int = _MODE_FILE) -> None:
        name = name.lstrip("./")
        if name in self._files:
            raise BuildError(f"{name} was added to the archive twice")
        self._files[name] = (data, mode)
        # Every parent directory, declared explicitly. dpkg relies on the
        # archive carrying its directories rather than inferring them, and an
        # inferred directory would land with whatever umask dpkg happened to
        # have.
        parent = Path(name).parent
        while str(parent) not in (".", "/"):
            self._dirs.add(str(parent))
            parent = parent.parent

    def has(self, name: str) -> bool:
        return name.lstrip("./") in self._files

    def add_tree(self, prefix: str, members: Sequence[tuple[str, Path]]) -> None:
        for relative, source in members:
            mode = _MODE_EXEC if relative.endswith(".sh") else _MODE_FILE
            self.add_file(f"{prefix}/{relative}", source.read_bytes(), mode=mode)

    def _info(self, name: str, *, mode: int, is_dir: bool, size: int) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name=f"./{name}")
        info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
        info.mode = mode
        info.size = size
        info.mtime = _FIXED_MTIME
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        return info

    def to_gzip(self) -> bytes:
        raw = io.BytesIO()
        # GNU_FORMAT rather than PAX: a PAX archive carries an extra header
        # member per entry, and dpkg on Ubuntu 22.04 reads GNU tar without
        # comment. The determinism properties are the same.
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name in sorted(self._dirs):
                archive.addfile(self._info(name, mode=_MODE_DIR, is_dir=True, size=0))
            for name in sorted(self._files):
                data, mode = self._files[name]
                archive.addfile(
                    self._info(name, mode=mode, is_dir=False, size=len(data)),
                    io.BytesIO(data),
                )
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gz:
            gz.write(raw.getvalue())
        return compressed.getvalue()

    def md5sums(self) -> bytes:
        """dpkg's manifest of shipped file digests, used by `dpkg --verify`."""
        lines = [
            f"{hashlib.md5(self._files[name][0]).hexdigest()}  {name}\n"
            for name in sorted(self._files)
        ]
        return "".join(lines).encode("utf-8")

    def installed_size_kib(self) -> int:
        total = sum(len(data) for data, _ in self._files.values())
        return max(1, total // 1024)


# --------------------------------------------------------------------------- #
# The wheelhouse
# --------------------------------------------------------------------------- #


def _target_interpreter(python_version: str, cache_dir: Path, uv: str) -> Path:
    """Provide a real CPython of `python_version`, via uv.

    A REAL interpreter, rather than `pip download --python-version`, because
    that flag does not do what this build needs. It constrains which wheel
    TAGS are acceptable, but environment markers are still evaluated against
    the interpreter running pip. Every marker-gated dependency therefore
    resolves for the build host instead of the target:
    `tomli; python_version < "3.11"` and
    `typing-extensions; python_version < "3.11"` were both silently omitted on
    this 3.14 host, and each one produced a wheelhouse that installed fine
    here and failed on Ubuntu 22.04.

    Discovering those one at a time and adding them to a list by hand is not a
    fix - it is a list that is wrong again the next time a dependency adds a
    marker. Running pip under the interpreter it is resolving for makes the
    markers correct by construction.
    """
    venv_dir = cache_dir / f"py{python_version}"
    python = venv_dir / "bin" / "python"
    if python.is_file():
        return python

    # --seed gives the venv its own pip, which is what resolves and downloads.
    result = subprocess.run(
        [uv, "venv", "--python", python_version, "--seed", str(venv_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BuildError(
            f"could not provide a Python {python_version} interpreter with uv:\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    if not python.is_file():
        raise BuildError(f"uv reported success but {python} does not exist")
    return python


def download_wheels(
    destination: Path,
    *,
    arch: str,
    uv: str,
    cache_dir: Path,
) -> list[Path]:
    """Fetch the dependency closure as wheels, once per target Python.

    One pass per version in `TARGET_PYTHONS`, each run by that version's own
    interpreter. Three reasons it is per-version rather than one pass:

    - PyYAML and cffi ship a wheel per interpreter version, while cryptography
      ships a single abi3 wheel that covers all of them. Duplicate downloads
      land on the same filename and cost nothing.
    - Marker-gated dependencies differ by version, and only the matching
      interpreter resolves them correctly. See `_target_interpreter`.
    - A version whose wheels cannot be resolved fails the build here, rather
      than failing `apt install` on whichever laptop happens to have it.

    All platform tags for the architecture are passed to every call.
    `--platform` matches wheel tags EXACTLY rather than by compatibility, so
    asking only for `manylinux_2_28` rejects a perfectly usable
    `manylinux_2_17` wheel - and the resolver's response to that is to walk
    backwards through versions looking for anything that matches, which on the
    first attempt at this meant silently selecting a cffi pre-release.
    """
    try:
        platform_tags = ARCH_PLATFORM_TAGS[arch]
    except KeyError:
        raise BuildError(
            f"unknown --arch {arch!r}; expected one of {', '.join(sorted(ARCH_PLATFORM_TAGS))}"
        ) from None

    destination.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    for python_version in TARGET_PYTHONS:
        python = _target_interpreter(python_version, cache_dir, uv)
        command = [
            str(python),
            "-m",
            "pip",
            "download",
            # Source distributions would have to be compiled on the employee's
            # laptop, which needs a toolchain and Python headers a desktop
            # install does not have.
            "--only-binary=:all:",
            "--dest",
            str(destination),
        ]
        for tag in platform_tags:
            command += ["--platform", tag]
        command += list(WHEELHOUSE_REQUIREMENTS)

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise BuildError(
                f"pip download failed under Python {python_version} for {arch}:\n"
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    wheels = sorted(destination.glob("*.whl"))
    if not wheels:
        raise BuildError(f"no wheels were downloaded into {destination}")

    # A pre-release reaching an employee's laptop is not something to discover
    # later. Checked against the resolved filenames rather than trusting the
    # flags above, because the failure mode that produced this check was pip
    # choosing a beta on its own.
    prereleases = [
        wheel.name for wheel in wheels if re.search(r"-\d[^-]*(a|b|rc)\d+[^-]*-", wheel.name)
    ]
    if prereleases:
        raise BuildError(
            "pip resolved pre-release wheels, which must not ship to employee "
            "laptops: " + ", ".join(prereleases)
        )

    check_wheelhouse(wheels)
    return wheels


def check_wheelhouse(wheels: Sequence[Path]) -> None:
    """Refuse a wheelhouse that cannot complete an offline install.

    Shared by the download path and `--wheel-dir`, so a reused directory is
    held to the same standard as a freshly downloaded one.
    """
    names = [wheel.name.lower() for wheel in wheels]
    missing = [
        prefix
        for prefix in REQUIRED_WHEEL_PREFIXES
        if not any(name.startswith(prefix) for name in names)
    ]
    if missing:
        raise BuildError(
            "the wheelhouse is missing wheels the offline install needs: "
            + ", ".join(prefix.rstrip("-") for prefix in missing)
            + ". Without them `apt install` fails on the employee's laptop."
        )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render(template: str, substitutions: dict[str, str], *, origin: str) -> str:
    """Substitute `@NAME@` placeholders, refusing to leave any behind.

    The leftover check is the point of doing this by hand: a renamed
    placeholder would otherwise ship a launcher that tells the employee to
    contact `@ADMIN_CONTACT@`.
    """
    rendered = template
    for placeholder, value in substitutions.items():
        rendered = rendered.replace(placeholder, value)
    leftover = sorted(set(re.findall(r"@[A-Z0-9_]+@", rendered)))
    if leftover:
        raise BuildError(f"{origin} has unsubstituted placeholder(s): {', '.join(leftover)}")
    return rendered


def agent_yaml(*, server_url: str, ca_bundle: str, agent_version: str) -> str:
    return f"""# UbuntuGuard agent configuration.
#
# Written by the .deb build for agent {agent_version}.
#
# Only these two keys are permitted. Every tunable - heartbeat interval,
# backoff, log level - comes from a signed policy from the server, not from
# this file, so editing one here would have no effect and adding a third key
# stops the agent from starting.
#
# server_ca_bundle validates the SERVER to this agent. It is NOT the device CA
# chain, which arrives in the enrollment response and is the issuer of this
# laptop's own client certificate (/var/lib/ubuntuguard/pki/ca-chain.pem).
server_url: {server_url}
server_ca_bundle: {ca_bundle}
"""


def copyright_text() -> str:
    return (
        "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
        f"Upstream-Name: {PACKAGE_NAME}\n"
        f"Source: {DEB_HOMEPAGE}\n"
    )


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def assemble(
    *,
    agent_dir: Path,
    server_url: str,
    server_ca_pem: str | None,
    agent_version: str,
    arch: str,
    deb_version: str,
    admin_contact: str,
    wheels: Sequence[Path],
) -> tuple[bytes, dict[str, object]]:
    """Build the `.deb` bytes and its manifest.

    Returns the artifact rather than writing it, so a test can build in memory
    with no filesystem at all.
    """
    debian_dir = agent_dir / "packaging" / "debian"

    def read(name: str) -> str:
        path = debian_dir / name
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BuildError(f"could not read {path}: {exc}") from exc

    # --- data.tar.gz ------------------------------------------------------- #
    data = TarBuilder()

    payload = _payload_members(agent_dir)
    shipped = {relative for relative, _ in payload}
    for unit in REQUIRED_UNITS:
        if unit not in shipped:
            raise BuildError(
                f"{unit} is not in the payload allowlist, but install.sh installs it. "
                "The package would install the agent and then fail in postinst."
            )
    data.add_tree(SOURCE_SUBDIR, payload)

    for wheel in wheels:
        data.add_file(f"{WHEEL_SUBDIR}/{wheel.name}", wheel.read_bytes())

    ca_bundle = SYSTEM_CA_BUNDLE
    if server_ca_pem is not None:
        ca_bundle = f"/{SERVER_CA_PATH}"
        data.add_file(SERVER_CA_PATH, server_ca_pem.encode("utf-8"))

    data.add_file(
        AGENT_YAML_PATH,
        agent_yaml(
            server_url=server_url,
            ca_bundle=ca_bundle,
            agent_version=agent_version,
        ).encode("utf-8"),
    )

    launcher = render(
        read("ubuntuguard-enroll.in"),
        {"@ADMIN_CONTACT@": admin_contact, "@SERVER_URL@": server_url},
        origin="ubuntuguard-enroll.in",
    )
    data.add_file(LAUNCHER_PATH, launcher.encode("utf-8"), mode=_MODE_EXEC)

    # pkexec refuses to run a helper that is writable by anyone but root, so
    # 0755 root:root is a requirement and not a convention.
    data.add_file(HELPER_PATH, read("ubuntuguard-enroll-root").encode("utf-8"), mode=_MODE_EXEC)
    data.add_file(DESKTOP_PATH, read("ubuntuguard-enroll.desktop").encode("utf-8"))
    data.add_file(POLICY_PATH, read("com.ubuntuguard.enroll.policy").encode("utf-8"))
    data.add_file(
        AUTOSTART_TEMPLATE_PATH,
        read("ubuntuguard-enroll-autostart.desktop").encode("utf-8"),
    )
    data.add_file(f"{DOC_DIR}/copyright", copyright_text().encode("utf-8"))

    data_tar = data.to_gzip()

    # --- control.tar.gz ---------------------------------------------------- #
    control = render(
        read("control.in"),
        {
            "@DEB_VERSION@": deb_version,
            "@DEB_ARCH@": arch,
            "@DEB_DEPENDS@": ", ".join(DEB_DEPENDS),
            "@DEB_MAINTAINER@": DEB_MAINTAINER,
            "@DEB_HOMEPAGE@": DEB_HOMEPAGE,
            "@DEB_INSTALLED_SIZE@": str(data.installed_size_kib()),
        },
        origin="control.in",
    )

    control_tar_builder = TarBuilder()
    control_tar_builder.add_file("control", control.encode("utf-8"))
    control_tar_builder.add_file("md5sums", data.md5sums())
    # Only the conffiles actually shipped. server-ca.pem is absent when the
    # server uses a publicly trusted certificate, and dpkg refuses to install a
    # package whose conffiles list names a file the archive does not contain.
    control_tar_builder.add_file(
        "conffiles",
        "".join(f"/{path}\n" for path in CONFFILES if data.has(path)).encode("utf-8"),
    )
    for script in ("postinst", "prerm", "postrm"):
        control_tar_builder.add_file(script, read(script).encode("utf-8"), mode=_MODE_EXEC)
    control_tar = control_tar_builder.to_gzip()

    artifact = build_ar(
        [
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", control_tar),
            ("data.tar.gz", data_tar),
        ]
    )

    filename = f"{PACKAGE_NAME}_{deb_version}_{arch}.deb"
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "package": PACKAGE_NAME,
        "agent_version": agent_version,
        "deb_version": deb_version,
        "architecture": arch,
        "filename": filename,
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "size_bytes": len(artifact),
        "installed_size_kib": data.installed_size_kib(),
        "server_url": server_url,
        "server_ca": "embedded" if server_ca_pem else "system trust store",
        "depends": list(DEB_DEPENDS),
        "bundled_wheels": sorted(wheel.name for wheel in wheels),
        "target_pythons": list(TARGET_PYTHONS),
        "enrols_on_install": False,
    }
    return artifact, manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_deb.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server-url", required=True, metavar="URL")
    parser.add_argument("--server-ca", type=Path, default=None, metavar="PATH")
    parser.add_argument("--output-dir", type=Path, required=True, metavar="DIR")
    parser.add_argument(
        "--arch",
        default="amd64",
        choices=sorted(ARCH_PLATFORM_TAGS),
        help="Debian architecture to build for. Default: amd64.",
    )
    parser.add_argument(
        "--deb-revision",
        default="1",
        metavar="N",
        help=(
            "Debian revision appended to the agent version, so that a "
            "packaging-only fix can supersede an installed package without the "
            "agent's own version moving. Default: 1."
        ),
    )
    parser.add_argument("--admin-contact", default="your IT administrator", metavar="TEXT")
    parser.add_argument(
        "--wheel-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Reuse an existing wheelhouse instead of downloading. For offline "
            "and repeat builds; the directory's contents are still checked."
        ),
    )
    parser.add_argument(
        "--uv",
        default="uv",
        metavar="PATH",
        help=(
            "uv executable, used to provide one real interpreter per target "
            "Python version so that dependency markers resolve for the target "
            "rather than for this build host. Default: uv on PATH."
        ),
    )
    parser.add_argument(
        "--no-vendor",
        action="store_true",
        help=(
            "Build without the bundled wheelhouse. The package is ~16 MB "
            "smaller, and postinst falls back to pip's configured index, which "
            "means the install needs network access to PyPI. Useful where the "
            "laptops can reach PyPI and the build host has no uv."
        ),
    )
    parser.add_argument("--allow-loopback-http", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    agent_dir = Path(__file__).resolve().parents[1]

    try:
        server_url = validate_server_url(
            args.server_url, allow_loopback_http=args.allow_loopback_http
        )
        server_ca_pem = None if args.server_ca is None else read_server_ca(args.server_ca)
        agent_version = _agent_version(agent_dir)
        deb_version = f"{agent_version}-{args.deb_revision}"

        output_dir: Path = args.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        wheels: list[Path]
        if args.no_vendor:
            wheels = []
            print("building WITHOUT a bundled wheelhouse; the install will need PyPI")
        elif args.wheel_dir is not None:
            wheel_dir = args.wheel_dir
            wheels = sorted(wheel_dir.glob("*.whl"))
            if not wheels:
                raise BuildError(f"--wheel-dir {wheel_dir} contains no .whl files")
            check_wheelhouse(wheels)
            print(f"wheelhouse {wheel_dir} ({len(wheels)} wheels, reused)")
        else:
            wheel_dir = output_dir / f"wheelhouse-{args.arch}"
            print(f"downloading wheels for {args.arch} into {wheel_dir}")
            wheels = download_wheels(
                wheel_dir,
                arch=args.arch,
                uv=args.uv,
                cache_dir=output_dir / "build-interpreters",
            )
            print(f"wheelhouse {wheel_dir} ({len(wheels)} wheels)")

        artifact, manifest = assemble(
            agent_dir=agent_dir,
            server_url=server_url,
            server_ca_pem=server_ca_pem,
            agent_version=agent_version,
            arch=args.arch,
            deb_version=deb_version,
            admin_contact=args.admin_contact,
            wheels=wheels,
        )

        filename = str(manifest["filename"])
        deb_path = output_dir / filename
        deb_path.write_bytes(artifact)
        (output_dir / f"{filename}.sha256").write_text(
            f"{manifest['sha256']}  {filename}\n", encoding="utf-8"
        )
        manifest_with_time = dict(manifest)
        manifest_with_time["built_at"] = (
            dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        )
        (output_dir / MANIFEST_FILENAME).write_text(
            json.dumps(manifest_with_time, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except BuildError as exc:
        print(f"build_deb: {exc}", file=sys.stderr)
        return 1

    print(f"built    {deb_path}")
    print(
        f"  package        {manifest['package']} {manifest['deb_version']} {manifest['architecture']}"
    )
    print(f"  server         {manifest['server_url']}")
    print(f"  size           {manifest['size_bytes']} bytes")
    print(f"  installed      {manifest['installed_size_kib']} KiB")
    print(f"  sha256         {manifest['sha256']}")
    print(f"  server CA      {manifest['server_ca']}")
    if wheels:
        print(f"  wheels         {len(wheels)} bundled, offline install")
    else:
        print("  wheels         none bundled -- the install needs PyPI")
    print("  enrols         NO -- installing prompts for a token, it does not enrol")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
