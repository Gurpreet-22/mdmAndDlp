#!/usr/bin/env python3
"""Build the employee-facing UbuntuGuard agent installer.

Produces three files from one source tree:

    ubuntuguard-agent-installer.sh          the artifact an employee downloads
    ubuntuguard-agent-installer.sh.sha256   the digest the enrollment page shows
    installer-manifest.json                 what the server serves as metadata

The artifact is `installer-template.sh` with the build-time values substituted
and a base64 `tar.gz` of the agent source appended after a marker line. One
file, one download, no repository checkout and no manual Python setup.

Why a self-extracting shell script rather than a `.deb`
-------------------------------------------------------
A `.deb` is the better long-term answer and is still feature D11. It is not the
right answer for *this* workflow, for one specific reason: `postinst` must not
enrol - that is D11's own constraint, asserted by the packaging tests - and a
`.deb` opened from a browser is handled by GNOME Software, which gives the
employee no terminal in which to type a token. They would install successfully
and then be stuck exactly where they are today. A script can install and then
prompt, in one command, which is the workflow that was asked for.

What goes in, and what must never
---------------------------------
In: the agent source, `pyproject.toml`, `README.md`, and the four packaging
files the install needs. The server URL and, optionally, the CA certificate
that validates the SERVER's TLS.

Never: a private key, a device certificate, or an enrollment token. There is no
code path here that reads any of those, and `--server-ca` actively refuses a
file containing a private key, because handing it `ca.key` instead of `ca.crt`
is a plausible slip with a serious outcome. `tests/test_installer_build.py`
asserts the absence from the built artifact rather than trusting this comment.

Determinism
-----------
Two builds of one tree, with the same server URL and CA, produce a
byte-identical installer: tar members are sorted, every mtime, uid, gid, uname
and gname is pinned, and gzip is given `mtime=0` because it stores a timestamp
in its own header that `tarfile`'s determinism does not reach.

That is why the build timestamp lives in the MANIFEST and not in the installer.
The digest is published on a web page for employees to check, and one that
changed on every rebuild of identical code would train everyone to ignore it.
The installer's banner shows the payload digest instead, which identifies the
build exactly and does not drift.

Usage
-----
    python3 agent/packaging/build_installer.py \\
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
import sys
import tarfile
from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

#: Marker after which the base64 payload begins. The script locates it in its
#: own text, so it must not appear anywhere else in the template.
PAYLOAD_MARKER = "__UBUNTUGUARD_PAYLOAD__"

#: Default artifact name. Fixed rather than derived from the version: the
#: enrollment page links to a stable URL, and an employee who bookmarked it
#: should not get a 404 after an upgrade.
INSTALLER_FILENAME = "ubuntuguard-agent-installer.sh"

MANIFEST_FILENAME = "installer-manifest.json"

#: Versioned so the server can refuse a manifest it does not understand rather
#: than reading fields that may have moved.
MANIFEST_SCHEMA = "ubuntuguard.installer.v1"

#: Files included in the payload, relative to the agent directory. An explicit
#: list rather than a glob with exclusions: a glob that accidentally matches
#: `var/` or a stray `.pem` is how key material ends up in a published
#: artifact, and an allowlist cannot do that.
PAYLOAD_FILES: tuple[str, ...] = (
    "pyproject.toml",
    "README.md",
    "packaging/install.sh",
    "packaging/uninstall.sh",
    "packaging/systemd/ubuntuguard-agent.service",
    # The root enforcer's unit. install.sh installs both units, so omitting
    # this one makes the install abort partway: the agent lands, then the
    # install fails on a file the archive does not contain. An explicit list
    # catches that at build time only if the list is kept in step with
    # install.sh, which is the trade-off the comment above describes.
    "packaging/systemd/ubuntuguard-enforcerd.service",
    "packaging/etc/agent.yaml.example",
)

#: Directories included wholesale, minus the exclusions below.
PAYLOAD_TREES: tuple[str, ...] = ("src",)

#: Never packaged, whatever else matches.
PAYLOAD_EXCLUDED_NAMES: frozenset[str] = frozenset({"__pycache__", ".mypy_cache", ".ruff_cache"})
PAYLOAD_EXCLUDED_SUFFIXES: tuple[str, ...] = (".pyc", ".pyo", ".pem", ".key", ".crt", ".csr")

#: Pinned into every tar member so the archive does not carry the builder's
#: identity or the checkout's timestamps.
_FIXED_MTIME = 0
_FIXED_MODE_FILE = 0o644
_FIXED_MODE_EXEC = 0o755

#: Platform facts, declared once here and carried to the server and the
#: enrollment page in the manifest. The server does not restate them, so there
#: is nothing to drift.
SUPPORTED_OS_ID = "ubuntu"
MINIMUM_PYTHON = "3.10"
SUPPORTED_ARCH: tuple[str, ...] = ("x86_64", "aarch64")

#: Releases the installer is WRITTEN FOR, which is not the same claim as
#: tested. `VALIDATED_OS_VERSIONS` is the tested set and is deliberately empty,
#: mirroring `osadapter.ubuntu.VALIDATED_OS_VERSION_IDS`. The two fields travel
#: together all the way to the web page so a target can never be read as a
#: guarantee.
TARGET_OS_VERSIONS: tuple[str, ...] = ("22.04", "24.04")
VALIDATED_OS_VERSIONS: tuple[str, ...] = ()

#: Shown by the installer when enrollment fails. Overridable, because "contact
#: your administrator" is useless if it does not say how.
DEFAULT_ADMIN_CONTACT = "your IT administrator"

_PRIVATE_KEY_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----"


class BuildError(Exception):
    """A build input is unusable. Reported as a message, not a traceback."""


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_server_url(url: str, *, allow_loopback_http: bool = False) -> str:
    """HTTPS only, with one narrow development exception.

    Mirrors `ubuntuguard_agent.config._validate_server_url`, and
    `tests/test_installer_build.py` asserts the two agree on a table of URLs
    rather than leaving that to inspection. Baking a URL the agent would then
    refuse to load would produce an installer that fails after it has already
    created an account and a virtualenv.

    The exception requires an explicit flag AND a loopback host, so there is no
    combination of arguments that bakes a plaintext URL for another machine
    into an artifact handed to employees.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise BuildError(
            f"--server-url must be an absolute URL such as https://mdm.company.com, got {url!r}"
        )
    if parsed.scheme == "https":
        return url
    if parsed.scheme != "http":
        raise BuildError(f"--server-url scheme must be https, got {parsed.scheme!r}")
    if not (allow_loopback_http and _is_loopback(parsed.hostname)):
        raise BuildError(
            "--server-url must use https. Plaintext HTTP is permitted only for a "
            "loopback address and only with --allow-loopback-http, which exists "
            "for local development against a server with no TLS in front of it."
        )
    return url


def read_server_ca(path: Path) -> str:
    """Read the CA that validates the SERVER's TLS certificate.

    Refuses two specific mistakes, both of which produce an artifact that looks
    fine:

    A file containing a PRIVATE KEY. Passing `ca.key` where `ca.crt` was meant
    would publish the internal CA's private key to every employee, and from
    there anyone could mint a device certificate. This is the single worst
    outcome available in this script, so it is checked first and refused rather
    than filtered.

    A file containing no certificate at all. That produces an installer whose
    agent cannot verify the server and fails at the first request, after the
    install has already happened.

    This is NOT the device CA. `server_ca_bundle` validates the server to the
    agent; the device CA chain arrives in the enrollment response and is the
    issuer of this laptop's own client certificate. Conflating them is the
    easiest serious mistake in the agent's configuration, which is why the
    example config and `deploy/nginx/README.md` both spell it out.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"could not read --server-ca {path}: {exc}") from exc

    if _PRIVATE_KEY_PEM.search(text):
        raise BuildError(
            f"{path} contains a PRIVATE KEY. --server-ca takes the CA "
            "CERTIFICATE, which is public material; a private key here would be "
            "published to every employee who downloads the installer. Refusing."
        )
    if _CERTIFICATE_PEM not in text:
        raise BuildError(
            f"{path} contains no PEM certificate. --server-ca takes the CA that "
            "issued the server's TLS certificate, in PEM form."
        )

    try:
        from cryptography import x509

        x509.load_pem_x509_certificate(text.encode("utf-8"))
    except ImportError:  # pragma: no cover - cryptography is an agent dependency
        pass
    except Exception as exc:
        raise BuildError(f"{path} is not a parseable PEM certificate: {exc}") from exc

    return text


# --------------------------------------------------------------------------- #
# The payload
# --------------------------------------------------------------------------- #


def _payload_members(agent_dir: Path) -> list[tuple[str, Path]]:
    """Resolve the allowlist to (archive name, source path), sorted.

    Sorted by archive name so the tar member order is a property of the file
    set rather than of the filesystem's directory order, which is not stable
    across machines.
    """
    members: list[tuple[str, Path]] = []

    for relative in PAYLOAD_FILES:
        source = agent_dir / relative
        if not source.is_file():
            raise BuildError(f"{source} is missing; cannot build an installer without it")
        members.append((relative, source))

    for tree in PAYLOAD_TREES:
        root = agent_dir / tree
        if not root.is_dir():
            raise BuildError(f"{root} is missing; cannot build an installer without it")
        for source in root.rglob("*"):
            if not source.is_file():
                continue
            if any(part in PAYLOAD_EXCLUDED_NAMES for part in source.parts):
                continue
            if source.suffix in PAYLOAD_EXCLUDED_SUFFIXES:
                continue
            members.append((source.relative_to(agent_dir).as_posix(), source))

    members.sort(key=lambda entry: entry[0])
    return members


def build_payload(agent_dir: Path) -> bytes:
    """A deterministic gzipped tar of the agent source.

    Every field that could carry build-host state is pinned: mtime, uid, gid,
    uname, gname and mode. gzip is handed `mtime=0` as well, because it stores
    a timestamp in its own header that `tarfile`'s determinism does not reach -
    forget that one and the digest changes every second.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, source in _payload_members(agent_dir):
            info = tarfile.TarInfo(name=name)
            data = source.read_bytes()
            info.size = len(data)
            info.mtime = _FIXED_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            # The two install scripts must arrive executable; `install.sh`
            # itself is invoked through `bash`, but `uninstall.sh` is left for
            # the operator to run directly and a 0644 copy would stop them.
            info.mode = _FIXED_MODE_EXEC if name.endswith(".sh") else _FIXED_MODE_FILE
            archive.addfile(info, io.BytesIO(data))

    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return compressed.getvalue()


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def render_template(
    template: str,
    *,
    agent_version: str,
    server_url: str,
    server_ca_pem: str | None,
    payload_sha256: str,
    admin_contact: str,
) -> str:
    """Substitute the build-time values, refusing to leave any behind.

    The unsubstituted-placeholder check is the point of doing this by hand
    rather than with `str.format`: a renamed placeholder would otherwise ship
    an installer that writes the literal text `@SERVER_URL@` into
    `/etc/ubuntuguard/agent.yaml`, and the agent would reject that as a
    malformed URL only after the install had completed.
    """
    # The CA is embedded base64-encoded so that a PEM's newlines cannot
    # terminate the shell assignment, and so the script body stays single-line
    # per variable regardless of the certificate's length.
    import base64

    ca_b64 = "" if server_ca_pem is None else base64.b64encode(server_ca_pem.encode()).decode()

    substitutions = {
        "@AGENT_VERSION@": agent_version,
        "@SERVER_URL@": server_url,
        "@SERVER_CA_PEM_B64@": ca_b64,
        "@PAYLOAD_SHA256@": payload_sha256,
        "@ADMIN_CONTACT@": admin_contact,
        "@SUPPORTED_OS_ID@": SUPPORTED_OS_ID,
        "@SUPPORTED_ARCH@": " ".join(SUPPORTED_ARCH),
        "@TARGET_OS_VERSIONS@": " ".join(TARGET_OS_VERSIONS),
        "@VALIDATED_OS_VERSIONS@": " ".join(VALIDATED_OS_VERSIONS),
        "@MINIMUM_PYTHON@": MINIMUM_PYTHON,
        "@PAYLOAD_MARKER@": PAYLOAD_MARKER,
    }

    rendered = template
    for placeholder, value in substitutions.items():
        rendered = rendered.replace(placeholder, value)

    leftover = sorted(set(re.findall(r"@[A-Z0-9_]+@", rendered)))
    if leftover:
        raise BuildError(
            "the template has placeholder(s) this builder does not substitute: "
            + ", ".join(leftover)
        )
    return rendered


def assemble(
    *,
    agent_dir: Path,
    server_url: str,
    server_ca_pem: str | None,
    agent_version: str,
    built_at: str,
    admin_contact: str,
) -> tuple[str, dict[str, object]]:
    """Build the installer text and its manifest.

    Returns the artifact and the manifest, rather than writing them, so tests
    can build in memory with no filesystem at all.
    """
    template_path = agent_dir / "packaging" / "installer-template.sh"
    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"could not read {template_path}: {exc}") from exc

    if PAYLOAD_MARKER in template:
        raise BuildError(
            f"{template_path} contains the literal payload marker {PAYLOAD_MARKER}. "
            "The script locates the payload by finding that marker in its own "
            "text, so a second occurrence would make extraction read the wrong "
            "offset. Reference it as @PAYLOAD_MARKER@ instead."
        )

    payload = build_payload(agent_dir)
    payload_sha256 = hashlib.sha256(payload).hexdigest()

    header = render_template(
        template,
        agent_version=agent_version,
        server_url=server_url,
        server_ca_pem=server_ca_pem,
        payload_sha256=payload_sha256,
        admin_contact=admin_contact,
    )
    if not header.endswith("\n"):
        header += "\n"

    import base64

    # Wrapped at 76 columns. `base64 -d` accepts either, but an unwrapped
    # 125 KB line makes the artifact unopenable in an editor, and a reviewer
    # who cannot open it cannot review it.
    encoded = base64.encodebytes(payload).decode("ascii")
    artifact = f"{header}{PAYLOAD_MARKER}\n{encoded}"

    installer_sha256 = hashlib.sha256(artifact.encode("utf-8")).hexdigest()

    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "agent_version": agent_version,
        "filename": INSTALLER_FILENAME,
        "sha256": installer_sha256,
        "size_bytes": len(artifact.encode("utf-8")),
        "payload_sha256": payload_sha256,
        "built_at": built_at,
        "server_url": server_url,
        "minimum_python": MINIMUM_PYTHON,
        "supported_os_id": SUPPORTED_OS_ID,
        "supported_arch": list(SUPPORTED_ARCH),
        "target_os_versions": list(TARGET_OS_VERSIONS),
        "validated_os_versions": list(VALIDATED_OS_VERSIONS),
    }
    return artifact, manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _agent_version(agent_dir: Path) -> str:
    """Read `__version__` without importing the package.

    Importing would pull in `cryptography` and `yaml`, so the builder would
    need the agent's runtime dependencies installed to produce an artifact that
    does not need them at build time. A three-line read avoids that.
    """
    init = agent_dir / "src" / "ubuntuguard_agent" / "__init__.py"
    try:
        text = init.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"could not read {init}: {exc}") from exc
    match = re.search(r'^__version__\s*[:=]\s*(?:str\s*=\s*)?["\']([^"\']+)["\']', text, re.M)
    if match is None:
        raise BuildError(f"no __version__ found in {init}")
    return match.group(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_installer.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--server-url",
        required=True,
        metavar="URL",
        help="The https URL of the UbuntuGuard API, baked into the installer.",
    )
    parser.add_argument(
        "--server-ca",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "PEM certificate of the CA that issued the SERVER's TLS certificate. "
            "Omit when the server uses a publicly trusted certificate, and the "
            "installer will point the agent at the system trust store."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        metavar="DIR",
        help="Directory to write the installer, its digest and the manifest into.",
    )
    parser.add_argument(
        "--admin-contact",
        default=DEFAULT_ADMIN_CONTACT,
        metavar="TEXT",
        help=(
            "How an employee should reach an administrator if enrollment fails, "
            f"e.g. 'it-help@company.com'. Default: {DEFAULT_ADMIN_CONTACT!r}."
        ),
    )
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help=(
            "Permit an http:// --server-url, but only for a loopback host. "
            "For local development against a server with no TLS in front of it."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    agent_dir = Path(__file__).resolve().parents[1]

    try:
        server_url = validate_server_url(
            args.server_url, allow_loopback_http=args.allow_loopback_http
        )
        server_ca_pem = None if args.server_ca is None else read_server_ca(args.server_ca)

        artifact, manifest = assemble(
            agent_dir=agent_dir,
            server_url=server_url,
            server_ca_pem=server_ca_pem,
            agent_version=_agent_version(agent_dir),
            # Second precision, not microsecond: the field is for a human
            # reading a web page, and a build is not reproducible to the
            # microsecond anyway.
            built_at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            admin_contact=args.admin_contact,
        )

        output_dir: Path = args.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        installer_path = output_dir / INSTALLER_FILENAME
        installer_path.write_text(artifact, encoding="utf-8")
        installer_path.chmod(_FIXED_MODE_EXEC)

        # The `sha256sum -c` format, so an employee can verify with the command
        # the enrollment page shows them and nothing has to be transcribed.
        (output_dir / f"{INSTALLER_FILENAME}.sha256").write_text(
            f"{manifest['sha256']}  {INSTALLER_FILENAME}\n", encoding="utf-8"
        )
        (output_dir / MANIFEST_FILENAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except BuildError as exc:
        print(f"build_installer: {exc}", file=sys.stderr)
        return 1

    print(f"built    {installer_path}")
    print(f"  version        {manifest['agent_version']}")
    print(f"  server         {manifest['server_url']}")
    print(f"  size           {manifest['size_bytes']} bytes")
    print(f"  sha256         {manifest['sha256']}")
    print(f"  server CA      {'embedded' if server_ca_pem else 'system trust store'}")
    print(f"  validated on   {manifest['validated_os_versions'] or 'nothing yet (UNVALIDATED)'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
