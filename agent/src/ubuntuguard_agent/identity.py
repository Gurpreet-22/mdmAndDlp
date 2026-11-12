"""Local device identity: where it lives, how private it is, and what it says.

Two halves, and the split is worth knowing when reading this file.

**Reading** - the directory layout, the permission guarantees on it, and enough
certificate parsing for `status` and `selftest` to tell an operator whether
this machine has an identity and whether it is still valid. This came first,
in Phase 1, which is why the Phase 2 code below is built against an invariant
that was already enforced and already tested.

**Creating** - the keypair, the CSR, and installing the certificate the server
issues. Added in Phase 2. The private key is generated here, written here, and
read here, and it is never passed to anything that could transmit it: the
enrollment request carries the CSR and nothing else derived from the key.

The permission check is the piece worth having early. The server refuses to load
a CA key that is group- or world-readable (`services/ca.py:assert_key_file_private`)
and the agent mirrors that for its own key, for the same reason: a private key
the rest of the machine can read is a failure to stop on, not something to note
in a log and continue past.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from ubuntuguard_agent.config import AgentPaths
from ubuntuguard_agent.constants import CERT_RENEW_AT_PCT
from ubuntuguard_agent.errors import IdentityError, InsecureFileError

#: Directory holding private key material. Owner-only, including execute, so
#: nobody else can even list it.
PKI_DIR_MODE = 0o700

#: State directory. Group-readable is not needed by anything today, so it is
#: not granted; Phase 7's enforcer talks over a socket, not through this.
STATE_DIR_MODE = 0o750

#: The private key, and anything else that must not be read by another user.
PRIVATE_FILE_MODE = 0o600


def assert_private_file(path: Path) -> None:
    """Refuse a file that is readable by group or others.

    Mirrors the server's `assert_key_file_private`. Raises rather than fixing
    the mode: a key that has been world-readable may already have been copied,
    and silently tightening the permissions would hide that from whoever needs
    to decide whether to re-enrol the device.
    """
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise InsecureFileError(f"could not check permissions on {path}: {exc}") from exc

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InsecureFileError(
            f"{path} is accessible to group or others "
            f"(mode {stat.S_IMODE(mode):04o}); expected {PRIVATE_FILE_MODE:04o}"
        )


def ensure_runtime_paths(paths: AgentPaths) -> None:
    """Create the directories the agent needs, at the right modes.

    `mkdir(mode=...)` is subject to the process umask, so the mode is set
    explicitly afterwards. Skipping that is how a 0700 directory becomes 0755 on
    a host whose umask is 022 - which is most of them.
    """
    for directory, mode in (
        (paths.state_dir, STATE_DIR_MODE),
        (paths.pki_dir, PKI_DIR_MODE),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode)  # noqa: PTH101 - chmod on an existing dir, not a create


@dataclasses.dataclass(frozen=True)
class CertificateSummary:
    """The parts of the device certificate the agent reasons about.

    `device_id` comes from the subject common name, which the server allocated;
    the agent never chooses it. `fingerprint` is SHA-256 over the DER, matching
    both what the server stored at enrollment and what the application
    recomputes from the forwarded certificate on every device-plane request.
    """

    device_id: str
    not_before: dt.datetime
    not_after: dt.datetime
    renew_after: dt.datetime
    fingerprint: str
    serial_number: int

    def is_expired(self, *, now: dt.datetime | None = None) -> bool:
        return self._now(now) > self.not_after

    def renewal_due(self, *, now: dt.datetime | None = None) -> bool:
        return self._now(now) >= self.renew_after

    def seconds_remaining(self, *, now: dt.datetime | None = None) -> int:
        return int((self.not_after - self._now(now)).total_seconds())

    @staticmethod
    def _now(now: dt.datetime | None) -> dt.datetime:
        # timezone.utc, not datetime.UTC: the latter is 3.11+, and the agent
        # targets 3.10 so one build covers Ubuntu 22.04 and 24.04.
        return now if now is not None else dt.datetime.now(dt.timezone.utc)


def renewal_due_at(certificate: x509.Certificate) -> dt.datetime:
    """When renewal should start: 50% through the certificate's lifetime.

    Identical to the server's `services/ca.renewal_due_at`, and computed locally
    rather than taken from the server's `certificate_renew_after` field so the
    agent can make the decision while offline. Renewing at half-life leaves the
    whole second half as the window to recover from a failed renewal, instead of
    discovering the problem on the last day.
    """
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    return not_before + (not_after - not_before) * (CERT_RENEW_AT_PCT / 100)


def summarise_certificate(pem: bytes) -> CertificateSummary:
    """Parse a device certificate. Raises ValueError on anything unparseable."""
    certificate = x509.load_pem_x509_certificate(pem)

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise ValueError(f"expected exactly one common name, found {len(common_names)}")
    device_id = common_names[0].value
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("certificate common name is empty")

    return CertificateSummary(
        device_id=device_id,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        renew_after=renewal_due_at(certificate),
        fingerprint="sha256:" + certificate.fingerprint(hashes.SHA256()).hex(),
        serial_number=certificate.serial_number,
    )


def read_certificate(paths: AgentPaths) -> CertificateSummary | None:
    """Summarise the installed certificate, or None if there is not one.

    None means "not enrolled", which is a normal state for a freshly installed
    agent and not an error. A certificate that exists but will not parse IS an
    error and raises, because silently treating a corrupt identity as "not
    enrolled" would send the agent off to enrol again and create a second device
    row for one laptop.
    """
    path = paths.certificate_path
    try:
        pem = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc
    return summarise_certificate(pem)


def is_enrolled(paths: AgentPaths) -> bool:
    """Whether both halves of an identity are present on disk.

    Both, because either one alone is a broken install rather than an identity:
    a key with no certificate never completed enrollment, and a certificate with
    no key cannot be used in a TLS handshake.
    """
    return paths.private_key_path.exists() and paths.certificate_path.exists()


# --------------------------------------------------------------------------- #
# Creating an identity
# --------------------------------------------------------------------------- #

#: EC P-256. Three reasons, in order of weight.
#:
#: The server accepts P-256, P-384, Ed25519 and RSA >= 3072
#: (`services/ca.ALLOWED_EC_CURVES`, `MIN_RSA_BITS`), so this is a choice
#: within an accepted set rather than a constraint.
#:
#: P-256 because the internal CA is itself P-256, so the chain is uniform;
#: because key generation is fast enough to be unnoticeable during an
#: enrollment on a laptop, where RSA-3072 is not; and because every TLS stack
#: that will ever terminate this connection supports it without negotiation
#: surprises. Ed25519 would be a defensible alternative but is still refused by
#: some TLS 1.2 paths as a client certificate, and the device plane has to work
#: through whatever nginx an operator deploys.
DEVICE_KEY_CURVE = ec.SECP256R1

#: Subject common name placed in the CSR.
#:
#: The server IGNORES the CSR's subject entirely and sets the certificate's
#: common name from the device UUID it allocates
#: (`services/ca.issue_device_certificate`). So this value never reaches a
#: certificate and cannot be used to claim an identity - `tools/demo_api.py`
#: demonstrates the refusal by submitting a CSR for "i-am-the-ceo-laptop".
#:
#: A CSR must still carry a subject to be well-formed, so rather than put a
#: hostname here - which would read as though it mattered - it says what is
#: actually true at the moment the CSR is built.
CSR_PLACEHOLDER_COMMON_NAME = "unenrolled"


@dataclasses.dataclass(frozen=True)
class DeviceKeypair:
    """The device's private key and the CSR that will be sent for it.

    `created` distinguishes "generated just now" from "already on disk and
    reused". Enrollment needs that distinction: reusing an existing keypair is
    what makes a retry land on the server's idempotency cache, and generating a
    new one mid-retry is the mistake the cache exists to punish.
    """

    private_key: ec.EllipticCurvePrivateKey
    csr_pem: bytes
    created: bool

    @property
    def public_key_der(self) -> bytes:
        """SubjectPublicKeyInfo DER, the form the server fingerprints."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def generate_device_key() -> ec.EllipticCurvePrivateKey:
    """Generate the device's private key. It never leaves this machine."""
    return ec.generate_private_key(DEVICE_KEY_CURVE())


def build_csr(private_key: ec.EllipticCurvePrivateKey) -> x509.CertificateSigningRequest:
    """Build a CSR for `private_key`, requesting nothing.

    No extensions are requested, deliberately. The server ignores CSR
    extensions when issuing - copying them is a classic CA vulnerability, and
    `services/ca.py` says so - but it also RECORDS which ones were asked for in
    the `device_enrolled` audit entry. Requesting none keeps that field empty,
    so if it is ever non-empty for a device enrolled by this agent, something
    other than this agent built the request.
    """
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CSR_PLACEHOLDER_COMMON_NAME)])
        )
        .sign(private_key, hashes.SHA256())
    )


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write `data` to `path` atomically, at `mode`, never wider.

    Two properties, both of which matter here.

    Atomic: the data goes to a temporary file in the same directory and is then
    `os.replace`d into position, so a reader either sees the old file or the
    complete new one. A half-written certificate that parses as far as the
    truncation point is a genuinely nasty thing to debug.

    Never wider than `mode`: the temporary file is created with `os.open` and
    the mode, rather than being created and then chmod'ed. A chmod afterwards
    leaves a window in which the file exists at the umask's mode, and for a
    private key that window is the whole problem.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    # Replace preserves the temporary file's mode, so the destination inherits
    # `mode` rather than whatever it had before.
    temporary.replace(path)


def write_private_key(path: Path, private_key: ec.EllipticCurvePrivateKey) -> None:
    """Persist the private key at mode 0600.

    Unencrypted PKCS#8. There is no passphrase because there is nobody to type
    one: this is an unattended service that must come back after a reboot
    without human involvement, so a passphrase would have to be stored beside
    the key it protects. The protection here is filesystem permissions plus a
    0700 parent directory, which is the same decision the server makes for its
    CA key.
    """
    _atomic_write(
        path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=PRIVATE_FILE_MODE,
    )


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load the device key, refusing it if the file is not private.

    The permission check runs BEFORE the key is parsed. Reading a key that
    turned out to be world-readable and then complaining would mean the key
    material was already in this process's memory and, worse, that the agent
    had decided to continue far enough to parse it.
    """
    assert_private_file(path)
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise IdentityError(f"could not load the device private key from {path}: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise IdentityError(
            f"{path} holds a {type(key).__name__}, but this agent generates EC keys; "
            "remove it to re-enrol, which will create a new identity"
        )
    return key


def _public_key_der(key: object) -> bytes | None:
    """SubjectPublicKeyInfo DER for any public key type, or None.

    Duck-typed rather than enumerating `cryptography`'s key classes. The caller
    compares a certificate's public key against a private key's, and both can
    be any of four types; listing all sixteen pairings to satisfy a type
    checker would obscure a function whose entire content is "serialize both
    and compare".
    """
    public_bytes = getattr(key, "public_bytes", None)
    if public_bytes is None:
        return None
    encoded = public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return encoded if isinstance(encoded, bytes) else None


def public_keys_match(left: object, right: object) -> bool:
    """Whether two public keys are the same key.

    Compared as SubjectPublicKeyInfo DER rather than with `==`. Equality is
    implemented for public key objects in current `cryptography`, but DER
    comparison is what the server does when it fingerprints a CSR, so this
    answers the same question the server will ask.

    A key that cannot be serialized returns False rather than raising. There is
    no sensible way to answer "are these the same key" for an object that is
    not a key, and every caller is in a security check where False is the safe
    answer.
    """
    left_der = _public_key_der(left)
    right_der = _public_key_der(right)
    return left_der is not None and left_der == right_der


def ensure_device_keypair(paths: AgentPaths) -> DeviceKeypair:
    """The device's enrollment keypair and CSR. See `ensure_keypair`."""
    return ensure_keypair(paths.private_key_path, paths.csr_path)


def ensure_keypair(key_path: Path, csr_path: Path) -> DeviceKeypair:
    """Return a keypair and CSR at these paths, generating them only if absent.

    **Idempotent, and that is the whole point.** The server caches an
    enrollment response keyed on `(token_hash, csr_public_key_fingerprint)` for
    60 seconds, so an agent retrying after a network failure gets its original
    certificate back only if it presents the SAME public key. Generating a
    fresh keypair on retry produces a different fingerprint, misses the cache,
    and gets `401 enrollment_token_invalid` for a token that was in fact spent
    successfully. The operator then has to mint another token for a device that
    already enrolled.

    So: generate once, persist before sending anything, and reuse thereafter.

    Three states are handled, and the asymmetry between them is deliberate:

    - **Neither file.** Generate both. Normal first enrollment.
    - **Key but no CSR.** Rebuild the CSR from the existing key. The key is the
      irreplaceable half; a CSR is a derived artefact and rebuilding it
      preserves the public key, which is what the cache keys on.
    - **CSR but no key.** Discard the CSR and generate both. A CSR whose
      private key is gone cannot be completed - a certificate issued against it
      would be unusable - so keeping it would only produce a confusing failure
      later.

    A stored CSR whose public key does not match the stored private key raises
    rather than being silently rebuilt. It should be impossible, so it means
    either tampering or a bug, and both are worth stopping for.

    Takes explicit paths rather than `AgentPaths` because renewal needs exactly
    this behaviour for the staged `.new` pair, and for the same reason: the
    server's renewal idempotency is keyed on the CSR's public key too.
    """
    if not key_path.exists():
        if csr_path.exists():
            # Explicitly removed rather than overwritten, so the window where
            # a stale CSR sits beside a brand-new key does not exist.
            csr_path.unlink()
        private_key = generate_device_key()
        write_private_key(key_path, private_key)
        csr = build_csr(private_key)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        _atomic_write(csr_path, csr_pem, mode=0o644)
        return DeviceKeypair(private_key=private_key, csr_pem=csr_pem, created=True)

    private_key = load_private_key(key_path)

    if csr_path.exists():
        try:
            stored = x509.load_pem_x509_csr(csr_path.read_bytes())
        except (OSError, ValueError) as exc:
            raise IdentityError(f"{csr_path} exists but could not be parsed: {exc}") from exc
        if not public_keys_match(stored.public_key(), private_key.public_key()):
            raise IdentityError(
                f"{csr_path} is for a different key than {key_path}. Refusing to "
                "guess which is correct: delete both to generate a new identity, "
                "which also requires a new enrollment token."
            )
        return DeviceKeypair(
            private_key=private_key,
            csr_pem=csr_path.read_bytes(),
            created=False,
        )

    csr = build_csr(private_key)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    _atomic_write(csr_path, csr_pem, mode=0o644)
    return DeviceKeypair(private_key=private_key, csr_pem=csr_pem, created=False)


def _verify_issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> None:
    """Check `certificate`'s signature against `issuer`'s public key.

    A direct signature check rather than a full path-validation API. That is
    the right tool for this one question: the agent is not validating an
    arbitrary chain from an untrusted source, it is confirming that the
    certificate it was just handed was signed by the CA that was handed over
    with it. Name chaining, validity and key usage are checked separately by
    the caller and by `summarise_certificate`.

    The real chain verification that matters for authentication happens on the
    other side, in nginx, against a CA an operator installed. This check
    catches a server that returns a certificate from the wrong CA - a
    misconfiguration or a half-completed key rotation - before the agent
    commits it to disk and starts failing every heartbeat for reasons it cannot
    see locally.
    """
    if certificate.issuer != issuer.subject:
        raise IdentityError(
            "the issued certificate's issuer does not match the CA chain that "
            "accompanied it; the server may have rotated its CA mid-enrollment"
        )

    public_key = issuer.public_key()
    algorithm = certificate.signature_hash_algorithm
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if algorithm is None:
                raise IdentityError("EC certificate has no signature hash algorithm")
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(algorithm),
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            if algorithm is None:
                raise IdentityError("RSA certificate has no signature hash algorithm")
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algorithm,
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            raise IdentityError(
                f"the CA chain uses an unsupported key type: {type(public_key).__name__}"
            )
    except InvalidSignature as exc:
        raise IdentityError(
            "the issued certificate was not signed by the CA chain that accompanied it"
        ) from exc


def verify_issued_certificate(
    *,
    certificate_pem: bytes,
    ca_chain_pem: bytes,
    expected_device_id: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> CertificateSummary:
    """Every check a certificate from the server must pass. Writes nothing.

    Separated from `install_certificate` so renewal can run the identical
    checks before it stages anything. Sharing the function rather than the list
    of checks is the point: a renewal path with its own slightly different
    verification is how one of these stops being enforced.

    Four checks, each catching something different:

    1. **It parses.** First, so later failures are about content rather than
       encoding.
    2. **The public key is ours.** The check that proves the certificate is
       usable at all. A certificate for someone else's key installs cleanly,
       verifies as a certificate, and then fails every TLS handshake with an
       error that points at nginx.
    3. **The common name is the device id the server reported.** `deps.py`
       re-checks this on every request as `device_identity_mismatch`, so a
       disagreement means every future call is refused.
    4. **It was signed by the accompanying CA.** See `_verify_issued_by`.
    """
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise IdentityError(
            f"the server returned a certificate that will not parse: {exc}"
        ) from exc

    try:
        ca_certificate = x509.load_pem_x509_certificate(ca_chain_pem)
    except ValueError as exc:
        raise IdentityError(f"the server returned a CA chain that will not parse: {exc}") from exc

    if not public_keys_match(certificate.public_key(), private_key.public_key()):
        raise IdentityError(
            "the issued certificate is for a different public key than this "
            "device holds; it could never complete a TLS handshake"
        )

    summary = summarise_certificate(certificate_pem)
    if summary.device_id != expected_device_id:
        raise IdentityError(
            f"the issued certificate names device {summary.device_id} but the "
            f"response reported {expected_device_id}; every device-plane request "
            "would be refused as device_identity_mismatch"
        )

    _verify_issued_by(certificate, ca_certificate)
    return summary


def stage_renewed_certificate(
    paths: AgentPaths,
    *,
    certificate_pem: bytes,
    ca_chain_pem: bytes,
    expected_device_id: str,
) -> CertificateSummary:
    """Verify a replacement certificate against the STAGED key, then stage it.

    The commit point of a renewal. After this returns, the three `.new` files
    are present and mutually consistent, so `complete_pending_renewal` can
    always finish the swap - which is what makes a crash during rotation cost a
    restart rather than an identity.

    The old key and certificate are untouched and still working. Nothing has
    been invalidated locally; the server has, but it keeps accepting the old
    certificate for the renewal endpoint during its grace window precisely so
    this sequence can be retried.
    """
    pending_key = load_private_key(paths.pending_private_key_path)
    summary = verify_issued_certificate(
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_chain_pem,
        expected_device_id=expected_device_id,
        private_key=pending_key,
    )
    # The CA chain is written to its final location rather than staged: the
    # issuer does not change during a renewal, and a renewal that did change it
    # would have failed `verify_issued_certificate` above.
    _atomic_write(paths.ca_chain_path, ca_chain_pem, mode=0o644)
    _atomic_write(paths.pending_certificate_path, certificate_pem, mode=0o644)
    return summary


def complete_pending_renewal(paths: AgentPaths) -> CertificateSummary | None:
    """Finish or discard an interrupted renewal. Safe to call at any time.

    Called at service start-up and before every renewal attempt, because the
    interesting states here are the ones a crash leaves behind and nothing else
    would notice them.

    The three recoverable states, and how each is identified rather than
    guessed:

    **Fully staged.** A pending certificate and a pending key that agree. The
    swap never happened, and it can be completed exactly as intended.

    **Half-swapped.** The installed certificate pairs with the PENDING key, not
    the installed one. That can only mean the certificate was replaced and the
    process died before the key was, so finishing means replacing the key. This
    is the state that would otherwise be a broken identity with no explanation.

    **Abandoned.** A pending certificate with no pending key, which is
    unusable, so it is removed. A pending key with no pending certificate is
    left alone deliberately: it is a renewal that never got a response, and
    reusing it is what makes the retry land on the server's idempotency check.

    Returns the newly installed certificate's summary when a swap completed,
    None when there was nothing to do.
    """
    pending_key_path = paths.pending_private_key_path
    pending_cert_path = paths.pending_certificate_path

    if pending_cert_path.exists() and pending_key_path.exists():
        pending_key = load_private_key(pending_key_path)
        try:
            staged = x509.load_pem_x509_certificate(pending_cert_path.read_bytes())
        except (OSError, ValueError):
            pending_cert_path.unlink(missing_ok=True)
            return None
        if public_keys_match(staged.public_key(), pending_key.public_key()):
            return _swap_pending(paths)
        # Staged certificate and staged key disagree. The certificate is the
        # replaceable half, so it goes and the key stays for a retry.
        pending_cert_path.unlink(missing_ok=True)
        return None

    if pending_key_path.exists() and paths.certificate_path.exists():
        pending_key = load_private_key(pending_key_path)
        try:
            installed = x509.load_pem_x509_certificate(paths.certificate_path.read_bytes())
        except (OSError, ValueError):
            return None
        if public_keys_match(installed.public_key(), pending_key.public_key()):
            # Half-swapped: the certificate landed, the key did not.
            pending_key_path.replace(paths.private_key_path)
            if paths.pending_csr_path.exists():
                paths.pending_csr_path.replace(paths.csr_path)
            return summarise_certificate(paths.certificate_path.read_bytes())
        return None

    if pending_cert_path.exists():
        pending_cert_path.unlink(missing_ok=True)

    return None


def _swap_pending(paths: AgentPaths) -> CertificateSummary:
    """Move the staged material into place.

    Certificate first, then key, then CSR. The order matters for recovery
    rather than for correctness: with the certificate moved first, a crash
    leaves an installed certificate whose key is still at the pending path,
    which `complete_pending_renewal` recognises as half-swapped and finishes.
    Moving the key first would leave an installed key with no certificate
    naming it, which is indistinguishable from a failed enrollment.

    Each `replace` is atomic on its own, so no reader ever sees a partial file.
    """
    paths.pending_certificate_path.replace(paths.certificate_path)
    paths.pending_private_key_path.replace(paths.private_key_path)
    if paths.pending_csr_path.exists():
        paths.pending_csr_path.replace(paths.csr_path)
    return summarise_certificate(paths.certificate_path.read_bytes())


def install_certificate(
    paths: AgentPaths,
    *,
    certificate_pem: bytes,
    ca_chain_pem: bytes,
    expected_device_id: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> CertificateSummary:
    """Verify an issued certificate, then write it and its CA chain.

    **Verify first, write second.** Every check below runs before anything
    touches the filesystem, so a response that fails any of them leaves the
    agent exactly as it was - still unenrolled, still holding the keypair that
    the server's idempotency cache recognises, and therefore still able to
    retry. Writing first and validating afterwards would mean a bad response
    could leave a certificate on disk that `is_enrolled()` reports as an
    identity and every subsequent request fails with.

    Four checks, each catching something different:

    1. **It parses.** Obvious, and it comes first so later failures are about
       content rather than encoding.
    2. **The public key is ours.** This is the one that proves the certificate
       is usable. A certificate for someone else's key would install cleanly,
       verify as a certificate, and then fail every TLS handshake with an
       error that points at nginx rather than at here.
    3. **The common name is the device id the server reported.** `deps.py`
       re-checks this on every request (`device_identity_mismatch`), so a
       disagreement means every future call is refused. Better to find out now.
    4. **It was signed by the accompanying CA.** See `_verify_issued_by`.

    The certificate and CA chain are written at 0644 rather than 0600: both are
    public material - a certificate is published by definition - and they live
    in a 0700 directory, so the mode is about intent rather than secrecy. The
    private key is the only thing here that needs hiding, and it was already
    written at 0600 before this function is ever called.
    """
    summary = verify_issued_certificate(
        certificate_pem=certificate_pem,
        ca_chain_pem=ca_chain_pem,
        expected_device_id=expected_device_id,
        private_key=private_key,
    )

    ensure_runtime_paths(paths)
    # The CA chain goes down first. If the process dies between the two writes,
    # `is_enrolled()` is still False (it requires the certificate), so the
    # agent retries rather than coming up with a certificate and no issuer.
    _atomic_write(paths.ca_chain_path, ca_chain_pem, mode=0o644)
    _atomic_write(paths.certificate_path, certificate_pem, mode=0o644)
    return summary


def load_identity(paths: AgentPaths) -> tuple[ec.EllipticCurvePrivateKey, CertificateSummary]:
    """Load a complete, self-consistent identity, or raise saying why not.

    Used by anything that is about to authenticate. The key-and-certificate
    agreement is re-checked on load rather than trusted from installation time,
    because the two files can be edited independently by root and the failure
    that results otherwise appears as an unexplained TLS error.
    """
    if not is_enrolled(paths):
        raise IdentityError(
            "this device is not enrolled: run `ubuntuguard-agent enroll` with a "
            "token from the dashboard"
        )

    private_key = load_private_key(paths.private_key_path)
    try:
        summary = read_certificate(paths)
    except ValueError as exc:
        raise IdentityError(f"the installed certificate could not be read: {exc}") from exc
    if summary is None:  # pragma: no cover - is_enrolled already required the file
        raise IdentityError("the installed certificate disappeared while being read")

    certificate = x509.load_pem_x509_certificate(paths.certificate_path.read_bytes())
    if not public_keys_match(certificate.public_key(), private_key.public_key()):
        raise IdentityError(
            f"{paths.certificate_path} and {paths.private_key_path} are not a pair; "
            "this device cannot authenticate and must be re-enrolled"
        )
    return private_key, summary
