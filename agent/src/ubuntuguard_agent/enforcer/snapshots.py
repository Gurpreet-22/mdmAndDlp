"""Root-owned snapshot store for rollback.

`OP_USB_ROLLBACK` takes a `snapshot_id` and nothing else. That signature is a
security property, not a convenience: the rules to restore come from this
store, which only root can write, so a compromised agentd can ask for a
previous state by name but cannot dictate what that state contains. Had the op
accepted the rules themselves, an unprivileged process would have gained a
path to install arbitrary USBGuard rules through root -- exactly the
escalation the typed-operation boundary exists to prevent.

Two consequences follow, and both are enforced here:

**The id is attacker-controlled input.** It arrives over the socket from a
process the threat model treats as compromisable. A snapshot id is therefore
matched against a strict pattern *and* the resolved path is confirmed to lie
inside the store, so `../../etc/shadow` is refused twice over by two
independent checks.

**The store is separate from the agent's database.** UbuntuGuard's apply
sequence has agentd snapshot to its own SQLite. That record is agentd's
bookkeeping; this is the authoritative copy, and it lives where an
unprivileged process cannot alter it.

Plain files rather than SQLite: the contents are a handful of text blobs
written once and read rarely, there is no query pattern to serve, and a
corrupt single-file database would take every rollback target with it.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STORE = "/var/lib/ubuntuguard/enforcer/snapshots"

#: Directory is root-only: snapshots contain the policy, which reveals which
#: devices are authorised.
STORE_MODE = 0o700
SNAPSHOT_MODE = 0o600

#: How many snapshots to keep. Enough to retreat past a bad run of policy
#: versions, bounded so a flapping server cannot fill the disk.
DEFAULT_RETENTION = 20

#: A snapshot id as *this* module generates them: UTC timestamp plus a short
#: random suffix. Anything else is refused, so the id can never be a path.
SNAPSHOT_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")


class SnapshotError(Exception):
    """A snapshot could not be taken or restored."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class Snapshot:
    snapshot_id: str
    taken_at: str
    rules_text: str
    daemon_params: dict
    rules_fingerprint: str | None
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "taken_at": self.taken_at,
            "rules_text": self.rules_text,
            "daemon_params": dict(self.daemon_params),
            "rules_fingerprint": self.rules_fingerprint,
            "note": self.note,
        }

    def summary(self) -> dict:
        """Metadata without the rules body, for inclusion in a response.

        The rules themselves are not echoed back over the socket. Nothing
        needs them there, and keeping them out means a response cannot become
        a way to read the policy out of a root-only store.
        """
        return {
            "snapshot_id": self.snapshot_id,
            "taken_at": self.taken_at,
            "rules_fingerprint": self.rules_fingerprint,
            "rule_count": len(
                [
                    line
                    for line in self.rules_text.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                ]
            ),
            "note": self.note,
        }


def _utc_stamp(now: dt.datetime) -> str:
    return now.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass
class SnapshotStore:
    directory: str = DEFAULT_STORE
    retention: int = DEFAULT_RETENTION

    # -- id handling -------------------------------------------------------

    def _path_for(self, snapshot_id: str) -> Path:
        """Resolve an id to a path, refusing anything that could escape.

        Both checks are deliberate. The pattern is the real defence; the
        containment check is there because a future loosening of the pattern
        must not silently become a path-traversal bug.
        """
        if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.match(snapshot_id):
            raise SnapshotError(
                "invalid_snapshot_id",
                f"snapshot_id must match {SNAPSHOT_ID_RE.pattern}",
            )
        root = Path(self.directory).resolve()
        candidate = (root / f"{snapshot_id}.json").resolve()
        if candidate.parent != root:
            raise SnapshotError(
                "invalid_snapshot_id", "snapshot_id resolved outside the store"
            )
        return candidate

    # -- writing -----------------------------------------------------------

    def _ensure_directory(self) -> Path:
        root = Path(self.directory)
        try:
            root.mkdir(parents=True, exist_ok=True)
            root.chmod(STORE_MODE)
        except OSError as exc:
            raise SnapshotError(
                "snapshot_failed", f"cannot prepare {self.directory}: {exc}"
            ) from exc
        return root

    def take(
        self,
        *,
        rules_text: str,
        daemon_params: dict,
        rules_fingerprint: str | None,
        note: str = "",
        now: dt.datetime | None = None,
    ) -> Snapshot:
        """Record the current state and return it with its new id."""
        now = now or dt.datetime.now(dt.timezone.utc)
        root = self._ensure_directory()

        # Random suffix rather than a counter: two snapshots inside the same
        # second must not collide, and a counter would need state of its own.
        snapshot_id = f"{_utc_stamp(now)}-{os.urandom(4).hex()}"
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            taken_at=now.astimezone(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            rules_text=rules_text,
            daemon_params=dict(daemon_params),
            rules_fingerprint=rules_fingerprint,
            note=note,
        )

        payload = json.dumps(snapshot.as_dict(), indent=2, sort_keys=True)
        try:
            fd, tmp = tempfile.mkstemp(dir=str(root), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            tmp_path = Path(tmp)
            tmp_path.chmod(SNAPSHOT_MODE)
            tmp_path.replace(self._path_for(snapshot_id))
        except (OSError, SnapshotError) as exc:
            raise SnapshotError(
                "snapshot_failed", f"cannot write snapshot: {exc}"
            ) from exc

        self.prune()
        return snapshot

    # -- reading -----------------------------------------------------------

    def load(self, snapshot_id: str) -> Snapshot:
        path = self._path_for(snapshot_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SnapshotError(
                "snapshot_not_found", f"no snapshot {snapshot_id}"
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise SnapshotError(
                "snapshot_unreadable", f"snapshot {snapshot_id} is unusable: {exc}"
            ) from exc

        rules_text = raw.get("rules_text")
        if not isinstance(rules_text, str):
            raise SnapshotError(
                "snapshot_unreadable",
                f"snapshot {snapshot_id} has no rules body",
            )
        return Snapshot(
            snapshot_id=snapshot_id,
            taken_at=str(raw.get("taken_at", "")),
            rules_text=rules_text,
            daemon_params=raw.get("daemon_params") or {},
            rules_fingerprint=raw.get("rules_fingerprint"),
            note=str(raw.get("note", "")),
        )

    def ids(self) -> list[str]:
        """Known snapshot ids, newest first.

        The id begins with a UTC timestamp in a fixed-width format, so a
        reverse lexicographic sort is a chronological one.
        """
        root = Path(self.directory)
        if not root.is_dir():
            return []
        found = []
        for entry in root.iterdir():
            if entry.suffix != ".json":
                continue
            stem = entry.stem
            if SNAPSHOT_ID_RE.match(stem):
                found.append(stem)
        return sorted(found, reverse=True)

    def latest(self) -> Snapshot | None:
        for snapshot_id in self.ids():
            try:
                return self.load(snapshot_id)
            except SnapshotError:
                # A corrupt newest snapshot should not hide a usable older
                # one; rollback is the path that runs when things are already
                # going wrong.
                continue
        return None

    def summaries(self) -> list[dict]:
        out = []
        for snapshot_id in self.ids():
            try:
                out.append(self.load(snapshot_id).summary())
            except SnapshotError:
                out.append(
                    {"snapshot_id": snapshot_id, "unreadable": True}
                )
        return out

    # -- retention ---------------------------------------------------------

    def prune(self) -> list[str]:
        """Delete all but the newest `retention` snapshots."""
        if self.retention <= 0:
            return []
        removed = []
        for snapshot_id in self.ids()[self.retention:]:
            try:
                self._path_for(snapshot_id).unlink(missing_ok=True)
                removed.append(snapshot_id)
            except (OSError, SnapshotError):
                # Retention is housekeeping. Failing to delete an old
                # snapshot must never fail the apply that triggered it.
                continue
        return removed
