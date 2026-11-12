"""Structured logging, with redaction that is tested rather than assumed.

Two requirements shape this module, and they pull in different directions.

Logs must be useful: an operator debugging a laptop that will not enrol needs
to see what happened, in a form a log collector can parse. Hence single-line
JSON with stable field names.

Logs must never carry secrets. The brief is explicit: no enrollment tokens, no
private keys, no certificate private material. `schemas/event.agent.v1` says the
same about the `detail` field. So redaction is not a convention here, it is a
filter that runs over the *fully serialized line* - after the message, the
structured extras and any exception text have all been rendered. Scrubbing only
the message would miss a token that arrived inside an exception string, which is
exactly how these leaks happen in practice.

Three defences, in order of reliability:

1. `SecretRegistry` - exact values registered at runtime. The enrollment token
   is registered the moment it is read and before anything is logged, so even
   an unanticipated code path cannot print it.
2. A regex for PEM private-key blocks, which catches key material nobody
   remembered to register.
3. A field-name denylist for structured extras, so `logger.info(..., extra={...})`
   with a sensitive key is redacted by name even when the value is unknown.

`redact()` is a plain function over a string. That is deliberate: "no secrets in
logs" is a hard requirement, so the test calls it directly rather than
inspecting captured output and hoping the handler was wired up.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from ubuntuguard_agent.constants import LOG_LEVEL_DEFAULT, LOG_LEVELS

#: What replaces redacted material. Distinctive so it is obvious in a log, and
#: fixed-width so it never hints at the length of what it replaced.
REDACTED: str = "***REDACTED***"

#: Shortest value the registry will accept. Registering a short string would
#: scrub harmless substrings out of every subsequent line and destroy the log.
MIN_SECRET_LENGTH: int = 8

#: PEM private-key blocks, in any of the armour variants OpenSSL emits
#: (PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY).
#: Matched with DOTALL because a PEM block spans lines, and non-greedily so two
#: blocks in one line do not merge into one match.
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

#: The same thing after json.dumps has escaped the newlines to \n, which is the
#: form it actually reaches the filter in once it is inside a serialized field.
_PRIVATE_KEY_BLOCK_ESCAPED = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\n|.)*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

#: Structured-extra keys whose value is redacted regardless of content. Names
#: are matched case-insensitively and by substring, so `device_private_key` and
#: `enrollmentToken` are both caught.
SENSITIVE_FIELD_FRAGMENTS: frozenset[str] = frozenset(
    {
        "token",
        "password",
        "passwd",
        "secret",
        "private_key",
        "privatekey",
        "private_bytes",
        "seed",
        "signature",
        "value_b64",
        "credential",
    }
)

#: Reserved by logging.LogRecord. Anything outside this set that a caller
#: attaches via `extra=` is treated as structured context and emitted.
_RECORD_RESERVED: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

#: The agent's level vocabulary (from policy.agent_settings.v1) mapped to the
#: stdlib's. "warn" is the policy spelling; WARNING is the stdlib's.
_LEVEL_MAP: dict[str, int] = {
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}


class SecretRegistry:
    """Exact secret values to scrub from every log line.

    Process-wide and deliberately simple. Values are never read back out, only
    replaced, so there is no accessor that could put one in front of a caller.
    """

    def __init__(self) -> None:
        self._secrets: set[str] = set()

    def register(self, value: str | None) -> None:
        """Add a value. Short or empty values are ignored, not an error.

        Ignoring them rather than raising matters: the caller is usually
        handling a credential it must not inspect or branch on, and turning
        "this token looked too short" into an exception would put the value into
        a traceback, which is the opposite of the point.
        """
        if value and len(value) >= MIN_SECRET_LENGTH:
            self._secrets.add(value)

    def clear(self) -> None:
        self._secrets.clear()

    def __len__(self) -> int:
        return len(self._secrets)

    def scrub(self, text: str) -> str:
        """Replace every registered value. Longest first.

        Longest-first matters when one secret contains another: replacing the
        shorter one first would corrupt the longer one into a form the second
        pass no longer recognises, leaving part of it in the log.
        """
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        return text


#: Process-wide registry. The enrollment token is registered here before the
#: first log call in the enrollment path (Phase 2).
SECRETS = SecretRegistry()


def redact(text: str, registry: SecretRegistry | None = None) -> str:
    """Remove known secrets and any PEM private key from a rendered log line.

    Order matters: registered values go first, because a registered token may
    sit inside a larger structure that a later pattern would otherwise rewrite
    around.
    """
    registry = SECRETS if registry is None else registry
    text = registry.scrub(text)
    text = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    return _PRIVATE_KEY_BLOCK_ESCAPED.sub(REDACTED, text)


def is_sensitive_field(name: str) -> bool:
    """Whether a structured-extra key should have its value replaced."""
    lowered = name.lower()
    return any(fragment in lowered for fragment in SENSITIVE_FIELD_FRAGMENTS)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with redaction applied to the whole line.

    Field names are short and stable because they end up in a log collector's
    index. `ts` is RFC 3339 UTC with milliseconds; the agent reports UTC
    everywhere so a laptop's local timezone never has to be reconciled with the
    server's view of when something happened.
    """

    def __init__(self, *, registry: SecretRegistry | None = None) -> None:
        super().__init__()
        self._registry = registry

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": dt.datetime.fromtimestamp(record.created, dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in _RECORD_RESERVED or key.startswith("_") or key in payload:
                continue
            payload[key] = REDACTED if is_sensitive_field(key) else value

        if record.exc_info:
            exc_type = record.exc_info[0]
            payload["exc_type"] = exc_type.__name__ if exc_type else None
            # The formatted traceback, not the live exception: str() on some
            # exceptions calls into user code, and this is not the place for a
            # surprise. It is redacted along with everything else below.
            payload["exc"] = self.formatException(record.exc_info)

        # default=str so an unexpected object in `extra=` degrades to its repr
        # instead of raising inside the logging handler, which would lose the
        # line entirely. ensure_ascii=False keeps non-ASCII hostnames readable;
        # json.dumps still escapes control characters, so the output stays on
        # one line.
        line = json.dumps(payload, default=str, ensure_ascii=False, separators=(",", ":"))
        return redact(line, self._registry)


def normalise_level(level: str | None) -> str:
    """Map a requested level onto the agent's vocabulary, clamping the unknown.

    Clamps rather than raises, for the same reason the numeric settings clamp:
    a signed policy from a newer server may name a level this build has never
    heard of, and that must not stop the agent.
    """
    if level is None:
        return LOG_LEVEL_DEFAULT
    candidate = level.strip().lower()
    if candidate in LOG_LEVELS:
        return candidate
    return LOG_LEVEL_DEFAULT


def configure_logging(
    level: str = LOG_LEVEL_DEFAULT,
    *,
    stream: TextIO | None = None,
    registry: SecretRegistry | None = None,
) -> logging.Logger:
    """Install the JSON handler on the agent's logger root.

    Logs go to stdout, not to a file. Under systemd stdout is the journal, which
    already handles rotation, size limits and persistence - and a log file the
    agent opens itself is one more path to get the permissions wrong on.

    Only the `ubuntuguard_agent` logger is configured. The root logger is left
    alone so importing this package cannot reshape another program's logging.
    """
    logger = logging.getLogger("ubuntuguard_agent")
    logger.setLevel(_LEVEL_MAP[normalise_level(level)])

    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        existing.close()

    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(JsonFormatter(registry=registry))
    logger.addHandler(handler)

    # Nothing above this logger should see these records: the root logger may be
    # configured by something else entirely, and duplicating every line into it
    # is how a secret ends up in an unredacted handler.
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """A child of the agent logger. `name` is appended, e.g. "runtime"."""
    if not name:
        return logging.getLogger("ubuntuguard_agent")
    return logging.getLogger(f"ubuntuguard_agent.{name}")


def register_secrets(values: Iterable[str | None]) -> None:
    """Register several values at once, before any of them could be logged."""
    for value in values:
        SECRETS.register(value)
