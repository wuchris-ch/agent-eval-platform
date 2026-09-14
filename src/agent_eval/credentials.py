"""Per-trial credential material with an optional short-lived broker hook.

Secrets are kept in memory until the runner creates a uniquely named
Kubernetes Secret for one trial.  The runner deletes that Secret in a finally
block.  A broker can mint genuinely short-lived credentials; the built-in
fallbacks only provide per-trial delivery of the user's existing credential
and are deliberately labelled as reusable.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_KEY = re.compile(r"^[A-Za-z0-9._-]+$")
BROKER_TIMEOUT_SECONDS = 30
SHORT_LIVED_MAX_TTL_SECONDS = 3600
MAX_BROKER_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_CREDENTIAL_VALUES = 64
MAX_CREDENTIAL_VALUE_BYTES = 512 * 1024
MAX_CREDENTIAL_TOTAL_BYTES = 1024 * 1024
MAX_REDACTION_PATTERNS = 512
MAX_REDACTION_PATTERN_BYTES = 3 * 1024 * 1024
MAX_REDACTION_PATTERN_BYTES_TOTAL = 8 * 1024 * 1024
MAX_JSON_CREDENTIAL_DEPTH = 32
REDACTION_READ_CHUNK_BYTES = 64 * 1024
# Provider event streams can contain JSON strings nested inside JSONL events.
# Inspect enough layers for those legitimate transcripts while retaining a
# finite fail-closed boundary for deliberately over-nested output.
MAX_JSON_ESCAPE_DECODE_ROUNDS = 8
_SENSITIVE_JSON_KEY = re.compile(
    r"(?:^|[_-])(?:"
    r"api[_-]?key|auth|authorization|bearer|cookie|credential|id[_-]?token|"
    r"passcode|password|pin|refresh[_-]?token|secret|session|token|tokens|otp"
    r")(?:$|[_-])",
    re.IGNORECASE,
)
_KNOWN_JSON_SCHEMA_KEYS = frozenset(
    {
        "account_id",
        "active_profile",
        "auth_mode",
        "default",
        "email",
        "expiration",
        "expires_at",
        "expires_in",
        "expiry",
        "last_refresh",
        "mode",
        "organization",
        "organization_id",
        "profiles",
        "project_id",
        "schema_version",
        "type",
        "user_id",
        "version",
    }
)
MIN_SAFE_JSON_COMPONENT_BYTES = 6
_REDACTION_MARKERS = (
    b"redacted-credential",
    b"[REDACTED_CREDENTIAL]",
    "\u27e6CREDENTIAL REDACTED\u27e7".encode(),
    b"<secret-removed>",
    b"***",
    b"",
)


class CredentialRedactionError(RuntimeError):
    """Credential material cannot be inspected or redacted within safe limits."""


class _CredentialJSONNumber(str):
    """Original spelling of a JSON number, retained for exact redaction."""


def _strict_credential_json(value: str) -> object:
    """Parse projected JSON without discarding duplicate keys or number spellings."""

    def object_from_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise CredentialRedactionError(
                    "credential JSON contains duplicate object keys"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise CredentialRedactionError(
            "credential JSON contains a non-finite numeric value"
        )

    try:
        return json.loads(
            value,
            object_pairs_hook=object_from_pairs,
            parse_int=_CredentialJSONNumber,
            parse_float=_CredentialJSONNumber,
            parse_constant=reject_constant,
        )
    except RecursionError as exc:
        raise CredentialRedactionError(
            "credential JSON exceeds the safe depth limit"
        ) from exc


def _known_json_schema_key(key: str) -> bool:
    return key.casefold() in _KNOWN_JSON_SCHEMA_KEYS or bool(
        _SENSITIVE_JSON_KEY.search(key)
    )


def _json_credential_strings(
    value: object,
    *,
    sensitive_parent: bool = False,
    depth: int = 0,
) -> set[str]:
    """Extract secret-like JSON leaves without treating common metadata as secret."""

    if depth > MAX_JSON_CREDENTIAL_DEPTH:
        raise CredentialRedactionError("credential JSON exceeds the safe depth limit")
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CredentialRedactionError(
                    "credential JSON contains a non-string object key"
                )
            key_is_sensitive = bool(_SENSITIVE_JSON_KEY.search(key))
            if not _known_json_schema_key(key):
                # JSON permits credential material to appear as a dynamic
                # object key. Known schema labels are harmless literals; every
                # other key is either redacted exactly or rejected when it is
                # too short to pattern safely without corrupting ordinary data.
                if len(key.encode("utf-8")) < MIN_SAFE_JSON_COMPONENT_BYTES:
                    raise CredentialRedactionError(
                        "credential JSON contains an unrecognized short object key"
                    )
                found.add(key)
            found.update(
                _json_credential_strings(
                    item,
                    sensitive_parent=sensitive_parent or key_is_sensitive,
                    depth=depth + 1,
                )
            )
    elif isinstance(value, list):
        for item in value:
            found.update(
                _json_credential_strings(
                    item,
                    sensitive_parent=sensitive_parent,
                    depth=depth + 1,
                )
            )
    elif isinstance(value, _CredentialJSONNumber):
        if len(value.encode("utf-8")) < MIN_SAFE_JSON_COMPONENT_BYTES:
            raise CredentialRedactionError(
                "credential JSON numbers shorter than six bytes must be strings"
            )
        found.add(str(value))
    elif isinstance(value, str) and value:
        # Opaque high-entropy values are normally long even when their schema
        # uses an unfamiliar field name. Short metadata is included only below
        # a credential-labelled parent to avoid rejecting ordinary source text.
        if sensitive_parent or len(value.encode("utf-8")) >= 16:
            found.add(value)
    return found


def _encoded_patterns(value: str) -> set[bytes]:
    patterns = {value.encode("utf-8")}
    for ensure_ascii in (False, True):
        escaped = json.dumps(value, ensure_ascii=ensure_ascii)[1:-1].encode("utf-8")
        patterns.add(escaped)
    return {pattern for pattern in patterns if pattern}


_JSON_SIMPLE_ESCAPES = {
    ord('"'): b'"',
    ord("\\"): b"\\",
    ord("/"): b"/",
    ord("b"): b"\b",
    ord("f"): b"\f",
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
}
_ASCII_HEX = frozenset(b"0123456789abcdefABCDEF")


def _json_unescape_bytes_once(value: bytes) -> tuple[bytes, bool]:
    """Decode valid JSON string escapes embedded in an arbitrary byte buffer.

    The input need not itself be a complete JSON document. This lets the
    credential boundary recognize alternate but valid spellings such as
    ``\\/`` and mixed ``\\uXXXX`` escapes in logs, filenames, and artifacts.
    Invalid and unpaired-surrogate escapes remain byte-for-byte unchanged.
    """

    output = bytearray()
    cursor = 0
    changed = False
    while cursor < len(value):
        if value[cursor] != ord("\\") or cursor + 1 >= len(value):
            output.append(value[cursor])
            cursor += 1
            continue
        marker = value[cursor + 1]
        simple = _JSON_SIMPLE_ESCAPES.get(marker)
        if simple is not None:
            output.extend(simple)
            cursor += 2
            changed = True
            continue
        if (
            marker != ord("u")
            or cursor + 6 > len(value)
            or any(byte not in _ASCII_HEX for byte in value[cursor + 2 : cursor + 6])
        ):
            output.append(value[cursor])
            cursor += 1
            continue
        codepoint = int(value[cursor + 2 : cursor + 6], 16)
        consumed = 6
        if 0xD800 <= codepoint <= 0xDBFF:
            low_start = cursor + 6
            if (
                low_start + 6 > len(value)
                or value[low_start : low_start + 2] != b"\\u"
                or any(
                    byte not in _ASCII_HEX
                    for byte in value[low_start + 2 : low_start + 6]
                )
            ):
                output.extend(value[cursor : cursor + 6])
                cursor += 6
                continue
            low = int(value[low_start + 2 : low_start + 6], 16)
            if not 0xDC00 <= low <= 0xDFFF:
                output.extend(value[cursor : cursor + 6])
                cursor += 6
                continue
            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
            consumed = 12
        elif 0xDC00 <= codepoint <= 0xDFFF:
            output.extend(value[cursor : cursor + 6])
            cursor += 6
            continue
        output.extend(chr(codepoint).encode("utf-8"))
        cursor += consumed
        changed = True
    return bytes(output), changed


class _StreamingJSONUnescaper:
    """Incrementally apply one JSON-string unescape pass.

    At most one incomplete simple escape, Unicode escape, or surrogate pair is
    retained between chunks. Complete output is byte-for-byte equivalent to
    ``_json_unescape_bytes_once`` over the concatenated input.
    """

    def __init__(self) -> None:
        self._pending = bytearray()
        self.changed = False

    def feed(self, value: bytes, *, final: bool = False) -> bytes:
        self._pending.extend(value)
        candidate = self._pending
        output = bytearray()
        cursor = 0

        while cursor < len(candidate):
            if candidate[cursor] != ord("\\"):
                output.append(candidate[cursor])
                cursor += 1
                continue

            remaining = len(candidate) - cursor
            if remaining < 2:
                if final:
                    output.append(candidate[cursor])
                    cursor += 1
                break

            marker = candidate[cursor + 1]
            simple = _JSON_SIMPLE_ESCAPES.get(marker)
            if simple is not None:
                output.extend(simple)
                cursor += 2
                self.changed = True
                continue

            if marker != ord("u"):
                output.append(candidate[cursor])
                cursor += 1
                continue

            if remaining < 6:
                if final:
                    output.append(candidate[cursor])
                    cursor += 1
                    continue
                break
            if any(
                byte not in _ASCII_HEX for byte in candidate[cursor + 2 : cursor + 6]
            ):
                output.append(candidate[cursor])
                cursor += 1
                continue

            codepoint = int(candidate[cursor + 2 : cursor + 6], 16)
            consumed = 6
            if 0xD800 <= codepoint <= 0xDBFF:
                if remaining < 12:
                    if final:
                        output.extend(candidate[cursor : cursor + 6])
                        cursor += 6
                        continue
                    break
                low_start = cursor + 6
                if candidate[low_start : low_start + 2] != b"\\u" or any(
                    byte not in _ASCII_HEX
                    for byte in candidate[low_start + 2 : low_start + 6]
                ):
                    output.extend(candidate[cursor : cursor + 6])
                    cursor += 6
                    continue
                low = int(candidate[low_start + 2 : low_start + 6], 16)
                if not 0xDC00 <= low <= 0xDFFF:
                    output.extend(candidate[cursor : cursor + 6])
                    cursor += 6
                    continue
                codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                consumed = 12
            elif 0xDC00 <= codepoint <= 0xDFFF:
                output.extend(candidate[cursor : cursor + 6])
                cursor += 6
                continue

            output.extend(chr(codepoint).encode("utf-8"))
            cursor += consumed
            self.changed = True

        if cursor:
            del self._pending[:cursor]
        return bytes(output)

    def finish(self) -> bytes:
        output = self.feed(b"", final=True)
        if self._pending:
            raise CredentialRedactionError(
                "credential JSON escape inspection did not finish"
            )
        return output


class _StreamingPatternMatcher:
    """Match exact patterns while retaining only direct-pattern overlap."""

    def __init__(self, patterns: tuple[bytes, ...], maximum_bytes: int) -> None:
        self._patterns = patterns
        self._overlap = max(0, maximum_bytes - 1)
        self._tail = b""

    def feed(self, value: bytes) -> bool:
        if not value:
            return False
        candidate = self._tail + value
        if any(pattern in candidate for pattern in self._patterns):
            return True
        self._tail = candidate[-self._overlap :] if self._overlap else b""
        return False


@dataclass(frozen=True)
class CredentialRedactor:
    """Exact, bounded redaction derived from the credential actually projected.

    Patterns include environment values, opaque credential-file contents, and
    secret-bearing leaves of JSON auth files. JSON-escaped forms are included
    so a transcript cannot evade redaction merely by serializing a token.
    """

    patterns: tuple[bytes, ...] = field(repr=False)
    placeholder: bytes = field(repr=False)

    @classmethod
    def from_material(cls, material: CredentialMaterial) -> CredentialRedactor:
        raw_values: set[str] = set()
        file_keys = set(material.file_items)
        for key, value in material.values.items():
            if key not in file_keys:
                raw_values.add(value)
                continue
            # The projected file is credential material regardless of whether
            # its schema happens to use a recognized token field today.
            raw_values.add(value)
            try:
                parsed = _strict_credential_json(value)
            except json.JSONDecodeError as exc:
                # An opaque file can contain a credential in any substring;
                # matching only the whole file cannot contain copied leaves.
                # Require one strict, structurally inspectable representation.
                raise CredentialRedactionError(
                    "projected credential files must contain strict JSON"
                ) from exc
            # Every string leaf in a projected credential file is credential
            # material. Treating unfamiliar short fields as harmless would
            # allow a custom auth schema to bypass the artifact boundary.
            embedded = _json_credential_strings(parsed, sensitive_parent=True)
            if embedded:
                # Also catch tokens copied out of the exact auth file.
                raw_values.update(embedded)
            elif isinstance(parsed, str) and parsed:
                raw_values.add(parsed)

        patterns: set[bytes] = set()
        for value in raw_values:
            patterns.update(_encoded_patterns(value))
            if len(patterns) > MAX_REDACTION_PATTERNS:
                raise CredentialRedactionError(
                    "credential material exceeds the redaction pattern limit"
                )
        if any(len(pattern) > MAX_REDACTION_PATTERN_BYTES for pattern in patterns):
            raise CredentialRedactionError(
                "credential material exceeds the redaction pattern size limit"
            )
        if sum(map(len, patterns)) > MAX_REDACTION_PATTERN_BYTES_TOTAL:
            raise CredentialRedactionError(
                "credential material exceeds the total redaction size limit"
            )
        ordered = tuple(sorted(patterns, key=lambda pattern: (-len(pattern), pattern)))
        placeholder = next(
            marker
            for marker in _REDACTION_MARKERS
            if all(pattern not in marker for pattern in ordered)
        )
        return cls(patterns=ordered, placeholder=placeholder)

    @property
    def maximum_pattern_bytes(self) -> int:
        return max(map(len, self.patterns), default=0)

    def contains_bytes(self, value: bytes) -> bool:
        candidate = value
        if any(pattern in candidate for pattern in self.patterns):
            return True
        for _ in range(MAX_JSON_ESCAPE_DECODE_ROUNDS):
            decoded, changed = _json_unescape_bytes_once(candidate)
            if not changed:
                return False
            candidate = decoded
            if any(pattern in candidate for pattern in self.patterns):
                return True
        # Deliberately nested escape layers are not a supported durable output
        # representation. Fail closed rather than accepting an uninspectable
        # serialization that could reveal a credential after further decoding.
        _decoded, changed = _json_unescape_bytes_once(candidate)
        if changed:
            raise CredentialRedactionError(
                "credential output exceeds the JSON escape inspection limit"
            )
        return False

    def contains_text(self, value: str) -> bool:
        return self.contains_bytes(value.encode("utf-8", errors="surrogateescape"))

    def redact_bytes(self, value: bytes) -> bytes:
        if not isinstance(value, bytes):
            raise TypeError("credential redaction requires bytes")
        if not self.patterns:
            return value
        output = bytearray()
        cursor = 0
        while cursor < len(value):
            match_index: int | None = None
            match_pattern: bytes | None = None
            for pattern in self.patterns:
                index = value.find(pattern, cursor)
                if index < 0:
                    continue
                if match_index is None or index < match_index:
                    match_index = index
                    match_pattern = pattern
                elif index == match_index and match_pattern is not None:
                    if len(pattern) > len(match_pattern):
                        match_pattern = pattern
            if match_index is None or match_pattern is None:
                output.extend(value[cursor:])
                break
            output.extend(value[cursor:match_index])
            output.extend(self.placeholder)
            cursor = match_index + len(match_pattern)
        redacted = bytes(output)
        if self.contains_bytes(redacted):
            raise CredentialRedactionError(
                "credential output could not be safely redacted"
            )
        return redacted

    def redact_text(self, value: str) -> str:
        encoded = value.encode("utf-8", errors="surrogateescape")
        return self.redact_bytes(encoded).decode("utf-8", errors="surrogateescape")

    def redact_value(self, value: object) -> object:
        """Recursively redact JSON-compatible values before record persistence."""

        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            return self.redact_bytes(value)
        if isinstance(value, dict):
            redacted: dict[object, object] = {}
            for key, item in value.items():
                safe_key = self.redact_text(key) if isinstance(key, str) else key
                if safe_key in redacted:
                    raise CredentialRedactionError(
                        "credential redaction produced duplicate record fields"
                    )
                redacted[safe_key] = self.redact_value(item)
            return redacted
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        return value

    def contains_stream(
        self,
        stream: BinaryIO,
        *,
        maximum_bytes: int,
        chunk_bytes: int = REDACTION_READ_CHUNK_BYTES,
    ) -> bool:
        """Search a bounded stream through every supported JSON escape layer."""

        if maximum_bytes < 0 or chunk_bytes <= 0:
            raise ValueError("credential stream limits must be positive")
        if not self.patterns:
            return False

        matchers = [
            _StreamingPatternMatcher(self.patterns, self.maximum_pattern_bytes)
            for _ in range(MAX_JSON_ESCAPE_DECODE_ROUNDS + 1)
        ]
        decoders = [
            _StreamingJSONUnescaper() for _ in range(MAX_JSON_ESCAPE_DECODE_ROUNDS + 1)
        ]
        read_bytes = max(chunk_bytes, self.maximum_pattern_bytes)

        def feed_layers(value: bytes, start: int = 0) -> bool:
            current = value
            for layer in range(start, MAX_JSON_ESCAPE_DECODE_ROUNDS):
                current = decoders[layer].feed(current)
                if matchers[layer + 1].feed(current):
                    return True
            # One extra decoder records whether the supported depth was
            # exceeded. Its output is deliberately not treated as evidence.
            decoders[MAX_JSON_ESCAPE_DECODE_ROUNDS].feed(current)
            return False

        consumed = 0
        while True:
            chunk = stream.read(read_bytes)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise CredentialRedactionError(
                    "credential inspection exceeded its byte limit"
                )
            if matchers[0].feed(chunk) or feed_layers(chunk):
                return True

        # Flush incomplete escapes from each layer, then pass that output only
        # through downstream layers that have not yet been finalized.
        for layer in range(MAX_JSON_ESCAPE_DECODE_ROUNDS):
            current = decoders[layer].finish()
            if matchers[layer + 1].feed(current):
                return True
            if feed_layers(current, start=layer + 1):
                return True

        decoders[MAX_JSON_ESCAPE_DECODE_ROUNDS].finish()
        if decoders[MAX_JSON_ESCAPE_DECODE_ROUNDS].changed:
            raise CredentialRedactionError(
                "credential output exceeds the JSON escape inspection limit"
            )
        return False


@dataclass(frozen=True)
class CredentialMaterial:
    """Credential values and their safe Kubernetes projections."""

    values: dict[str, str] = field(repr=False)
    env_keys: tuple[str, ...] = ()
    file_items: dict[str, str] = field(default_factory=dict)
    source: str = "unknown"
    expires_at: str | None = None
    short_lived: bool = False

    def __post_init__(self) -> None:
        if not self.values:
            raise ValueError("credential material must contain at least one value")
        if len(self.values) > MAX_CREDENTIAL_VALUES:
            raise ValueError("credential material contains too many values")
        total_bytes = 0
        for key, value in self.values.items():
            if not isinstance(key, str) or not isinstance(value, str) or not value:
                raise ValueError("credential values must be non-empty strings")
            value_bytes = len(value.encode("utf-8"))
            if value_bytes > MAX_CREDENTIAL_VALUE_BYTES:
                raise ValueError("credential value exceeds the safe size limit")
            total_bytes += value_bytes
        if total_bytes > MAX_CREDENTIAL_TOTAL_BYTES:
            raise ValueError("credential material exceeds the safe total size limit")
        unknown_env = set(self.env_keys) - set(self.values)
        unknown_files = set(self.file_items) - set(self.values)
        if unknown_env or unknown_files:
            raise ValueError("credential projections reference missing values")
        if any(not _ENV_NAME.fullmatch(key) for key in self.env_keys):
            raise ValueError("credential environment names must be valid identifiers")
        for key, path in self.file_items.items():
            if not _SECRET_KEY.fullmatch(key):
                raise ValueError(f"invalid Kubernetes Secret key {key!r}")
            pure = PurePosixPath(path)
            if (
                pure.is_absolute()
                or len(pure.parts) != 1
                or pure.name in ("", ".", "..")
            ):
                raise ValueError("credential file paths must be safe basenames")

    @property
    def mode(self) -> str:
        if self.short_lived:
            return "short-lived"
        if self.expires_at:
            return "expiring-broker-credential"
        return "reusable-fallback"


def _parse_expiry(
    value: object, *, minimum_ttl_seconds: int = 0
) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if not isinstance(value, str):
        raise ValueError("credential broker expires_at must be an ISO-8601 string")
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("credential broker expires_at is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("credential broker expires_at must include a timezone")
    remaining = (parsed - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        raise ValueError("credential broker returned an expired credential")
    if remaining < minimum_ttl_seconds:
        raise ValueError(
            "credential broker expiry does not cover the configured trial timeout"
        )
    return value, remaining <= SHORT_LIVED_MAX_TTL_SECONDS


def _terminate_broker_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the broker and descendants that remain in its process group."""

    if hasattr(os, "killpg"):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _from_broker(
    command: str, agent: str, *, minimum_ttl_seconds: int = 0
) -> CredentialMaterial:
    argv = shlex.split(command)
    if not argv:
        raise ValueError("AGENT_EVAL_CREDENTIAL_COMMAND is empty")
    env = dict(os.environ)
    env["AGENT_EVAL_AGENT"] = agent
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env=env,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + BROKER_TIMEOUT_SECONDS
                while proc.poll() is None:
                    output_bytes = (
                        os.fstat(stdout.fileno()).st_size
                        + os.fstat(stderr.fileno()).st_size
                    )
                    if output_bytes > MAX_BROKER_OUTPUT_BYTES:
                        raise RuntimeError(
                            "credential broker output exceeded the safe size limit"
                        )
                    if time.monotonic() >= deadline:
                        raise RuntimeError("credential broker timed out")
                    time.sleep(0.01)
                output_bytes = (
                    os.fstat(stdout.fileno()).st_size
                    + os.fstat(stderr.fileno()).st_size
                )
                if output_bytes > MAX_BROKER_OUTPUT_BYTES:
                    raise RuntimeError(
                        "credential broker output exceeded the safe size limit"
                    )
                stdout.seek(0)
                broker_output = stdout.read(MAX_BROKER_OUTPUT_BYTES + 1)
            finally:
                # End the trusted broker's process group after the leader exits
                # or the bounded broker contract fails.
                _terminate_broker_group(proc)
    except OSError as exc:
        raise RuntimeError("credential broker could not be executed") from exc
    if proc.returncode != 0:
        # Broker output may contain credentials.  Never include it in errors.
        raise RuntimeError(f"credential broker exited {proc.returncode}")
    try:
        payload = json.loads(broker_output)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("credential broker did not return valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("credential broker output must be a JSON object")
    allowed = {"env", "files", "expires_at"}
    extra = set(payload) - allowed
    if extra:
        raise ValueError("credential broker returned unsupported fields")
    raw_env = payload.get("env") or {}
    raw_files = payload.get("files") or {}
    if not isinstance(raw_env, dict) or not isinstance(raw_files, dict):
        raise ValueError("credential broker env and files must be JSON objects")

    values: dict[str, str] = {}
    env_keys: list[str] = []
    file_items: dict[str, str] = {}
    for key, value in raw_env.items():
        if not isinstance(key, str) or not _ENV_NAME.fullmatch(key):
            raise ValueError("credential broker returned an invalid environment name")
        if not isinstance(value, str) or not value:
            raise ValueError("credential broker values must be non-empty strings")
        values[key] = value
        env_keys.append(key)
    for index, (path, value) in enumerate(raw_files.items()):
        if not isinstance(path, str) or not isinstance(value, str) or not value:
            raise ValueError(
                "credential broker files must map names to non-empty strings"
            )
        secret_key = f"broker-file-{index}"
        values[secret_key] = value
        file_items[secret_key] = path

    expires_at, short_lived = _parse_expiry(
        payload.get("expires_at"), minimum_ttl_seconds=minimum_ttl_seconds
    )
    return CredentialMaterial(
        values=values,
        env_keys=tuple(env_keys),
        file_items=file_items,
        source="credential-broker",
        expires_at=expires_at,
        short_lived=short_lived,
    )


def load_trial_credentials(
    agent: str, *, minimum_ttl_seconds: int = 0
) -> CredentialMaterial:
    """Load only the credential needed by ``agent`` for one trial.

    Set ``AGENT_EVAL_CREDENTIAL_COMMAND`` to an argv-style command whose JSON
    stdout contains ``env``, ``files``, and an optional ``expires_at``.  When
    no broker is configured, supported adapters use the current reusable host
    credential, but it is still delivered through a unique per-trial Secret.
    """

    broker = os.environ.get("AGENT_EVAL_CREDENTIAL_COMMAND")
    if broker:
        return _from_broker(broker, agent, minimum_ttl_seconds=minimum_ttl_seconds)

    if agent == "claude-code":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set and no credential broker is configured"
            )
        return CredentialMaterial(
            values={"ANTHROPIC_API_KEY": key},
            env_keys=("ANTHROPIC_API_KEY",),
            source="host-environment",
        )

    if agent == "codex":
        auth = Path.home() / ".codex" / "auth.json"
        if not auth.is_file():
            raise RuntimeError("~/.codex/auth.json not found; run `codex login` first")
        with auth.open("rb") as stream:
            auth_bytes = stream.read(MAX_CREDENTIAL_VALUE_BYTES + 1)
        if len(auth_bytes) > MAX_CREDENTIAL_VALUE_BYTES:
            raise RuntimeError("~/.codex/auth.json exceeds the safe size limit")
        try:
            auth_text = auth_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("~/.codex/auth.json is not valid UTF-8") from exc
        return CredentialMaterial(
            values={"codex-auth": auth_text},
            file_items={"codex-auth": "codex-auth.json"},
            source="host-codex-auth",
        )

    raise RuntimeError(
        f"agent {agent!r} needs AGENT_EVAL_CREDENTIAL_COMMAND credential material"
    )
