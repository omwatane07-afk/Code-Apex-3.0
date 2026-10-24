"""Strict RFC 8785 (JSON Canonicalization Scheme) engine for the CYBERQ ledger.

This module is the single place where ledger bytes are produced. Everything that
is hashed or signed (entry envelopes, checkpoints, manifests) passes through
``canonicalize``. The Go verifier must reproduce its output byte for byte, so
the rules below are deliberately *stricter* than RFC 8785 requires.

RFC 8785 rules implemented here
-------------------------------
* No insignificant whitespace.
* Object members sorted by the UTF-16 code units of their (unescaped) names,
  NOT by Unicode code point. The two orders differ for U+E000..U+FFFF versus
  supplementary-plane characters.
* Strings: only ``"`` and ``\\`` and U+0000..U+001F are escaped. Control
  characters use ``\\b \\t \\n \\f \\r`` where defined and lowercase
  ``\\u00xx`` otherwise. ``/``, DEL (U+007F), U+2028/U+2029 and every
  non-ASCII character are emitted literally. Output is UTF-8.
* No Unicode normalization (JCS does not normalize).

CYBERQ restrictions on top of RFC 8785 (I-JSON profile)
-------------------------------------------------------
* **Floats are banned outright** (including NaN and +/-Infinity). Timestamps are
  integer microseconds; counts are integers; anything fractional is a decimal
  *string*. This removes the whole ES6 number-formatting interop problem.
* Integers must lie within +/-(2**53 - 1). Larger values must be strings.
* Binary values must be base64url (no padding) strings; ``bytes`` is rejected.
* Lone surrogates are rejected in both strings and object names.
* Only exact types ``None, bool, int, str, list, tuple, dict`` are accepted.
  Subclasses (``IntEnum``, ``StrEnum`` ...) are rejected so that two encoders
  can never disagree about how an enum serialises; convert explicitly first.
* Object names must be ``str``. Duplicate names are rejected when parsing.
* Nesting depth and output size are bounded (denial-of-service guard).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Final

__all__ = [
    "CHECKPOINT_DOMAIN",
    "ENTRY_DOMAIN",
    "MAX_DEPTH",
    "MAX_OUTPUT_BYTES",
    "MAX_SAFE_INT",
    "CanonicalizationError",
    "DepthExceededError",
    "DuplicateKeyError",
    "FloatNotAllowedError",
    "InvalidEncodingError",
    "InvalidKeyError",
    "InvalidStringError",
    "MalformedJSONError",
    "SizeExceededError",
    "UnsafeIntegerError",
    "UnsupportedTypeError",
    "b64url_decode",
    "b64url_encode",
    "canonicalize",
    "canonicalize_json",
    "checkpoint_digest",
    "datetime_to_us",
    "domain_hash",
    "entry_hash",
    "is_canonical",
    "loads",
    "us_to_datetime",
]

MAX_SAFE_INT: Final[int] = 2**53 - 1
MAX_DEPTH: Final[int] = 64
MAX_OUTPUT_BYTES: Final[int] = 8 * 1024 * 1024

ENTRY_DOMAIN: Final[bytes] = b"CQ-LEDGER-ENTRY-v1\x00"
CHECKPOINT_DOMAIN: Final[bytes] = b"CQ-CKPT-v1\x00"


# --------------------------------------------------------------------------- #
# Errors. Each class carries a stable ``code`` shared with the Go verifier's
# test vectors, so differential tests compare failure *kinds*, not messages.
# --------------------------------------------------------------------------- #
class CanonicalizationError(ValueError):
    code = "CQ-CANON-ERROR"


class FloatNotAllowedError(CanonicalizationError):
    code = "CQ-CANON-FLOAT"


class UnsafeIntegerError(CanonicalizationError):
    code = "CQ-CANON-UNSAFE-INT"


class UnsupportedTypeError(CanonicalizationError):
    code = "CQ-CANON-TYPE"


class InvalidStringError(CanonicalizationError):
    code = "CQ-CANON-STRING"


class InvalidKeyError(CanonicalizationError):
    code = "CQ-CANON-KEY"


class DuplicateKeyError(CanonicalizationError):
    code = "CQ-CANON-DUPLICATE-KEY"


class DepthExceededError(CanonicalizationError):
    code = "CQ-CANON-DEPTH"


class SizeExceededError(CanonicalizationError):
    code = "CQ-CANON-SIZE"


class MalformedJSONError(CanonicalizationError):
    code = "CQ-CANON-MALFORMED"


class InvalidEncodingError(CanonicalizationError):
    code = "CQ-CANON-ENCODING"


# --------------------------------------------------------------------------- #
# String quoting
# --------------------------------------------------------------------------- #
_ESCAPES: Final[dict[int, str]] = {i: f"\\u{i:04x}" for i in range(0x20)}
_ESCAPES.update(
    {
        0x08: "\\b",
        0x09: "\\t",
        0x0A: "\\n",
        0x0C: "\\f",
        0x0D: "\\r",
        0x22: '\\"',
        0x5C: "\\\\",
    }
)
_ESCAPE_TABLE: Final[dict[int, str]] = str.maketrans(_ESCAPES)


def _check_string(s: str) -> None:
    """Reject strings that cannot be encoded as well-formed UTF-8 (lone surrogates)."""
    if s.isascii():
        return
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidStringError("lone surrogate in string") from exc


def _quote(s: str) -> str:
    _check_string(s)
    return '"' + s.translate(_ESCAPE_TABLE) + '"'


def _utf16_sort_key(name: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly like sequences of 16-bit code
    # units, which is the ordering RFC 8785 section 3.2.3 mandates.
    return name.encode("utf-16-be")


# --------------------------------------------------------------------------- #
# Encoder
# --------------------------------------------------------------------------- #
class _Encoder:
    __slots__ = ("max_bytes", "max_depth", "parts", "size")

    def __init__(self, max_depth: int, max_bytes: int) -> None:
        self.max_depth = max_depth
        self.max_bytes = max_bytes
        self.parts: list[str] = []
        self.size = 0

    def _emit(self, piece: str) -> None:
        # len(str) <= len(utf-8 bytes), so this under-counts and the final
        # byte-length check is the authoritative one. It still bounds memory.
        self.size += len(piece)
        if self.size > self.max_bytes:
            raise SizeExceededError(f"canonical output exceeds {self.max_bytes} bytes")
        self.parts.append(piece)

    def encode(self, value: Any, depth: int) -> None:
        t = type(value)
        if value is None:
            self._emit("null")
        elif t is bool:
            self._emit("true" if value else "false")
        elif t is int:
            if value > MAX_SAFE_INT or value < -MAX_SAFE_INT:
                raise UnsafeIntegerError(
                    "integer outside +/-(2**53-1); encode it as a decimal string"
                )
            self._emit(str(value))
        elif t is str:
            self._emit(_quote(value))
        elif t is float:
            raise FloatNotAllowedError(
                "floats are forbidden; use integer microseconds or a decimal string"
            )
        elif t is list or t is tuple:
            self._array(value, depth + 1)
        elif t is dict:
            self._object(value, depth + 1)
        else:
            raise UnsupportedTypeError(
                f"type {t.__module__}.{t.__qualname__} is not canonicalizable; "
                "convert to None/bool/int/str/list/dict first"
            )

    def _array(self, items: Any, depth: int) -> None:
        if depth > self.max_depth:
            raise DepthExceededError(f"nesting deeper than {self.max_depth}")
        self._emit("[")
        first = True
        for item in items:
            if not first:
                self._emit(",")
            first = False
            self.encode(item, depth)
        self._emit("]")

    def _object(self, obj: dict[Any, Any], depth: int) -> None:
        if depth > self.max_depth:
            raise DepthExceededError(f"nesting deeper than {self.max_depth}")
        for name in obj:
            if type(name) is not str:
                raise InvalidKeyError(f"object names must be str, got {type(name).__qualname__}")
            _check_string(name)
        self._emit("{")
        first = True
        for name in sorted(obj, key=_utf16_sort_key):
            if not first:
                self._emit(",")
            first = False
            self._emit(_quote(name))
            self._emit(":")
            self.encode(obj[name], depth)
        self._emit("}")


def canonicalize(
    value: Any,
    *,
    max_depth: int = MAX_DEPTH,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> bytes:
    """Return the strict RFC 8785 canonical UTF-8 encoding of ``value``."""
    enc = _Encoder(max_depth, max_bytes)
    enc.encode(value, 0)
    out = "".join(enc.parts).encode("utf-8")
    if len(out) > max_bytes:
        raise SizeExceededError(f"canonical output exceeds {max_bytes} bytes")
    return out


# --------------------------------------------------------------------------- #
# Strict parsing (used by the verifier to re-canonicalize stored bytes)
# --------------------------------------------------------------------------- #
def _reject_float(text: str) -> Any:
    raise FloatNotAllowedError(f"floating-point number {text!r} is forbidden")


def _reject_constant(name: str) -> Any:
    raise FloatNotAllowedError(f"{name} is forbidden")


def _parse_int(text: str) -> int:
    value = int(text)
    if value > MAX_SAFE_INT or value < -MAX_SAFE_INT:
        raise UnsafeIntegerError("integer outside +/-(2**53-1)")
    return value


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise DuplicateKeyError(f"duplicate object name {name!r}")
        out[name] = value
    return out


def _parse(data: bytes | bytearray | memoryview | str, max_bytes: int) -> Any:
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
        if len(raw) > max_bytes:
            raise SizeExceededError(f"input exceeds {max_bytes} bytes")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise MalformedJSONError("UTF-8 byte-order mark is not permitted")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidStringError("input is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
        if len(text) > max_bytes:
            raise SizeExceededError(f"input exceeds {max_bytes} characters")
    else:
        raise UnsupportedTypeError("expected bytes or str")
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        raise DepthExceededError("nesting too deep to parse") from exc
    except ValueError as exc:  # includes json.JSONDecodeError and int-digit limits
        raise MalformedJSONError(str(exc)) from exc


def loads(
    data: bytes | bytearray | memoryview | str,
    *,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> Any:
    """Parse JSON under the full CYBERQ ledger profile, or raise.

    Rejects floats, NaN/Infinity, unsafe integers, duplicate names, lone
    surrogates, a UTF-8 BOM, invalid UTF-8 and over-deep nesting.
    """
    value = _parse(data, max_bytes)
    canonicalize(value, max_bytes=max_bytes)  # validates strings, keys and depth
    return value


def canonicalize_json(
    data: bytes | bytearray | memoryview | str,
    *,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> bytes:
    """Parse ``data`` strictly and return its canonical form."""
    return canonicalize(_parse(data, max_bytes), max_bytes=max_bytes)


def is_canonical(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> bool:
    """True iff ``data`` parses under the profile and is already byte-identical canonical form.

    This is verifier check #2: stored envelope bytes must equal their own
    re-canonicalization.
    """
    try:
        return canonicalize_json(data, max_bytes=max_bytes) == bytes(data)
    except CanonicalizationError:
        return False


# --------------------------------------------------------------------------- #
# base64url (RFC 4648 section 5), unpadded, strictly canonical
# --------------------------------------------------------------------------- #
_B64URL_RE: Final = re.compile(r"[A-Za-z0-9_-]*")


def b64url_encode(raw: bytes) -> str:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise InvalidEncodingError("expected bytes")
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, rejecting padding, other alphabets and non-zero trailing bits."""
    if not isinstance(text, str) or _B64URL_RE.fullmatch(text) is None:
        raise InvalidEncodingError("not unpadded base64url")
    if len(text) % 4 == 1:
        raise InvalidEncodingError("impossible base64url length")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(raw) != text:
        raise InvalidEncodingError("non-canonical base64url (non-zero trailing bits)")
    return raw


# --------------------------------------------------------------------------- #
# Integer-microsecond timestamps (no float arithmetic anywhere)
# --------------------------------------------------------------------------- #
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_US: Final = timedelta(microseconds=1)


def datetime_to_us(moment: datetime) -> int:
    """Timezone-aware datetime -> integer microseconds since the Unix epoch (UTC)."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise InvalidEncodingError("naive datetime; timestamps must be timezone-aware")
    micros = (moment.astimezone(UTC) - _EPOCH) // _ONE_US
    if abs(micros) > MAX_SAFE_INT:
        raise UnsafeIntegerError("timestamp outside safe integer range")
    return micros


def us_to_datetime(micros: int) -> datetime:
    """Integer microseconds since the Unix epoch -> aware UTC datetime."""
    if type(micros) is not int:
        raise InvalidEncodingError("microseconds must be an int")
    if abs(micros) > MAX_SAFE_INT:
        raise UnsafeIntegerError("timestamp outside safe integer range")
    return _EPOCH + timedelta(microseconds=micros)


# --------------------------------------------------------------------------- #
# Domain-separated hashing
# --------------------------------------------------------------------------- #
def domain_hash(domain: bytes, canonical: bytes) -> bytes:
    """SHA-256(domain || canonical). ``domain`` must be NUL-terminated."""
    if not domain.endswith(b"\x00"):
        raise ValueError("domain separator must end with a NUL byte")
    return hashlib.sha256(domain + canonical).digest()


def entry_hash(envelope: dict[str, Any]) -> bytes:
    """SHA-256("CQ-LEDGER-ENTRY-v1\\x00" || JCS(envelope))."""
    if type(envelope) is not dict:
        raise UnsupportedTypeError("ledger envelope must be a dict")
    return domain_hash(ENTRY_DOMAIN, canonicalize(envelope))


def checkpoint_digest(checkpoint: dict[str, Any]) -> bytes:
    """Digest the HSM signs: SHA-256("CQ-CKPT-v1\\x00" || JCS(checkpoint))."""
    if type(checkpoint) is not dict:
        raise UnsupportedTypeError("checkpoint must be a dict")
    return domain_hash(CHECKPOINT_DOMAIN, canonicalize(checkpoint))
