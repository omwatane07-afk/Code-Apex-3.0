"""Test suite for cyberq.ledger.canonical (strict RFC 8785 profile)."""

from __future__ import annotations

import enum
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cyberq.ledger import canonical as c
from tests.ledger import vectors
from tools.export_jcs_vectors import OUT as VECTORS_JSON
from tools.export_jcs_vectors import build as build_vectors_json


# --------------------------------------------------------------------------- #
# Shared conformance vectors (also consumed by the Go verifier)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("name", "text", "expected"), vectors.VALID, ids=[v[0] for v in vectors.VALID]
)
def test_valid_vectors(name: str, text: str, expected: bytes) -> None:
    assert c.canonicalize_json(text) == expected
    assert c.canonicalize_json(text.encode("utf-8")) == expected
    # Canonical output is a fixed point of parse -> canonicalize and is canonical.
    assert c.canonicalize(c.loads(expected)) == expected
    assert c.is_canonical(expected)


@pytest.mark.parametrize(
    ("name", "raw", "code"), vectors.INVALID, ids=[v[0] for v in vectors.INVALID]
)
def test_invalid_vectors(name: str, raw: bytes, code: str) -> None:
    with pytest.raises(c.CanonicalizationError) as excinfo:
        c.canonicalize_json(raw)
    assert excinfo.value.code == code
    with pytest.raises(c.CanonicalizationError) as excinfo2:
        c.loads(raw)
    assert excinfo2.value.code == code
    assert c.is_canonical(raw) is False


def test_vectors_json_in_sync_with_source() -> None:
    on_disk = json.loads(Path(VECTORS_JSON).read_text(encoding="utf-8"))
    assert on_disk == build_vectors_json(), "run: python -m tools.export_jcs_vectors"


# --------------------------------------------------------------------------- #
# Ordering: UTF-16 code units, not code points
# --------------------------------------------------------------------------- #
def test_member_order_is_utf16_not_codepoint() -> None:
    emoji, hebrew = "\U0001f600", "\ufb33"  # U+1F600 > U+FB33 by code point, < by UTF-16
    assert emoji > hebrew  # code-point order would put emoji last
    out = c.canonicalize({hebrew: 1, emoji: 2})
    assert out.index(emoji.encode()) < out.index(hebrew.encode())


def test_insertion_order_is_irrelevant() -> None:
    items = [(f"k{i}", i) for i in range(50)] + [("\U0001f600", 0), ("\ufb33", 1), ("\r", 2)]
    rng = random.Random(1234)
    reference = c.canonicalize(dict(items))
    for _ in range(20):
        rng.shuffle(items)
        assert c.canonicalize(dict(items)) == reference


def test_arrays_keep_order_and_tuples_match_lists() -> None:
    assert c.canonicalize([3, 1, 2]) == b"[3,1,2]"
    assert c.canonicalize((3, 1, 2)) == b"[3,1,2]"


# --------------------------------------------------------------------------- #
# Strings
# --------------------------------------------------------------------------- #
def test_every_control_character_is_escaped_exactly() -> None:
    short = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
    for cp in range(0x20):
        expected = short.get(cp, f"\\u{cp:04x}")
        assert c.canonicalize(chr(cp)) == f'"{expected}"'.encode(), hex(cp)


def test_non_escaped_characters_are_literal() -> None:
    for ch in ["/", "\x7f", "\u0080", "\u009f", "\u2028", "\u2029", "\ufeff", "\U0010ffff"]:
        assert c.canonicalize(ch) == b'"' + ch.encode("utf-8") + b'"'


def test_quote_and_backslash_escaped() -> None:
    assert c.canonicalize('"\\') == b'"\\"\\\\"'


def test_no_unicode_normalization() -> None:
    nfc, nfd = "\u00e9", "e\u0301"
    assert c.canonicalize(nfc) != c.canonicalize(nfd)


@pytest.mark.parametrize("bad", ["\ud800", "\udfff", "a\udc00b", "\ud83d\ude00"])
def test_lone_surrogates_rejected_in_values(bad: str) -> None:
    # Note: "\ud83d\ude00" in Python source is TWO lone surrogates, not U+1F600.
    with pytest.raises(c.InvalidStringError):
        c.canonicalize(bad)
    with pytest.raises(c.InvalidStringError):
        c.canonicalize([{"k": bad}])


def test_lone_surrogate_rejected_in_names() -> None:
    with pytest.raises(c.InvalidStringError):
        c.canonicalize({"\ud800": 1})


# --------------------------------------------------------------------------- #
# Numbers: floats banned, integers bounded
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value", [0.0, -0.0, 1.0, 1.5, float("nan"), float("inf"), float("-inf"), 1e300]
)
def test_floats_rejected(value: float) -> None:
    with pytest.raises(c.FloatNotAllowedError):
        c.canonicalize(value)
    with pytest.raises(c.FloatNotAllowedError):
        c.canonicalize({"a": [value]})


@pytest.mark.parametrize(
    "value", [0, 1, -1, c.MAX_SAFE_INT, -c.MAX_SAFE_INT, 1_700_000_000_000_000]
)
def test_safe_integers_accepted(value: int) -> None:
    assert c.canonicalize(value) == str(value).encode()


@pytest.mark.parametrize("value", [c.MAX_SAFE_INT + 1, -c.MAX_SAFE_INT - 1, 2**63, -(2**64)])
def test_unsafe_integers_rejected(value: int) -> None:
    with pytest.raises(c.UnsafeIntegerError):
        c.canonicalize(value)


def test_bool_is_not_treated_as_int() -> None:
    assert c.canonicalize([True, False, 1, 0]) == b"[true,false,1,0]"


# --------------------------------------------------------------------------- #
# Type strictness
# --------------------------------------------------------------------------- #
class _Color(enum.IntEnum):
    RED = 1


class _Label(enum.StrEnum):
    A = "a"


@pytest.mark.parametrize(
    "value",
    [
        b"raw bytes",
        bytearray(b"x"),
        Decimal("1"),
        datetime(2026, 1, 1, tzinfo=UTC),
        {1, 2},
        object(),
        _Color.RED,
        _Label.A,
    ],
)
def test_unsupported_types_rejected(value: object) -> None:
    with pytest.raises(c.UnsupportedTypeError):
        c.canonicalize(value)
    with pytest.raises(c.UnsupportedTypeError):
        c.canonicalize({"k": [value]})


@pytest.mark.parametrize("key", [1, None, b"k", ("a",), 1.5, True])
def test_non_string_names_rejected(key: object) -> None:
    with pytest.raises(c.InvalidKeyError):
        c.canonicalize({key: 1})


def test_dict_subclass_rejected() -> None:
    class D(dict):  # type: ignore[type-arg]
        pass

    with pytest.raises(c.UnsupportedTypeError):
        c.canonicalize(D(a=1))


# --------------------------------------------------------------------------- #
# Resource limits
# --------------------------------------------------------------------------- #
def _nested(depth: int) -> list:  # type: ignore[type-arg]
    value: list = []  # type: ignore[type-arg]
    for _ in range(depth - 1):
        value = [value]
    return value


def test_depth_limit_boundary() -> None:
    assert c.canonicalize(_nested(c.MAX_DEPTH)) == b"[" * c.MAX_DEPTH + b"]" * c.MAX_DEPTH
    with pytest.raises(c.DepthExceededError):
        c.canonicalize(_nested(c.MAX_DEPTH + 1))


def test_cyclic_structure_rejected_not_infinite() -> None:
    a: list = []  # type: ignore[type-arg]
    a.append(a)
    with pytest.raises(c.DepthExceededError):
        c.canonicalize(a)
    d: dict = {}  # type: ignore[type-arg]
    d["self"] = d
    with pytest.raises(c.DepthExceededError):
        c.canonicalize(d)


def test_output_size_limit() -> None:
    with pytest.raises(c.SizeExceededError):
        c.canonicalize(["x" * 100] * 100, max_bytes=1000)
    assert len(c.canonicalize(["x" * 100] * 10, max_bytes=2000)) < 2000


def test_input_size_limit_on_parse() -> None:
    with pytest.raises(c.SizeExceededError):
        c.loads(b"[" + b"0," * 1000 + b"0]", max_bytes=100)


def test_deep_nesting_bomb_is_a_clean_error() -> None:
    with pytest.raises(c.CanonicalizationError):
        c.loads(b"[" * 200_000)


# --------------------------------------------------------------------------- #
# is_canonical (verifier check #2)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "stored",
    [
        b'{"a": 1}',  # whitespace
        b'{"b":1,"a":2}',  # unsorted
        b'{"a":"\\u00f6"}',  # escaped non-ASCII
        b'{"a":"\\/"}',  # escaped solidus
        b'{"a":"\\u000A"}',  # uppercase hex / non-short form
        b"[-0]",  # negative zero
        b"[1,]",  # malformed
    ],
)
def test_non_canonical_inputs_detected(stored: bytes) -> None:
    assert c.is_canonical(stored) is False


def test_is_canonical_accepts_own_output() -> None:
    obj = {"seq": 7, "epoch": 2, "payload": {"reason": "caf\u00e9 \U0001f600", "ids": [3, 1]}}
    assert c.is_canonical(c.canonicalize(obj))


# --------------------------------------------------------------------------- #
# Property tests against an independent oracle (stdlib json.dumps)
# --------------------------------------------------------------------------- #
_names = st.text(max_size=12)  # hypothesis text excludes lone surrogates by default
_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-c.MAX_SAFE_INT, max_value=c.MAX_SAFE_INT),
    st.text(max_size=20),
)
_json = st.recursive(
    _scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=5),
        st.dictionaries(_names, inner, max_size=5),
    ),
    max_leaves=25,
)


def _oracle(value: object) -> str:
    """Independent reference: sort members by UTF-16 units, then stdlib compact dumps."""

    def reorder(v: object) -> object:
        if isinstance(v, dict):
            return {k: reorder(v[k]) for k in sorted(v, key=lambda s: s.encode("utf-16-be"))}
        if isinstance(v, list):
            return [reorder(x) for x in v]
        return v

    return json.dumps(reorder(value), ensure_ascii=False, separators=(",", ":"))


@settings(max_examples=400, deadline=None)
@given(_json)
def test_matches_stdlib_oracle(value: object) -> None:
    assert c.canonicalize(value) == _oracle(value).encode("utf-8")


@settings(max_examples=300, deadline=None)
@given(_json)
def test_idempotent_and_self_canonical(value: object) -> None:
    once = c.canonicalize(value)
    assert c.canonicalize(c.loads(once)) == once
    assert c.is_canonical(once)


@settings(max_examples=300, deadline=None)
@given(_json)
def test_output_is_valid_json_with_utf16_sorted_names(value: object) -> None:
    out = c.canonicalize(value)

    def check(pairs: list[tuple[str, object]]) -> dict[str, object]:
        names = [k for k, _ in pairs]
        assert names == sorted(names, key=lambda s: s.encode("utf-16-be"))
        return dict(pairs)

    json.loads(out.decode("utf-8"), object_pairs_hook=check)


# --------------------------------------------------------------------------- #
# base64url
# --------------------------------------------------------------------------- #
@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=64))
def test_b64url_roundtrip(raw: bytes) -> None:
    text = c.b64url_encode(raw)
    assert "=" not in text and "+" not in text and "/" not in text
    assert c.b64url_decode(text) == raw


@pytest.mark.parametrize(
    "bad",
    [
        "AA==",  # padding
        "AA+/",  # standard alphabet
        "AB",  # non-zero trailing bits (canonical form is "AA")
        "A",  # impossible length
        "AAAAA",  # impossible length
        "AA A",  # whitespace
        "AA\n",  # trailing newline must not slip past a $-anchored regex
        "\u0661\u0662\u0663\u0664",  # non-ASCII digits
    ],
)
def test_b64url_decode_rejects_malformed(bad: str) -> None:
    with pytest.raises(c.InvalidEncodingError):
        c.b64url_decode(bad)


def test_b64url_known_values() -> None:
    assert c.b64url_encode(b"") == ""
    assert c.b64url_encode(b"\xfb\xff") == "-_8"
    assert c.b64url_decode("-_8") == b"\xfb\xff"


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def test_datetime_to_us_epoch_and_ist() -> None:
    assert c.datetime_to_us(datetime(1970, 1, 1, tzinfo=UTC)) == 0
    ist = timezone(timedelta(hours=5, minutes=30))
    moment = datetime(2026, 10, 20, 12, 30, 0, 123456, tzinfo=ist)
    utc = datetime(2026, 10, 20, 7, 0, 0, 123456, tzinfo=UTC)
    assert c.datetime_to_us(moment) == c.datetime_to_us(utc)
    assert c.us_to_datetime(c.datetime_to_us(moment)) == utc


def test_datetime_to_us_is_exact_for_microseconds() -> None:
    moment = datetime(2200, 4, 11, 23, 47, 16, 999999, tzinfo=UTC)
    us = c.datetime_to_us(moment)
    assert us % 1_000_000 == 999999  # a float intermediate would lose this
    assert c.us_to_datetime(us) == moment


def test_timestamp_safe_range_ends_in_year_2255() -> None:
    last_ok = c.us_to_datetime(c.MAX_SAFE_INT)
    assert last_ok.year == 2255
    assert c.datetime_to_us(last_ok) == c.MAX_SAFE_INT
    with pytest.raises(c.UnsafeIntegerError):
        c.datetime_to_us(last_ok + timedelta(microseconds=1))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(c.InvalidEncodingError):
        c.datetime_to_us(datetime(2026, 1, 1))


def test_us_to_datetime_type_and_range_checks() -> None:
    with pytest.raises(c.InvalidEncodingError):
        c.us_to_datetime(True)  # bool is not an int here
    with pytest.raises(c.InvalidEncodingError):
        c.us_to_datetime(1.0)  # type: ignore[arg-type]
    with pytest.raises(c.UnsafeIntegerError):
        c.us_to_datetime(c.MAX_SAFE_INT + 1)


# --------------------------------------------------------------------------- #
# Domain-separated hashing
# --------------------------------------------------------------------------- #
def test_entry_hash_matches_independent_computation() -> None:
    env = {"seq": 1, "v": 1, "payload": {"b": 2, "a": 1}}
    expected = hashlib.sha256(
        b"CQ-LEDGER-ENTRY-v1\x00" + b'{"payload":{"a":1,"b":2},"seq":1,"v":1}'
    ).digest()
    assert c.entry_hash(env) == expected


def test_domains_are_separated() -> None:
    obj = {"a": 1}
    plain = hashlib.sha256(c.canonicalize(obj)).digest()
    assert c.entry_hash(obj) != plain
    assert c.entry_hash(obj) != c.checkpoint_digest(obj)
    assert c.checkpoint_digest(obj) == hashlib.sha256(b"CQ-CKPT-v1\x00" + b'{"a":1}').digest()


def test_domain_hash_requires_nul_terminator() -> None:
    with pytest.raises(ValueError):
        c.domain_hash(b"NO-NUL", b"{}")


def test_entry_hash_requires_plain_dict() -> None:
    with pytest.raises(c.UnsupportedTypeError):
        c.entry_hash([1, 2])  # type: ignore[arg-type]
