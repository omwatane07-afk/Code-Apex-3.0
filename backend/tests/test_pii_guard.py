"""Tests for PII Guard: Verhoeff algorithm test vectors, independent generator, evasion defenses, and audited overrides."""

import pytest

from cyberq.core.pii_guard import (
    PIIGuard,
    compute_verhoeff_check_digit,
    scan_and_redact,
    validate_verhoeff,
    validate_verhoeff_checksum,
)


class IndependentVerhoeffReference:
    """Independent second implementation of the Verhoeff check digit algorithm using D5 group arithmetic."""

    # Multiplication in D5 represented as permutation groups
    MULT = (
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
        (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
        (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
        (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
        (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
        (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
        (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
        (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
        (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
    )

    PERM = (
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
        (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
        (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
        (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
        (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
        (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
        (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
    )

    INVERSE = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

    @classmethod
    def generate_check_digit(cls, number_str: str) -> int:
        digits = [int(c) for c in number_str if c.isdigit()]
        acc = 0
        for i, digit in enumerate(reversed(digits)):
            acc = cls.MULT[acc][cls.PERM[(i + 1) % 8][digit]]
        return cls.INVERSE[acc]

    @classmethod
    def validate(cls, number_str: str) -> bool:
        digits = [int(c) for c in number_str if c.isdigit()]
        acc = 0
        for i, digit in enumerate(reversed(digits)):
            acc = cls.MULT[acc][cls.PERM[i % 8][digit]]
        return acc == 0


def test_verhoeff_published_test_vectors():
    """Verify published standard Verhoeff test vectors: 236 -> 3, 12345 -> 1."""
    # Vector 1: 236 -> 3
    assert compute_verhoeff_check_digit("236") == 3
    assert validate_verhoeff_checksum("2363") is True
    assert IndependentVerhoeffReference.generate_check_digit("236") == 3
    assert IndependentVerhoeffReference.validate("2363") is True

    # Vector 2: 12345 -> 1
    assert compute_verhoeff_check_digit("12345") == 1
    assert validate_verhoeff_checksum("123451") is True
    assert IndependentVerhoeffReference.generate_check_digit("12345") == 1
    assert IndependentVerhoeffReference.validate("123451") is True


def test_verhoeff_single_digit_and_transposition_errors():
    """Verify Verhoeff catches all single-digit errors and adjacent transpositions."""
    valid_aadhaar = "999941057058"
    assert validate_verhoeff(valid_aadhaar) is True

    # Single digit alterations
    for pos in range(len(valid_aadhaar)):
        original_digit = int(valid_aadhaar[pos])
        for alt in range(10):
            if alt != original_digit:
                tampered = valid_aadhaar[:pos] + str(alt) + valid_aadhaar[pos + 1:]
                assert validate_verhoeff(tampered) is False, f"Failed to detect single-digit error at {pos}: {tampered}"

    # Adjacent transposition errors
    digits = list(valid_aadhaar)
    for i in range(len(digits) - 1):
        if digits[i] != digits[i + 1]:
            transposed = list(digits)
            transposed[i], transposed[i + 1] = transposed[i + 1], transposed[i]
            tampered = "".join(transposed)
            assert validate_verhoeff(tampered) is False, f"Failed to detect transposition at {i}: {tampered}"


def test_aadhaar_evasion_defenses():
    """Verify Aadhaar detection catches spaces, hyphens, dots, zero-width chars, and Unicode digits."""
    valid_aadhaar = "999941057058"

    # 1. Hyphen and space separated
    text1 = f"Customer provided UIDAI number: {valid_aadhaar[:4]}-{valid_aadhaar[4:8]}-{valid_aadhaar[8:]}"
    findings1 = PIIGuard.scan(text1)
    assert any(f["type"] == "AADHAAR" for f in findings1)

    # 2. Dot separated evasion
    text2 = f"Identifier recorded as {valid_aadhaar[:4]}.{valid_aadhaar[4:8]}.{valid_aadhaar[8:]}"
    findings2 = PIIGuard.scan(text2)
    assert any(f["type"] == "AADHAAR" for f in findings2)

    # 3. Zero-width spaces and joiners (\u200b, \u200c, \u200d)
    text3 = f"Obfuscated UID: {valid_aadhaar[:4]}\u200b{valid_aadhaar[4:8]}\u200c{valid_aadhaar[8:]}"
    findings3 = PIIGuard.scan(text3)
    assert any(f["type"] == "AADHAAR" for f in findings3)

    # 4. Unicode fullwidth digits
    # Convert '999941057058' to fullwidth '９９９９４１０５７０５８'
    fullwidth = "".join(chr(0xFF10 + int(c)) for c in valid_aadhaar)
    text4 = f"User record contains Unicode digits: {fullwidth}"
    findings4 = PIIGuard.scan(text4)
    assert any(f["type"] == "AADHAAR" for f in findings4)


def test_pre_filter_exclusions_do_not_trigger_pii():
    """Verify technical patterns (IPv4, IPv6, timestamps, hashes, UUIDs) are excluded and not flagged."""
    technical_payload = (
        "Core Switch Flap: Interface xe-0/0/1 on 192.168.100.254 flapped at 2026-10-11T14:59:49Z. "
        "BGP Neighbor 10.0.0.1 session reset. "
        "Commit SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
        "Message UUID 550e8400-e29b-41d4-a716-446655440000 logged across cluster."
    )
    findings = PIIGuard.scan(technical_payload)
    assert len(findings) == 0, f"False positives on benign technical data: {findings}"


def test_soft_warning_and_audited_override():
    """Verify PII guard redacts with warning notice, and supports audited 'not personal data' overrides."""
    valid_aadhaar = "999941057058"
    raw_text = f"Suspicious activity tied to Aadhaar {valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}."

    # Case 1: Default scan_and_redact (no override) -> redacts and issues warning
    res1 = scan_and_redact(raw_text, override_pii=False)
    assert res1["has_pii"] is True
    assert res1["overridden"] is False
    assert "[REDACTED_AADHAAR]" in res1["clean_text"]
    assert valid_aadhaar not in res1["clean_text"]
    assert "Personal data detected and redacted" in res1["warning"]

    # Case 2: Audited override with valid justification -> preserves text and records override
    res2 = scan_and_redact(
        raw_text,
        override_pii=True,
        override_reason="Synthetic test vector generated during simulated pen-test.",
    )
    assert res2["has_pii"] is True
    assert res2["overridden"] is True
    assert valid_aadhaar[:4] in res2["clean_text"]
    assert "Audited PII override applied" in res2["warning"]
    assert res2["override_reason"] == "Synthetic test vector generated during simulated pen-test."

    # Case 3: Override attempted without justification -> rejects with ValueError
    with pytest.raises(ValueError, match="mandatory justification"):
        scan_and_redact(raw_text, override_pii=True, override_reason="")
