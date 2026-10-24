"""Banking PII Guard: Pre-filter exclusions, Verhoeff & Luhn validation, redaction, and audited overrides."""

import re
import unicodedata
from typing import Any

# Verhoeff algorithm multiplication table
_VERHOEFF_D = (
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

# Verhoeff algorithm permutation table
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# Verhoeff algorithm inverse table
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def compute_verhoeff_check_digit(num_str: str) -> int:
    """Calculate the Verhoeff check digit for an arbitrary digit sequence."""
    digits = [int(c) for c in num_str if c.isdigit()]
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][digit]]
    return _VERHOEFF_INV[c]


def validate_verhoeff_checksum(num_str: str) -> bool:
    """Validate any numeric string with its check digit under the Verhoeff algorithm."""
    digits = [int(c) for c in num_str if c.isdigit()]
    if not digits:
        return False
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


def validate_verhoeff(number_str: str) -> bool:
    """Validate 12-digit Aadhaar using Verhoeff algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) != 12:
        return False
    # First digit of Aadhaar cannot be 0 or 1
    if digits[0] in (0, 1):
        return False
    return validate_verhoeff_checksum("".join(str(d) for d in digits))


def validate_luhn(number_str: str) -> bool:
    """Validate payment card number using Luhn algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False

    total = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


# Pre-filter exclusions: patterns recognized as benign technical data
_TECH_EXCLUSIONS_REGEX = re.compile(
    r"("
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"  # IPv4
    r"|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"  # IPv6
    r"|\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"  # Timestamps ISO
    r"|\b\d{2}[/-]\d{2}[/-]\d{4}\b"  # Dates
    r"|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"  # UUID
    r"|\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b"  # MD5, SHA1, SHA256 hashes
    r"|\bCVE-\d{4}-\d{4,7}\b"  # CVE identifiers
    r"|\bT\d{4}(?:\.\d{3})?\b"  # MITRE ATT&CK technique IDs
    r"|\b(?:INC|ALT|ANOM|EVD|INV)-\d{4,}[A-Za-z0-9\-]*\b"  # System incident IDs
    r")",
    re.IGNORECASE,
)

_PAN_REGEX = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z]{5}[\s\-_.]?[0-9]{4}[\s\-_.]?[A-Za-z])(?![A-Za-z0-9])"
)
_CARD_CANDIDATE_REGEX = re.compile(r"\b([3-6][0-9]{3}[\s\-_.]?[0-9]{4}[\s\-_.]?[0-9]{4}[\s\-_.]?[0-9]{1,7})\b")

# Aadhaar candidate regex supporting evasions: spaces, dots, hyphens, underscores, colons, commas, pipes, slashes, and zero-width characters
_AADHAAR_CANDIDATE_REGEX = re.compile(
    r"(?<!\d)([2-9][0-9]{3}[\s\-._/:,\|\u200b-\u200d\ufeff\u00a0]*[0-9]{4}[\s\-._/:,\|\u200b-\u200d\ufeff\u00a0]*[0-9]{4})(?!\d)"
)

# Bank Account Number with contextual prefix (A/C, Account, Acct, IBAN)
_BANK_ACCOUNT_REGEX = re.compile(
    r"(?:\b(?:A\/C|acc|account|acct|iban)\s*(?:no\.?|num\.?|number)?\s*[:#-]?\s*)([0-9]{9,18})\b",
    re.IGNORECASE,
)

# Indian mobile phone number: 10 digits starting with 6-9, optionally prefixed by +91, 91, or 0
_PHONE_REGEX = re.compile(
    r"(?<!\d)(?:(?:\+91|91|0)[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)"
)

# Email address regex
_EMAIL_REGEX = re.compile(
    r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b",
    re.IGNORECASE,
)


# Maximum recursion depth for nested scanning to prevent stack exhaustion DoS
_MAX_SCAN_DEPTH = 64


class PIIGuard:
    """Bank PII detection, redaction, and audited override engine."""

    @staticmethod
    def scan(text: str) -> list[dict[str, str]]:
        """Return list of detected PII entities, after excluding benign technical patterns."""
        findings: list[dict[str, str]] = []
        if not text:
            return findings

        # Normalize Unicode representations (fullwidth digits, Devanagari, NFKC)
        normalized = unicodedata.normalize("NFKC", text)

        # Pre-filter exclusions: replace technical patterns with equal-length masking characters
        # so character offsets match exactly
        masked_text = _TECH_EXCLUSIONS_REGEX.sub(lambda m: "X" * len(m.group(0)), normalized)

        # 1. PAN detection (case-insensitive and format-tolerant)
        for match in _PAN_REGEX.finditer(masked_text):
            findings.append({"type": "PAN", "match": match.group(1)})

        # 2. Aadhaar detection with Verhoeff validation and evasion handling
        for match in _AADHAAR_CANDIDATE_REGEX.finditer(masked_text):
            raw = match.group(1)
            digits = "".join(filter(str.isdigit, raw))
            if validate_verhoeff(digits):
                findings.append({"type": "AADHAAR", "match": raw})

        # 3. Card detection with Luhn validation
        for match in _CARD_CANDIDATE_REGEX.finditer(masked_text):
            raw = match.group(1)
            digits = "".join(filter(str.isdigit, raw))
            if len(digits) == 12 and validate_verhoeff(digits):
                continue
            if validate_luhn(digits):
                findings.append({"type": "CARD", "match": raw})

        # 4. Bank Account detection
        for match in _BANK_ACCOUNT_REGEX.finditer(masked_text):
            findings.append({"type": "BANK_ACCOUNT", "match": match.group(1)})

        # 5. Mobile Phone detection
        for match in _PHONE_REGEX.finditer(masked_text):
            raw_phone = match.group(0)
            digits = "".join(filter(str.isdigit, raw_phone))
            if 10 <= len(digits) <= 12 and digits[-10] in "6789":
                findings.append({"type": "PHONE", "match": raw_phone})

        # 6. Email detection
        for match in _EMAIL_REGEX.finditer(masked_text):
            findings.append({"type": "EMAIL", "match": match.group(1)})

        return findings

    @classmethod
    def scan_nested(cls, data: Any, _depth: int = 0) -> list[dict[str, str]]:
        """Recursively scans dictionaries, lists, sets, and strings for customer PII.

        Enforces a maximum recursion depth to prevent stack exhaustion DoS.
        """
        if _depth > _MAX_SCAN_DEPTH:
            return []
        findings: list[dict[str, str]] = []
        if isinstance(data, str):
            findings.extend(cls.scan(data))
        elif isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str):
                    findings.extend(cls.scan(k))
                findings.extend(cls.scan_nested(v, _depth=_depth + 1))
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                findings.extend(cls.scan_nested(item, _depth=_depth + 1))
        return findings

    @classmethod
    def redact_nested(cls, data: Any, _depth: int = 0) -> Any:
        """Recursively redacts customer PII within nested JSON dictionaries, lists, and strings.

        Enforces a maximum recursion depth to prevent stack exhaustion DoS.
        """
        if _depth > _MAX_SCAN_DEPTH:
            return data
        if isinstance(data, str):
            return cls.redact(data)
        elif isinstance(data, dict):
            return {k: cls.redact_nested(v, _depth=_depth + 1) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.redact_nested(item, _depth=_depth + 1) for item in data]
        elif isinstance(data, tuple):
            return tuple(cls.redact_nested(item, _depth=_depth + 1) for item in data)
        return data

    @classmethod
    def redact(cls, text: str) -> str:
        """Redact detected PII entities from text."""
        findings = cls.scan(text)
        redacted = text
        for item in findings:
            pii_type = item["type"]
            match_str = item["match"]
            redacted = redacted.replace(match_str, f"[REDACTED_{pii_type}]")
        return redacted

    @classmethod
    def scan_and_redact(
        cls,
        text: str,
        override_pii: bool = False,
        override_reason: str = "",
    ) -> dict[str, Any]:
        """Scan text, redact if needed, or apply audited override."""
        findings = cls.scan(text)
        if not findings:
            return {
                "clean_text": text,
                "has_pii": False,
                "overridden": False,
                "override_reason": None,
                "findings": [],
                "warning": None,
            }

        types = ", ".join(sorted({f["type"] for f in findings}))

        if override_pii:
            if not override_reason or len(override_reason.strip()) < 5:
                raise ValueError("An audited PII override requires a mandatory justification (minimum 5 characters).")
            return {
                "clean_text": text,
                "has_pii": True,
                "overridden": True,
                "override_reason": override_reason.strip(),
                "findings": findings,
                "warning": f"Audited PII override applied ({types}). Justification: {override_reason.strip()}",
            }

        redacted = cls.redact(text)
        return {
            "clean_text": redacted,
            "has_pii": True,
            "overridden": False,
            "override_reason": None,
            "findings": findings,
            "warning": f"Personal data detected and redacted ({types}). Use audited override if this is not customer personal data.",
        }

    @classmethod
    def assert_clean(cls, text: str, field_name: str = "text") -> None:
        """Legacy helper: raise ValueError if unredacted PII is found in text."""
        findings = cls.scan(text)
        if findings:
            types = ", ".join(sorted({f["type"] for f in findings}))
            raise ValueError(
                f"Prohibited customer PII detected in {field_name} ({types}). "
                "CYBERQ strictly forbids customer identity or account data per AGENTS.md."
            )


validate_text_or_raise = PIIGuard.assert_clean
scan_and_redact = PIIGuard.scan_and_redact
