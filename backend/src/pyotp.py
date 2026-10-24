"""CYBERQ Air-Gapped Pure-Python RFC 6238 TOTP and RFC 4226 HOTP Engine.

Zero external dependencies; fully compliant with standard pyotp API.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Any

__all__ = ["TOTP", "random_base32"]


def random_base32(length: int = 32) -> str:
    """Generates a random base32 string using standard RFC 4648 alphabet."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(chars) for _ in range(length))


class TOTP:
    """Time-based One-Time Password algorithm (RFC 6238)."""

    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = None,
        name: str | None = None,
        issuer: str | None = None,
        interval: int = 30,
    ) -> None:
        self.secret = s
        self.digits = digits
        self.digest = digest or hashlib.sha1
        self.name = name
        self.issuer = issuer
        self.interval = interval

    def _get_key_bytes(self) -> bytes:
        clean = self.secret.strip().replace(" ", "").upper()
        missing_padding = len(clean) % 8
        if missing_padding != 0:
            clean += "=" * (8 - missing_padding)
        return base64.b32decode(clean, casefold=True)

    def generate_otp(self, input_val: int) -> str:
        """Computes the HOTP value for a given counter value (RFC 4226)."""
        key_bytes = self._get_key_bytes()
        msg = struct.pack(">Q", input_val)
        mac = hmac.new(key_bytes, msg, self.digest).digest()
        offset = mac[-1] & 0x0F
        binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        token = str(binary % (10**self.digits)).zfill(self.digits)
        return token

    def timecode(self, for_time: float | int | None = None) -> int:
        """Returns the integer time-step counter."""
        t = time.time() if for_time is None else float(for_time)
        return int(t) // self.interval

    def now(self) -> str:
        """Generates the current valid 6-digit TOTP code."""
        return self.generate_otp(self.timecode())

    def at(self, for_time: float | int) -> str:
        """Generates the TOTP code for a specific timestamp."""
        return self.generate_otp(self.timecode(for_time))

    def verify(
        self,
        otp: str,
        for_time: float | int | None = None,
        valid_window: int = 0,
    ) -> bool:
        """Verifies a TOTP code against the secret, supporting clock drift windows."""
        if not otp:
            return False
        clean_otp = otp.strip().replace(" ", "")
        if not clean_otp.isdigit():
            return False

        try:
            current_step = self.timecode(for_time)
            for window_offset in range(-valid_window, valid_window + 1):
                expected = self.generate_otp(current_step + window_offset)
                if hmac.compare_digest(expected, clean_otp):
                    return True
        except Exception:
            return False

        return False
