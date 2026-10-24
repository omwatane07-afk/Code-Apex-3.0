import hashlib
import threading
import time

try:
    import pyotp
except ImportError:
    import sys
    from pathlib import Path

    _src = str(Path(__file__).resolve().parent.parent.parent)
    if _src not in sys.path:
        sys.path.insert(0, _src)
    import pyotp


class TOTPReplayProtection:
    """Thread-safe in-memory cache tracking recently consumed TOTP tokens to prevent replay."""

    def __init__(self, window_seconds: int = 120) -> None:
        self.window_seconds = window_seconds
        self._consumed: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_consume(self, secret: str, code: str) -> bool:
        """Returns True if the token is fresh and consumed; False if already used."""
        now = time.monotonic()
        secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        key = f"{secret_hash}:{code}"

        with self._lock:
            # Purge entries older than window
            cutoff = now - self.window_seconds
            expired = [k for k, t in self._consumed.items() if t < cutoff]
            for k in expired:
                del self._consumed[k]

            if key in self._consumed:
                return False

            self._consumed[key] = now
            return True

    def clear(self) -> None:
        with self._lock:
            self._consumed.clear()


_GLOBAL_TOTP_REPLAY_CACHE = TOTPReplayProtection(window_seconds=120)


def clear_totp_replay_cache() -> None:
    """Flushes all consumed tokens from the global TOTP replay cache."""
    _GLOBAL_TOTP_REPLAY_CACHE.clear()


def verify_totp_code(
    secret: str,
    code: str,
    replay_cache: TOTPReplayProtection | None = None,
) -> bool:
    """Verifies a 6-digit TOTP code against the user's secret with replay protection."""
    clean_code = code.strip().replace(" ", "")
    if not clean_code or not clean_code.isdigit():
        return False

    try:
        totp = pyotp.TOTP(secret)
        if not totp.verify(clean_code, valid_window=1):
            return False
    except Exception:
        return False

    cache = replay_cache if replay_cache is not None else _GLOBAL_TOTP_REPLAY_CACHE
    if not cache.check_and_consume(secret, clean_code):
        return False

    return True


def validate_break_glass_eligibility(
    elapsed_minutes: float,
    remaining_minutes: float,
    reason: str,
) -> tuple[bool, str]:
    """Validates if the current regulatory timeline qualifies for the 3 AM Break-Glass override.

    Rule: Break-Glass unlocks ONLY when:
    (Elapsed >= 30m AND Remaining <= 90m) OR (Remaining <= 30m).
    ReasonCode must be at least 20 characters.
    """
    clean_reason = reason.strip()
    if len(clean_reason) < 20:
        return False, f"Break-Glass justification must be at least 20 characters, got {len(clean_reason)}"

    # Window check
    is_eligible = (elapsed_minutes >= 30 and remaining_minutes <= 90) or (remaining_minutes <= 30)
    if not is_eligible:
        return False, (
            f"Break-Glass protocol unavailable: current status (Elapsed={elapsed_minutes:.1f}m, "
            f"Remaining={remaining_minutes:.1f}m) does not meet statutory critical threshold "
            "(Requires Elapsed >= 30m & Remaining <= 90m, or Remaining <= 30m)."
        )

    return True, "Eligible for Break-Glass override"
