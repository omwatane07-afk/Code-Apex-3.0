"""HMAC-SHA256 signature verification, replay protection, and timestamp validation."""

import hashlib
import hmac
import threading
from datetime import UTC, datetime, timedelta


class ReplayDefenseCache:
    """Thread-safe TTL sliding window cache for webhook nonces."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self._cache: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: datetime) -> bool:
        """Returns True if nonce is fresh and added, False if duplicate/replayed."""
        with self._lock:
            # Purge expired nonces
            cutoff = now - self.ttl
            expired = [k for k, ts in self._cache.items() if ts < cutoff]
            for k in expired:
                del self._cache[k]

            if nonce in self._cache:
                return False

            self._cache[nonce] = now
            return True


_GLOBAL_NONCE_CACHE = ReplayDefenseCache(ttl_seconds=300)


def verify_webhook_hmac(
    payload_bytes: bytes,
    secret_key: str,
    signature_header: str,
    timestamp_header: str,
    nonce_header: str | None = None,
    now: datetime | None = None,
    tolerance_seconds: int = 300,
) -> tuple[bool, str]:
    """Verifies HMAC-SHA256 signature and validates replay protection.

    Format: HMAC-SHA256(secret, timestamp || payload)
    """
    if now is None:
        now = datetime.now(UTC)

    # 1. Parse and validate timestamp
    try:
        ts = datetime.fromisoformat(timestamp_header.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
    except Exception:
        return False, f"Invalid timestamp format: {timestamp_header}"

    # 2. Replay window check (<= 300s)
    drift = abs((now - ts).total_seconds())
    if drift > tolerance_seconds:
        return False, f"Timestamp drift {drift:.1f}s exceeds allowable window of {tolerance_seconds}s"

    # 3. Nonce verification if provided
    if nonce_header:
        if not _GLOBAL_NONCE_CACHE.check_and_add(nonce_header, now):
            return False, f"Replay detected: nonce '{nonce_header}' has already been processed"

    # 4. HMAC-SHA256 computation
    mac = hmac.new(secret_key.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(timestamp_header.encode("utf-8"))
    mac.update(b".")
    mac.update(payload_bytes)
    expected_sig = mac.hexdigest()

    # Clean incoming signature
    clean_sig = signature_header.strip()
    if clean_sig.startswith("sha256="):
        clean_sig = clean_sig[7:]

    if not hmac.compare_digest(expected_sig.lower(), clean_sig.lower()):
        return False, "Invalid HMAC signature"

    return True, "Valid signature"
