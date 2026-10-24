"""Scope Guard for CYBERQ Red Team & Offensive Security testing.

Enforces Rules of Engagement: any request or connection target outside
the allow-list defined in scope.json immediately aborts the test run
and appends a critical entry to docs/BLOCKERS.md.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SCOPE_FILE = Path(__file__).parent / "scope.json"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BLOCKERS_FILE = REPO_ROOT / "docs" / "BLOCKERS.md"


def load_scope() -> set[str]:
    with open(SCOPE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("allow_list", []))


ALLOW_LIST = load_scope()


class ScopeViolationError(PermissionError):
    """Raised when an attack script attempts to access an out-of-scope host."""
    pass


def enforce_scope(target: str) -> None:
    """Validates that a URL, hostname, or IP address is strictly within the allowed red-team scope.

    Raises ScopeViolationError and logs a blocker if the target is out of scope.
    """
    if "://" in target:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
    else:
        host = target.split(":")[0].strip().lower()

    if not host:
        return

    if host not in ALLOW_LIST:
        now = datetime.now(timezone.utc).isoformat()
        blocker_entry = (
            f"\n\n### Scope Violation: {now}\n"
            f"- Milestone/Round: Red Team Engagement\n"
            f"- Attempted Target: `{target}` (Host: `{host}`)\n"
            f"- Action: Execution aborted immediately per non-negotiable Rules of Engagement.\n"
            f"- Need: Confirmation whether `{host}` should be explicitly added to scope.json.\n"
        )
        try:
            with open(BLOCKERS_FILE, "a", encoding="utf-8") as bf:
                bf.write(blocker_entry)
        except Exception:
            pass

        raise ScopeViolationError(
            f"CRITICAL: Scope violation! Target '{host}' is outside allowed test sandbox: {ALLOW_LIST}"
        )


def verify_target(target: str) -> bool:
    try:
        enforce_scope(target)
        return True
    except ScopeViolationError:
        return False
