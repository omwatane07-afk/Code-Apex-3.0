"""72-Hour Statutory Countdown Timer for DPDP Rule 7 Breach Notifications."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field

IST_TZ = ZoneInfo("Asia/Kolkata")
DPDP_STATUTORY_WINDOW_HOURS = 72


def to_ist_str(dt: datetime | None, fmt: str = "%d-%m-%Y %H:%M") -> str:
    """Converts a UTC datetime to Indian Standard Time (IST) formatted string."""
    if dt is None:
        return "[DD-MM-YYYY HH:MM]"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    ist_dt = dt.astimezone(IST_TZ)
    return ist_dt.strftime(fmt)


class DpdpTimerStatus(BaseModel):
    """Real-time status of the 72-hour statutory DPDP reporting countdown."""

    became_aware_at_utc: datetime
    became_aware_ist: str
    deadline_at_utc: datetime
    deadline_72h_ist: str
    evaluated_at_utc: datetime
    hours_remaining: float
    minutes_remaining: float
    is_expired: bool
    status: str = Field(..., description="RUNNING, DUE_SOON, CRITICAL, or BREACHED")
    should_auto_trigger: bool = Field(
        ..., description="True if countdown has reached or exceeded statutory deadline"
    )


def evaluate_72h_timer(
    became_aware_at: datetime,
    now: datetime | None = None,
) -> DpdpTimerStatus:
    """Evaluates the 72-hour countdown from the 'became aware' moment.

    Args:
        became_aware_at: Timezone-aware UTC timestamp when bank became aware of the breach.
        now: Current evaluation time (defaults to datetime.now(UTC)).

    Returns:
        DpdpTimerStatus with calculated intervals, IST strings, and status flags.
    """
    if became_aware_at.tzinfo is None:
        became_aware_at = became_aware_at.replace(tzinfo=UTC)

    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    deadline = became_aware_at + timedelta(hours=DPDP_STATUTORY_WINDOW_HOURS)
    remaining_delta = deadline - now
    total_remaining_seconds = remaining_delta.total_seconds()

    hours_remaining = round(total_remaining_seconds / 3600.0, 2)
    minutes_remaining = round(total_remaining_seconds / 60.0, 1)

    is_expired = total_remaining_seconds <= 0
    should_auto_trigger = is_expired

    if is_expired:
        status = "BREACHED"
    elif remaining_delta <= timedelta(hours=4):
        status = "CRITICAL"
    elif remaining_delta <= timedelta(hours=12):
        status = "DUE_SOON"
    else:
        status = "RUNNING"

    return DpdpTimerStatus(
        became_aware_at_utc=became_aware_at,
        became_aware_ist=to_ist_str(became_aware_at),
        deadline_at_utc=deadline,
        deadline_72h_ist=to_ist_str(deadline),
        evaluated_at_utc=now,
        hours_remaining=hours_remaining,
        minutes_remaining=minutes_remaining,
        is_expired=is_expired,
        status=status,
        should_auto_trigger=should_auto_trigger,
    )
