"""CYBERQ Regulatory Clock Engine.

Enforces:
1. Strict UTC timezone adherence (rejection of naive and non-UTC datetimes).
2. Monotonic deadline calculations from asserted trigger events.
3. Non-future occurred_at assertions relative to recorded_at.
4. Alert correlation validation.
5. Conservative dispute resolution (preserves earlier statutory deadline).
6. Deterministic escalation ladder computation.
"""

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class EscalationRung(StrEnum):
    T_MINUS_4H = "t_minus_4h"
    T_MINUS_2H = "t_minus_2h"
    T_MINUS_1H = "t_minus_1h"
    T_MINUS_30M = "t_minus_30m"
    T_MINUS_10M = "t_minus_10m"
    BREACH = "breach"


class ClockStatus(StrEnum):
    PROVISIONAL_TRIAGE = "provisional_triage"
    PENDING_TRIGGER = "pending_trigger"
    RUNNING = "running"
    DUE_SOON = "due_soon"
    CRITICAL = "critical"
    BREACHED = "breached"
    FILED = "filed"
    NOT_APPLICABLE = "not_applicable"
    DISPUTED = "disputed"


def validate_utc_datetime(dt: datetime, field_name: str = "datetime") -> datetime:
    """Validate that datetime is timezone-aware and explicitly UTC."""
    if dt.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware with UTC timezone, got naive datetime: {dt}")
    # Verify UTC offset is exactly 0
    utcoffset = dt.utcoffset()
    if utcoffset is None or utcoffset.total_seconds() != 0:
        raise ValueError(f"{field_name} must have UTC timezone (offset 0), got: {dt.tzinfo}")
    return dt


class RungSchedule(BaseModel):
    model_config = ConfigDict(frozen=True)

    rung: EscalationRung
    scheduled_at: datetime
    lead_time: timedelta


class ClockCalculationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    occurred_at: datetime
    recorded_at: datetime
    deadline_at: datetime
    status: ClockStatus
    rungs: list[RungSchedule]
    next_due_at: datetime | None
    requires_review: bool
    review_reason: str | None = None
    disputed_deadline_at: datetime | None = None
    active_deadline_at: datetime


# Standard escalation lead times relative to deadline
RUNG_OFFSETS: list[tuple[EscalationRung, timedelta]] = [
    (EscalationRung.T_MINUS_4H, timedelta(hours=4)),
    (EscalationRung.T_MINUS_2H, timedelta(hours=2)),
    (EscalationRung.T_MINUS_1H, timedelta(hours=1)),
    (EscalationRung.T_MINUS_30M, timedelta(minutes=30)),
    (EscalationRung.T_MINUS_10M, timedelta(minutes=10)),
    (EscalationRung.BREACH, timedelta(seconds=0)),
]


def calculate_clock(
    occurred_at: datetime,
    recorded_at: datetime,
    deadline_hours: int,
    now: datetime | None = None,
    alert_detected_at: datetime | None = None,
    disputed_occurred_at: datetime | None = None,
    cleared_rungs: set[EscalationRung] | None = None,
    is_filed: bool = False,
) -> ClockCalculationResult:
    """Calculate regulatory deadline, escalation rungs, and active status.
    
    Args:
        occurred_at: When the incident trigger was asserted to have occurred.
        recorded_at: Server time when the trigger assertion was entered.
        deadline_hours: Statutory window duration in hours (e.g. 6 or 72).
        now: Current server time (defaults to recorded_at if not provided).
        alert_detected_at: Optional earliest automated alert timestamp for correlation.
        disputed_occurred_at: Optional counter-asserted trigger timestamp under dispute.
        cleared_rungs: Set of rungs that have already been fired/acknowledged.
        is_filed: Whether filing has already been completed.
    """
    validate_utc_datetime(occurred_at, "occurred_at")
    validate_utc_datetime(recorded_at, "recorded_at")

    if occurred_at > recorded_at:
        raise ValueError(
            f"Trigger occurred_at ({occurred_at.isoformat()}) cannot be in the future relative to recorded_at ({recorded_at.isoformat()})"
        )

    if deadline_hours <= 0:
        raise ValueError(f"deadline_hours must be strictly positive, got {deadline_hours}")

    if now is None:
        now = recorded_at
    else:
        validate_utc_datetime(now, "now")

    # Alert correlation verification
    requires_review = False
    review_reason: str | None = None
    if alert_detected_at is not None:
        validate_utc_datetime(alert_detected_at, "alert_detected_at")
        if occurred_at > alert_detected_at:
            requires_review = True
            review_reason = (
                f"Asserted trigger occurred_at ({occurred_at.isoformat()}) is later than "
                f"automated alert timestamp ({alert_detected_at.isoformat()})"
            )

    # Statutory deadline
    total_duration = timedelta(hours=deadline_hours)
    deadline_at = occurred_at + total_duration

    # Dispute resolution
    disputed_deadline_at: datetime | None = None
    active_deadline_at = deadline_at

    if disputed_occurred_at is not None:
        validate_utc_datetime(disputed_occurred_at, "disputed_occurred_at")
        disputed_deadline_at = disputed_occurred_at + total_duration
        # Preserve earlier deadline until resolved per regulatory rules
        active_deadline_at = min(deadline_at, disputed_deadline_at)

    # Compute valid escalation rungs (only rungs with offset < total_duration)
    rungs: list[RungSchedule] = []
    for rung, offset in RUNG_OFFSETS:
        if offset < total_duration or rung == EscalationRung.BREACH:
            scheduled_time = active_deadline_at - offset
            if scheduled_time >= occurred_at:
                rungs.append(RungSchedule(rung=rung, scheduled_at=scheduled_time, lead_time=offset))

    # Determine status
    if is_filed:
        status = ClockStatus.FILED
    elif disputed_deadline_at is not None:
        status = ClockStatus.DISPUTED
    elif now >= active_deadline_at:
        status = ClockStatus.BREACHED
    elif active_deadline_at - now <= timedelta(hours=1):
        status = ClockStatus.CRITICAL
    elif active_deadline_at - now <= timedelta(hours=2):
        status = ClockStatus.DUE_SOON
    else:
        status = ClockStatus.RUNNING

    # Determine next_due_at from uncleared rungs
    cleared = cleared_rungs or set()
    next_due_at: datetime | None = None
    for r in rungs:
        if r.rung not in cleared:
            next_due_at = r.scheduled_at
            break

    return ClockCalculationResult(
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        deadline_at=deadline_at,
        status=status,
        rungs=rungs,
        next_due_at=next_due_at,
        requires_review=requires_review,
        review_reason=review_reason,
        disputed_deadline_at=disputed_deadline_at,
        active_deadline_at=active_deadline_at,
    )


def calculate_dpdp_aware_clock(
    occurred_at: datetime,
    recorded_at: datetime,
    now: datetime | None = None,
    alert_detected_at: datetime | None = None,
    disputed_occurred_at: datetime | None = None,
    cleared_rungs: set[EscalationRung] | None = None,
    is_filed: bool = False,
) -> ClockCalculationResult:
    """Calculate DPDP 72-hour statutory countdown clock bound to the 'aware' trigger assertion.

    Statutory Basis: DPDP Rules 2025 Rule 7 (72 hours from becoming aware of personal data breach).
    """
    return calculate_clock(
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        deadline_hours=72,
        now=now,
        alert_detected_at=alert_detected_at,
        disputed_occurred_at=disputed_occurred_at,
        cleared_rungs=cleared_rungs,
        is_filed=is_filed,
    )


def calculate_provisional_triage(
    first_signal_at: datetime,
    now: datetime,
    safe_harbor_minutes: int = 30,
) -> tuple[bool, datetime, timedelta]:
    """Evaluates the 30-minute MSSP Provisional Triage Safe-Harbor window.

    Locks first_signal_at in microseconds at initial alert/webhook intake.
    Allows L1/L2 SOC analysts 30 minutes to correlate multi-tool noise before
    firing executive breach alerts.
    Returns (is_active, expires_at, remaining_time).
    """
    validate_utc_datetime(first_signal_at, "first_signal_at")
    validate_utc_datetime(now, "now")
    expires_at = first_signal_at + timedelta(minutes=safe_harbor_minutes)
    if now < expires_at:
        return True, expires_at, expires_at - now
    return False, expires_at, timedelta(seconds=0)
