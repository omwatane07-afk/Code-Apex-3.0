"""Unit and Hypothesis property tests for Regulatory Clock Engine.

Verifies:
1. Strict UTC enforcement (naive datetime rejection, non-UTC rejection).
2. Monotonicity of statutory deadlines across arbitrary time deltas.
3. Non-future assertion constraints.
4. Alert correlation logic.
5. Conservative dispute handling (preserves earlier statutory deadline).
6. 100% branch coverage of calculation states.
"""

from datetime import UTC, datetime, timedelta, tzinfo

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cyberq.clocks.engine import (
    ClockStatus,
    EscalationRung,
    calculate_clock,
    validate_utc_datetime,
)


class FixedOffset(tzinfo):
    """Non-UTC timezone for rejection tests."""
    def utcoffset(self, dt):
        return timedelta(hours=5, minutes=30)
    def dst(self, dt):
        return timedelta(0)
    def tzname(self, dt):
        return "IST"


def test_naive_datetime_rejected():
    naive_dt = datetime(2026, 10, 11, 10, 0, 0)
    with pytest.raises(ValueError, match="must be timezone-aware with UTC timezone"):
        validate_utc_datetime(naive_dt, "naive_time")


def test_non_utc_timezone_rejected():
    ist_dt = datetime(2026, 10, 11, 15, 30, 0, tzinfo=FixedOffset())
    with pytest.raises(ValueError, match="must have UTC timezone"):
        validate_utc_datetime(ist_dt, "ist_time")


def test_future_occurred_at_rejected():
    now = datetime.now(UTC)
    future = now + timedelta(minutes=5)
    with pytest.raises(ValueError, match="cannot be in the future relative to recorded_at"):
        calculate_clock(
            occurred_at=future,
            recorded_at=now,
            deadline_hours=6,
        )


def test_invalid_deadline_hours_rejected():
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="deadline_hours must be strictly positive"):
        calculate_clock(
            occurred_at=now,
            recorded_at=now,
            deadline_hours=0,
        )


def test_alert_correlation_flag():
    now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)
    alert_time = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    
    # Trigger occurred after alert detected -> suspicious, flag for review
    asserted_late = datetime(2026, 10, 11, 11, 0, 0, tzinfo=UTC)
    res = calculate_clock(
        occurred_at=asserted_late,
        recorded_at=now,
        deadline_hours=6,
        alert_detected_at=alert_time,
    )
    assert res.requires_review is True
    assert "later than automated alert timestamp" in (res.review_reason or "")

    # Trigger occurred at or before alert -> normal
    asserted_early = datetime(2026, 10, 11, 9, 30, 0, tzinfo=UTC)
    res2 = calculate_clock(
        occurred_at=asserted_early,
        recorded_at=now,
        deadline_hours=6,
        alert_detected_at=alert_time,
    )
    assert res2.requires_review is False


def test_disputed_triggers_preserve_earliest_deadline():
    now = datetime(2026, 10, 11, 14, 0, 0, tzinfo=UTC)
    occurred_1 = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    occurred_2 = datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)

    # Disputed occurred time is later (12:00 vs 10:00) -> active deadline must be earlier (from 10:00)
    res = calculate_clock(
        occurred_at=occurred_1,
        recorded_at=now,
        deadline_hours=6,
        disputed_occurred_at=occurred_2,
    )
    assert res.status == ClockStatus.DISPUTED
    assert res.deadline_at == occurred_1 + timedelta(hours=6)
    assert res.disputed_deadline_at == occurred_2 + timedelta(hours=6)
    assert res.active_deadline_at == res.deadline_at

    # If disputed occurred time is earlier (08:00 vs 10:00) -> active deadline must be earlier (from 08:00)
    occurred_earlier = datetime(2026, 10, 11, 8, 0, 0, tzinfo=UTC)
    res_earlier = calculate_clock(
        occurred_at=occurred_1,
        recorded_at=now,
        deadline_hours=6,
        disputed_occurred_at=occurred_earlier,
    )
    assert res_earlier.active_deadline_at == occurred_earlier + timedelta(hours=6)


def test_status_lifecycle_and_rungs():
    start = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    deadline = start + timedelta(hours=6)

    # T+1h -> Running
    t1 = start + timedelta(hours=1)
    res1 = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6, now=t1)
    assert res1.status == ClockStatus.RUNNING
    assert len(res1.rungs) == 6  # t-4h, t-2h, t-1h, t-30m, t-10m, breach

    # T+4h30m (1h30m left) -> Due Soon
    t_due = deadline - timedelta(minutes=90)
    res_due = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6, now=t_due)
    assert res_due.status == ClockStatus.DUE_SOON

    # T+5h30m (30m left) -> Critical
    t_crit = deadline - timedelta(minutes=30)
    res_crit = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6, now=t_crit)
    assert res_crit.status == ClockStatus.CRITICAL

    # T+6h01m -> Breached
    t_breach = deadline + timedelta(minutes=1)
    res_breach = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6, now=t_breach)
    assert res_breach.status == ClockStatus.BREACHED

    # Filed flag overrides breach/running
    res_filed = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6, now=t_breach, is_filed=True)
    assert res_filed.status == ClockStatus.FILED


def test_next_due_at_advancement():
    start = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    res = calculate_clock(occurred_at=start, recorded_at=start, deadline_hours=6)
    # First rung is t_minus_4h (at 12:00)
    assert res.next_due_at == start + timedelta(hours=2)

    # Clear t_minus_4h
    res2 = calculate_clock(
        occurred_at=start,
        recorded_at=start,
        deadline_hours=6,
        cleared_rungs={EscalationRung.T_MINUS_4H},
    )
    # Next rung is t_minus_2h (at 14:00)
    assert res2.next_due_at == start + timedelta(hours=4)


@given(
    offset_seconds=st.integers(min_value=0, max_value=86400 * 7),
    deadline_hours=st.integers(min_value=1, max_value=168),
)
def test_deadline_monotonicity_hypothesis(offset_seconds: int, deadline_hours: int):
    """Property test: statutory deadline strictly monotonically exceeds occurred_at."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    occurred = base + timedelta(seconds=offset_seconds)
    recorded = occurred + timedelta(seconds=10)

    result = calculate_clock(
        occurred_at=occurred,
        recorded_at=recorded,
        deadline_hours=deadline_hours,
    )
    assert result.deadline_at > result.occurred_at
    assert result.deadline_at == result.occurred_at + timedelta(hours=deadline_hours)

    # Rungs must be strictly monotonic
    scheduled_times = [r.scheduled_at for r in result.rungs]
    for i in range(len(scheduled_times) - 1):
        assert scheduled_times[i] < scheduled_times[i + 1]
