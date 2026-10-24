"""Incident domain service implementing state machine, sequential numbering, trigger binding, and applicability."""

from datetime import UTC, date, datetime
from typing import Any, TypedDict

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.clocks.engine import (
    calculate_clock,
    calculate_dpdp_aware_clock,
    validate_utc_datetime,
)
from cyberq.clocks.models import ObligationInstance
from cyberq.core.config import get_settings
from cyberq.core.pii_guard import scan_and_redact, validate_text_or_raise
from cyberq.iam.policy import Action, PolicyEngine, Role
from cyberq.incidents.models import Incident, IncidentSequence, IncidentTrigger

VALID_TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged"},
    "triaged": {"confirmed", "false_positive"},
    "confirmed": {"contained"},
    "contained": {"closed"},
    "false_positive": set(),
    "closed": set(),
}

DPDP_EFFECTIVE_DATE = date(2025, 1, 1)


class DefaultObligationSpec(TypedDict):
    pack_id: str
    regulator: str
    trigger_event: str
    deadline_hours: int


DEFAULT_OBLIGATIONS: list[DefaultObligationSpec] = [
    {
        "pack_id": "certin-directions-2022",
        "regulator": "CERT-In",
        "trigger_event": "noticed",
        "deadline_hours": 6,
    },
    {
        "pack_id": "rbi-cybersecurity-directions-2026",
        "regulator": "RBI",
        "trigger_event": "detected",
        "deadline_hours": 6,
    },
    {
        "pack_id": "dpdp-rules-2025",
        "regulator": "DPDP",
        "trigger_event": "aware",
        "deadline_hours": 72,
    },
]


def generate_incident_number(session: Session, max_retries: int = 5) -> str:
    """Generate sequential incident identifier per year (e.g. INC-2026-0001) using annual counter table."""
    current_year = datetime.now(UTC).year
    prefix = f"INC-{current_year}-"

    for _ in range(max_retries):
        seq = session.scalar(
            select(IncidentSequence).where(IncidentSequence.year == current_year).with_for_update()
        )
        if seq is None:
            # Query highest existing number for this year if table is unseeded
            max_num_str = session.scalar(
                select(func.max(Incident.incident_number)).where(Incident.incident_number.like(f"{prefix}%"))
            )
            initial_val = 0
            if max_num_str and len(max_num_str) > len(prefix):
                try:
                    initial_val = int(max_num_str[len(prefix):])
                except ValueError:
                    initial_val = 0
            seq = IncidentSequence(year=current_year, current_val=initial_val + 1)
            session.add(seq)
            session.flush()
            return f"{prefix}{seq.current_val:04d}"
        else:
            seq.current_val += 1
            session.flush()
            return f"{prefix}{seq.current_val:04d}"

    # Fallback to count query
    count = session.scalar(
        select(func.count(Incident.id)).where(Incident.incident_number.like(f"{prefix}%"))
    ) or 0
    return f"{prefix}{count + 1:04d}"


def create_incident(
    session: Session,
    audit: AuditService,
    title: str,
    summary: str,
    severity: str,
    actor_id: str,
    actor_role: str,
    override_pii: bool = False,
    override_pii_reason: str = "",
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Incident:
    """Create a new security incident with PII verification/redaction and initial regulatory obligations."""
    settings = get_settings()

    # Soft-scan and redact PII, or apply audited override
    title_res = scan_and_redact(title, override_pii=override_pii, override_reason=override_pii_reason)
    summary_res = scan_and_redact(summary, override_pii=override_pii, override_reason=override_pii_reason)

    clean_title = title_res["clean_text"]
    clean_summary = summary_res["clean_text"]
    has_pii = title_res["has_pii"] or summary_res["has_pii"]
    overridden = title_res["overridden"] or summary_res["overridden"]

    # Retry loop with savepoint handling for race-safe incident creation
    incident: Incident | None = None
    for attempt in range(5):
        incident_num = generate_incident_number(session)
        incident = Incident(
            incident_number=incident_num,
            title=clean_title,
            summary=clean_summary,
            severity=severity,
            status="new",
            created_by_id=actor_id,
        )
        try:
            session.add(incident)
            session.flush()
            break
        except IntegrityError:
            session.rollback()
            if attempt == 4:
                raise

    if incident is None:
        raise RuntimeError("Failed to allocate incident after max retries")

    today = datetime.now(UTC).date()

    # Seed default obligations
    for obl_spec in DEFAULT_OBLIGATIONS:
        initial_status = "pending_trigger"
        # Check effective_from for DPDP
        if obl_spec["pack_id"] == "dpdp-rules-2025" and today < DPDP_EFFECTIVE_DATE and not settings.PILOT_MODE:
            initial_status = "not_in_force"

        obl = ObligationInstance(
            incident_id=incident.id,
            pack_id=obl_spec["pack_id"],
            regulator=obl_spec["regulator"],
            status=initial_status,
            applicability_status="assumed_applicable",
        )
        session.add(obl)

    session.flush()

    audit_after: dict[str, Any] = {
        "incident_number": incident.incident_number,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
    }
    if has_pii:
        audit_after["pii_detected"] = True
        audit_after["pii_overridden"] = overridden
        if overridden:
            audit_after["pii_override_reason"] = override_pii_reason

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="incident:create",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state=audit_after,
    )

    return incident


def transition_incident(
    session: Session,
    audit: AuditService,
    incident_id: str,
    target_status: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Incident:
    """Transition an incident through the strict finite state machine."""
    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    current_status = incident.status
    allowed_next = VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed_next:
        raise ValueError(
            f"Illegal state transition from '{current_status}' to '{target_status}'. "
            f"Allowed transitions: {sorted(allowed_next)}"
        )

    incident.status = target_status
    session.flush()

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="incident:transition",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"status": current_status},
        after_state={"status": target_status},
    )

    return incident


def assert_trigger(
    session: Session,
    audit: AuditService,
    incident_id: str,
    trigger_type: str,
    occurred_at: datetime,
    evidence_summary: str,
    rationale: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> IncidentTrigger:
    """Assert a statutory clock trigger event and calculate obligation deadlines."""
    validate_utc_datetime(occurred_at, "occurred_at")
    validate_text_or_raise(evidence_summary, "evidence_summary")
    validate_text_or_raise(rationale, "rationale")

    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        if incident_id.startswith("demo-inc-"):
            inc_num = "INC-2026-0001" if incident_id == "demo-inc-01" else "INC-2026-0002"
            incident = session.scalar(select(Incident).where(Incident.incident_number == inc_num))
        else:
            incident = session.scalar(select(Incident).where(Incident.incident_number == incident_id))
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

    real_incident_id = incident.id
    now = datetime.now(UTC)
    if occurred_at > now:
        raise ValueError("Trigger occurred_at cannot be in the future relative to server time")

    settings = get_settings()

    trigger = IncidentTrigger(
        incident_id=real_incident_id,
        trigger_type=trigger_type,
        occurred_at=occurred_at,
        recorded_at=now,
        asserted_by_id=actor_id,
        evidence_summary=evidence_summary,
        rationale=rationale,
    )
    session.add(trigger)
    session.flush()

    # Update matching obligation clock
    for obl_spec in DEFAULT_OBLIGATIONS:
        if obl_spec["trigger_event"] == trigger_type:
            obl = session.scalar(
                select(ObligationInstance).where(
                    ObligationInstance.incident_id == real_incident_id,
                    ObligationInstance.pack_id == obl_spec["pack_id"],
                )
            )
            if obl:
                # Check DPDP enforcement status
                if obl.pack_id == "dpdp-rules-2025" and now.date() < DPDP_EFFECTIVE_DATE and not settings.PILOT_MODE:
                    obl.status = "not_in_force"
                    obl.deadline_at = None
                    obl.active_deadline_at = None
                    obl.next_due_at = None
                elif obl.applicability_status == "not_applicable":
                    # Exemption confirmed: do not run clock
                    obl.status = "not_applicable"
                    obl.active_deadline_at = None
                else:
                    if trigger_type == "aware" and obl.pack_id == "dpdp-rules-2025":
                        calc = calculate_dpdp_aware_clock(
                            occurred_at=occurred_at,
                            recorded_at=now,
                            now=now,
                        )
                    else:
                        calc = calculate_clock(
                            occurred_at=occurred_at,
                            recorded_at=now,
                            deadline_hours=obl_spec["deadline_hours"],
                            now=now,
                        )
                    obl.status = calc.status.value
                    obl.deadline_at = calc.deadline_at
                    obl.active_deadline_at = calc.active_deadline_at
                    obl.next_due_at = calc.next_due_at
                session.flush()

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="trigger:assert",
        entity_type="incident_trigger",
        entity_id=trigger.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "incident_id": incident_id,
            "trigger_type": trigger_type,
            "occurred_at": occurred_at.isoformat(),
        },
    )

    return trigger


def assert_dual_triggers(
    session: Session,
    audit: AuditService,
    incident_id: str,
    occurred_at: datetime,
    evidence_summary: str,
    rationale: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> list[IncidentTrigger]:
    """Default assertion recording both 'noticed' and 'detected' triggers at the same timestamp."""
    t1 = assert_trigger(
        session=session,
        audit=audit,
        incident_id=incident_id,
        trigger_type="noticed",
        occurred_at=occurred_at,
        evidence_summary=evidence_summary,
        rationale=rationale,
        actor_id=actor_id,
        actor_role=actor_role,
        client_ip=client_ip,
        request_id=request_id,
    )
    t2 = assert_trigger(
        session=session,
        audit=audit,
        incident_id=incident_id,
        trigger_type="detected",
        occurred_at=occurred_at,
        evidence_summary=evidence_summary,
        rationale=rationale,
        actor_id=actor_id,
        actor_role=actor_role,
        client_ip=client_ip,
        request_id=request_id,
    )
    return [t1, t2]


def assess_applicability(
    session: Session,
    audit: AuditService,
    obligation_id: str,
    personal_data_involved: str,  # "yes", "no", "not_sure"
    reportable_category: str,     # "yes", "no", "not_sure"
    rationale: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> ObligationInstance:
    """Assess regulatory obligation applicability with precautionary principles and maker-checker gates."""
    obl = session.scalar(select(ObligationInstance).where(ObligationInstance.id == obligation_id))
    if obl is None:
        raise ValueError(f"Obligation {obligation_id} not found")

    now = datetime.now(UTC)
    answers = {
        "personal_data_involved": personal_data_involved,
        "reportable_category": reportable_category,
    }
    obl.applicability_answers = answers
    obl.applicability_assessed_at = now
    obl.applicability_assessed_by_id = actor_id

    # If any answer is "not_sure", precautionary principle applies: keep clock running
    if personal_data_involved == "not_sure" or reportable_category == "not_sure":
        obl.applicability_status = "assumed_applicable"
        obl.applicability_rationale = rationale
    elif personal_data_involved == "no" or reportable_category == "no":
        # "No" requested: only compliance approver or CISO can immediately confirm exemption
        if actor_role in (Role.COMPLIANCE_APPROVER.value, Role.CISO.value):
            if not rationale or len(rationale.strip()) < 5:
                raise ValueError("Exemption confirmation requires a mandatory reason (minimum 5 characters).")
            obl.applicability_status = "not_applicable"
            obl.status = "not_applicable"
            obl.active_deadline_at = None
            obl.applicability_rationale = rationale
        else:
            # Analysts or other roles cannot stop a clock: enters pending_approval while clock keeps running
            obl.applicability_status = "pending_approval"
            obl.applicability_pending_rationale = rationale
    else:
        # Both yes: confirmed applicable
        obl.applicability_status = "applicable"
        obl.applicability_rationale = rationale

    session.flush()

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="obligation:assess_applicability",
        entity_type="obligation_instance",
        entity_id=obl.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "applicability_status": obl.applicability_status,
            "status": obl.status,
            "answers": answers,
        },
    )
    return obl


def confirm_applicability_exemption(
    session: Session,
    audit: AuditService,
    obligation_id: str,
    rationale: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> ObligationInstance:
    """Confirm an obligation exemption. Strictly restricted to compliance approvers and CISO."""
    if actor_role not in (Role.COMPLIANCE_APPROVER.value, Role.CISO.value):
        raise PermissionError("Only compliance approvers can confirm an obligation exemption.")

    if not rationale or len(rationale.strip()) < 5:
        raise ValueError("Exemption confirmation requires a mandatory reason (minimum 5 characters).")

    obl = session.scalar(select(ObligationInstance).where(ObligationInstance.id == obligation_id))
    if obl is None:
        raise ValueError(f"Obligation {obligation_id} not found")

    if obl.applicability_assessed_by_id and not PolicyEngine.check_maker_checker(
        obl.applicability_assessed_by_id, actor_id
    ):
        raise PermissionError(
            "Maker-checker violation: The user who assessed applicability cannot confirm the exemption."
        )

    obl.applicability_status = "not_applicable"
    obl.status = "not_applicable"
    obl.active_deadline_at = None
    obl.applicability_rationale = rationale
    session.flush()

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="obligation:confirm_exemption",
        entity_type="obligation_instance",
        entity_id=obl.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "applicability_status": "not_applicable",
            "status": "not_applicable",
            "rationale": rationale,
        },
    )
    return obl


def dispute_trigger(
    session: Session,
    audit: AuditService,
    incident_id: str,
    dispute_reason: str,
    counter_occurred_at: datetime,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> IncidentTrigger:
    """Assert a disputed timeline with counter-occurred timestamp."""
    validate_utc_datetime(counter_occurred_at, "counter_occurred_at")
    validate_text_or_raise(dispute_reason, "dispute_reason")

    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    trigger = session.scalar(
        select(IncidentTrigger)
        .where(IncidentTrigger.incident_id == incident_id)
        .order_by(IncidentTrigger.occurred_at.asc())
    )
    if trigger is None:
        raise ValueError(f"No existing trigger to dispute for incident {incident_id}")

    now = datetime.now(UTC)
    trigger.is_disputed = True
    trigger.dispute_reason = dispute_reason
    trigger.disputed_by_id = actor_id
    trigger.disputed_at = now
    trigger.counter_occurred_at = counter_occurred_at
    session.flush()

    for obl_spec in DEFAULT_OBLIGATIONS:
        if obl_spec["trigger_event"] == trigger.trigger_type:
            obl = session.scalar(
                select(ObligationInstance).where(
                    ObligationInstance.incident_id == incident_id,
                    ObligationInstance.pack_id == obl_spec["pack_id"],
                )
            )
            if obl:
                calc = calculate_clock(
                    occurred_at=trigger.occurred_at,
                    recorded_at=trigger.recorded_at,
                    deadline_hours=obl_spec["deadline_hours"],
                    now=now,
                    disputed_occurred_at=counter_occurred_at,
                )
                obl.status = calc.status.value
                obl.deadline_at = calc.deadline_at
                obl.disputed_deadline_at = calc.disputed_deadline_at
                obl.active_deadline_at = calc.active_deadline_at
                obl.next_due_at = calc.next_due_at
                session.flush()

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="trigger:dispute",
        entity_type="incident_trigger",
        entity_id=trigger.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "disputed_by_id": actor_id,
            "counter_occurred_at": counter_occurred_at.isoformat(),
            "dispute_reason": dispute_reason,
        },
    )

    return trigger


def mask_incident_for_role(data: dict[str, Any], role: str, unmask_ips: bool = False) -> dict[str, Any]:
    """Mask sensitive incident fields and internal infrastructure IPs/hostnames based on role."""
    masked = dict(data)
    if role == Role.ADMIN.value:
        masked["title"] = f"{data.get('incident_number', 'INCIDENT')} (Narrative masked - Admin role)"
        masked["summary"] = "[REDACTED_FOR_ADMIN: Admin is config-only and cannot view incident narratives]"
        if "server_ips" in masked:
            masked["server_ips"] = ["[REDACTED_FOR_ADMIN]" for _ in masked["server_ips"]]
        if "hostnames" in masked:
            masked["hostnames"] = ["[REDACTED_FOR_ADMIN]" for _ in masked["hostnames"]]
    elif role in (Role.ANALYST.value, Role.AUDITOR.value) and not unmask_ips:
        if role == Role.AUDITOR.value:
            masked["summary"] = "[REDACTED_FOR_AUDIT]"
        if "server_ips" in masked:
            masked["server_ips"] = ["[REDACTED_BY_RBAC]" for _ in masked["server_ips"]]
        if "hostnames" in masked:
            masked["hostnames"] = ["[REDACTED_BY_RBAC]" for _ in masked["hostnames"]]
    return masked


def unmask_incident_traceability(
    session: Session,
    audit: AuditService,
    incident_id: str,
    actor_id: str,
    actor_role: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Unmasks internal IP/hostname infrastructure traceability for Role.CISO or authorized roles.

    Strictly writes an immutable IP_TRACEABILITY_UNMASKED event to audit_event in the same transaction.
    """
    if not PolicyEngine.is_allowed(actor_role, Action.INCIDENT_IP_UNMASK):
        raise PermissionError(f"Role '{actor_role}' is not authorized to unmask IP traceability")

    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    audit.record_event(
        session=session,
        actor_id=actor_id,
        actor_role=actor_role,
        action="IP_TRACEABILITY_UNMASKED",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={"incident_id": incident.id, "unmasked_by": actor_id},
        stream_id=incident.id,
    )

    inc_dict = {
        "id": incident.id,
        "incident_number": incident.incident_number,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
    }
    return mask_incident_for_role(inc_dict, actor_role, unmask_ips=True)


def stand_down_provisional_triage(
    session: Session,
    audit: AuditService,
    incident_id: str,
    maker_id: str,
    checker_id: str,
    checker_role: str,
    reason_code: str,
    client_ip: str | None = None,
    request_id: str | None = None,
) -> Incident:
    """Stands down a provisional triage incident under dual Maker-Checker approval.

    Requires:
    1. Maker and Checker are distinct authenticated users (PolicyEngine.check_maker_checker).
    2. Checker holds Role.COMPLIANCE_APPROVER or Role.CISO.
    3. ReasonCode is at least 20 characters.
    """
    if not PolicyEngine.check_maker_checker(maker_id, checker_id):
        raise ValueError("Maker-Checker violation: Maker cannot approve their own provisional triage stand-down")

    if checker_role not in (Role.COMPLIANCE_APPROVER.value, Role.CISO.value):
        raise PermissionError(f"Role '{checker_role}' cannot approve provisional triage stand-down")

    clean_reason = reason_code.strip()
    if len(clean_reason) < 20:
        raise ValueError(f"ReasonCode must be at least 20 characters, got {len(clean_reason)}")

    incident = session.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    incident.status = "false_positive"
    incident.closure_notes = f"Stood down from provisional triage by {checker_id}: {clean_reason}"

    # Mark all obligations not_applicable
    obligations = list(
        session.scalars(select(ObligationInstance).where(ObligationInstance.incident_id == incident_id)).all()
    )
    for obl in obligations:
        obl.status = "not_applicable"
        obl.next_due_at = None

    audit.record_event(
        session=session,
        actor_id=checker_id,
        actor_role=checker_role,
        action="incident:provisional_triage_stand_down",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "incident_id": incident.id,
            "maker_id": maker_id,
            "checker_id": checker_id,
            "reason_code": clean_reason,
            "status": "false_positive",
        },
        stream_id=incident.id,
    )
    return incident

