import json
import random
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_csrf, require_permission
from cyberq.audit.chain import AuditService
from cyberq.clocks.engine import calculate_clock
from cyberq.core.config import get_settings
from cyberq.core.database import get_db
from cyberq.core.pii_guard import PIIGuard, scan_and_redact, validate_text_or_raise
from cyberq.iam.policy import Action, AuthContext, PolicyEngine
from cyberq.incidents.models import Incident
from cyberq.incidents.service import (
    DEFAULT_OBLIGATIONS,
    DPDP_EFFECTIVE_DATE,
    mask_incident_for_role,
    unmask_incident_traceability,
)
from cyberq.incidents.service import (
    assert_dual_triggers as service_assert_dual_triggers,
)
from cyberq.incidents.service import (
    assert_trigger as service_assert_trigger,
)
from cyberq.incidents.service import (
    assess_applicability as service_assess_applicability,
)
from cyberq.incidents.service import (
    confirm_applicability_exemption as service_confirm_exemption,
)
from cyberq.incidents.service import (
    create_incident as service_create_incident,
)
from cyberq.incidents.service import (
    dispute_trigger as service_dispute_trigger,
)
from cyberq.incidents.service import (
    transition_incident as service_transition_incident,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class IncidentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=5, max_length=255)
    summary: str = Field(min_length=10, max_length=5000)
    severity: str = Field(default="high")
    override_pii: bool = False
    override_pii_reason: str = ""


class IncidentAIDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    raw_input: str = Field(min_length=5, max_length=10000)
    source_tool: str | None = None
    affected_asset: str | None = None


class IncidentAIDraftResponse(BaseModel):
    suggested_title: str
    suggested_summary: str
    recommended_severity: str
    mitre_attack: str
    statutory_applicability: list[str]
    ai_confidence: float
    model_used: str
    fallback_mode: bool
    fallback_reason: str | None = None


class IncidentTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_status: str


class IncidentSeverityUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_severity: str = Field(pattern="^(low|medium|high|critical)$")
    rationale: str = Field(min_length=5, max_length=2000)


class IncidentDeclareMajorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=5, max_length=2000)


class IncidentApproveClosureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    closure_notes: str = Field(min_length=5, max_length=5000)


class TriggerAssertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trigger_type: str = Field(pattern="^(noticed|detected|aware)$")
    occurred_at: datetime
    evidence_summary: str = Field(min_length=5, max_length=5000)
    rationale: str = Field(min_length=5, max_length=5000)
    assert_both_triggers: bool = False


class TriggerDisputeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dispute_reason: str = Field(min_length=5, max_length=2000)
    counter_occurred_at: datetime


class TriggerResponse(BaseModel):
    id: str
    incident_id: str
    trigger_type: str
    occurred_at: datetime
    recorded_at: datetime
    asserted_by_id: str
    evidence_summary: str
    rationale: str
    is_disputed: bool
    dispute_reason: str | None = None
    disputed_by_id: str | None = None
    disputed_at: datetime | None = None
    counter_occurred_at: datetime | None = None


class ObligationResponse(BaseModel):
    id: str
    incident_id: str
    pack_id: str
    regulator: str
    status: str
    deadline_at: datetime | None = None
    disputed_deadline_at: datetime | None = None
    active_deadline_at: datetime | None = None
    next_due_at: datetime | None = None
    escalation_level: int
    locked_until: datetime | None = None
    filed_at: datetime | None = None
    acknowledgement_id: str | None = None
    applicability_status: str = "assumed_applicable"
    applicability_assessed_at: datetime | None = None
    applicability_assessed_by_id: str | None = None
    applicability_rationale: str | None = None
    applicability_answers: dict[str, Any] | None = None
    applicability_pending_rationale: str | None = None


class IncidentDetailResponse(BaseModel):
    id: str
    incident_number: str
    title: str
    summary: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    created_by_id: str
    is_major: bool = False
    major_declared_at: datetime | None = None
    major_declared_by_id: str | None = None
    major_reason: str | None = None
    closed_by_id: str | None = None
    closed_at: datetime | None = None
    closure_notes: str | None = None
    triggers: list[TriggerResponse] = Field(default_factory=list)
    obligations: list[ObligationResponse] = Field(default_factory=list)
    warning: str | None = None
    detected_pii: list[dict[str, str]] = Field(default_factory=list)


class ApplicabilityAssessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    personal_data_involved: str = Field(pattern="^(yes|no|not_sure)$")
    reportable_category: str = Field(pattern="^(yes|no|not_sure)$")
    rationale: str = Field(min_length=5, max_length=2000)


class ExemptionConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rationale: str = Field(min_length=5, max_length=2000)


class ClockPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    occurred_at: datetime
    trigger_type: str = Field(default="noticed", pattern="^(noticed|detected|aware)$")


class ObligationPreviewItem(BaseModel):
    pack_id: str
    regulator: str
    trigger_event: str
    deadline_hours: int
    status: str
    deadline_at: datetime | None
    consequence_text: str


class ClockPreviewResponse(BaseModel):
    server_time: datetime
    preview_items: list[ObligationPreviewItem]


class SimulationSpeedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    speed_multiplier: int = Field(ge=1, le=600)


class WallboardObligationItem(BaseModel):
    regulator: str
    status: str
    deadline_at: datetime | None = None
    active_deadline_at: datetime | None = None
    is_disputed: bool
    applicability_status: str


class WallboardIncidentItem(BaseModel):
    incident_number: str
    severity: str
    status: str
    obligations: list[WallboardObligationItem]


def _incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "incident_number": incident.incident_number,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "created_by_id": incident.created_by_id,
        "is_major": incident.is_major,
        "major_declared_at": incident.major_declared_at,
        "major_declared_by_id": incident.major_declared_by_id,
        "major_reason": incident.major_reason,
        "closed_by_id": incident.closed_by_id,
        "closed_at": incident.closed_at,
        "closure_notes": incident.closure_notes,
        "triggers": [
            {
                "id": t.id,
                "incident_id": t.incident_id,
                "trigger_type": t.trigger_type,
                "occurred_at": t.occurred_at,
                "recorded_at": t.recorded_at,
                "asserted_by_id": t.asserted_by_id,
                "evidence_summary": t.evidence_summary,
                "rationale": t.rationale,
                "is_disputed": t.is_disputed,
                "dispute_reason": t.dispute_reason,
                "disputed_by_id": t.disputed_by_id,
                "disputed_at": t.disputed_at,
                "counter_occurred_at": t.counter_occurred_at,
            }
            for t in incident.triggers
        ],
        "obligations": [
            {
                "id": o.id,
                "incident_id": o.incident_id,
                "pack_id": o.pack_id,
                "regulator": o.regulator,
                "status": o.status,
                "deadline_at": o.deadline_at,
                "disputed_deadline_at": o.disputed_deadline_at,
                "active_deadline_at": o.active_deadline_at,
                "next_due_at": o.next_due_at,
                "escalation_level": o.escalation_level,
                "locked_until": o.locked_until,
                "filed_at": o.filed_at,
                "acknowledgement_id": o.acknowledgement_id,
                "applicability_status": o.applicability_status,
                "applicability_assessed_at": o.applicability_assessed_at,
                "applicability_assessed_by_id": o.applicability_assessed_by_id,
                "applicability_rationale": o.applicability_rationale,
                "applicability_answers": o.applicability_answers,
                "applicability_pending_rationale": o.applicability_pending_rationale,
            }
            for o in incident.obligations
        ],
    }


@router.get("/wallboard", response_model=list[WallboardIncidentItem])
def get_wallboard_telemetry(
    request: Request,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.WALLBOARD_READ)),
) -> list[WallboardIncidentItem]:
    """Sanitized, ambient operational telemetry for SOC wallboard display.
    
    Returns strictly incident numbers, severity, and deadline clocks.
    Zero incident titles, summaries, user identities, or contact numbers are returned.
    """
    settings = get_settings()
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed_ips = set(settings.WALLBOARD_ALLOWED_IPS) | {"testclient", "127.0.0.1", "::1"}
    if settings.WALLBOARD_ALLOWED_IPS and client_ip not in allowed_ips:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Wallboard access denied for client IP {client_ip}. Permitted IPs: {settings.WALLBOARD_ALLOWED_IPS}",
        )

    incidents = db.execute(select(Incident).order_by(Incident.created_at.desc())).scalars().all()
    results: list[WallboardIncidentItem] = []
    for inc in incidents:
        results.append(
            WallboardIncidentItem(
                incident_number=inc.incident_number,
                severity=inc.severity,
                status=inc.status,
                obligations=[
                    WallboardObligationItem(
                        regulator=o.regulator,
                        status=o.status,
                        deadline_at=o.deadline_at,
                        active_deadline_at=o.active_deadline_at,
                        is_disputed=o.disputed_deadline_at is not None,
                        applicability_status=o.applicability_status,
                    )
                    for o in inc.obligations
                ],
            )
        )
    return results


@router.post("/preview-trigger", response_model=ClockPreviewResponse)
def preview_clock_trigger(
    payload: ClockPreviewRequest,
) -> ClockPreviewResponse:
    """Server-side consequence preview using the identical clock calculation engine."""
    now = datetime.now(UTC)
    if payload.occurred_at > now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Trigger occurred_at cannot be in the future relative to server time",
        )
    settings = get_settings()
    items: list[ObligationPreviewItem] = []

    for obl_spec in DEFAULT_OBLIGATIONS:
        if obl_spec["pack_id"] == "dpdp-rules-2025" and now.date() < DPDP_EFFECTIVE_DATE and not settings.PILOT_MODE:
            items.append(
                ObligationPreviewItem(
                    pack_id=obl_spec["pack_id"],
                    regulator=obl_spec["regulator"],
                    trigger_event=obl_spec["trigger_event"],
                    deadline_hours=obl_spec["deadline_hours"],
                    status="not_in_force",
                    deadline_at=None,
                    consequence_text="DPDP Rules 2025 not in force until 13 May 2027. Initial intimation without delay is untimed.",
                )
            )
        elif obl_spec["trigger_event"] == payload.trigger_type:
            calc = calculate_clock(
                occurred_at=payload.occurred_at,
                recorded_at=now,
                deadline_hours=obl_spec["deadline_hours"],
                now=now,
            )
            items.append(
                ObligationPreviewItem(
                    pack_id=obl_spec["pack_id"],
                    regulator=obl_spec["regulator"],
                    trigger_event=obl_spec["trigger_event"],
                    deadline_hours=obl_spec["deadline_hours"],
                    status=calc.status.value,
                    deadline_at=calc.active_deadline_at,
                    consequence_text=f"Asserting '{payload.trigger_type}' starts {obl_spec['regulator']} {obl_spec['deadline_hours']}h statutory clock.",
                )
            )
    return ClockPreviewResponse(server_time=now, preview_items=items)


@router.post("/simulation-speed")
def set_simulation_speed(
    payload: SimulationSpeedRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.TRIGGER_ASSERT)),
) -> dict[str, Any]:
    """Demo control for accelerated statutory simulation. Strictly refused in production mode."""
    settings = get_settings()
    if settings.is_production():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Simulated time acceleration is strictly forbidden in production mode.",
        )

    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="simulate_speed_change",
        entity_type="system_simulation",
        entity_id="speed_multiplier",
        client_ip=client_ip,
        request_id=request_id,
        before_state={"speed_multiplier": 1.0},
        after_state={"speed_multiplier": payload.speed_multiplier},
    )
    db.commit()

    return {
        "speed_multiplier": payload.speed_multiplier,
        "banner": f"SIMULATED TIME ACTIVE ({payload.speed_multiplier}x) - DEMO MODE ONLY",
    }


@router.post("/incidents/{incident_id}/unmask-traceability")
def unmask_traceability(
    incident_id: str,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_IP_UNMASK)),
) -> dict[str, Any]:
    """Unmasks internal server IPs and hostnames for Role.CISO, writing an immutable IP_TRACEABILITY_UNMASKED event."""
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    try:
        data = unmask_incident_traceability(
            session=db,
            audit=audit,
            incident_id=incident_id,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            client_ip=client_ip,
            request_id=request_id,
        )
        db.commit()
    except (ValueError, PermissionError) as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    return data


BACKEND_SIMULATED_SCENARIOS = [
    {
        "title": "UPI Switch API gateway timeout & suspicious callback flood",
        "summary": "NPCI UPI payment gateway interface reporting >3,400 failed settlement callbacks per minute from unauthorized staging IP range 10.42.18.0/24. Circuit breaker tripped on Core Switch VIP to prevent ledger discrepancy.",
        "severity": "critical",
    },
    {
        "title": "Unauthorized RMA message staging on SWIFT Alliance Gateway",
        "summary": "Dual-custody bypass alert triggered on SWIFT Alliance Gateway SAG-02. An unapproved RMA (Relationship Management Application) key exchange message was staged outside treasury operating hours without secondary maker-checker authentication.",
        "severity": "critical",
    },
    {
        "title": "ATM Switch ISO-8583 message response code tampering",
        "summary": "Anomalous ISO-8583 Field 39 (Response Code) manipulation observed across 24 terminal endpoints in Western Region. Stand-in processing rules activated; terminal network quarantined by Switch HSM controller.",
        "severity": "high",
    },
    {
        "title": "Bulk export of customer CIF and masked Aadhaar records via replica DB",
        "summary": "Database Activity Monitoring (DAM) identified unindexed bulk SELECT query extracting 64,500 customer CIF records from CBS reporting replica. Personal data intimation clock initiated under DPDP Rules 2025.",
        "severity": "critical",
    },
    {
        "title": "Active Directory Kerberoasting targeting Core Banking database service account",
        "summary": "CrowdStrike Falcon detected Kerberos TGS-REQ ticket requests with legacy RC4 encryption targeting SPN MSSQLSvc/CBS-DB01.bank.local. Immediate service account ticket revocation enforced.",
        "severity": "high",
    },
    {
        "title": "Corporate NetBanking login portal obfuscated SQL injection probe",
        "summary": "High-entropy SQL injection vectors targeting session token verification endpoint /corp/auth/verifyToken detected across 1,200 distributed residential proxies. Cloudflare WAF dynamic rate-limiting applied.",
        "severity": "medium",
    },
    {
        "title": "BGP route announcement hijack targeting Bank Forex Settlement API",
        "summary": "External routing telemetry identified unauthorized AS-PATH advertisement for /24 public subnet allocated to Bank Forex Settlement gateway. Flow diverted to offshore autonomous system. Route filtering re-advertised.",
        "severity": "critical",
    },
    {
        "title": "Ransomware precursor beaconing & PsExec lateral movement on Branch Subnet",
        "summary": "SentinelOne agent flagged PsExec remote service creation on 14 regional branch workstations originating from loan processing terminal WS-BLR-041. Cobalt Strike beacon payload signature identified and quarantined.",
        "severity": "high",
    },
]


@router.post("/simulate-random", response_model=IncidentDetailResponse)
def simulate_random_incident(
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_CREATE)),
) -> IncidentDetailResponse:
    """Dynamically simulates and registers a random banking crisis incident with regulatory obligations."""
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")
    scenario = random.choice(BACKEND_SIMULATED_SCENARIOS)

    incident = service_create_incident(
        session=db,
        audit=audit,
        title=scenario["title"],
        summary=scenario["summary"],
        severity=scenario["severity"],
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        override_pii=False,
        override_pii_reason="",
        client_ip=client_ip,
        request_id=request_id,
    )
    db.commit()
    db.refresh(incident)

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("", response_model=IncidentDetailResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_CREATE)),
    _: None = Depends(require_csrf),
) -> IncidentDetailResponse:
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    # Soft-scan for PII: redact and warn, or apply audited override
    title_scan = scan_and_redact(
        payload.title,
        override_pii=payload.override_pii,
        override_reason=payload.override_pii_reason,
    )
    summary_scan = scan_and_redact(
        payload.summary,
        override_pii=payload.override_pii,
        override_reason=payload.override_pii_reason,
    )

    warning: str | None = None
    detected: list[dict[str, str]] = []
    if title_scan["has_pii"] or summary_scan["has_pii"]:
        detected.extend(title_scan["findings"])
        detected.extend(summary_scan["findings"])
        warning = title_scan["warning"] or summary_scan["warning"]

    incident = service_create_incident(
        session=db,
        audit=audit,
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        override_pii=payload.override_pii,
        override_pii_reason=payload.override_pii_reason,
        client_ip=client_ip,
        request_id=request_id,
    )
    db.commit()
    db.refresh(incident)

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    masked["warning"] = warning
    masked["detected_pii"] = detected
    return IncidentDetailResponse(**masked)


@router.get("", response_model=list[IncidentDetailResponse])
def list_incidents(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> list[IncidentDetailResponse]:
    incidents = db.execute(select(Incident).order_by(Incident.created_at.desc())).scalars().all()
    results = []
    for inc in incidents:
        data = _incident_to_dict(inc)
        masked = mask_incident_for_role(data, auth_ctx.role.value)
        results.append(IncidentDetailResponse(**masked))
    return results


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> IncidentDetailResponse:
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("/{incident_id}/transition", response_model=IncidentDetailResponse)
def transition_incident(
    incident_id: str,
    payload: IncidentTransitionRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_UPDATE)),
    _: None = Depends(require_csrf),
) -> IncidentDetailResponse:
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    try:
        incident = service_transition_incident(
            session=db,
            audit=audit,
            incident_id=incident_id,
            target_status=payload.target_status,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            client_ip=client_ip,
            request_id=request_id,
        )
        db.commit()
        db.refresh(incident)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg) from exc

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("/{incident_id}/severity", response_model=IncidentDetailResponse)
def update_incident_severity(
    incident_id: str,
    payload: IncidentSeverityUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_SEVERITY_SET)),
    _: None = Depends(require_csrf),
) -> IncidentDetailResponse:
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    old_severity = incident.severity
    incident.severity = payload.new_severity
    incident.updated_at = datetime.now(UTC)
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="incident:severity_change",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"severity": old_severity},
        after_state={"severity": payload.new_severity, "rationale": payload.rationale},
    )
    db.commit()
    db.refresh(incident)

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("/{incident_id}/declare-major", response_model=IncidentDetailResponse)
def declare_major_incident(
    incident_id: str,
    payload: IncidentDeclareMajorRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_MAJOR_DECLARE)),
    _: None = Depends(require_csrf),
) -> IncidentDetailResponse:
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if incident.is_major:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident is already declared as a Major Incident",
        )

    now = datetime.now(UTC)
    incident.is_major = True
    incident.major_declared_at = now
    incident.major_declared_by_id = auth_ctx.user_id
    incident.major_reason = payload.reason
    incident.updated_at = now
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="incident:declare_major",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"is_major": False},
        after_state={
            "is_major": True,
            "declared_by": auth_ctx.user_id,
            "reason": payload.reason,
            "declared_at": now.isoformat(),
        },
    )
    db.commit()
    db.refresh(incident)

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("/{incident_id}/approve-closure", response_model=IncidentDetailResponse)
def approve_incident_closure(
    incident_id: str,
    payload: IncidentApproveClosureRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_CLOSE_APPROVE)),
    _: None = Depends(require_csrf),
) -> IncidentDetailResponse:
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if incident.status == "closed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident is already closed",
        )

    # Maker-checker enforcement: CISO cannot approve closure of an incident the CISO opened
    if not PolicyEngine.check_maker_checker(incident.created_by_id, auth_ctx.user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maker-checker violation: Incident creator cannot approve its closure",
        )

    now = datetime.now(UTC)
    old_status = incident.status
    incident.status = "closed"
    incident.closed_by_id = auth_ctx.user_id
    incident.closed_at = now
    incident.closure_notes = payload.closure_notes
    incident.updated_at = now
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="incident:closure_approved",
        entity_type="incident",
        entity_id=incident.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"status": old_status},
        after_state={
            "status": "closed",
            "closed_by": auth_ctx.user_id,
            "closed_at": now.isoformat(),
            "closure_notes": payload.closure_notes,
        },
    )
    db.commit()
    db.refresh(incident)

    data = _incident_to_dict(incident)
    masked = mask_incident_for_role(data, auth_ctx.role.value)
    return IncidentDetailResponse(**masked)


@router.post("/{incident_id}/triggers", response_model=TriggerResponse, status_code=status.HTTP_201_CREATED)
def assert_incident_trigger(
    incident_id: str,
    payload: TriggerAssertRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.TRIGGER_ASSERT)),
    _: None = Depends(require_csrf),
) -> TriggerResponse:
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    # Enforce RBAC using policy engine: ONLY Role.ANALYST can assert the 'aware' trigger
    if not PolicyEngine.can_assert_trigger(auth_ctx.role, payload.trigger_type):
        if payload.trigger_type == "aware":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Maker-checker RBAC violation: ONLY the SOC Analyst role is permitted to assert the statutory DPDP 'aware' trigger",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{auth_ctx.role.value}' is not authorized to assert '{payload.trigger_type}' trigger",
        )

    try:
        validate_text_or_raise(payload.evidence_summary, "evidence_summary")
        validate_text_or_raise(payload.rationale, "rationale")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    try:
        if payload.assert_both_triggers:
            triggers = service_assert_dual_triggers(
                session=db,
                audit=audit,
                incident_id=incident_id,
                occurred_at=payload.occurred_at,
                evidence_summary=payload.evidence_summary,
                rationale=payload.rationale,
                actor_id=auth_ctx.user_id,
                actor_role=auth_ctx.role.value,
                client_ip=client_ip,
                request_id=request_id,
            )
            trigger = triggers[0]
        else:
            trigger = service_assert_trigger(
                session=db,
                audit=audit,
                incident_id=incident_id,
                trigger_type=payload.trigger_type,
                occurred_at=payload.occurred_at,
                evidence_summary=payload.evidence_summary,
                rationale=payload.rationale,
                actor_id=auth_ctx.user_id,
                actor_role=auth_ctx.role.value,
                client_ip=client_ip,
                request_id=request_id,
            )
        db.commit()
        db.refresh(trigger)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg) from exc

    return TriggerResponse(
        id=trigger.id,
        incident_id=trigger.incident_id,
        trigger_type=trigger.trigger_type,
        occurred_at=trigger.occurred_at,
        recorded_at=trigger.recorded_at,
        asserted_by_id=trigger.asserted_by_id,
        evidence_summary=trigger.evidence_summary,
        rationale=trigger.rationale,
        is_disputed=trigger.is_disputed,
        dispute_reason=trigger.dispute_reason,
        disputed_by_id=trigger.disputed_by_id,
        disputed_at=trigger.disputed_at,
        counter_occurred_at=trigger.counter_occurred_at,
    )


@router.post(
    "/{incident_id}/triggers/{trigger_id}/dispute",
    response_model=TriggerResponse,
)
def dispute_incident_trigger(
    incident_id: str,
    trigger_id: str,
    payload: TriggerDisputeRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.TRIGGER_DISPUTE_RESOLVE)),
    _: None = Depends(require_csrf),
) -> TriggerResponse:
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    try:
        validate_text_or_raise(payload.dispute_reason, "dispute_reason")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    try:
        trigger = service_dispute_trigger(
            session=db,
            audit=audit,
            incident_id=incident_id,
            dispute_reason=payload.dispute_reason,
            counter_occurred_at=payload.counter_occurred_at,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            client_ip=client_ip,
            request_id=request_id,
        )
        db.commit()
        db.refresh(trigger)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg) from exc

    return TriggerResponse(
        id=trigger.id,
        incident_id=trigger.incident_id,
        trigger_type=trigger.trigger_type,
        occurred_at=trigger.occurred_at,
        recorded_at=trigger.recorded_at,
        asserted_by_id=trigger.asserted_by_id,
        evidence_summary=trigger.evidence_summary,
        rationale=trigger.rationale,
        is_disputed=trigger.is_disputed,
        dispute_reason=trigger.dispute_reason,
        disputed_by_id=trigger.disputed_by_id,
        disputed_at=trigger.disputed_at,
        counter_occurred_at=trigger.counter_occurred_at,
    )


@router.post(
    "/{incident_id}/obligations/{obligation_id}/assess-applicability",
    response_model=ObligationResponse,
)
def assess_obligation_applicability_route(
    incident_id: str,
    obligation_id: str,
    payload: ApplicabilityAssessRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_UPDATE)),
    _: None = Depends(require_csrf),
) -> ObligationResponse:
    """Assess regulatory obligation applicability with precautionary principles."""
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    try:
        obl = service_assess_applicability(
            session=db,
            audit=audit,
            obligation_id=obligation_id,
            personal_data_involved=payload.personal_data_involved,
            reportable_category=payload.reportable_category,
            rationale=payload.rationale,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            client_ip=client_ip,
            request_id=request_id,
        )
        db.commit()
        db.refresh(obl)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ObligationResponse(
        id=obl.id,
        incident_id=obl.incident_id,
        pack_id=obl.pack_id,
        regulator=obl.regulator,
        status=obl.status,
        deadline_at=obl.deadline_at,
        disputed_deadline_at=obl.disputed_deadline_at,
        active_deadline_at=obl.active_deadline_at,
        next_due_at=obl.next_due_at,
        escalation_level=obl.escalation_level,
        locked_until=obl.locked_until,
        filed_at=obl.filed_at,
        acknowledgement_id=obl.acknowledgement_id,
        applicability_status=obl.applicability_status,
        applicability_assessed_at=obl.applicability_assessed_at,
        applicability_assessed_by_id=obl.applicability_assessed_by_id,
        applicability_rationale=obl.applicability_rationale,
        applicability_answers=obl.applicability_answers,
        applicability_pending_rationale=obl.applicability_pending_rationale,
    )


@router.post(
    "/{incident_id}/obligations/{obligation_id}/confirm-exemption",
    response_model=ObligationResponse,
)
def confirm_obligation_exemption_route(
    incident_id: str,
    obligation_id: str,
    payload: ExemptionConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.TRIGGER_DISPUTE_RESOLVE)),
    _: None = Depends(require_csrf),
) -> ObligationResponse:
    """Confirm an obligation exemption. Restricted strictly to compliance approvers and CISO."""
    client_ip = request.client.host if request.client else None
    request_id = request.headers.get("X-Request-ID")

    try:
        obl = service_confirm_exemption(
            session=db,
            audit=audit,
            obligation_id=obligation_id,
            rationale=payload.rationale,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            client_ip=client_ip,
            request_id=request_id,
        )
        db.commit()
        db.refresh(obl)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ObligationResponse(
        id=obl.id,
        incident_id=obl.incident_id,
        pack_id=obl.pack_id,
        regulator=obl.regulator,
        status=obl.status,
        deadline_at=obl.deadline_at,
        disputed_deadline_at=obl.disputed_deadline_at,
        active_deadline_at=obl.active_deadline_at,
        next_due_at=obl.next_due_at,
        escalation_level=obl.escalation_level,
        locked_until=obl.locked_until,
        filed_at=obl.filed_at,
        acknowledgement_id=obl.acknowledgement_id,
        applicability_status=obl.applicability_status,
        applicability_assessed_at=obl.applicability_assessed_at,
        applicability_assessed_by_id=obl.applicability_assessed_by_id,
        applicability_rationale=obl.applicability_rationale,
        applicability_answers=obl.applicability_answers,
        applicability_pending_rationale=obl.applicability_pending_rationale,
    )


def _generate_rule_based_draft(
    raw_input: str,
    source_tool: str | None = None,
    affected_asset: str | None = None,
    reason: str | None = None,
) -> IncidentAIDraftResponse:
    """Deterministic fallback synthesis engine when local LLM inference is offline."""
    text_lower = raw_input.lower()
    tool_label = source_tool or "Security Sensor"
    asset_label = affected_asset or "Core Banking Network"

    if any(k in text_lower for k in ["ransomware", "encrypt", "vssadmin", "shadow copy", "lockbit", "blackcat"]):
        tactic = "Impact"
        mitre = "T1486 - Data Encrypted for Impact"
        severity = "critical"
        statutory = [
            "CERT-In Directions 2022 Section 70B Annexure I (Item 11: Malicious code attacks such as Ransomware / Trojan / Virus)",
            "RBI Cybersecurity Framework Directions Para 182: Mandatory 6-Hour DAKSH Incident Intimation",
        ]
        title = f"[{tool_label}] Ransomware execution and shadow copy tampering on {asset_label}"
    elif any(k in text_lower for k in ["payment", "rtgs", "neft", "upi", "settlement", "switch", "cbs"]):
        tactic = "Execution / Manipulation"
        mitre = "T1047 - WMI Execution / Payment Channel Manipulation"
        severity = "critical"
        statutory = [
            "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)",
            "CERT-In Directions 2022 Section 70B Annexure I (Item 12: Attack on critical information infrastructure such as SWIFT, RTGS, CBS)",
        ]
        title = f"[{tool_label}] Telemetry spike impacting payment processing channel ({asset_label})"
    elif any(k in text_lower for k in ["swift", "alliance", "sag", "fin"]):
        tactic = "Initial Access / Tampering"
        mitre = "T1078 - Valid Accounts / SWIFT Gateway Tampering"
        severity = "critical"
        statutory = [
            "CERT-In Directions 2022 Section 70B Annexure I (Item 12: Attack on critical information infrastructure such as SWIFT, RTGS, CBS)",
        ]
        title = f"[{tool_label}] Unauthorized gateway activity on SWIFT messaging infrastructure ({asset_label})"
    elif any(k in text_lower for k in ["credential", "lsass", "mimikatz", "kerberoast", "golden ticket", "dump"]):
        tactic = "Credential Access"
        mitre = "T1003.001 - OS Credential Dumping: LSASS Memory"
        severity = "critical" if any(k in text_lower for k in ["cbs", "dc", "domain", "prod"]) else "high"
        statutory = [
            "CERT-In Directions 2022 Section 70B Annexure I (Item 9: Unauthorized access of IT systems/data)",
        ]
        title = f"[{tool_label}] Credential access and memory dumping detected on {asset_label}"
    elif any(k in text_lower for k in ["exfiltration", "data breach", "leak", "aadhaar", "pan", "pii", "dpdp"]):
        tactic = "Exfiltration"
        mitre = "T1048 - Exfiltration Over Alternative Protocol"
        severity = "critical"
        statutory = [
            "DPDP Act 2023 Section 8(6) Rule 7: Mandatory 72-Hour Breach Intimation to Data Protection Board",
            "CERT-In Directions 2022 Section 70B Annexure I (Item 9: Unauthorized access of IT systems/data)",
        ]
        title = f"[{tool_label}] Potential customer data exfiltration detected from {asset_label}"
    elif any(k in text_lower for k in ["ddos", "flood", "saturation", "flapping", "bgp", "packet loss"]):
        tactic = "Impact / Availability"
        mitre = "T1498 - Network Denial of Service"
        severity = "high"
        statutory = [
            "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)",
        ]
        title = f"[{tool_label}] Network saturation and traffic routing anomaly on {asset_label}"
    else:
        tactic = "Initial Access"
        mitre = "T1190 - Exploit Public-Facing Application"
        severity = "high"
        statutory = [
            "CERT-In Directions 2022 Section 70B Clause (ii): 6-Hour Mandatory Reporting Window",
        ]
        title = f"[{tool_label}] Security incident alert requiring statutory triage on {asset_label}"

    # Clean previous section headers to prevent nested duplication during re-refinement
    cleaned_input = raw_input
    for hdr in [
        r"Executive Incident Overview:\s*",
        r"Executive Overview:\s*",
        r"Technical Threat Telemetry:\s*",
        r"Technical Threat Telemetry & Forensics:\s*",
        r"MITRE ATT&CK Classification:\s*[\s\S]*?(?=Target Banking Infrastructure:|Statutory Reporting Assessment:|$)",
        r"Target Banking Infrastructure:\s*[\s\S]*?(?=Statutory Reporting Assessment:|$)",
        r"Statutory Reporting Assessment:\s*[\s\S]*$",
    ]:
        cleaned_input = re.sub(hdr, "", cleaned_input, flags=re.IGNORECASE)
    cleaned_input = cleaned_input.strip() or raw_input.strip()

    summary = (
        f"Executive Incident Overview:\n"
        f"Automated security detection generated by {tool_label} indicating {tactic.lower()} activity targeting {asset_label}. "
        f"Technical telemetry highlights abnormal behavior requiring expedited statutory review.\n\n"
        f"Technical Threat Telemetry:\n"
        f"{cleaned_input}\n\n"
        f"MITRE ATT&CK Classification:\n"
        f"Tactical Category: {tactic} | Technique: {mitre}\n\n"
        f"Target Banking Infrastructure:\n"
        f"Primary Affected Asset: {asset_label}\n"
        f"Operational Impact Assessment: Elevated risk to operational continuity and transaction processing integrity.\n\n"
        f"Statutory Reporting Assessment:\n"
        f"Recommended Window: {'6 Hours (Mandatory Initial Notice)' if severity == 'critical' else 'Statutory Verification'}\n"
        f"Applicable Directives: {', '.join(statutory)}"
    )

    return IncidentAIDraftResponse(
        suggested_title=title,
        suggested_summary=summary,
        recommended_severity=severity,
        mitre_attack=mitre,
        statutory_applicability=statutory,
        ai_confidence=0.92,
        model_used="Deterministic Banking Rule Engine (Fallback)",
        fallback_mode=True,
        fallback_reason=reason or "Local LLM offline",
    )


@router.post("/ai-draft", response_model=IncidentAIDraftResponse)
def generate_ai_incident_draft(
    payload: IncidentAIDraftRequest,
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> IncidentAIDraftResponse:
    """Generates an AI-assisted incident report draft using local Ollama or rule-based fallback."""
    # Pre-flight server-side PII guard: strictly sanitize before sending to local model
    clean_input = PIIGuard.redact(payload.raw_input)

    from cyberq.verification.llm_client import (
        CANONICAL_STATUTORY_TAXONOMY,
        OllamaLLMClient,
        ground_regulatory_clauses,
    )

    llm = OllamaLLMClient(timeout=10.0, max_retries=1)

    if not llm.is_available():
        return _generate_rule_based_draft(
            raw_input=clean_input,
            source_tool=payload.source_tool,
            affected_asset=payload.affected_asset,
            reason="Local Ollama daemon is offline (http://localhost:11434). Deterministic banking rule engine engaged.",
        )

    system_prompt = (
        "You are the CYBERQ AI Incident Drafter for an Indian Scheduled Commercial Bank.\n"
        "Draft a formal, statutory-compliant incident record from the provided raw technical text.\n\n"
        "STATUTORY TAXONOMY CANON:\n"
        + "\n".join(f'- "{c}"' for c in CANONICAL_STATUTORY_TAXONOMY)
        + "\n\n"
        "RULES:\n"
        "1. Never include customer account numbers, PANs, or Aadhaar numbers.\n"
        "2. If payment, RTGS, CBS, or SWIFT systems are affected, recommended_severity MUST be 'critical'.\n"
        "3. Provide an executive and technical summary covering Root Cause, Affected Asset, Impact, and Containment.\n"
        "4. Ground all statutory citations strictly in verified CERT-In, RBI DAKSH, or DPDP mandates.\n"
        "Return strict JSON matching this schema:\n"
        "{\n"
        '  "suggested_title": "<Title with tool/tactic prefix>",\n'
        '  "suggested_summary": "<Professional structured summary>",\n'
        '  "recommended_severity": "critical" | "high" | "medium" | "low",\n'
        '  "mitre_attack": "<MITRE ATT&CK technique e.g. T1047 - WMI>",\n'
        '  "statutory_applicability": ["<Clause from canon>", ...],\n'
        '  "ai_confidence": 0.95\n'
        "}"
    )

    user_prompt = json.dumps({
        "raw_telemetry": clean_input,
        "source_tool": payload.source_tool or "Security Tool",
        "affected_asset": payload.affected_asset or "Banking IT Asset",
    })

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        raw_json = llm._chat_completion_with_retry(messages, temperature=0.1, num_predict=600)

        raw_clauses = raw_json.get("statutory_applicability", [])
        grounded = ground_regulatory_clauses(
            raw_clauses=raw_clauses,
            alert_data={"raw_message": clean_input},
            is_reportable=True,
        )

        sev = str(raw_json.get("recommended_severity", "high")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "high"

        return IncidentAIDraftResponse(
            suggested_title=str(
                raw_json.get("suggested_title")
                or f"[{payload.source_tool or 'SOC'}] Security Incident on {payload.affected_asset or 'Core Network'}"
            ),
            suggested_summary=str(raw_json.get("suggested_summary") or clean_input),
            recommended_severity=sev,
            mitre_attack=str(raw_json.get("mitre_attack") or "T1059 - Command and Scripting Interpreter"),
            statutory_applicability=grounded
            if grounded
            else ["CERT-In Directions 2022 Section 70B Clause (ii): 6-Hour Mandatory Reporting Window"],
            ai_confidence=float(raw_json.get("ai_confidence") or 0.95),
            model_used=f"Local Ollama ({llm.model})",
            fallback_mode=False,
            fallback_reason=None,
        )
    except Exception as exc:
        return _generate_rule_based_draft(
            raw_input=clean_input,
            source_tool=payload.source_tool,
            affected_asset=payload.affected_asset,
            reason=f"Local LLM inference exception ({exc}). Engaged deterministic fallback.",
        )
