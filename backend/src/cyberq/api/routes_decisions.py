"""Statutory Risk Decision Ledger, Para 59 Exceptions, and Board Governance routes."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_csrf, require_permission
from cyberq.audit.chain import AuditService
from cyberq.clocks.models import ObligationInstance
from cyberq.core.database import get_db
from cyberq.governance.board_pack import generate_board_pack_pdf, generate_quarterly_board_pack_data
from cyberq.governance.models import Para59Exception, RiskDecision
from cyberq.iam.policy import Action, AuthContext, PolicyEngine
from cyberq.incidents.models import Incident

router = APIRouter(tags=["Governance & Decisions"])


class DecisionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision_type: str = Field(
        pattern="^(Risk Acceptance|Regulatory Deferral|Control Compensating|Policy Exception|ACCEPT|MITIGATE|TRANSFER|AVOID)$"
    )
    rationale: str = Field(min_length=5, max_length=5000)
    compensating_controls: str = Field(min_length=5, max_length=5000)
    owner: str = Field(min_length=3, max_length=128)
    expiry_date: datetime
    incident_id: str | None = None


class DecisionCountersignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notes: str = Field(min_length=5, max_length=2000)


class DecisionResponse(BaseModel):
    id: str
    decision_number: str
    incident_id: str | None = None
    decision_type: str
    status: str
    rationale: str
    compensating_controls: str
    owner: str
    expiry_date: datetime
    created_by_id: str
    created_at: datetime
    countersigned_by_id: str | None = None
    countersigned_at: datetime | None = None
    countersign_notes: str | None = None
    updated_at: datetime


class Para59ExceptionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_or_system: str = Field(min_length=2, max_length=256)
    control_reference: str = Field(min_length=2, max_length=256)
    rationale: str = Field(min_length=5, max_length=5000)
    compensating_controls: str = Field(min_length=5, max_length=5000)
    owner: str = Field(min_length=2, max_length=128)
    risk_level: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    expiry_date: datetime


class Para59ExceptionReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_status: str = Field(pattern="^(active|remediated|revoked|renewed)$")
    review_notes: str = Field(min_length=5, max_length=2000)
    new_expiry_date: datetime | None = None


class Para59ExceptionResponse(BaseModel):
    id: str
    exception_number: str
    asset_or_system: str
    control_reference: str
    rationale: str
    compensating_controls: str
    owner: str
    risk_level: str
    status: str
    computed_status: str
    days_remaining: int
    issue_date: datetime
    expiry_date: datetime
    last_reviewed_at: datetime | None
    reviewed_by_id: str | None
    review_notes: str | None
    created_by_id: str
    created_at: datetime


class BoardPreviewResponse(BaseModel):
    total_incidents: int
    open_incidents: int
    active_countdowns: list[dict[str, Any]]
    open_risk_decisions: int
    active_risk_decisions: int
    pending_closure_approvals: int
    top_risks: list[dict[str, Any]]
    generated_at: datetime


class CisoAlertsResponse(BaseModel):
    total_alerts: int
    severity_reviews: int
    closure_approvals_waiting: int
    decisions_expiring_soon: int
    items: list[dict[str, Any]]


def generate_decision_number(session: Session) -> str:
    current_year = datetime.now(UTC).year
    prefix = f"DEC-{current_year}-"
    count = (
        session.scalar(
            select(func.count(RiskDecision.id)).where(RiskDecision.decision_number.like(f"{prefix}%"))
        )
        or 0
    )
    return f"{prefix}{count + 1:04d}"


def generate_exception_number(session: Session) -> str:
    current_year = datetime.now(UTC).year
    prefix = f"EXC-{current_year}-"
    count = (
        session.scalar(
            select(func.count(Para59Exception.id)).where(Para59Exception.exception_number.like(f"{prefix}%"))
        )
        or 0
    )
    return f"{prefix}{count + 1:04d}"


def _decision_to_response(d: RiskDecision) -> DecisionResponse:
    return DecisionResponse(
        id=d.id,
        decision_number=d.decision_number,
        incident_id=d.incident_id,
        decision_type=d.decision_type,
        status=d.status,
        rationale=d.rationale,
        compensating_controls=d.compensating_controls,
        owner=d.owner,
        expiry_date=d.expiry_date,
        created_by_id=d.created_by_id,
        created_at=d.created_at,
        countersigned_by_id=d.countersigned_by_id,
        countersigned_at=d.countersigned_at,
        countersign_notes=d.countersign_notes,
        updated_at=d.updated_at,
    )


def _exception_to_response(exc: Para59Exception, now: datetime | None = None) -> Para59ExceptionResponse:
    cur = now or datetime.now(UTC)
    return Para59ExceptionResponse(
        id=exc.id,
        exception_number=exc.exception_number,
        asset_or_system=exc.asset_or_system,
        control_reference=exc.control_reference,
        rationale=exc.rationale,
        compensating_controls=exc.compensating_controls,
        owner=exc.owner,
        risk_level=exc.risk_level,
        status=exc.status,
        computed_status=exc.computed_status(cur),
        days_remaining=exc.days_remaining(cur),
        issue_date=exc.issue_date,
        expiry_date=exc.expiry_date,
        last_reviewed_at=exc.last_reviewed_at,
        reviewed_by_id=exc.reviewed_by_id,
        review_notes=exc.review_notes,
        created_by_id=exc.created_by_id,
        created_at=exc.created_at,
    )


@router.get("/decisions", response_model=list[DecisionResponse])
def list_decisions(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission(Action.DECISION_READ)),
) -> list[DecisionResponse]:
    """List all risk decisions in the statutory decision ledger."""
    decisions = (
        db.execute(select(RiskDecision).order_by(RiskDecision.created_at.desc())).scalars().all()
    )
    return [_decision_to_response(d) for d in decisions]


@router.post("/decisions", response_model=DecisionResponse, status_code=status.HTTP_201_CREATED)
def create_decision(
    payload: DecisionCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DECISION_CREATE)),
    _: None = Depends(require_csrf),
) -> DecisionResponse:
    """Draft a new statutory risk decision. Only CISO can draft.

    Requires second user countersignature (maker-checker) before becoming Active.
    """
    if payload.incident_id:
        inc = db.scalar(select(Incident).where(Incident.id == payload.incident_id))
        if not inc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked incident not found")

    decision_num = generate_decision_number(db)
    now = datetime.now(UTC)

    decision = RiskDecision(
        decision_number=decision_num,
        incident_id=payload.incident_id,
        decision_type=payload.decision_type,
        status="awaiting_countersignature",
        rationale=payload.rationale,
        compensating_controls=payload.compensating_controls,
        owner=payload.owner,
        expiry_date=payload.expiry_date,
        created_by_id=auth_ctx.user_id,
        created_at=now,
        updated_at=now,
    )
    db.add(decision)
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="decision:create",
        entity_type="risk_decision",
        entity_id=decision.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "decision_number": decision.decision_number,
            "decision_type": decision.decision_type,
            "status": decision.status,
            "owner": decision.owner,
            "expiry_date": decision.expiry_date.isoformat(),
        },
    )
    db.commit()
    db.refresh(decision)
    return _decision_to_response(decision)


@router.post("/decisions/{decision_id}/countersign", response_model=DecisionResponse)
def countersign_decision(
    decision_id: str,
    payload: DecisionCountersignRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DECISION_APPROVE)),
    _: None = Depends(require_csrf),
) -> DecisionResponse:
    """Countersign a risk decision to activate it.

    Maker-checker rule: Decision creator cannot countersign own decision.
    """
    decision = db.scalar(select(RiskDecision).where(RiskDecision.id == decision_id))
    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk decision not found")

    if decision.status == "active":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Decision is already active")

    if not PolicyEngine.check_maker_checker(decision.created_by_id, auth_ctx.user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maker-checker violation: Decision maker cannot countersign own decision",
        )

    now = datetime.now(UTC)
    old_status = decision.status
    decision.status = "active"
    decision.countersigned_by_id = auth_ctx.user_id
    decision.countersigned_at = now
    decision.countersign_notes = payload.notes
    decision.updated_at = now
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="decision:countersign",
        entity_type="risk_decision",
        entity_id=decision.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"status": old_status},
        after_state={
            "status": "active",
            "countersigned_by": auth_ctx.user_id,
            "countersigned_at": now.isoformat(),
            "countersign_notes": payload.notes,
        },
    )
    db.commit()
    db.refresh(decision)
    return _decision_to_response(decision)


# ---------------------------------------------------------------------------
# RBI Master Directions Para 59 Technical Exceptions Register
# ---------------------------------------------------------------------------


@router.get("/decisions/exceptions", response_model=list[Para59ExceptionResponse])
def list_exceptions(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission(Action.DECISION_READ)),
) -> list[Para59ExceptionResponse]:
    """List all registered Para 59 cybersecurity exceptions with computed warning status."""
    now = datetime.now(UTC)
    exceptions = db.execute(select(Para59Exception).order_by(Para59Exception.created_at.desc())).scalars().all()
    return [_exception_to_response(e, now) for e in exceptions]


@router.post("/decisions/exceptions", response_model=Para59ExceptionResponse, status_code=status.HTTP_201_CREATED)
def create_exception(
    payload: Para59ExceptionCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DECISION_CREATE)),
    _: None = Depends(require_csrf),
) -> Para59ExceptionResponse:
    """Creates a new Para 59 technical control exception with compensating controls."""
    now = datetime.now(UTC)
    exc_num = generate_exception_number(db)

    exc = Para59Exception(
        exception_number=exc_num,
        asset_or_system=payload.asset_or_system,
        control_reference=payload.control_reference,
        rationale=payload.rationale,
        compensating_controls=payload.compensating_controls,
        owner=payload.owner,
        risk_level=payload.risk_level,
        status="active",
        issue_date=now,
        expiry_date=payload.expiry_date,
        created_by_id=auth_ctx.user_id,
        created_at=now,
        updated_at=now,
    )
    db.add(exc)
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="exception:create",
        entity_type="para59_exception",
        entity_id=exc.id,
        client_ip=client_ip,
        request_id=request_id,
        after_state={
            "exception_number": exc.exception_number,
            "asset_or_system": exc.asset_or_system,
            "control_reference": exc.control_reference,
            "risk_level": exc.risk_level,
            "expiry_date": exc.expiry_date.isoformat(),
        },
    )
    db.commit()
    db.refresh(exc)
    return _exception_to_response(exc, now)


@router.post("/decisions/exceptions/{exception_id}/review", response_model=Para59ExceptionResponse)
def review_exception(
    exception_id: str,
    payload: Para59ExceptionReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DECISION_APPROVE)),
    _: None = Depends(require_csrf),
) -> Para59ExceptionResponse:
    """Performs mandatory quarterly review, remediation, or extension of Para 59 exception."""
    exc = db.scalar(select(Para59Exception).where(Para59Exception.id == exception_id))
    if not exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Para 59 exception not found")

    now = datetime.now(UTC)
    old_status = exc.status

    if payload.new_status == "renewed":
        if not payload.new_expiry_date:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Renewal requires new_expiry_date")
        exc.status = "active"
        exc.expiry_date = payload.new_expiry_date
    else:
        exc.status = payload.new_status

    exc.last_reviewed_at = now
    exc.reviewed_by_id = auth_ctx.user_id
    exc.review_notes = payload.review_notes
    exc.updated_at = now
    db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    request_id = request.headers.get("X-Request-ID")
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="exception:review",
        entity_type="para59_exception",
        entity_id=exc.id,
        client_ip=client_ip,
        request_id=request_id,
        before_state={"status": old_status},
        after_state={
            "status": exc.status,
            "reviewed_by_id": auth_ctx.user_id,
            "review_notes": payload.review_notes,
        },
    )
    db.commit()
    db.refresh(exc)
    return _exception_to_response(exc, now)


# ---------------------------------------------------------------------------
# Board Risk Pack Endpoints (RBI Para 28(7))
# ---------------------------------------------------------------------------


@router.get("/governance/board-preview", response_model=BoardPreviewResponse)
def get_board_preview(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission(Action.BOARD_PACK_READ)),
) -> BoardPreviewResponse:
    """Generate high-level executive summary preview for CISO and Board."""
    incidents = db.execute(select(Incident)).scalars().all()
    total_incidents = len(incidents)
    open_incidents = len([i for i in incidents if i.status not in ("closed", "false_positive")])
    pending_closure = len([i for i in incidents if i.status in ("resolved", "contained")])

    running_obls = (
        db.execute(select(ObligationInstance).where(ObligationInstance.status == "running"))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    active_countdowns: list[dict[str, Any]] = []
    for obl in running_obls:
        secs = (
            int((obl.active_deadline_at - now).total_seconds()) if obl.active_deadline_at else 0
        )
        active_countdowns.append(
            {
                "id": obl.id,
                "incident_id": obl.incident_id,
                "regulator": obl.regulator,
                "seconds_remaining": max(0, secs),
                "deadline_at": obl.active_deadline_at.isoformat() if obl.active_deadline_at else None,
            }
        )

    decisions = db.execute(select(RiskDecision)).scalars().all()
    open_decisions = len([d for d in decisions if d.status in ("draft", "awaiting_countersignature")])
    active_decisions = len([d for d in decisions if d.status == "active"])

    top_risks = [
        {
            "id": i.id,
            "incident_number": i.incident_number,
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "is_major": i.is_major,
        }
        for i in incidents
        if i.severity == "critical" or i.is_major
    ]

    return BoardPreviewResponse(
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        active_countdowns=active_countdowns,
        open_risk_decisions=open_decisions,
        active_risk_decisions=active_decisions,
        pending_closure_approvals=pending_closure,
        top_risks=top_risks,
        generated_at=now,
    )


@router.get("/governance/board-pack/quarterly")
def get_quarterly_board_pack(
    quarter: str = Query(default="Q1 FY2026-27"),
    lang: str = Query(default="en"),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.BOARD_PACK_READ)),
) -> dict[str, Any]:
    """Generates the statutory quarterly board risk pack data (RBI Para 28(7))."""
    return generate_quarterly_board_pack_data(
        session=db,
        quarter=quarter,
        lang=lang,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
    )


@router.get("/governance/board-pack/quarterly/pdf")
def download_quarterly_board_pack_pdf(
    quarter: str = Query(default="Q1 FY2026-27"),
    lang: str = Query(default="en"),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.BOARD_PACK_READ)),
) -> Response:
    """Generates and downloads a byte-reproducible PDF of the RBI Para 28(7) Board Pack."""
    pack_data = generate_quarterly_board_pack_data(
        session=db,
        quarter=quarter,
        lang=lang,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
    )
    pdf_bytes = generate_board_pack_pdf(pack_data)
    safe_q = quarter.replace(" ", "-").replace("/", "-")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="cyberq-board-pack-{safe_q}.pdf"',
            "X-CyberQ-Pack-Hash": pack_data["pack_hash"],
        },
    )


@router.get("/governance/ciso-alerts", response_model=CisoAlertsResponse)
def get_ciso_alerts(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> CisoAlertsResponse:
    """Get count of active action items requiring CISO attention."""
    incidents = db.execute(select(Incident)).scalars().all()
    severity_reviews = [
        {
            "type": "severity_review",
            "incident_number": i.incident_number,
            "title": i.title,
            "severity": i.severity,
        }
        for i in incidents
        if i.status not in ("closed", "false_positive") and i.severity in ("critical", "high")
    ]

    closure_approvals = [
        {
            "type": "closure_approval",
            "incident_number": i.incident_number,
            "title": i.title,
            "status": i.status,
        }
        for i in incidents
        if i.status in ("resolved", "contained")
    ]

    now = datetime.now(UTC)
    near_future = now + timedelta(days=7)
    decisions = db.execute(select(RiskDecision)).scalars().all()
    expiring_decisions = [
        {
            "type": "decision_expiring",
            "decision_number": d.decision_number,
            "owner": d.owner,
            "expiry_date": d.expiry_date.isoformat(),
        }
        for d in decisions
        if d.status == "active" and d.expiry_date <= near_future
    ]

    all_items = severity_reviews + closure_approvals + expiring_decisions
    return CisoAlertsResponse(
        total_alerts=len(all_items),
        severity_reviews=len(severity_reviews),
        closure_approvals_waiting=len(closure_approvals),
        decisions_expiring_soon=len(expiring_decisions),
        items=all_items,
    )
