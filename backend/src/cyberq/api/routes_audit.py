"""Audit chain export and verification routes."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_permission
from cyberq.audit.chain import AuditService
from cyberq.audit.models import AuditCheckpoint, AuditEvent
from cyberq.core.database import get_db
from cyberq.iam.policy import Action, AuthContext

router = APIRouter(prefix="/audit", tags=["Audit"])


class AuditExportResponse(BaseModel):
    public_key: str
    events: list[dict[str, Any]]
    checkpoints: list[dict[str, Any]]


class AuditVerifyResponse(BaseModel):
    is_valid: bool
    reason: str
    event_count: int
    checkpoint_count: int
    latest_hash: str | None


@router.get("/export", response_model=AuditExportResponse)
def export_audit_chain(
    db: Session = Depends(get_db),
    audit_svc: AuditService = Depends(get_audit_service),
    _: AuthContext = Depends(require_permission(Action.AUDIT_READ)),
) -> AuditExportResponse:
    """Exports full audit event ledger and signed checkpoints for offline verification."""
    events = (
        db.execute(select(AuditEvent).order_by(AuditEvent.sequence_number.asc())).scalars().all()
    )

    checkpoints = (
        db.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.sequence_number.asc()))
        .scalars()
        .all()
    )

    event_dicts = [
        {
            "id": e.id,
            "sequence_number": e.sequence_number,
            "timestamp": str(e.timestamp),
            "prev_hash": e.prev_hash,
            "hash": e.hash,
            "actor_id": e.actor_id,
            "actor_role": e.actor_role,
            "client_ip": e.client_ip,
            "request_id": e.request_id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "before_state": e.before_state,
            "after_state": e.after_state,
        }
        for e in events
    ]

    cp_dicts = [
        {
            "id": cp.id,
            "sequence_number": cp.sequence_number,
            "timestamp": str(cp.timestamp),
            "from_sequence": cp.from_sequence,
            "to_sequence": cp.to_sequence,
            "from_event_id": cp.from_event_id,
            "to_event_id": cp.to_event_id,
            "root_hash": cp.root_hash,
            "signature": cp.signature,
            "signer_public_key": cp.signer_public_key,
        }
        for cp in checkpoints
    ]

    return AuditExportResponse(
        public_key=audit_svc.public_key_hex,
        events=event_dicts,
        checkpoints=cp_dicts,
    )


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_audit_chain(
    db: Session = Depends(get_db),
    audit_svc: AuditService = Depends(get_audit_service),
    _: AuthContext = Depends(require_permission(Action.AUDIT_VERIFY)),
) -> AuditVerifyResponse:
    """Runs verification on the active chain and reports status."""
    events = (
        db.execute(select(AuditEvent).order_by(AuditEvent.sequence_number.asc())).scalars().all()
    )

    checkpoints = (
        db.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.sequence_number.asc()))
        .scalars()
        .all()
    )

    event_dicts = [
        {
            "id": e.id,
            "sequence_number": e.sequence_number,
            "timestamp": str(e.timestamp),
            "prev_hash": e.prev_hash,
            "hash": e.hash,
            "actor_id": e.actor_id,
            "actor_role": e.actor_role,
            "client_ip": e.client_ip,
            "request_id": e.request_id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "before_state": e.before_state,
            "after_state": e.after_state,
        }
        for e in events
    ]

    cp_dicts = [
        {
            "id": cp.id,
            "sequence_number": cp.sequence_number,
            "timestamp": str(cp.timestamp),
            "from_sequence": cp.from_sequence,
            "to_sequence": cp.to_sequence,
            "from_event_id": cp.from_event_id,
            "to_event_id": cp.to_event_id,
            "root_hash": cp.root_hash,
            "signature": cp.signature,
            "signer_public_key": cp.signer_public_key,
        }
        for cp in checkpoints
    ]

    is_valid, reason = AuditService.verify_chain(event_dicts, cp_dicts, audit_svc.public_key_hex)
    latest_hash = events[-1].hash if events else None

    return AuditVerifyResponse(
        is_valid=is_valid,
        reason=reason,
        event_count=len(events),
        checkpoint_count=len(checkpoints),
        latest_hash=latest_hash,
    )
