"""FastAPI routes for Administrative controls and 1-Click Live Hackathon Demo Seeder."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_permission
from cyberq.audit.chain import AuditService
from cyberq.clocks.models import ObligationInstance
from cyberq.core.config import get_settings
from cyberq.core.database import get_db
from cyberq.core.demo_seed import seed_demo_crisis_data
from cyberq.governance.models import Para59Exception, RiskDecision
from cyberq.iam.policy import Action, AuthContext
from cyberq.incidents.models import Incident
from cyberq.intake.models import ToolCompliancePassport

router = APIRouter(prefix="/admin", tags=["Admin & Demo Orchestration"])


@router.post("/seed-demo")
def trigger_demo_seeder(
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.ADMIN_CONFIG)),
) -> dict[str, Any]:
    """1-Click Hackathon Demo Seeder: populates 22 tool passports, 3 realistic crisis incidents,

    running clocks, Para 59 exceptions, and risk decisions.
    Strictly forbidden in production mode per ADR-0004.
    """
    settings = get_settings()
    if settings.is_production():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo data seeding is strictly forbidden in production mode.",
        )

    return seed_demo_crisis_data(session=db, audit=audit)


@router.get("/telemetry")
def get_admin_telemetry(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.ADMIN_CONFIG)),
) -> dict[str, Any]:
    """Returns real-time platform system telemetry for the admin dashboard."""
    settings = get_settings()
    total_tools = db.scalar(select(func.count(ToolCompliancePassport.tool_id))) or 0
    total_incidents = db.scalar(select(func.count(Incident.id))) or 0
    running_clocks = (
        db.scalar(
            select(func.count(ObligationInstance.id)).where(ObligationInstance.status == "running")
        )
        or 0
    )
    active_exceptions = (
        db.scalar(
            select(func.count(Para59Exception.id)).where(Para59Exception.status == "active")
        )
        or 0
    )
    active_decisions = (
        db.scalar(select(func.count(RiskDecision.id)).where(RiskDecision.status == "active")) or 0
    )

    return {
        "version": settings.APP_VERSION,
        "environment": settings.ENV.value,
        "total_security_tools_monitored": total_tools,
        "total_cyber_incidents": total_incidents,
        "running_statutory_clocks": running_clocks,
        "active_para59_exceptions": active_exceptions,
        "active_risk_decisions": active_decisions,
        "database_connected": True,
    }
