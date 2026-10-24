"""FastAPI routes for Open FAIR Rupee Cyber Risk Exposure and PuLP Capital Optimizer."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_permission
from cyberq.audit.chain import AuditService
from cyberq.core.database import get_db
from cyberq.exposure.engine import ExposureEngine
from cyberq.exposure.models import ExposureResult, ExposureScenario
from cyberq.iam.policy import Action, AuthContext
from cyberq.optimizer.engine import DEFAULT_BANK_CONTROLS, CapitalOptimizer
from cyberq.optimizer.models import OptimizationRequest, OptimizationResult, SecurityControl

router = APIRouter(prefix="/exposure", tags=["Rupee Exposure & Capital Optimizer"])


@router.get("/controls", response_model=list[SecurityControl])
def get_control_catalog(
    _: AuthContext = Depends(require_permission(Action.BOARD_PACK_READ)),
) -> list[SecurityControl]:
    """Retrieves the default enterprise banking cybersecurity control catalog."""
    return DEFAULT_BANK_CONTROLS


@router.post("/simulate", response_model=ExposureResult)
def simulate_exposure(
    scenario: ExposureScenario,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.EXPOSURE_RUN)),
) -> ExposureResult:
    """Executes Open FAIR 16,384 Sobol Quasi-Monte Carlo quantitative VaR simulation."""
    return ExposureEngine.simulate_scenario(
        scenario=scenario,
        session=db,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
    )


@router.post("/optimize", response_model=OptimizationResult)
def optimize_capital(
    payload: OptimizationRequest,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.EXPOSURE_RUN)),
) -> OptimizationResult:
    """Solves Mixed-Integer Linear Program for optimal control portfolio under budget cap."""
    return CapitalOptimizer.solve_allocation(
        budget_cap_lakhs=payload.budget_cap_lakhs,
        controls=payload.candidate_controls,
        session=db,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
    )


@router.get("/pareto")
def get_pareto_curve(
    budget_cap_lakhs: float = Query(default=150.0, gt=0.0),
    _: AuthContext = Depends(require_permission(Action.EXPOSURE_RUN)),
) -> list[dict[str, Any]]:
    """Generates the Pareto-optimal frontier curve of risk reduction vs budget allocation."""
    return CapitalOptimizer._compute_pareto_frontier(DEFAULT_BANK_CONTROLS, budget_cap_lakhs)
