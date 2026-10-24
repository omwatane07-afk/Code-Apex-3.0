"""Pydantic schemas for Mixed-Integer Linear Programming (MILP) cybersecurity capital allocation."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityControl(BaseModel):
    """Candidate security control parameter model for PuLP MILP optimization."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=2, max_length=128)
    category: str = Field(default="general")
    cost_lakhs: float = Field(gt=0.0)
    risk_reduction_lakhs: float = Field(gt=0.0)
    dependencies: list[str] = Field(default_factory=list)
    mutually_exclusive_with: list[str] = Field(default_factory=list)


class OptimizationRequest(BaseModel):
    """Input parameters for capital allocation optimization."""

    model_config = ConfigDict(extra="forbid")

    budget_cap_lakhs: float = Field(gt=0.0, default=150.0)
    candidate_controls: list[SecurityControl] = Field(default_factory=list)


class OptimizationResult(BaseModel):
    """Optimal cybersecurity investment portfolio under budget and technical constraints."""

    budget_cap_lakhs: float
    selected_control_ids: list[str]
    selected_controls: list[SecurityControl]
    total_cost_lakhs: float
    total_cost_crores: float
    total_risk_reduction_lakhs: float
    total_risk_reduction_crores: float
    roi_ratio: float
    solver_status: str
    pareto_frontier: list[dict[str, Any]]
    optimized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
