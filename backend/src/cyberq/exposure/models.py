"""Pydantic schemas and dataclasses for Open FAIR quantitative cyber risk exposure modeling."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExposureScenario(BaseModel):
    """Input parameters for an Open FAIR cyber risk scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=2, max_length=64, default="SCEN-DEFAULT")
    name: str = Field(min_length=2, max_length=128, default="Ransomware & Core Banking Exfiltration")
    threat_event_frequency_min: float = Field(gt=0.0, default=0.5)
    threat_event_frequency_mode: float = Field(gt=0.0, default=2.0)
    threat_event_frequency_max: float = Field(gt=0.0, default=6.0)
    vulnerability: float = Field(ge=0.0, le=1.0, default=0.25)
    primary_loss_min_lakhs: float = Field(ge=0.0, default=25.0)
    primary_loss_mode_lakhs: float = Field(ge=0.0, default=120.0)
    primary_loss_max_lakhs: float = Field(ge=0.0, default=600.0)
    secondary_loss_prob: float = Field(ge=0.0, le=1.0, default=0.40)
    secondary_loss_min_lakhs: float = Field(ge=0.0, default=50.0)
    secondary_loss_mode_lakhs: float = Field(ge=0.0, default=500.0)
    secondary_loss_max_lakhs: float = Field(ge=0.0, default=2500.0)


class ExposureResult(BaseModel):
    """Quantified Value-at-Risk output and Model Risk Management manifest."""

    scenario_id: str
    scenario_name: str
    iterations: int = 16384
    seed_hash: str
    p10_lakhs: float
    p50_lakhs: float
    p90_lakhs: float
    p99_lakhs: float
    p10_crores: float
    p50_crores: float
    p90_crores: float
    p99_crores: float
    expected_annual_loss_lakhs: float
    expected_annual_loss_crores: float
    ks_stat: float
    ks_pvalue: float
    rbi_mrm_manifest: dict[str, Any]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
