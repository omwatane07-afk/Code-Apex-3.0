"""Regulatory obligation pack loader and production gate.

Enforces:
1. yaml.safe_load exclusively, forbidding arbitrary Python object execution (CWE-502).
2. Provenance metadata and raw file byte SHA-256 integrity verification.
3. Production gate: rejects startup if any pack is draft or modified post-verification.
"""

import hashlib
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class TriggerEventType(StrEnum):
    NOTICED = "noticed"
    DETECTED = "detected"
    AWARE = "aware"


class PackStatus(StrEnum):
    DRAFT = "draft"
    VERIFIED = "verified"


class ObligationPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    regulator: str
    instrument: str
    clause_ref: str
    applies_to: list[str]
    trigger_event: TriggerEventType
    deadline_hours: int = Field(gt=0)
    effective_from: date
    enforcement_date: date | None = None
    channel: str
    channel_notes: str
    filing_fields: list[dict[str, Any]] = Field(default_factory=list)
    source_url: str
    source_checked_on: date | None = None
    verified_by: str | None = None
    status: PackStatus = PackStatus.DRAFT
    notes: str = ""

    # Computed integrity
    raw_sha256: str = ""
    verified_sha256: str | None = None

    @property
    def is_verified(self) -> bool:
        """Pack is verified only if status is verified and byte checksum matches."""
        if self.status != PackStatus.VERIFIED:
            return False
        if not self.verified_by or not self.source_checked_on:
            return False
        if self.verified_sha256 and self.verified_sha256 != self.raw_sha256:
            return False
        return True


def compute_pack_bytes_hash(raw_bytes: bytes) -> str:
    """Computes SHA-256 over exact raw pack bytes, excluding verified_sha256 declaration.
    
    Exact byte hashing without CRLF normalization. Line endings are enforced via .gitattributes.
    """
    lines = [
        line for line in raw_bytes.splitlines(keepends=True)
        if not line.strip().startswith(b"verified_sha256:")
    ]
    return hashlib.sha256(b"".join(lines)).hexdigest()


class ObligationPackLoader:
    """Loads and validates regulatory packs from disk."""

    def __init__(self, packs_dir: str | Path | None = None):
        if packs_dir is None:
            # Default to repo root packs/obligations
            self.packs_dir = Path(__file__).resolve().parents[4] / "packs" / "obligations"
        else:
            self.packs_dir = Path(packs_dir)

    def load_pack_from_path(self, path: Path) -> ObligationPack:
        """Load single YAML pack with raw byte hashing and safe parsing."""
        raw_bytes = path.read_bytes()
        file_sha256 = compute_pack_bytes_hash(raw_bytes)

        # Parse safely
        try:
            parsed = yaml.safe_load(raw_bytes.decode("utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"Failed to parse obligation pack {path.name}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise ValueError(f"Invalid pack structure in {path.name}: expected mapping")

        pack = ObligationPack(**parsed)
        pack.raw_sha256 = file_sha256

        # Invalidate status if declared verified but checksum doesn't match or is absent
        if pack.status == PackStatus.VERIFIED:
            if not pack.verified_sha256 or pack.verified_sha256 != file_sha256:
                pack.status = PackStatus.DRAFT

        return pack

    def load_all_packs(self) -> list[ObligationPack]:
        """Load all .yaml packs from packs directory, deduplicated by pack ID."""
        if not self.packs_dir.exists():
            return []

        packs: list[ObligationPack] = []
        seen_ids: set[str] = set()
        for file_path in sorted(self.packs_dir.glob("*.yaml")):
            pack = self.load_pack_from_path(file_path)
            if pack.id not in seen_ids:
                seen_ids.add(pack.id)
                packs.append(pack)
        return packs

    def verify_production_readiness(self, is_production: bool) -> list[ObligationPack]:
        """Validate packs for current environment. Raises RuntimeError in production if drafts found."""
        packs = self.load_all_packs()
        if not packs:
            raise RuntimeError(f"Zero obligation packs found in {self.packs_dir}")

        if is_production:
            unverified = [p.id for p in packs if not p.is_verified]
            if unverified:
                raise RuntimeError(
                    f"Production startup aborted: Unverified or draft obligation packs detected: {unverified}. "
                    "All regulatory packs must be verified before production deployment per .agents/rules/30-regulatory-content.md"
                )

        return packs
