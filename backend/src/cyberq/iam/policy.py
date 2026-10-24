"""Centralized IAM policy engine. Deny by default.

Implements banking-grade RBAC, separation of duties, and explicit permission checks.
"""

import unicodedata
import uuid
from enum import StrEnum
from typing import NamedTuple


class Role(StrEnum):
    ANALYST = "analyst"
    COMPLIANCE_APPROVER = "compliance_approver"
    CISO = "ciso"
    DPO = "dpo"
    AUDITOR = "auditor"
    MODEL_VALIDATOR = "model_validator"
    ADMIN = "admin"
    WALLBOARD = "wallboard"


class Action(StrEnum):
    # Incidents & Triggers
    INCIDENT_CREATE = "incident:create"
    INCIDENT_READ = "incident:read"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_SEVERITY_SET = "incident:severity_set"
    INCIDENT_MAJOR_DECLARE = "incident:major_declare"
    INCIDENT_CLOSE_APPROVE = "incident:close_approve"
    INCIDENT_IP_UNMASK = "incident:ip_unmask"
    IP_TRACEABILITY_UNMASK = "incident:ip_traceability_unmask"
    TRIGGER_ASSERT = "trigger:assert"
    TRIGGER_DISPUTE_RESOLVE = "trigger:dispute_resolve"
    WALLBOARD_READ = "wallboard:read"

    # Filing Packets & Reports
    PACKET_PREPARE = "packet:prepare"
    PACKET_APPROVE = "packet:approve"
    PACKET_RECORD_FILED = "packet:record_filed"
    PACKET_READ = "packet:read"
    STATUTORY_REPORT_DOWNLOAD = "report:statutory_download"
    DPDP_REPORT_TRIGGER = "report:dpdp_trigger"
    DPDP_REPORT_DOWNLOAD = "report:dpdp_download"

    # Decisions & Governance
    DECISION_READ = "decision:read"
    DECISION_CREATE = "decision:create"
    DECISION_APPROVE = "decision:approve"
    BOARD_PACK_READ = "board_pack:read"
    BOARD_PACK_EXPORT = "board_pack:export"

    # Exposure & Models
    EXPOSURE_RUN = "exposure:run"
    MODEL_INVENTORY_READ = "model_inventory:read"
    MODEL_VALIDATE = "model:validate"

    # Audit & Evidence
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    EVIDENCE_EXPORT = "evidence:export"

    # Administration
    ADMIN_CONFIG = "admin:config"
    ADMIN_USER_MANAGE = "admin:user_manage"


# Explicit Role Permission Allow-lists
# Deny by default: any role not explicitly listed for an action is denied.
ROLE_PERMISSIONS: dict[Role, set[Action]] = {
    Role.ANALYST: {
        Action.INCIDENT_CREATE,
        Action.INCIDENT_READ,
        Action.INCIDENT_UPDATE,
        Action.TRIGGER_ASSERT,
        Action.PACKET_PREPARE,
        Action.PACKET_READ,
        Action.DECISION_READ,
        Action.BOARD_PACK_READ,
        Action.WALLBOARD_READ,
    },
    Role.COMPLIANCE_APPROVER: {
        Action.INCIDENT_READ,
        Action.INCIDENT_UPDATE,
        Action.TRIGGER_ASSERT,
        Action.TRIGGER_DISPUTE_RESOLVE,
        Action.PACKET_READ,
        Action.PACKET_APPROVE,
        Action.PACKET_RECORD_FILED,
        Action.STATUTORY_REPORT_DOWNLOAD,
        Action.DPDP_REPORT_TRIGGER,
        Action.DPDP_REPORT_DOWNLOAD,
        Action.DECISION_READ,
        Action.DECISION_APPROVE,
        Action.BOARD_PACK_READ,
        Action.WALLBOARD_READ,
    },
    Role.CISO: {
        Action.INCIDENT_READ,
        Action.INCIDENT_UPDATE,
        Action.INCIDENT_SEVERITY_SET,
        Action.INCIDENT_MAJOR_DECLARE,
        Action.INCIDENT_CLOSE_APPROVE,
        Action.INCIDENT_IP_UNMASK,
        Action.IP_TRACEABILITY_UNMASK,
        Action.TRIGGER_DISPUTE_RESOLVE,
        Action.PACKET_READ,
        Action.STATUTORY_REPORT_DOWNLOAD,
        Action.DPDP_REPORT_TRIGGER,
        Action.DPDP_REPORT_DOWNLOAD,
        Action.DECISION_READ,
        Action.DECISION_CREATE,
        Action.DECISION_APPROVE,
        Action.BOARD_PACK_READ,
        Action.BOARD_PACK_EXPORT,
        Action.EXPOSURE_RUN,
        Action.MODEL_INVENTORY_READ,
        Action.AUDIT_READ,
        Action.AUDIT_VERIFY,
        Action.WALLBOARD_READ,
    },
    Role.DPO: {
        Action.INCIDENT_READ,
        Action.INCIDENT_UPDATE,
        Action.TRIGGER_ASSERT,
        Action.PACKET_READ,
        Action.PACKET_APPROVE,
        Action.STATUTORY_REPORT_DOWNLOAD,
        Action.DPDP_REPORT_TRIGGER,
        Action.DPDP_REPORT_DOWNLOAD,
        Action.DECISION_READ,
        Action.BOARD_PACK_READ,
        Action.WALLBOARD_READ,
        Action.AUDIT_READ,
        Action.AUDIT_VERIFY,
    },
    Role.AUDITOR: {
        Action.INCIDENT_READ,
        Action.PACKET_READ,
        Action.STATUTORY_REPORT_DOWNLOAD,
        Action.DPDP_REPORT_DOWNLOAD,
        Action.DECISION_READ,
        Action.BOARD_PACK_READ,
        Action.AUDIT_READ,
        Action.AUDIT_VERIFY,
        Action.EVIDENCE_EXPORT,
        Action.MODEL_INVENTORY_READ,
        Action.WALLBOARD_READ,
    },
    Role.MODEL_VALIDATOR: {
        Action.MODEL_INVENTORY_READ,
        Action.MODEL_VALIDATE,
        Action.DECISION_READ,
        Action.BOARD_PACK_READ,
        Action.AUDIT_READ,
        Action.AUDIT_VERIFY,
    },
    Role.ADMIN: {
        Action.ADMIN_CONFIG,
        Action.ADMIN_USER_MANAGE,
        Action.AUDIT_VERIFY,
    },
    Role.WALLBOARD: {
        Action.WALLBOARD_READ,
    },
}


class AuthContext(NamedTuple):
    user_id: str
    role: Role


class PolicyEngine:
    """Evaluates whether an actor has permission to perform an action on a resource."""

    @staticmethod
    def is_allowed(role: Role | str, action: Action | str) -> bool:
        """Deny-by-default role permission evaluation."""
        try:
            r = Role(role)
            a = Action(action)
        except ValueError:
            return False

        allowed_actions = ROLE_PERMISSIONS.get(r, set())
        return a in allowed_actions

    @staticmethod
    def can_assert_trigger(role: Role | str, trigger_type: str) -> bool:
        """Enforces role-based statutory trigger assertion rules.

        Strict constraint: ONLY Role.ANALYST is permitted to assert the statutory DPDP 'aware' trigger.
        Other triggers require Action.TRIGGER_ASSERT.
        """
        try:
            r = Role(role)
        except ValueError:
            return False

        if not PolicyEngine.is_allowed(r, Action.TRIGGER_ASSERT):
            return False

        if trigger_type == "aware":
            return r == Role.ANALYST

        return True

    @staticmethod
    def _normalize_id(val: str) -> str:
        if not val:
            return ""
        norm = unicodedata.normalize("NFKC", str(val))
        cleaned = "".join(ch for ch in norm if unicodedata.category(ch) not in {"Cf", "Cc", "Cs"})
        return cleaned.strip().casefold()

    @staticmethod
    def check_maker_checker(prepared_by_user_id: str, approver_user_id: str) -> bool:
        """Enforces maker-checker separation: the user who prepared an item cannot approve it.

        Compares immutable server-issued user UUIDs bound to the IdP subject.
        Rejects identical users regardless of casing, whitespace, or unicode variations.
        """
        if not prepared_by_user_id or not approver_user_id:
            return False
        prep = PolicyEngine._normalize_id(prepared_by_user_id)
        appr = PolicyEngine._normalize_id(approver_user_id)
        if not prep or not appr:
            return False

        # If IDs are valid UUIDs, compare their canonical 128-bit values
        try:
            prep_uuid = uuid.UUID(prep)
            appr_uuid = uuid.UUID(appr)
            return prep_uuid != appr_uuid
        except (ValueError, AttributeError):
            # Fall back to normalized identifier comparison for legacy/test identifiers
            return prep != appr
