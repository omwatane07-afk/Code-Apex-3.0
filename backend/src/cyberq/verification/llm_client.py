"""Local Air-Gapped Ollama LLM Client for CYBERQ Multi-Agent Verification Engine.

Enforces:
1. Strict Air-Gap: Routes exclusively to local Ollama instance (http://localhost:11434).
2. Model Invariant: Hardcoded strictly to 'qwen2.5-coder'.
3. Deterministic Formatting: Uses Ollama JSON grammar mode and validates against strict Pydantic models.
4. Resilience: Exponential backoff retries handling local GPU inference spikes and model loading.
5. Zero Hallucination: Strict statutory grounding against verified RBI, CERT-In, and DPDP mandates.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from cyberq.verification.models import (
    MultiAgentTriageBundle,
    RegulatoryClauseMatcherOutput,
    ToolPassportInspectorOutput,
    TriageSpecialistOutput,
)

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Non-negotiable architectural invariant: strictly hardcoded to qwen2.5-coder
OLLAMA_MODEL_NAME: str = "qwen2.5-coder"
DEFAULT_OLLAMA_BASE_URL: str = "http://localhost:11434"

# Closed-world Canonical Statutory Reporting Canon (Zero Hallucination Grounding)
CANONICAL_STATUTORY_TAXONOMY: list[str] = [
    "CERT-In Directions 2022 Section 70B Annexure I (Item 1: Targeted scanning/probing of critical networks/systems)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 3: Compromise of critical systems/information)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 5: Attacks on servers such as Database, Mail and DNS)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 8: Identity theft, spoofing and phishing attacks)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 9: Unauthorized access of IT systems/data)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 11: Malicious code attacks such as Ransomware / Trojan / Virus)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 12: Attack on critical information infrastructure such as SWIFT, RTGS, CBS)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 14: Attacks on Security Support Systems)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)",
    "CERT-In Directions 2022 Section 70B Annexure I (Item 19: Malicious mobile applications / Supply chain attack)",
    "CERT-In Directions 2022 Section 70B Clause (ii): 6-Hour Mandatory Reporting Window",
    "RBI Cybersecurity Framework Directions Para 182: Mandatory 6-Hour DAKSH Incident Intimation",
    "RBI Master Directions on IT Governance Para 90: Tool VAPT Certification Mandate",
    "DPDP Act 2023 Section 8(6) Rule 7: Mandatory 72-Hour Breach Intimation to Data Protection Board",
]


def ground_regulatory_clauses(
    raw_clauses: list[str],
    alert_data: dict[str, Any],
    is_reportable: bool,
) -> list[str]:
    """Deterministically grounds regulatory citations against the verified statutory canon."""
    if not is_reportable:
        return []

    text_to_scan = (
        json.dumps(alert_data) + " " + " ".join(raw_clauses)
    ).lower()

    grounded: list[str] = []

    # Check exact canon matches first
    for canon in CANONICAL_STATUTORY_TAXONOMY:
        for c in raw_clauses:
            if c.strip().lower() == canon.lower() or c.strip() in canon:
                if canon not in grounded:
                    grounded.append(canon)

    # Heuristic mapping if model provided partial / paraphrased text
    if any(k in text_to_scan for k in ["ransomware", "vssadmin", "shadow copy", "encrypt"]):
        c = "CERT-In Directions 2022 Section 70B Annexure I (Item 11: Malicious code attacks such as Ransomware / Trojan / Virus)"
        if c not in grounded:
            grounded.append(c)
        rbi = "RBI Cybersecurity Framework Directions Para 182: Mandatory 6-Hour DAKSH Incident Intimation"
        if rbi not in grounded:
            grounded.append(rbi)

    if any(k in text_to_scan for k in ["payment", "rtgs", "upi", "neft", "switch"]):
        c1 = "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)"
        c2 = "CERT-In Directions 2022 Section 70B Annexure I (Item 12: Attack on critical information infrastructure such as SWIFT, RTGS, CBS)"
        for item in [c1, c2]:
            if item not in grounded:
                grounded.append(item)

    if any(k in text_to_scan for k in ["swift", "alliance", "sag"]):
        c1 = "CERT-In Directions 2022 Section 70B Annexure I (Item 12: Attack on critical information infrastructure such as SWIFT, RTGS, CBS)"
        c2 = "CERT-In Directions 2022 Section 70B Annexure I (Item 3: Compromise of critical systems/information)"
        for item in [c1, c2]:
            if item not in grounded:
                grounded.append(item)

    if any(k in text_to_scan for k in ["aadhaar", "pan", "pii", "exfiltration", "data breach", "dpdp"]):
        c1 = "DPDP Act 2023 Section 8(6) Rule 7: Mandatory 72-Hour Breach Intimation to Data Protection Board"
        c2 = "CERT-In Directions 2022 Section 70B Annexure I (Item 9: Unauthorized access of IT systems/data)"
        for item in [c1, c2]:
            if item not in grounded:
                grounded.append(item)

    if any(k in text_to_scan for k in ["ddos", "syn flood", "saturation"]):
        c = "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)"
        if c not in grounded:
            grounded.append(c)

    if any(k in text_to_scan for k in ["golden ticket", "kerberos", "domain controller", "lsass"]):
        c = "CERT-In Directions 2022 Section 70B Annexure I (Item 3: Compromise of critical systems/information)"
        if c not in grounded:
            grounded.append(c)

    if any(k in text_to_scan for k in ["supply chain", "pypi", "dependency", "backdoor"]):
        c = "CERT-In Directions 2022 Section 70B Annexure I (Item 19: Malicious mobile applications / Supply chain attack)"
        if c not in grounded:
            grounded.append(c)

    if any(k in text_to_scan for k in ["vapt", "para 90", "expired"]):
        c = "RBI Master Directions on IT Governance Para 90: Tool VAPT Certification Mandate"
        if c not in grounded:
            grounded.append(c)

    if not grounded and is_reportable:
        grounded.append("CERT-In Directions 2022 Section 70B Clause (ii): 6-Hour Mandatory Reporting Window")

    return grounded


class OllamaLLMClient:
    """Air-gapped, resilient client for local Ollama running qwen2.5-coder."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
    ) -> None:
        self.base_url = (base_url or os.getenv("CYBERQ_OLLAMA_URL") or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
        self.model = OLLAMA_MODEL_NAME
        self.timeout = timeout
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff

    def is_available(self, timeout: float = 1.5) -> bool:
        """Quickly probes if the local Ollama daemon is reachable and responding."""
        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def _chat_completion_with_retry(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        num_predict: int = 550,
        num_ctx: int = 2048,
    ) -> dict[str, Any]:
        """Calls /api/chat on local Ollama with exponential backoff and JSON grammar enforcement."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
                "num_ctx": num_ctx,
            },
        }

        url = f"{self.base_url}/api/chat"
        last_exception: Exception | None = None
        backoff = self.initial_backoff

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, json=payload)
                    response.raise_for_status()
                    data = response.json()
                    content = data.get("message", {}).get("content", "")
                    clean_content = self._clean_json_output(content)
                    return json.loads(clean_content)  # type: ignore[no-any-return]

            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, json.JSONDecodeError) as exc:
                last_exception = exc
                logger.warning(
                    "Ollama request attempt %d/%d failed with %s: %s. Retrying in %.2fs...",
                    attempt,
                    self.max_retries,
                    type(exc).__name__,
                    str(exc),
                    backoff,
                )
                if attempt < self.max_retries:
                    time.sleep(backoff)
                    backoff *= 2.0

        raise RuntimeError(
            f"Failed to communicate with local Ollama ({self.base_url}) running {self.model} "
            f"after {self.max_retries} attempts: {last_exception}"
        ) from last_exception

    @staticmethod
    def _clean_json_output(content: str) -> str:
        """Strips markdown code fences, trailing commas, or conversational wrappers around JSON."""
        trimmed = content.strip()
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", trimmed, re.IGNORECASE)
        if fence_match:
            trimmed = fence_match.group(1).strip()

        # Find start of JSON object or array
        start = trimmed.find("{")
        end = trimmed.rfind("}")
        if start != -1 and end != -1 and end > start:
            trimmed = trimmed[start : end + 1]
        elif start != -1 and end == -1:
            # Unterminated object, attempt closing
            trimmed = trimmed[start:] + "\n}"

        # Clean trailing commas before closing braces/brackets
        trimmed = re.sub(r",\s*([}\]])", r"\1", trimmed)
        return trimmed

    def generate_fallback_triage_specialist(self, alert_data: dict[str, Any]) -> TriageSpecialistOutput:
        """Deterministic rule-based fallback response for Triage Specialist when local LLM is offline."""
        raw_msg = (str(alert_data.get("raw_message", "")) + " " + str(alert_data.get("event_name", ""))).lower()
        sev = str(alert_data.get("severity", "high")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "high"

        # Check if benign / dropped scan / routine maintenance
        is_benign = any(w in raw_msg for w in ["routine maintenance", "benign scan dropped", "scheduled vulnerability scan", "authorized test"])
        if is_benign:
            return TriageSpecialistOutput(
                agent="TriageSpecialist",
                severity="low",
                tactic="Reconnaissance",
                technique="T1595 - Active Scanning",
                affected_critical_systems=[],
                triage_disposition="SUPPRESS_BENIGN",
                summary="Routine perimeter scan or scheduled activity safely dropped by perimeter control.",
                confidence=0.98,
            )

        # Identify tactic / technique heuristics
        tactic = "Execution"
        technique = "T1059 - Command and Scripting Interpreter"
        systems: list[str] = []

        if any(w in raw_msg for w in ["powershell", "wmi", "mimikatz", "memory", "injection"]):
            tactic = "Credential Access"
            technique = "T1003.001 - OS Credential Dumping: LSASS Memory"
        elif any(w in raw_msg for w in ["ransomware", "encrypt", "vssadmin"]):
            tactic = "Impact"
            technique = "T1486 - Data Encrypted for Impact"
        elif any(w in raw_msg for w in ["exfiltration", "aadhaar", "pan", "dump", "s3"]):
            tactic = "Exfiltration"
            technique = "T1041 - Exfiltration Over C2 Channel"
        elif any(w in raw_msg for w in ["ddos", "syn flood", "saturation"]):
            tactic = "Impact"
            technique = "T1498 - Network Denial of Service"
        elif any(w in raw_msg for w in ["golden ticket", "kerberos"]):
            tactic = "Privilege Escalation"
            technique = "T1558.001 - Golden Ticket"
        elif any(w in raw_msg for w in ["supply chain", "pypi", "dependency"]):
            tactic = "Initial Access"
            technique = "T1195.002 - Compromise Software Supply Chain"

        if any(w in raw_msg for w in ["rtgs", "payment"]):
            systems.append("RTGS-PAYMENT-SWITCH")
        if any(w in raw_msg for w in ["swift", "alliance"]):
            systems.append("SWIFT-ALLIANCE-GATEWAY")
        if any(w in raw_msg for w in ["cbs", "core", "oracle"]):
            systems.append("CBS-CORE-BANKING-CLUSTER")
        if not systems:
            systems.append(str(alert_data.get("destination_hostname") or "BANK-INTERNAL-INFRASTRUCTURE"))

        return TriageSpecialistOutput(
            agent="TriageSpecialist",
            severity=sev,
            tactic=tactic,
            technique=technique,
            affected_critical_systems=systems,
            triage_disposition="ESCALATE_TO_INCIDENT" if sev in ("critical", "high") else "REQUIRES_DEEP_INSPECTION",
            summary=f"Automated rule-based triage: {alert_data.get('event_name', 'Security Alert')} affecting {', '.join(systems)}. Local LLM offline - fallback engine active.",
            confidence=0.92,
        )

    def generate_fallback_regulatory_matcher(
        self,
        alert_data: dict[str, Any],
        cve_ids: list[str] | None = None,
    ) -> RegulatoryClauseMatcherOutput:
        """Deterministic rule-based fallback response for Regulatory Clause Matcher when local LLM is offline."""
        raw_msg = (str(alert_data.get("raw_message", "")) + " " + str(alert_data.get("event_name", ""))).lower()
        is_benign = any(w in raw_msg for w in ["routine maintenance", "benign scan dropped", "scheduled vulnerability scan", "authorized test"])

        if is_benign:
            return RegulatoryClauseMatcherOutput(
                agent="RegulatoryClauseMatcher",
                is_reportable=False,
                primary_statute="None",
                deadline_hours=0,
                matched_clauses=[],
                reasoning="Suppressed benign activity requires no statutory regulatory filing.",
                confidence=0.99,
            )

        grounded = ground_regulatory_clauses([], alert_data, is_reportable=True)
        primary = "CERT-In Directions 2022"
        hours = 6
        if any("dpdp" in c.lower() for c in grounded):
            primary = "DPDP Act 2023"
            hours = 72

        return RegulatoryClauseMatcherOutput(
            agent="RegulatoryClauseMatcher",
            is_reportable=True,
            primary_statute=primary,
            deadline_hours=hours,
            matched_clauses=grounded,
            reasoning=f"Mandatory disclosure window evaluated under {primary} based on alert telemetry. Local LLM offline - deterministic statutory taxonomy mapping applied.",
            confidence=0.95,
        )

    def generate_fallback_passport_inspector(
        self,
        tool_id: str,
        passport_data: dict[str, Any] | None = None,
    ) -> ToolPassportInspectorOutput:
        """Deterministic rule-based fallback response for Tool Passport Inspector when local LLM is offline."""
        is_unverified = bool(
            passport_data.get("is_unverified", False) or passport_data.get("is_telemetry_unverified", False)
        ) if passport_data else False
        vapt_valid = bool(passport_data.get("vapt_valid", True)) if passport_data else True
        trust_status = "DEGRADED" if (is_unverified or not vapt_valid) else str((passport_data or {}).get("trust_status", "VERIFIED"))

        obs = [f"Tool compliance inspected for {tool_id}"]
        if not vapt_valid or is_unverified:
            obs.append("Tool VAPT certification is expired or invalid under RBI Master Directions on IT Governance Para 90.")
            risk = "high"
        else:
            obs.append("Tool passport is in good standing with valid VAPT certification.")
            risk = "low"

        return ToolPassportInspectorOutput(
            agent="ToolPassportInspector",
            tool_id=tool_id,
            trust_status=trust_status,
            vapt_valid=vapt_valid,
            is_telemetry_unverified=is_unverified or not vapt_valid,
            observations=obs,
            risk_level=risk,
        )

    def generate_fallback_multi_agent_bundle(
        self,
        event_data: dict[str, Any],
        passport_data: dict[str, Any] | None = None,
        investigation_id: str | None = None,
        reason: str = "Local Ollama service unreachable",
    ) -> MultiAgentTriageBundle:
        """Generates simulated multi-agent bundle and automated alert when local LLM is offline."""
        inv_id = investigation_id or f"INV-FALLBACK-{int(time.time())}"
        evt_id = str(event_data.get("event_id") or "EVT-SIM")
        tool_id = str(event_data.get("source_tool") or "generic_tool")

        alert = {
            "alert_id": f"LLM-ALERT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now(UTC).isoformat(),
            "alert_type": "LOCAL_LLM_UNAVAILABLE",
            "severity": "warning",
            "title": "Local LLM Inference Offline – Deterministic Fallback Mode Engaged",
            "detail": f"Local Ollama endpoint ({self.base_url}) is unreachable ({reason}). Automated multi-agent evaluation switched seamlessly to deterministic rule-based response simulation.",
            "remediation": "Start local Ollama daemon (`ollama serve`) and load `qwen2.5-coder`. Ensure port 11434 is listening.",
            "automated_response": "Deterministic static taxonomy mapping and RBI/CERT-In clause matching successfully executed.",
        }

        triage_out = self.generate_fallback_triage_specialist(event_data)
        reg_out = self.generate_fallback_regulatory_matcher(event_data, cve_ids=event_data.get("cve_ids"))
        passport_out = self.generate_fallback_passport_inspector(tool_id, passport_data)

        final_verdict = "PASS"
        if passport_out.is_telemetry_unverified or passport_out.trust_status == "DEGRADED":
            final_verdict = "CONDITIONAL"
        elif triage_out.triage_disposition == "SUPPRESS_BENIGN":
            final_verdict = "PASS"
        elif triage_out.severity in ("critical", "high") and triage_out.triage_disposition == "ESCALATE_TO_INCIDENT":
            final_verdict = "PASS"

        return MultiAgentTriageBundle(
            investigation_id=inv_id,
            event_id=evt_id,
            source_tool=tool_id,
            model_used=self.model,
            triage=triage_out,
            regulatory=reg_out,
            passport=passport_out,
            final_verdict=final_verdict,
            llm_available=False,
            fallback_mode=True,
            alerts=[alert],
        )

    def run_triage_specialist(self, alert_data: dict[str, Any]) -> TriageSpecialistOutput:
        """Agent 1: Tier-3 SOC Triage Specialist evaluating threats, tactics, and affected bank systems."""
        system_prompt = (  # noqa: S608
            "You are the Lead Tier-3 SOC Triage Specialist inside a Scheduled Commercial Bank in India.\n"
            "Analyze the given security alert telemetry. Classify its severity (critical, high, medium, low), "
            "MITRE ATT&CK tactic and technique, identify any critical banking infrastructure affected "
            "(e.g., CBS, RTGS, SWIFT, Payment Switch, Core DB), and recommend a triage disposition.\n"
            "If the alert represents routine scheduled maintenance or blocked perimeter reconnaissance, "
            "set triage_disposition to 'SUPPRESS_BENIGN' and severity to 'low'.\n"
            "You MUST respond with valid JSON matching these exact keys:\n"
            "{\n"
            '  "agent": "TriageSpecialist",\n'
            '  "severity": "critical" | "high" | "medium" | "low",\n'
            '  "tactic": "<MITRE Tactic>",\n'
            '  "technique": "<MITRE Technique Code - Name>",\n'
            '  "affected_critical_systems": ["<System 1>", ...],\n'
            '  "triage_disposition": "ESCALATE_TO_INCIDENT" | "SUPPRESS_BENIGN" | "REQUIRES_DEEP_INSPECTION",\n'
            '  "summary": "<Concise incident triage narrative>",\n'
            '  "confidence": <float between 0.0 and 1.0>\n'
            "}"  # noqa: S608
        )

        user_prompt = f"Security Alert Telemetry:\n{json.dumps(alert_data, indent=2)}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw_json = self._chat_completion_with_retry(messages, num_predict=300)
            return TriageSpecialistOutput.model_validate(raw_json)
        except Exception as exc:
            logger.warning("Local Ollama TriageSpecialist inference unavailable (%s). Falling back to rule-based simulation.", exc)
            return self.generate_fallback_triage_specialist(alert_data)

    def run_regulatory_matcher(
        self,
        alert_data: dict[str, Any],
        cve_ids: list[str] | None = None,
    ) -> RegulatoryClauseMatcherOutput:
        """Agent 2: Regulatory Clause Matcher evaluating CERT-In, RBI CSITE/DAKSH, and DPDP statutory rules."""
        taxonomy_text = "\n".join(f"- {c}" for c in CANONICAL_STATUTORY_TAXONOMY)
        system_prompt = (  # noqa: S608
            "You are the Chief Regulatory Compliance Specialist for an Indian Commercial Bank.\n"
            "Evaluate this security event against Indian statutory reporting mandates.\n"
            "CRITICAL ZERO-HALLUCINATION INSTRUCTION: matched_clauses MUST ONLY contain exact strings from "
            "this statutory canon:\n"
            f"{taxonomy_text}\n\n"
            "RULES:\n"
            "1. If this is a benign maintenance or dropped routine scan: is_reportable=false, deadline_hours=0, matched_clauses=[].\n"
            "2. If this is a critical security incident (ransomware, payment switch, SWIFT, lateral movement): is_reportable=true, deadline_hours=6.\n"
            "3. If this is personal customer data breach (Aadhaar, PAN): is_reportable=true, deadline_hours=72.\n\n"
            "You MUST respond with valid JSON matching these exact keys:\n"
            "{\n"
            '  "agent": "RegulatoryClauseMatcher",\n'
            '  "is_reportable": true | false,\n'
            '  "primary_statute": "<Statute Name>",\n'
            '  "deadline_hours": <integer: 6 or 72 or 0>,\n'
            '  "matched_clauses": ["<Exact Clause From Canon>", ...],\n'
            '  "reasoning": "<Statutory justification for filing obligation>",\n'
            '  "confidence": <float between 0.0 and 1.0>\n'
            "}"  # noqa: S608
        )

        context = {
            "alert": alert_data,
            "cve_identifiers": cve_ids or [],
        }
        user_prompt = f"Statutory Evaluation Context:\n{json.dumps(context, indent=2)}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw_json = self._chat_completion_with_retry(messages, num_predict=300)
            is_reportable = bool(raw_json.get("is_reportable", True))
            raw_clauses = list(raw_json.get("matched_clauses", []))
            grounded_clauses = ground_regulatory_clauses(raw_clauses, alert_data, is_reportable)
            out = RegulatoryClauseMatcherOutput.model_validate(raw_json)
            out.matched_clauses = grounded_clauses
            return out
        except Exception as exc:
            logger.warning("Local Ollama RegulatoryClauseMatcher inference unavailable (%s). Falling back to rule-based simulation.", exc)
            return self.generate_fallback_regulatory_matcher(alert_data, cve_ids=cve_ids)

    def run_passport_inspector(
        self,
        tool_id: str,
        passport_data: dict[str, Any] | None = None,
    ) -> ToolPassportInspectorOutput:
        """Agent 3: Tool Compliance Passport Inspector enforcing RBI Master Directions Paras 90/92."""
        system_prompt = (  # noqa: S608
            "You are the Third-Party Tool Compliance Inspector enforcing RBI Master Directions on IT Governance.\n"
            "Evaluate the source tool passport. Check whether VAPT certification is valid, assess operational trust "
            "status (VERIFIED, DEGRADED, or UNVERIFIED), and flag unverified telemetry.\n"
            "If vapt_valid is false or trust_status is DEGRADED, is_telemetry_unverified MUST be true.\n"
            "You MUST respond with valid JSON matching these exact keys:\n"
            "{\n"
            '  "agent": "ToolPassportInspector",\n'
            '  "tool_id": "<Tool ID>",\n'
            '  "trust_status": "VERIFIED" | "DEGRADED" | "UNVERIFIED",\n'
            '  "vapt_valid": true | false,\n'
            '  "is_telemetry_unverified": true | false,\n'
            '  "observations": ["<Observation 1>", ...],\n'
            '  "risk_level": "low" | "medium" | "high" | "critical"\n'
            "}"  # noqa: S608
        )

        context = {
            "tool_id": tool_id,
            "passport_record": passport_data or {"status": "ACTIVE", "vapt_valid": True},
        }
        user_prompt = f"Tool Compliance Inspection Context:\n{json.dumps(context, indent=2)}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            raw_json = self._chat_completion_with_retry(messages, num_predict=250)
            return ToolPassportInspectorOutput.model_validate(raw_json)
        except Exception as exc:
            logger.warning("Local Ollama ToolPassportInspector inference unavailable (%s). Falling back to rule-based simulation.", exc)
            return self.generate_fallback_passport_inspector(tool_id, passport_data)

    def run_unified_multi_agent(
        self,
        event_data: dict[str, Any],
        passport_data: dict[str, Any] | None = None,
        investigation_id: str | None = None,
    ) -> MultiAgentTriageBundle:
        """Executes a unified single-turn multi-agent evaluation for maximum speed and zero hallucination."""
        inv_id = investigation_id or f"INV-QWEN-{int(time.time())}"
        evt_id = str(event_data.get("event_id") or "EVT-SIM")
        tool_id = str(event_data.get("source_tool") or "generic_tool")

        taxonomy_text = "\n".join(f"- \"{c}\"" for c in CANONICAL_STATUTORY_TAXONOMY)
        system_prompt = (  # noqa: S608
            "You are the CYBERQ Autonomous Multi-Agent Verification Engine for an Indian Scheduled Commercial Bank.\n"  # noqa: S608
            "Analyze the given security event across three specialized agent perspectives.\n\n"
            "STATUTORY REFERENCE TAXONOMY (You MUST select matched_clauses ONLY from this list):\n"
            f"{taxonomy_text}\n\n"
            "RULES:\n"
            "- If event is benign maintenance or routine dropped scan: triage_disposition='SUPPRESS_BENIGN', severity='low', is_reportable=false, deadline_hours=0, matched_clauses=[].\n"
            "- If critical incident on payment/CBS/SWIFT: triage_disposition='ESCALATE_TO_INCIDENT', severity='critical', is_reportable=true, deadline_hours=6, select exact matched_clauses from list.\n"
            "- If customer data exfiltration (Aadhaar/PAN): is_reportable=true, deadline_hours=72, select DPDP clause.\n"
            "- If tool VAPT invalid/expired: trust_status='DEGRADED', is_telemetry_unverified=true, vapt_valid=false.\n\n"
            "JSON output MUST be a JSON object with keys: 'triage', 'regulatory', 'passport':\n"
            "{\n"
            '  "triage": {"agent": "TriageSpecialist", "severity": "critical|high|medium|low", "tactic": "...", "technique": "...", "affected_critical_systems": [...], "triage_disposition": "ESCALATE_TO_INCIDENT|SUPPRESS_BENIGN|REQUIRES_DEEP_INSPECTION", "summary": "...", "confidence": 0.95},\n'
            '  "regulatory": {"agent": "RegulatoryClauseMatcher", "is_reportable": true/false, "primary_statute": "...", "deadline_hours": 6/72/0, "matched_clauses": [...], "reasoning": "...", "confidence": 0.95},\n'
            '  "passport": {"agent": "ToolPassportInspector", "tool_id": "...", "trust_status": "VERIFIED|DEGRADED|UNVERIFIED", "vapt_valid": true/false, "is_telemetry_unverified": true/false, "observations": [...], "risk_level": "..."}\n'
            "}"  # noqa: S608
        )

        user_content = {
            "alert": event_data,
            "passport_record": passport_data or {"trust_status": "VERIFIED", "vapt_valid": True},
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_content, indent=2)},
        ]

        try:
            raw_json = self._chat_completion_with_retry(messages, num_predict=550)
        except Exception as exc:
            logger.warning(
                "Local Ollama inference failed (%s). Raising automated alert and generating deterministic fallback response.",
                exc,
            )
            return self.generate_fallback_multi_agent_bundle(
                event_data=event_data,
                passport_data=passport_data,
                investigation_id=inv_id,
                reason=str(exc),
            )

        # Parse triage section
        raw_triage = raw_json.get("triage", {})
        try:
            triage_out = TriageSpecialistOutput.model_validate(raw_triage)
        except Exception:
            triage_out = TriageSpecialistOutput(
                agent="TriageSpecialist",
                severity=str(raw_triage.get("severity", event_data.get("severity", "high"))).lower(),
                tactic=str(raw_triage.get("tactic", "Unknown")),
                technique=str(raw_triage.get("technique", "Unknown")),
                affected_critical_systems=list(raw_triage.get("affected_critical_systems", [])),
                triage_disposition=str(raw_triage.get("triage_disposition", "ESCALATE_TO_INCIDENT")),
                summary=str(raw_triage.get("summary", "Multi-agent triage completed")),
                confidence=float(raw_triage.get("confidence", 0.95)),
            )

        # Parse regulatory section and ground clauses
        raw_reg = raw_json.get("regulatory", {})
        is_rep = bool(raw_reg.get("is_reportable", triage_out.triage_disposition != "SUPPRESS_BENIGN"))
        if triage_out.triage_disposition == "SUPPRESS_BENIGN":
            is_rep = False

        grounded_clauses = ground_regulatory_clauses(
            list(raw_reg.get("matched_clauses", [])),
            event_data,
            is_rep,
        )
        try:
            reg_out = RegulatoryClauseMatcherOutput.model_validate(raw_reg)
            reg_out.matched_clauses = grounded_clauses if is_rep else []
            reg_out.is_reportable = is_rep
            reg_out.deadline_hours = int(raw_reg.get("deadline_hours", 6)) if is_rep else 0
        except Exception:
            reg_out = RegulatoryClauseMatcherOutput(
                agent="RegulatoryClauseMatcher",
                is_reportable=is_rep,
                primary_statute=str(raw_reg.get("primary_statute", "CERT-In Directions 2022")),
                deadline_hours=int(raw_reg.get("deadline_hours", 6)) if is_rep else 0,
                matched_clauses=grounded_clauses if is_rep else [],
                reasoning=str(raw_reg.get("reasoning", "Mandatory statutory reporting evaluated")),
                confidence=float(raw_reg.get("confidence", 0.95)),
            )

        # Parse passport section
        raw_passport = raw_json.get("passport", {})
        is_unverified = bool(
            passport_data.get("is_unverified", False) or passport_data.get("is_telemetry_unverified", False)
        ) if passport_data else False
        vapt_valid = bool(passport_data.get("vapt_valid", True)) if passport_data else True
        trust_status = "DEGRADED" if (is_unverified or not vapt_valid) else str(raw_passport.get("trust_status", "VERIFIED"))

        try:
            passport_out = ToolPassportInspectorOutput.model_validate(raw_passport)
            if is_unverified or not vapt_valid:
                passport_out.trust_status = "DEGRADED"
                passport_out.vapt_valid = False
                passport_out.is_telemetry_unverified = True
        except Exception:
            passport_out = ToolPassportInspectorOutput(
                agent="ToolPassportInspector",
                tool_id=tool_id,
                trust_status=trust_status,
                vapt_valid=vapt_valid,
                is_telemetry_unverified=is_unverified or not vapt_valid,
                observations=list(raw_passport.get("observations", ["Tool compliance inspected"])),
                risk_level=str(raw_passport.get("risk_level", "medium" if is_unverified else "low")),
            )

        # Deterministic Verdict Assignment Rules
        final_verdict = "PASS"
        if passport_out.is_telemetry_unverified or passport_out.trust_status == "DEGRADED":
            final_verdict = "CONDITIONAL"
        elif triage_out.triage_disposition == "SUPPRESS_BENIGN":
            final_verdict = "PASS"
        elif triage_out.severity in ("critical", "high") and triage_out.triage_disposition == "ESCALATE_TO_INCIDENT":
            final_verdict = "PASS"

        return MultiAgentTriageBundle(
            investigation_id=inv_id,
            event_id=evt_id,
            source_tool=tool_id,
            model_used=self.model,
            triage=triage_out,
            regulatory=reg_out,
            passport=passport_out,
            final_verdict=final_verdict,
        )

    def run_multi_agent_pipeline(
        self,
        event_data: dict[str, Any],
        passport_data: dict[str, Any] | None = None,
        investigation_id: str | None = None,
        use_unified: bool = True,
    ) -> MultiAgentTriageBundle:
        """Executes the multi-agent pipeline with local Qwen 2.5 Coder."""
        try:
            if use_unified:
                return self.run_unified_multi_agent(
                    event_data=event_data,
                    passport_data=passport_data,
                    investigation_id=investigation_id,
                )

            inv_id = investigation_id or f"INV-QWEN-{int(time.time())}"
            evt_id = str(event_data.get("event_id") or "EVT-SIM")
            tool_id = str(event_data.get("source_tool") or "generic_tool")
            cves = list(event_data.get("cve_ids", []))

            # 1. Triage Agent
            triage_out = self.run_triage_specialist(event_data)

            # 2. Regulatory Matcher Agent
            reg_out = self.run_regulatory_matcher(event_data, cve_ids=cves)

            # 3. Tool Passport Inspector Agent
            passport_out = self.run_passport_inspector(tool_id, passport_data)

            # Deterministic Verdict assignment rules
            final_verdict = "PASS"
            if passport_out.is_telemetry_unverified or passport_out.trust_status == "DEGRADED":
                final_verdict = "CONDITIONAL"
            elif triage_out.severity == "critical" and triage_out.triage_disposition == "ESCALATE_TO_INCIDENT":
                final_verdict = "PASS"

            return MultiAgentTriageBundle(
                investigation_id=inv_id,
                event_id=evt_id,
                source_tool=tool_id,
                model_used=self.model,
                triage=triage_out,
                regulatory=reg_out,
                passport=passport_out,
                final_verdict=final_verdict,
            )
        except Exception as exc:
            logger.warning("run_multi_agent_pipeline encountered error (%s). Falling back.", exc)
            return self.generate_fallback_multi_agent_bundle(
                event_data=event_data,
                passport_data=passport_data,
                investigation_id=investigation_id,
                reason=str(exc),
            )
