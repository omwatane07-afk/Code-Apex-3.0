"""Tests for UNIT 2: Milestone M2 - 20+ Tool High-Throughput Intake & Compliance Passports."""

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberq.api.app import app
from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.intake.certin_mapping import correlate_certin_reportability
from cyberq.intake.models import IntakeDeadLetter, ToolCompliancePassport
from cyberq.intake.parser import parse_cef_syslog, parse_json_event
from cyberq.intake.service import IntakePipelineService
from cyberq.intake.verifier import verify_webhook_hmac

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_SECRET = "banking-hmac-shared-secret-key-32chars!"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_cef_syslog_parser():
    """Verify RFC 5424 / CEF Syslog parsing with extensions and CVE extraction."""
    raw_cef = (
        "CEF:0|Palo Alto Networks|PAN-OS|11.0.2|threat|Palo Alto Threat Alert|8|"
        "src=10.14.2.55 dst=172.16.0.4 dhost=rtgs-switch.bank.internal cve=CVE-2024-3400 "
        "msg=Command injection exploit in GlobalProtect gateway"
    )
    event = parse_cef_syslog(raw_cef)
    assert event.source_ip == "10.14.2.55"
    assert event.destination_ip == "172.16.0.4"
    assert event.destination_hostname == "rtgs-switch.bank.internal"
    assert "CVE-2024-3400" in event.cve_ids
    assert event.severity == "high"


def test_20_plus_tool_profile_parsers():
    """Verify JSON normalizers across key bank security tools."""
    # 1. Splunk ES
    splunk_payload = {
        "result": {
            "sid": "SPLUNK-1234",
            "src_ip": "10.0.1.20",
            "dest_ip": "10.0.1.50",
            "search_name": "Lateral movement via WMI",
            "urgency": "critical",
            "description": "Correlated WMI process creation across tier-1 hosts",
        }
    }
    ev_splunk = parse_json_event("splunk-es", splunk_payload)
    assert ev_splunk.source_tool == "Splunk Enterprise Security"
    assert ev_splunk.severity == "critical"
    assert ev_splunk.source_ip == "10.0.1.20"

    # 2. CrowdStrike Falcon
    cs_payload = {
        "composite_id": "CS-998877",
        "event": {
            "LocalIP": "10.10.5.12",
            "ComputerName": "CORE-SRV-01",
            "DetectDescription": "Mimikatz memory injection",
            "SeverityName": "Critical",
            "Tactic": "Credential Access",
        }
    }
    ev_cs = parse_json_event("crowdstrike", cs_payload)
    assert ev_cs.source_tool == "CrowdStrike Falcon"
    assert ev_cs.source_hostname == "CORE-SRV-01"

    # 3. Imperva DAM
    imp_payload = {
        "alertId": "IMP-4433",
        "clientIp": "192.168.10.88",
        "serverIp": "10.20.1.5",
        "policyName": "UNAUTHORIZED_CUSTOMER_PAN_EXTRACTION",
        "description": "Mass SELECT executed on customer_cards table",
    }
    ev_imp = parse_json_event("imperva", imp_payload)
    assert ev_imp.category == "DAM"
    assert ev_imp.severity == "critical"

    # 4. CyberArk PAM
    cyb_payload = {
        "IncidentId": "CYB-7722",
        "SourceAddress": "10.5.1.99",
        "ActivityType": "SUSPICIOUS_VAULT_ACCESS",
        "Details": "Unscheduled domain controller password retrieval",
    }
    ev_cyb = parse_json_event("cyberark", cyb_payload)
    assert ev_cyb.category == "IAM/PAM"
    assert ev_cyb.source_ip == "10.5.1.99"


def test_hmac_replay_defense_and_timestamp_drift():
    """Verify HMAC-SHA256 signature verification and replay prevention."""
    payload = b'{"alert": "Suspicious login from TOR node"}'
    now = datetime.now(UTC)
    ts_header = now.isoformat()
    nonce = "nonce-unique-12345"

    # Compute valid signature
    mac = hmac.new(TEST_SECRET.encode("utf-8"), digestmod=hashlib.sha256)
    mac.update(ts_header.encode("utf-8"))
    mac.update(b".")
    mac.update(payload)
    valid_sig = mac.hexdigest()

    # 1. Valid request succeeds
    valid, _ = verify_webhook_hmac(
        payload_bytes=payload,
        secret_key=TEST_SECRET,
        signature_header=valid_sig,
        timestamp_header=ts_header,
        nonce_header=nonce,
        now=now,
    )
    assert valid is True

    # 2. Replayed nonce rejected
    replayed, reason_replay = verify_webhook_hmac(
        payload_bytes=payload,
        secret_key=TEST_SECRET,
        signature_header=valid_sig,
        timestamp_header=ts_header,
        nonce_header=nonce,
        now=now,
    )
    assert replayed is False
    assert "Replay detected" in reason_replay

    # 3. Timestamp drift > 300s rejected
    stale_ts = (now - timedelta(seconds=350)).isoformat()
    mac_stale = hmac.new(TEST_SECRET.encode("utf-8"), digestmod=hashlib.sha256)
    mac_stale.update(stale_ts.encode("utf-8"))
    mac_stale.update(b".")
    mac_stale.update(payload)
    stale_sig = mac_stale.hexdigest()

    stale_valid, reason_stale = verify_webhook_hmac(
        payload_bytes=payload,
        secret_key=TEST_SECRET,
        signature_header=stale_sig,
        timestamp_header=stale_ts,
        nonce_header="nonce-new-6789",
        now=now,
    )
    assert stale_valid is False
    assert "drift" in reason_stale


def test_dead_letter_queue_and_pii_strip_on_malformed_input(db_session):
    """Verify malformed payload is routed to Dead-Letter Queue with PII scrubbed."""
    svc = AuditService(TEST_SEED)
    pipeline = IntakePipelineService(svc)

    # Malformed JSON with an Aadhaar number (valid Verhoeff: 200000004118)
    malformed_body = b'{"malformed_json_missing_brace: "true", "aadhaar": "200000004118" '

    with pytest.raises(ValueError, match="Dead-Letter Queue"):
        pipeline.ingest_webhook(
            session=db_session,
            tool_identifier="splunk-es",
            raw_body=malformed_body,
            headers={"x-request-id": "req-dl-1"},
            client_ip="10.1.1.5",
        )
    db_session.commit()

    # Verify dead-letter entry
    dl = db_session.query(IntakeDeadLetter).first()
    assert dl is not None
    assert dl.source_tool == "splunk-es"
    assert "200000004118" not in dl.raw_payload_redacted
    assert "[REDACTED_AADHAAR]" in dl.raw_payload_redacted


def test_tool_compliance_passport_degraded_trust(db_session):
    """Verify expired VAPT certificate transitions tool to DEGRADED and flags UNVERIFIED_TELEMETRY."""
    svc = AuditService(TEST_SEED)
    pipeline = IntakePipelineService(svc)
    now = datetime.now(UTC)

    # Register expired passport
    passport = ToolCompliancePassport(
        tool_id="crowdstrike-falcon-tier1",
        tool_name="CrowdStrike Falcon Cluster",
        vendor="CrowdStrike",
        category="EDR/XDR",
        stqc_certificate_ref="STQC-CERT-2024-9912",
        auditor_name="KPMG Advisory Services (CERT-In Empanelled)",
        vapt_valid_from=now - timedelta(days=400),
        vapt_valid_until=now - timedelta(days=10),  # Expired 10 days ago!
        pades_signature_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        cyclonedx_sbom_digest="a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
        trust_status="VALID",
    )
    db_session.add(passport)
    db_session.commit()

    # Ingest alert from this tool
    raw_alert = json.dumps({
        "composite_id": "CS-ALERT-001",
        "event": {
            "LocalIP": "10.14.2.55",
            "DetectDescription": "Critical ransomware vssadmin shadow copy deletion",
            "SeverityName": "Critical",
        }
    }).encode("utf-8")

    event, incident = pipeline.ingest_webhook(
        session=db_session,
        tool_identifier="crowdstrike-falcon-tier1",
        raw_body=raw_alert,
        headers={},
    )
    db_session.commit()

    # Verify event flagged unverified telemetry
    assert event.is_telemetry_unverified is True
    # Verify tool passport marked DEGRADED
    db_session.refresh(passport)
    assert passport.trust_status == "DEGRADED"
    assert passport.para59_exception_ref is not None
    # Verify incident summary contains warning
    assert incident is not None
    assert "UNVERIFIED_TELEMETRY" in incident.summary


def test_certin_advisory_correlation():
    """Verify automatic correlation with statutory CERT-In advisories."""
    reportable, advisories, sev = correlate_certin_reportability(
        raw_text="Exploitation of CVE-2024-21413 Microsoft Outlook NTLM credential leak",
        cve_ids=["CVE-2024-21413"],
        signature_name="Outlook Exploit",
    )
    assert reportable is True
    assert sev == "critical"
    assert any("CIVN-2024-0089" in a for a in advisories)

    # Ransomware keywords
    rep_rw, adv_rw, sev_rw = correlate_certin_reportability(
        raw_text="Threat actor executed cryptolocker binary and purged vssadmin volume shadows",
        cve_ids=[],
    )
    assert rep_rw is True
    assert sev_rw == "critical"
    assert any("CERTIN-CAT-05" in a for a in adv_rw)
