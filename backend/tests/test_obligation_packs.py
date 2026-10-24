"""Tests for Obligation Pack Loader, safe YAML deserialization, and production gate."""

import pytest

from cyberq.obligations.loader import ObligationPackLoader, PackStatus, TriggerEventType


def test_obligation_pack_loader_loads_starter_packs():
    loader = ObligationPackLoader()
    packs = loader.load_all_packs()
    assert len(packs) == 3

    pack_map = {p.id: p for p in packs}
    assert "certin-directions-2022" in pack_map
    assert "rbi-cybersecurity-directions-2026" in pack_map
    assert "dpdp-rules-2025" in pack_map

    # Check CERT-In pack
    certin = pack_map["certin-directions-2022"]
    assert certin.regulator == "CERT-In"
    assert certin.trigger_event == TriggerEventType.NOTICED
    assert certin.deadline_hours == 6
    assert certin.filing_fields == []
    assert certin.status == PackStatus.DRAFT

    # Check RBI pack
    rbi = pack_map["rbi-cybersecurity-directions-2026"]
    assert rbi.regulator == "RBI"
    assert rbi.trigger_event == TriggerEventType.DETECTED
    assert rbi.deadline_hours == 6
    assert rbi.filing_fields == []

    # Check DPDP pack
    dpdp = pack_map["dpdp-rules-2025"]
    assert dpdp.regulator == "DPDP"
    assert dpdp.trigger_event == TriggerEventType.AWARE
    assert dpdp.deadline_hours == 72
    assert dpdp.filing_fields == []


def test_safe_yaml_loading_rejects_object_execution_tags(tmp_path):
    malicious_yaml = tmp_path / "malicious.yaml"
    malicious_yaml.write_text(
        "id: pwn\n"
        "regulator: BAD\n"
        "instrument: BAD\n"
        "payload: !!python/object/apply:os.system ['echo pwned']\n"
    )

    loader = ObligationPackLoader(tmp_path)
    with pytest.raises(ValueError, match="Failed to parse|could not determine a constructor"):
        loader.load_pack_from_path(malicious_yaml)


def test_production_mode_refuses_draft_packs():
    loader = ObligationPackLoader()
    with pytest.raises(RuntimeError, match="Production startup aborted: Unverified or draft obligation packs detected"):
        loader.verify_production_readiness(is_production=True)


def test_post_verification_byte_mutation_invalidates_pack(tmp_path):
    pack_file = tmp_path / "test_pack.yaml"
    pack_content = (
        "id: verified-test-pack\n"
        "regulator: CERT-In\n"
        "instrument: Test Instrument\n"
        "clause_ref: Clause 1\n"
        "applies_to: [commercial_bank]\n"
        "trigger_event: noticed\n"
        "deadline_hours: 6\n"
        "effective_from: '2026-01-01'\n"
        "channel: portal\n"
        "channel_notes: portal notes\n"
        "filing_fields: []\n"
        "source_url: https://bank.internal/rule\n"
        "source_checked_on: '2026-10-11'\n"
        "verified_by: 'Senior Compliance Officer'\n"
        "status: verified\n"
        "notes: 'Verified against primary gazette'\n"
    )
    pack_file.write_bytes(pack_content.encode("utf-8"))
    from cyberq.obligations.loader import compute_pack_bytes_hash

    # 1. Compute stable content hash
    p1_hash = compute_pack_bytes_hash(pack_content.encode("utf-8"))

    # 2. Save with verified_sha256 explicitly matching (exact LF bytes per .gitattributes)
    verified_content = pack_content + f"verified_sha256: '{p1_hash}'\n"
    pack_file.write_bytes(verified_content.encode("utf-8"))

    loader = ObligationPackLoader(tmp_path)
    verified_pack = loader.load_pack_from_path(pack_file)
    assert verified_pack.status == PackStatus.VERIFIED
    assert verified_pack.is_verified is True

    # 3. Tamper by changing a single byte in the file
    tampered_content = verified_content.replace("Clause 1", "Clause 2")
    pack_file.write_bytes(tampered_content.encode("utf-8"))

    tampered_pack = loader.load_pack_from_path(pack_file)
    assert tampered_pack.status == PackStatus.DRAFT
    assert tampered_pack.is_verified is False
