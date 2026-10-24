#!/usr/bin/env python3
"""Offline audit chain and selective disclosure verifier CLI tool for RBI CSITE.

Verifies SHA-256 hash chains, sharded Merkle batch checkpoints, dual-curve (Ed25519 & ECDSA P-256)
signatures, and RFC 6962 selective disclosure proofs from an exported JSON or .cqb bundle file.
Exits 0 if valid, non-zero if tampered, corrupted, or invalid.
"""

import argparse
import io
import json
from pathlib import Path
import sys
import tarfile
import zipfile

# Add backend to sys.path so we can import the verified audit chain logic
repo_root = Path(__file__).resolve().parent.parent.parent
backend_src = repo_root / "backend" / "src"
if str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))

import os

os.environ.setdefault("CYBERQ_ENV", "demo")
os.environ.setdefault("SESSION_SECRET", "demo-fallback-secret-for-offline-audit-tool-only")

from cyberq.audit.chain import AuditService
from cyberq.audit.merkle import MerkleProofStep


def load_input_data(input_path: Path) -> dict:
    """Loads export data from JSON, .cqb (tar.gz or zip), or raw file."""
    if input_path.suffix.lower() == ".json":
        with open(input_path, "r", encoding="utf-8") as f:
            return json.load(f)

    # Check for tar.gz or zip bundle (.cqb)
    if tarfile.is_tarfile(input_path):
        with tarfile.open(input_path, "r:*") as tar:
            events_f = tar.extractfile("events.json") or tar.extractfile("events.jsonl")
            ckpts_f = tar.extractfile("checkpoints.json") or tar.extractfile("checkpoints.jsonl")
            if events_f and ckpts_f:
                return {
                    "events": json.load(events_f),
                    "checkpoints": json.load(ckpts_f),
                }

    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path, "r") as z:
            namelist = z.namelist()
            if "manifest.json" in namelist:
                manifest = json.loads(z.read("manifest.json").decode("utf-8"))
                return manifest
            elif "events.json" in namelist and "checkpoints.json" in namelist:
                return {
                    "events": json.loads(z.read("events.json").decode("utf-8")),
                    "checkpoints": json.loads(z.read("checkpoints.json").decode("utf-8")),
                }

    # Fallback to direct JSON read
    with open(input_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify CYBERQ audit chain, Merkle batch checkpoints, and selective disclosure proofs."
    )
    parser.add_argument("--input", "-i", required=True, help="Path to audit export JSON or .cqb bundle file")
    parser.add_argument("--public-key", "-k", required=False, help="Hex-encoded signer public key")
    parser.add_argument("--selective-disclosure", "-s", action="store_true", help="Verify single event selective disclosure proof")
    parser.add_argument("--event-hash", required=False, help="SHA-256 event hash to selectively verify")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file does not exist: {input_path}", file=sys.stderr)
        return 2

    try:
        data = load_input_data(input_path)
    except Exception as e:
        print(f"ERROR: Failed to parse input file: {e}", file=sys.stderr)
        return 3

    public_key = args.public_key or data.get("public_key")

    # Selective Disclosure Verification Mode
    if args.selective_disclosure:
        event_hash = args.event_hash or data.get("event_hash")
        raw_proof = data.get("proof", [])
        checkpoint = data.get("checkpoint", {})

        if not event_hash or not checkpoint:
            print("ERROR: Selective disclosure requires event_hash and checkpoint in input file", file=sys.stderr)
            return 4

        proof_steps = [
            MerkleProofStep(
                position=step.get("position") or step.get("direction") or "right",
                hash=step.get("hash") or step.get("hash_val") or "",
            )
            for step in raw_proof
        ]

        print(f"Verifying selective disclosure for event {event_hash[:16]}... against checkpoint {checkpoint.get('sequence_number')}")
        valid, reason = AuditService.verify_selective_disclosure(
            event_hash=event_hash,
            proof=proof_steps,
            checkpoint=checkpoint,
            public_key_hex=public_key,
        )
        if valid:
            print(f"[SELECTIVE DISCLOSURE VERIFIED] {reason}")
            return 0
        else:
            print(f"[SELECTIVE DISCLOSURE FAILED] {reason}", file=sys.stderr)
            return 1

    # Standard Chain & Merkle Checkpoints Verification Mode
    events = data.get("events", [])
    checkpoints = data.get("checkpoints", [])

    print(f"Inspecting {len(events)} audit events and {len(checkpoints)} checkpoints...")
    is_valid, reason = AuditService.verify_chain(events, checkpoints, public_key)

    if is_valid:
        print(f"[VERIFIED] {reason}")
        return 0
    else:
        print(f"[INTEGRITY VIOLATION] Verification failed: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
