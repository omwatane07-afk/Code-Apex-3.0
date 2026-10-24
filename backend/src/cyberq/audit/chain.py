"""Tamper-evident audit chain implementation with RFC 8785 canonical JSON, Merkle batching, and dual-curve signing."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cyberq.audit.crypto import KeyProvider, LocalKeyProvider, verify_signature
from cyberq.audit.merkle import MerkleProofStep, build_merkle_tree, verify_merkle_proof
from cyberq.audit.models import AuditCheckpoint, AuditEvent, utc_now_iso

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
AUDIT_ADVISORY_LOCK_ID = 88889999

def _normalize_canonical_value(v: Any) -> Any:
    """Recursively normalizes floats to deterministic decimal strings per RFC 8785 strict profile."""
    if isinstance(v, float):
        if v.is_integer():
            return int(v)
        return f"{v:.8f}".rstrip("0").rstrip(".")
    elif isinstance(v, dict):
        return {k: _normalize_canonical_value(val) for k, val in v.items()}
    elif isinstance(v, list | tuple):
        return [_normalize_canonical_value(item) for item in v]
    return v


try:
    import orjson

    def canonical_json(obj: Any) -> bytes:
        """Fast RFC 8785 JSON canonicalizer via orjson with sorted keys and compact separators."""
        normalized = _normalize_canonical_value(obj)
        return orjson.dumps(normalized, option=orjson.OPT_SORT_KEYS)

except ImportError:
    def canonical_json(obj: Any) -> bytes:
        """Serializes a Python object to canonical JSON (RFC 8785 subset: sorted keys, compact separators, UTF-8)."""
        normalized = _normalize_canonical_value(obj)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")


def compute_event_hash(payload_dict: dict[str, Any], prev_hash: str) -> str:
    """Computes SHA-256(canonical_json(payload) || prev_hash.encode('ascii'))."""
    canonical_bytes = canonical_json(payload_dict)
    hasher = hashlib.sha256()
    hasher.update(canonical_bytes)
    hasher.update(prev_hash.encode("ascii"))
    return hasher.hexdigest()


class AuditService:
    def __init__(
        self,
        key_source: KeyProvider | str | None = None,
        algorithm: str = "Ed25519",
    ) -> None:
        if key_source is None:
            from cyberq.core.config import get_settings

            key_source = get_settings().AUDIT_SIGNING_SEED
        if isinstance(key_source, str):
            self._key_provider: KeyProvider = LocalKeyProvider(key_source, algorithm=algorithm)
        else:
            self._key_provider = key_source
        self.public_key_hex = self._key_provider.get_public_key_hex()
        self.algorithm = self._key_provider.algorithm
        self._lock = threading.RLock()

    def record_event(
        self,
        session: Session,
        actor_id: str,
        actor_role: str,
        action: str,
        entity_type: str,
        entity_id: str,
        client_ip: str | None = None,
        request_id: str | None = None,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        stream_id: str | None = None,
    ) -> AuditEvent:
        """Appends a new event to the audit chain within the current DB transaction.

        Supports Tier-1 per-stream sharding: locks per stream_id on Postgres to eliminate
        cross-incident serialization bottlenecks.
        """
        if stream_id is None and entity_type == "incident":
            stream_id = entity_id

        with self._lock:
            bind = session.get_bind()
            if bind and bind.dialect.name == "postgresql":
                if stream_id:
                    session.execute(
                        text("SELECT pg_advisory_xact_lock(hashtext(:stream_id))"),
                        {"stream_id": stream_id},
                    )
                else:
                    session.execute(
                        text("SELECT pg_advisory_xact_lock(:lock_id)"),
                        {"lock_id": AUDIT_ADVISORY_LOCK_ID},
                    )

            # Global sequence tracking
            last_event = session.execute(
                select(AuditEvent).order_by(AuditEvent.sequence_number.desc()).limit(1)
            ).scalar_one_or_none()

            if last_event is None:
                seq = 1
                prev_hash = GENESIS_HASH
            else:
                seq = last_event.sequence_number + 1
                prev_hash = last_event.hash

            # Stream-level sequence tracking
            stream_seq: int | None = None
            stream_prev_hash: str | None = None
            if stream_id is not None:
                last_stream_event = session.execute(
                    select(AuditEvent)
                    .where(AuditEvent.stream_id == stream_id)
                    .order_by(AuditEvent.sequence_number.desc())
                    .limit(1)
                ).scalar_one_or_none()
                if last_stream_event is None:
                    stream_seq = 1
                    stream_prev_hash = GENESIS_HASH
                else:
                    stream_seq = (last_stream_event.stream_sequence_number or 0) + 1
                    stream_prev_hash = last_stream_event.hash

            event_id = str(uuid.uuid4())
            event = AuditEvent(
                id=event_id,
                sequence_number=seq,
                timestamp=utc_now_iso(),
                prev_hash=prev_hash,
                hash="",
                stream_id=stream_id,
                stream_sequence_number=stream_seq,
                stream_prev_hash=stream_prev_hash,
                actor_id=actor_id,
                actor_role=actor_role,
                client_ip=client_ip,
                request_id=request_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                before_state=before_state,
                after_state=after_state,
            )

            # Calculate deterministic hash over canonical payload
            payload_dict = event.to_canonical_dict()
            event.hash = compute_event_hash(payload_dict, prev_hash)

            session.add(event)
            session.flush()
            return event

    def create_checkpoint(
        self,
        session: Session,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
    ) -> AuditCheckpoint | None:
        """Creates and cryptographically signs a periodic checkpoint over a chain slice.

        Derives an RFC 6962 Merkle tree root over all event hashes in the slice for selective disclosure.
        Returns None if no events exist to checkpoint.
        """
        if from_sequence is None:
            last_cp = session.execute(
                select(AuditCheckpoint).order_by(AuditCheckpoint.sequence_number.desc()).limit(1)
            ).scalar_one_or_none()
            from_sequence = (last_cp.to_sequence + 1) if last_cp else 1

        if to_sequence is None:
            latest_ev = session.execute(
                select(AuditEvent).order_by(AuditEvent.sequence_number.desc()).limit(1)
            ).scalar_one_or_none()
            if latest_ev is None or latest_ev.sequence_number < from_sequence:
                return None
            to_sequence = latest_ev.sequence_number

        if from_sequence > to_sequence:
            return None

        # Fetch all events in range to bind root hash and compute Merkle tree root
        events_in_range = list(
            session.execute(
                select(AuditEvent)
                .where(AuditEvent.sequence_number.between(from_sequence, to_sequence))
                .order_by(AuditEvent.sequence_number.asc())
            ).scalars().all()
        )
        if not events_in_range:
            return None

        from_event_id = events_in_range[0].id
        to_event_id = events_in_range[-1].id
        root_hash = events_in_range[-1].hash

        # Compute RFC 6962 Merkle root over all event hashes in range
        event_leaf_hashes = [ev.hash.encode("ascii") for ev in events_in_range]
        merkle_root_hex, _ = build_merkle_tree(event_leaf_hashes)

        last_cp = session.execute(
            select(AuditCheckpoint).order_by(AuditCheckpoint.sequence_number.desc()).limit(1)
        ).scalar_one_or_none()
        cp_seq = (last_cp.sequence_number + 1) if last_cp else 1

        checkpoint_id = str(uuid.uuid4())
        checkpoint = AuditCheckpoint(
            id=checkpoint_id,
            sequence_number=cp_seq,
            timestamp=utc_now_iso(),
            from_sequence=from_sequence,
            to_sequence=to_sequence,
            from_event_id=from_event_id,
            to_event_id=to_event_id,
            root_hash=root_hash,
            merkle_root=merkle_root_hex,
            algorithm=self._key_provider.algorithm,
            signature="",
            signer_public_key=self.public_key_hex,
        )

        cp_dict = checkpoint.to_canonical_dict()
        sig_bytes = self._key_provider.sign(canonical_json(cp_dict))
        checkpoint.signature = sig_bytes.hex()

        session.add(checkpoint)
        session.flush()
        return checkpoint

    @staticmethod
    def verify_chain(
        events: list[dict[str, Any]],
        checkpoints: list[dict[str, Any]] | None = None,
        public_key_hex: str | None = None,
    ) -> tuple[bool, str]:
        """Offline verification of an audit chain slice and its signed checkpoints."""
        if not events:
            return True, "Chain is empty"

        expected_prev = GENESIS_HASH
        for i, ev in enumerate(events):
            if i > 0 and ev["sequence_number"] != events[i - 1]["sequence_number"] + 1:
                return (
                    False,
                    f"Sequence discontinuity at index {i}: expected {events[i - 1]['sequence_number'] + 1}, got {ev['sequence_number']}",
                )

            if i == 0:
                if ev["sequence_number"] == 1 and ev["prev_hash"] != GENESIS_HASH:
                    return (
                        False,
                        f"Invalid genesis event: sequence 1 must have prev_hash == GENESIS_HASH, got {ev['prev_hash']}",
                    )
            else:
                if ev["prev_hash"] != expected_prev:
                    return (
                        False,
                        f"Broken hash chain at sequence {ev['sequence_number']}: expected prev_hash {expected_prev}, got {ev['prev_hash']}",
                    )

            payload: dict[str, Any] = {
                "id": ev["id"],
                "sequence_number": ev["sequence_number"],
                "timestamp": str(ev["timestamp"]),
                "prev_hash": ev["prev_hash"],
                "actor_id": ev["actor_id"],
                "actor_role": ev["actor_role"],
                "client_ip": ev.get("client_ip"),
                "request_id": ev.get("request_id"),
                "action": ev["action"],
                "entity_type": ev["entity_type"],
                "entity_id": ev["entity_id"],
                "before_state": ev.get("before_state"),
                "after_state": ev.get("after_state"),
            }
            if ev.get("stream_id") is not None:
                payload["stream_id"] = ev["stream_id"]
            if ev.get("stream_sequence_number") is not None:
                payload["stream_sequence_number"] = ev["stream_sequence_number"]
            if ev.get("stream_prev_hash") is not None:
                payload["stream_prev_hash"] = ev["stream_prev_hash"]

            computed_hash = compute_event_hash(payload, ev["prev_hash"])
            if computed_hash != ev["hash"]:
                return (
                    False,
                    f"Tampered event at sequence {ev['sequence_number']}: recorded hash {ev['hash']} != computed {computed_hash}",
                )

            expected_prev = ev["hash"]

        if checkpoints and public_key_hex:
            try:
                bytes.fromhex(public_key_hex)
            except Exception as e:
                return False, f"Invalid public key hex: {e}"

            event_by_seq = {ev["sequence_number"]: ev for ev in events}

            for cp in checkpoints:
                # 1. Range coverage validation
                to_seq = cp["to_sequence"]
                from_seq = cp["from_sequence"]
                if to_seq not in event_by_seq:
                    return (
                        False,
                        f"Checkpoint {cp['sequence_number']} sequence range {from_seq}..{to_seq} extends beyond presented events (latest event is {events[-1]['sequence_number']})",
                    )
                if from_seq not in event_by_seq:
                    return (
                        False,
                        f"Checkpoint {cp['sequence_number']} starting sequence {from_seq} is missing from presented events",
                    )

                # 2. Event ID binding validation
                expected_from_id = event_by_seq[from_seq]["id"]
                if cp["from_event_id"] != expected_from_id:
                    return (
                        False,
                        f"Checkpoint {cp['sequence_number']} from_event_id mismatch: claims {cp['from_event_id']} but event at sequence {from_seq} is {expected_from_id}",
                    )

                expected_to_id = event_by_seq[to_seq]["id"]
                if cp["to_event_id"] != expected_to_id:
                    return (
                        False,
                        f"Checkpoint {cp['sequence_number']} to_event_id mismatch: claims {cp['to_event_id']} but event at sequence {to_seq} is {expected_to_id}",
                    )

                # 3. Root hash binding validation
                expected_root_hash = event_by_seq[to_seq]["hash"]
                if cp["root_hash"] != expected_root_hash:
                    return (
                        False,
                        f"Checkpoint {cp['sequence_number']} root_hash mismatch: claims {cp['root_hash']} but event at sequence {to_seq} has hash {expected_root_hash}",
                    )

                # 4. Merkle Root validation if present
                if cp.get("merkle_root"):
                    range_hashes = [
                        event_by_seq[s]["hash"].encode("ascii")
                        for s in range(from_seq, to_seq + 1)
                    ]
                    expected_merkle, _ = build_merkle_tree(range_hashes)
                    if cp["merkle_root"].lower() != expected_merkle.lower():
                        return (
                            False,
                            f"Checkpoint {cp['sequence_number']} merkle_root mismatch: claims {cp['merkle_root']} but computed is {expected_merkle}",
                        )

                # 5. Cryptographic signature verification (Ed25519 or ECDSA P-256)
                if "signature" not in cp:
                    return False, f"Missing signature on checkpoint {cp.get('sequence_number')}"
                try:
                    sig_bytes = bytes.fromhex(cp["signature"])
                except Exception as e:
                    return False, f"Invalid signature hex on checkpoint {cp.get('sequence_number')}: {e}"
                cp_payload: dict[str, Any] = {
                    "id": cp["id"],
                    "sequence_number": cp["sequence_number"],
                    "timestamp": str(cp["timestamp"]),
                    "from_sequence": cp["from_sequence"],
                    "to_sequence": cp["to_sequence"],
                    "from_event_id": cp["from_event_id"],
                    "to_event_id": cp["to_event_id"],
                    "root_hash": cp["root_hash"],
                    "signer_public_key": cp["signer_public_key"],
                }
                if cp.get("merkle_root") is not None:
                    cp_payload["merkle_root"] = cp["merkle_root"]
                if cp.get("algorithm") and cp["algorithm"] != "Ed25519":
                    cp_payload["algorithm"] = cp["algorithm"]

                algo = cp.get("algorithm", "Ed25519")
                signer_pk = cp.get("signer_public_key") or public_key_hex
                valid_sig = verify_signature(
                    message=canonical_json(cp_payload),
                    signature_bytes=sig_bytes,
                    public_key_hex=signer_pk,
                    algorithm=algo,
                )
                if not valid_sig:
                    return False, f"Invalid {algo} signature on checkpoint {cp['sequence_number']}"

        return True, "Chain and signatures are valid"

    @staticmethod
    def verify_selective_disclosure(
        event_hash: str,
        proof: list[MerkleProofStep],
        checkpoint: dict[str, Any],
        public_key_hex: str | None = None,
    ) -> tuple[bool, str]:
        """RBI CSITE Selective Disclosure verification: proves an individual event hash

        is part of a checkpoint's Merkle root without requiring access to other events.
        """
        merkle_root = checkpoint.get("merkle_root")
        if not merkle_root:
            return False, "Checkpoint does not contain a Merkle root"

        # 1. Verify Merkle proof
        valid_inclusion = verify_merkle_proof(
            leaf=event_hash.encode("ascii"),
            proof=proof,
            expected_root_hex=merkle_root,
        )
        if not valid_inclusion:
            return False, "Merkle inclusion proof failed against checkpoint merkle_root"

        # 2. Verify checkpoint signature
        sig_bytes = bytes.fromhex(checkpoint["signature"])
        cp_payload: dict[str, Any] = {
            "id": checkpoint["id"],
            "sequence_number": checkpoint["sequence_number"],
            "timestamp": str(checkpoint["timestamp"]),
            "from_sequence": checkpoint["from_sequence"],
            "to_sequence": checkpoint["to_sequence"],
            "from_event_id": checkpoint["from_event_id"],
            "to_event_id": checkpoint["to_event_id"],
            "root_hash": checkpoint["root_hash"],
            "signer_public_key": checkpoint["signer_public_key"],
            "merkle_root": merkle_root,
        }
        if checkpoint.get("algorithm") and checkpoint["algorithm"] != "Ed25519":
            cp_payload["algorithm"] = checkpoint["algorithm"]

        algo = checkpoint.get("algorithm", "Ed25519")
        pk = checkpoint.get("signer_public_key") or public_key_hex
        if not pk:
            return False, "Missing signer public key for checkpoint verification"

        valid_sig = verify_signature(
            message=canonical_json(cp_payload),
            signature_bytes=sig_bytes,
            public_key_hex=pk,
            algorithm=algo,
        )
        if not valid_sig:
            return False, f"Invalid {algo} signature on checkpoint {checkpoint.get('sequence_number')}"

        return True, "Selective disclosure proof verified successfully"
