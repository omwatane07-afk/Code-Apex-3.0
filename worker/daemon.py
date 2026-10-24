"""CYBERQ Background Worker Process.

Periodically claims due obligations using SELECT ... FOR UPDATE SKIP LOCKED,
evaluates escalation rungs chronologically, updates notification outboxes,
and records worker heartbeat for readiness probes.
"""

import argparse
import signal
import sys
import time
from datetime import UTC, datetime
from typing import NoReturn

import structlog

from cyberq.audit.chain import AuditService
from cyberq.clocks.worker import (
    claim_due_obligations,
    process_obligation_escalations,
    record_worker_heartbeat,
)
from cyberq.core.config import get_settings
from cyberq.core.database import SessionLocal, init_db
from cyberq.core.logging import configure_logging

logger = structlog.get_logger("cyberq.worker")
settings = get_settings()

_RUNNING = True


def _handle_exit(sig: int, frame: object) -> None:
    global _RUNNING
    logger.info("worker_shutdown_signal_received", signal=sig)
    _RUNNING = False


def run_worker_loop(poll_interval: float = 5.0, once: bool = False) -> None:
    """Main worker poll loop."""
    configure_logging()
    init_db()

    audit_service = AuditService(settings.AUDIT_SIGNING_SEED)
    worker_id = f"worker-{settings.ENV.value}"

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    logger.info("worker_started", worker_id=worker_id, poll_interval=poll_interval)

    while _RUNNING:
        start_time = time.time()
        try:
            with SessionLocal() as db:
                # 1. Heartbeat
                record_worker_heartbeat(session=db, worker_id=worker_id)
                db.commit()

                # 2. Claim and process due obligations
                due_obligations = claim_due_obligations(session=db, worker_id=worker_id)
                for obl in due_obligations:
                    escalations = process_obligation_escalations(
                        session=db,
                        audit=audit_service,
                        obligation=obl,
                        worker_id=worker_id,
                    )
                    if escalations:
                        logger.info(
                            "obligation_escalations_fired",
                            obligation_id=obl.id,
                            regulator=obl.regulator,
                            count=len(escalations),
                        )
                db.commit()
        except Exception as exc:
            logger.error("worker_loop_error", error=str(exc))

        if once:
            break

        elapsed = time.time() - start_time
        sleep_time = max(0.1, poll_interval - elapsed)
        time.sleep(sleep_time)

    logger.info("worker_stopped", worker_id=worker_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="CYBERQ Regulatory Clock Worker")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run single poll cycle and exit")
    args = parser.parse_args()

    run_worker_loop(poll_interval=args.interval, once=args.once)


if __name__ == "__main__":
    main()
