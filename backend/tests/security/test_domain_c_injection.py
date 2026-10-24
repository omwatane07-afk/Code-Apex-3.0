"""Executable security exploit tests for Domain C: Injection and Parsing.

Covers:
- ATTACK C-04: CRLF log injection in structured JSON logging (CWE-117)

Note on other Domain C targets per Red Team rules:
- CSV formula injection: not testable until M4 (Board pack/export). Added to M4 acceptance tests.
- YAML pack loader deserialization: not testable until M1 (Obligation engine). Added to M1 acceptance tests.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local fixtures.
"""

import io
import json
import logging

from tools.redteam.scope_guard import enforce_scope

from cyberq.core.logging import configure_logging, get_logger

enforce_scope("localhost")


def test_crlf_log_injection_escaped_in_structured_logging():
    """ATTACK C-04: CRLF log injection via incident metadata.

    Attacker attempts log forging by inserting newline characters (\\r\\n)
    into incident titles or user attributes to split log lines or inject
    forged JSON event entries into log sinks (CWE-117).
    """
    # Configure structlog to capture output
    output_stream = io.StringIO()
    root_logger = logging.getLogger()
    handler = logging.StreamHandler(output_stream)
    root_logger.handlers = [handler]
    root_logger.setLevel(logging.INFO)

    configure_logging("INFO")
    logger = get_logger("cyberq.test")

    # Injected title containing newline and forged JSON log entry
    forged_event = '{"event": "admin_granted", "actor_id": "attacker", "status": "approved"}'
    crlf_title = f"Unauthorized Access\r\n{forged_event}\r\nContinuing Title"

    logger.info("incident_logged", title=crlf_title, incident_id="INC-999")
    handler.flush()

    raw_output = output_stream.getvalue().strip()

    # The entire log entry MUST be on a SINGLE line
    lines = [line for line in raw_output.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"VULNERABILITY: CRLF injection split log into {len(lines)} lines! Output: {raw_output}"
    )

    # The line must be valid JSON containing the escaped newline characters
    parsed = json.loads(lines[0])
    assert parsed["event"] == "incident_logged"
    assert parsed["title"] == crlf_title
    assert "\r\n" in parsed["title"]  # Kept safely as literal in JSON string
