"""CYBERQ Intake Engine: High-throughput async ingestion for 20+ banking security tools,

RFC 5424/CEF syslog parsing, HMAC replay defense, Dead-Letter Queue, and CERT-In advisory correlation.
"""

from cyberq.intake.simulator import (
    TelemetrySimulator,
    generate_synthetic_aadhaar,
    generate_synthetic_card,
    generate_synthetic_pan,
)

__all__ = [
    "TelemetrySimulator",
    "generate_synthetic_aadhaar",
    "generate_synthetic_card",
    "generate_synthetic_pan",
]
