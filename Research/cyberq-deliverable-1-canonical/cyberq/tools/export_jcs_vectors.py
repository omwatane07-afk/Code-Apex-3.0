"""Export the JCS conformance vectors as JSON for the Go verifier.

Usage (from the repo root): python -m tools.export_jcs_vectors
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.ledger import vectors

OUT = Path(__file__).resolve().parent.parent / "tests" / "ledger" / "data" / "jcs-v1.json"


def build() -> dict[str, object]:
    return {
        "spec": "CQ-JCS-VECTORS-v1",
        "valid": [
            {
                "name": name,
                "input_hex": text.encode("utf-8").hex(),
                "expected_hex": expected.hex(),
            }
            for name, text, expected in vectors.VALID
        ],
        "invalid": [
            {"name": name, "input_hex": raw.hex(), "code": code}
            for name, raw, code in vectors.INVALID
        ],
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
