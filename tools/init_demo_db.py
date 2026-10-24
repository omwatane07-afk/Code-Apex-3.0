"""Database initialization and crisis demo seeder script.

Loads tables and pre-populates the 22 tool passports and 3 banking crisis incidents.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_SRC = ROOT / "backend" / "src"

sys.path.insert(0, str(BACKEND_SRC))
sys.path.insert(0, str(ROOT))

os.environ["PYTHONPATH"] = f"{BACKEND_SRC};{ROOT}"
os.environ["CYBERQ_ENV"] = "demo"

from cyberq.core.database import SessionLocal, init_db
from cyberq.core.demo_seed import seed_demo_crisis_data


def main() -> None:
    init_db()
    session = SessionLocal()
    seed_demo_crisis_data(session)
    session.commit()
    session.close()
    print("[OK] Database ready: 22 Tool Passports and 3 Crisis Incidents loaded.")


if __name__ == "__main__":
    main()
