"""CYBERQ Platform Launcher.

Initializes database, seeds demo crisis data, starts backend and frontend servers,
and opens the tactical command center in your default browser.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"
WEB_DIR = ROOT / "web"
SRC_DIR = BACKEND_DIR / "src"

# Prepend src to sys.path so cyberq and pyotp are immediately importable
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["PYTHONPATH"] = f"{SRC_DIR};{ROOT}"
os.environ["CYBERQ_ENV"] = "demo"


def main() -> None:
    print("=" * 70)
    print("  STARTING CYBERQ (CODE APEX 4.0 HYPERSCALE PLATFORM)")
    print("  Bank-Deployable Incident-to-Board * Air-Gapped * Zero-PII")
    print("=" * 70)
    print()

    # 1. Pre-flight checks
    if shutil.which("npm") is None:
        print("[WARNING] 'npm' was not found in PATH.")
        print("Please ensure Node.js (v18+) is installed to run the frontend UI.")
        print()

    # 2. Initialize Database and Seed Demo Crisis Data
    print("[1/3] Initializing SQLite database & seeding crisis scenario...")
    try:
        from cyberq.core.database import SessionLocal, init_db
        from cyberq.core.demo_seed import seed_demo_crisis_data

        init_db()
        session = SessionLocal()
        seed_demo_crisis_data(session)
        session.commit()
        session.close()
        print("  -> Success: 22 Tool Passports and 3 Crisis Incidents Pre-loaded.")
    except Exception as e:
        print(f"  [ERROR] Database initialization failed: {e}")
        try:
            input("\nPress Enter to exit...")
        except (KeyboardInterrupt, EOFError):
            pass
        sys.exit(1)

    print()

    # 3. Launch Backend (FastAPI via uvicorn)
    print("[2/3] Launching FastAPI Backend on http://127.0.0.1:8000 ...")
    backend_env = os.environ.copy()
    backend_env["PYTHONPATH"] = f"src;{ROOT}"
    backend_env["CYBERQ_ENV"] = "demo"

    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "cyberq.api.app:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
        "--reload",
    ]
    if sys.platform == "win32":
        subprocess.Popen(
            backend_cmd,
            cwd=str(BACKEND_DIR),
            env=backend_env,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
    else:
        subprocess.Popen(backend_cmd, cwd=str(BACKEND_DIR), env=backend_env)

    # 4. Launch Frontend (React + Vite)
    print("[3/3] Launching Vite Frontend on http://localhost:5173 ...")
    npm_bin = shutil.which("npm.cmd") or shutil.which("npm") or "npm"
    npm_cmd = [npm_bin, "run", "dev"]
    try:
        if sys.platform == "win32":
            subprocess.Popen(
                npm_cmd,
                cwd=str(WEB_DIR),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            subprocess.Popen(npm_cmd, cwd=str(WEB_DIR))
    except Exception as e:
        print(f"  [WARNING] Could not start frontend automatically: {e}")
        print("  You can run 'cd web && npm run dev' in another terminal.")

    # 5. Open browser
    time.sleep(2)
    try:
        webbrowser.open("http://localhost:5173")
    except Exception:
        pass

    print()
    print("=" * 70)
    print("  CYBERQ is now live:")
    print("  - Frontend UI:       http://localhost:5173")
    print("  - Ambient Wallboard: http://localhost:5173/wall")
    print("  - Backend API Docs:  http://127.0.0.1:8000/docs")
    print("  - Demo CISO Account: ciso@cyberq.bank")
    print("=" * 70)
    print()
    print("Backend and Frontend services are running in their respective windows.")
    print("Press Enter to close this launcher window...")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
