# CYBERQ Demo Environment Check

Generated at: 2026-10-17T23:35:00+05:30
Host: Windows 11 (x64) | Shell: Windows PowerShell

---

## 1. System Runtime & Tooling

| Component | Target / Expected | Discovered Value | Status |
|---|---|---|---|
| **OS** | Windows 10/11 | Windows 11 (Build 26100) | PASS |
| **Python** | 3.12+ (standard stack) | 3.13.9 (`.venv\Scripts\python.exe`) | PASS |
| **Node.js** | 20+ | v22.14.0 | PASS |
| **npm** | 10+ | 10.9.2 | PASS |
| **Google Chrome** | Chromium-based | 155.0.8059.84 (`C:\Program Files\Google\Chrome\Application\chrome.exe`) | PASS |
| **Antigravity Extension / Bin** | AGY native binary tools | Present in `C:\Users\Om Avinash Watane\.gemini\antigravity\bin` (`webm_encoder.exe`, `agentapi.bat`) | PASS |
| **FFmpeg** | `ffmpeg -version` | Installed (v9.0.1 Essentials Build at `AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials...`) | PASS |
| **Database** | PostgreSQL 16 (production) | SQLite 3 development mode (`cyberq_dev.db`). PostgreSQL gate skipped cleanly per M1 specification. | SQLite Mode (Captioned honestly) |

---

## 2. Server Startup Command

- **Backend (Development & Demo Server)**:
  ```powershell
  $env:CYBERQ_ENV = "demo"
  $env:SESSION_SECRET = "cyberq-super-secret-key-32-chars-minimum!"
  .\.venv\Scripts\python -m uvicorn cyberq.api.app:app --host 127.0.0.1 --port 8000
  ```
- **Frontend Build & Static Serving**:
  ```powershell
  cd web
  npm run build
  node scripts/start-prod-server.mjs
  ```
- **Orchestrated Make Target**:
  ```powershell
  powershell -File .\make.ps1 dev
  ```
