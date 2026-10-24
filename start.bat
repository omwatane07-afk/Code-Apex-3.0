@echo off
setlocal enabledelayedexpansion
title CYBERQ 4.0 - Command Center Launcher

:: =====================================================================
:: Force working directory to script root (handles paths with spaces)
:: =====================================================================
cd /d "%~dp0"
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

:: =====================================================================
:: Startup log: capture diagnostics to logs/startup.log
:: =====================================================================
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
set "LOGFILE=%ROOT%\logs\startup.log"
echo. > "%LOGFILE%"
echo [%date% %time%] CYBERQ Launcher starting >> "%LOGFILE%"

echo =====================================================================
echo   CYBERQ - BANK-DEPLOYABLE INCIDENT-TO-BOARD PLATFORM
echo   Air-Gapped * Zero-PII * Maker-Checker * Cryptographic Ledger
echo =====================================================================
echo.

:: =====================================================================
:: 1. Detect Python executable (venv > system python > py launcher)
:: =====================================================================
set "PY="
if exist "%ROOT%\.venv\Scripts\python.exe" (
    set "PY=%ROOT%\.venv\Scripts\python.exe"
    echo [*] Found virtualenv Python: !PY!
    echo [*] Found virtualenv Python: !PY! >> "%LOGFILE%"
) else (
    python --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY=python"
        for /f "tokens=*" %%V in ('python --version 2^>^&1') do (
            echo [*] Found system %%V
            echo [*] Found system %%V >> "%LOGFILE%"
        )
    ) else (
        py -3 --version >nul 2>&1
        if !errorlevel! equ 0 (
            set "PY=py -3"
            echo [*] Found Python Launcher (py -3^)
            echo [*] Found Python Launcher (py -3^) >> "%LOGFILE%"
        ) else (
            echo [ERROR] Python 3.12+ was not found in PATH or .venv!
            echo [ERROR] Python 3.12+ was not found in PATH or .venv! >> "%LOGFILE%"
            echo Please install Python 3.12+ from https://python.org
            echo Ensure "Add Python to PATH" is checked during installation.
            goto :fail
        )
    )
)

:: =====================================================================
:: 2. Check Node / npm
:: =====================================================================
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] 'npm' was not found in PATH.
    echo [WARNING] npm not found >> "%LOGFILE%"
    echo Node.js 18+ is required for the React frontend.
    echo Download from https://nodejs.org
    echo.
) else (
    for /f "tokens=*" %%V in ('node --version 2^>^&1') do (
        echo [*] Found Node.js %%V
        echo [*] Found Node.js %%V >> "%LOGFILE%"
    )
    for /f "tokens=*" %%V in ('npm --version 2^>^&1') do (
        echo [*] Found npm %%V
        echo [*] Found npm %%V >> "%LOGFILE%"
    )
)

:: =====================================================================
:: 3. Check Python dependencies are installed
:: =====================================================================
echo.
echo [PRE] Checking Python dependencies...
!PY! -c "import fastapi, uvicorn, sqlalchemy, pydantic" >nul 2>&1
if !errorlevel! neq 0 (
    echo [!] Core Python dependencies missing. Installing from requirements.txt...
    echo [!] Installing Python dependencies >> "%LOGFILE%"
    !PY! -m pip install -r "%ROOT%\requirements.txt" --quiet 2>>"%LOGFILE%"
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install Python dependencies.
        echo [ERROR] pip install failed >> "%LOGFILE%"
        echo Run manually: pip install -r requirements.txt
        goto :fail
    )
    echo [OK] Python dependencies installed.
) else (
    echo [OK] Python dependencies found.
)

:: =====================================================================
:: 4. Check frontend node_modules
:: =====================================================================
if not exist "%ROOT%\web\node_modules" (
    echo [!] Frontend node_modules missing. Running npm install...
    echo [!] Running npm install >> "%LOGFILE%"
    pushd "%ROOT%\web"
    call npm install --ignore-scripts 2>>"%LOGFILE%"
    if !errorlevel! neq 0 (
        echo [WARNING] npm install failed. Frontend may not start.
        echo [WARNING] npm install failed >> "%LOGFILE%"
    ) else (
        echo [OK] Frontend dependencies installed.
    )
    popd
) else (
    echo [OK] Frontend node_modules found.
)

echo.

:: =====================================================================
:: 5. Initialize SQLite database and seed crisis scenario
:: =====================================================================
echo [1/3] Initializing SQLite database and crisis scenario...
echo [1/3] Database init starting >> "%LOGFILE%"
!PY! "%ROOT%\tools\init_demo_db.py" 2>>"%LOGFILE%"
if !errorlevel! neq 0 (
    echo [ERROR] Database initialization failed. See logs\startup.log for details.
    echo [ERROR] Database init failed >> "%LOGFILE%"
    goto :fail
)
echo [OK] Database initialized.
echo [OK] Database initialized >> "%LOGFILE%"

echo.

:: =====================================================================
:: 6. Launch FastAPI Backend in a dedicated window
:: =====================================================================
echo [2/3] Launching FastAPI Backend on http://127.0.0.1:8000 ...
echo [2/3] Starting backend >> "%LOGFILE%"
start "CYBERQ Backend (FastAPI)" "%ROOT%\backend\start_backend.bat"

:: =====================================================================
:: 7. Launch Vite Frontend in a dedicated window
:: =====================================================================
echo [3/3] Launching Vite Frontend on http://localhost:5173 ...
echo [3/3] Starting frontend >> "%LOGFILE%"
start "CYBERQ Frontend (Vite)" "%ROOT%\web\start_frontend.bat"

echo.
echo Waiting 3 seconds for services to initialize...
timeout /t 3 >nul

:: =====================================================================
:: 8. Open browser
:: =====================================================================
echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo =====================================================================
echo   CYBERQ is now live:
echo   - Frontend Command Center: http://localhost:5173
echo   - Ambient SOC Wallboard:   http://localhost:5173/wall
echo   - Backend Swagger Docs:    http://127.0.0.1:8000/docs
echo   - Demo CISO Account:       ciso@cyberq.bank
echo =====================================================================
echo.
echo Note: The Backend and Frontend run in their own dedicated cmd windows.
echo To shut down CYBERQ, close those two cmd windows.
echo Startup log saved to: logs\startup.log
echo.
echo [%date% %time%] CYBERQ Launcher completed successfully >> "%LOGFILE%"
pause
exit /b 0

:fail
echo.
echo =====================================================================
echo [FAILED] Startup could not complete. See error message above.
echo          Diagnostic log saved to: logs\startup.log
echo =====================================================================
echo.
echo [%date% %time%] CYBERQ Launcher FAILED >> "%LOGFILE%"
pause
exit /b 1
