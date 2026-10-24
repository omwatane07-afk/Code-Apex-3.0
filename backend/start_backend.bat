@echo off
title CYBERQ Backend Service (FastAPI)
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%~dp0.."
set "CYBERQ_ENV=demo"

echo =====================================================================
echo   CYBERQ Backend - FastAPI + Uvicorn
echo   API Endpoint:    http://127.0.0.1:8000
echo   Swagger Docs:    http://127.0.0.1:8000/docs
echo   Environment:     %CYBERQ_ENV%
echo =====================================================================
echo.

:: Verify Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not available in PATH.
    echo Please install Python 3.12+ and ensure it is on your PATH.
    pause
    exit /b 1
)

:: Verify uvicorn is installed
python -c "import uvicorn" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] uvicorn is not installed.
    echo Run: pip install -r requirements.txt
    pause
    exit /b 1
)

echo Starting backend server... (Press Ctrl+C to stop)
echo.
python -m uvicorn cyberq.api.app:app --host 127.0.0.1 --port 8000 --reload

echo.
echo =====================================================================
echo [INFO] Backend service has stopped.
echo =====================================================================
echo.
pause
