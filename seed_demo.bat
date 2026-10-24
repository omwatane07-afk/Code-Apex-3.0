@echo off
setlocal
cd /d "%~dp0"
title CYBERQ - Database Seeder

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

if exist "%ROOT%\.venv\Scripts\python.exe" (
    set "PY=%ROOT%\.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

echo =====================================================================
echo   CYBERQ - Seeding Demo Crisis Data (22 Tools, 3 Incidents)
echo =====================================================================
echo.

%PY% "%ROOT%\tools\init_demo_db.py"

echo.
pause
