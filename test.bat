@echo off
setlocal
cd /d "%~dp0"
title CYBERQ Test Runner

if exist ".venv\Scripts\python.exe" (
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

set "PYTHONPATH=backend\src;%~dp0"
set "CYBERQ_ENV=demo"

echo =====================================================================
echo   Running Backend Tests (pytest)
echo =====================================================================
echo.

"%PY_EXE%" -m pytest backend/tests -v %*

echo.
echo =====================================================================
echo   Test run complete.
echo =====================================================================
pause
