@echo off
title CYBERQ Frontend Service (React + Vite)
cd /d "%~dp0"

echo =====================================================================
echo   CYBERQ Frontend - React 18 + TypeScript + Vite
echo   Dev Server:      http://localhost:5173
echo =====================================================================
echo.

:: Verify npm is available
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] npm is not available in PATH.
    echo Please install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

:: Verify node_modules exists
if not exist "%~dp0node_modules" (
    echo [!] node_modules not found. Running npm install...
    call npm install --ignore-scripts
    if %errorlevel% neq 0 (
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
)

echo Starting frontend dev server... (Press Ctrl+C to stop)
echo.
call npm run dev

echo.
echo =====================================================================
echo [INFO] Frontend service has stopped.
echo =====================================================================
echo.
pause
