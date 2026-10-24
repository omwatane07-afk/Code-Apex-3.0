@echo off
:: CYBERQ Quick Launcher - delegates to start.bat
:: Ensures the window stays open if start.bat is not found
cd /d "%~dp0"
if not exist "%~dp0start.bat" (
    echo [ERROR] start.bat not found in %~dp0
    echo Please ensure the CYBERQ repository is intact.
    pause
    exit /b 1
)
call "%~dp0start.bat"
