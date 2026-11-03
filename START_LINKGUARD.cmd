@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" launcher.py %*
) else (
    where py >nul 2>nul
    if errorlevel 1 (
        python launcher.py %*
    ) else (
        py -3.13 launcher.py %*
    )
)
if errorlevel 1 (
    echo.
    echo Install Python 3.13 and retry. See README.md for setup instructions.
    pause
)
