@echo off
REM AWARE Launcher (Windows)
REM Creates venv if missing, installs requirements, then runs AWARE

setlocal
cd /d "%~dp0"

REM Check for Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% neq 0 (
        echo Python not found. Please install Python 3.8+.
        pause
        exit /b 1
    )
    set PYTHON=py -3
) else (
    set PYTHON=python
)

REM Create venv if missing
if not exist .venv (
    echo Creating virtual environment...
    %PYTHON% -m venv .venv
)

REM Activate venv
call .venv\Scripts\activate.bat

REM Install requirements
pip install -r requirements.txt

REM Run AWARE scan on current folder
python aware\aware.py scan . --quarantine

pause