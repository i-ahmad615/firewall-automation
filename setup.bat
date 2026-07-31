@echo off
setlocal EnableExtensions
title Security Alert Automation - Setup

cd /d "%~dp0"

echo.
echo ============================================================
echo   Security Alert Automation - Windows Setup
echo ============================================================
echo.

if not exist "requirements.txt" (
    echo [ERROR] requirements.txt was not found.
    echo Run this setup file from the project directory.
    goto :failed
)

if not exist ".env.example" (
    echo [ERROR] .env.example was not found.
    goto :failed
)

set "PYTHON_BOOTSTRAP="
where py >nul 2>&1
if not errorlevel 1 set "PYTHON_BOOTSTRAP=py -3"

if not defined PYTHON_BOOTSTRAP (
    where python >nul 2>&1
    if not errorlevel 1 set "PYTHON_BOOTSTRAP=python"
)

if not defined PYTHON_BOOTSTRAP (
    echo [ERROR] Python was not found on PATH.
    echo Install Python 3.10 or newer, enable "Add Python to PATH", and run setup again.
    goto :failed
)

echo [1/6] Checking Python version...
%PYTHON_BOOTSTRAP% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10 or newer is required.
    goto :failed
)

if not exist ".venv\Scripts\python.exe" (
    echo [2/6] Creating virtual environment...
    %PYTHON_BOOTSTRAP% -m venv .venv
    if errorlevel 1 goto :venv_failed
) else (
    echo [2/6] Reusing existing virtual environment.
)

set "VENV_PYTHON=%CD%\.venv\Scripts\python.exe"
if not exist "%VENV_PYTHON%" goto :venv_failed

echo [3/6] Updating pip...
"%VENV_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 goto :dependency_failed

echo [4/6] Installing project dependencies...
"%VENV_PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 goto :dependency_failed

echo [5/6] Preparing configuration and runtime folders...
if not exist "data" mkdir "data"
if not exist "logs" mkdir "logs"
if not exist "config" mkdir "config"

set "CREATED_ENV=0"
if not exist ".env" (
    copy /Y ".env.example" ".env" >nul
    if errorlevel 1 (
        echo [ERROR] Could not create .env from .env.example.
        goto :failed
    )
    set "CREATED_ENV=1"
    echo       Created .env from .env.example.
) else (
    echo       Existing .env preserved.
)

echo [6/6] Running installation checks...
"%VENV_PYTHON%" -c "import fastapi, bs4, requests, dotenv, uvicorn; print('      Dependency check passed.')"
if errorlevel 1 goto :dependency_failed

"%VENV_PYTHON%" -m py_compile main.py
if errorlevel 1 (
    echo [ERROR] main.py did not pass the Python syntax check.
    goto :failed
)

if "%CREATED_ENV%"=="1" (
    echo.
    echo [ACTION REQUIRED] Add your IMAP, SMTP, firewall, and dashboard values to .env.
    echo Opening .env in Notepad now...
    start "" notepad.exe "%CD%\.env"
) else (
    "%VENV_PYTHON%" -c "from core.config import load_config; load_config()" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo [WARNING] The installation is ready, but .env still needs valid configuration values.
    ) else (
        echo       Configuration check passed.
    )
)

echo.
echo ============================================================
echo   Setup completed successfully.
echo ============================================================
echo After saving .env, double-click run_firewall.bat to start the application.
echo.
pause
exit /b 0

:venv_failed
echo [ERROR] The Python virtual environment could not be created or opened.
goto :failed

:dependency_failed
echo [ERROR] Dependency installation failed. Check your internet or package index access.
goto :failed

:failed
echo.
echo Setup did not complete. Correct the error above and run setup.bat again.
echo.
pause
exit /b 1
