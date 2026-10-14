@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title DDoS-Guard: AI-Powered Intrusion ^& DDoS Detection System

echo =========================================================================
echo       DDoS-Guard: AI-Powered Real-Time Intrusion Detection System
echo =========================================================================
echo.

set "PY_EXE="

:: 1. Check local virtual environment
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY_EXE=%~dp0.venv\Scripts\python.exe"
    goto :found_python
)

:: 2. Check system PATH python
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_EXE=python"
    goto :found_python
)

:: 3. Check specific Windows custom path
if exist "C:\Users\alifa\AppData\Local\Python\pythoncore-3.15-64\python.exe" (
    set "PY_EXE=C:\Users\alifa\AppData\Local\Python\pythoncore-3.15-64\python.exe"
    goto :found_python
)

:: 4. Check standard AppData Python installs
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
    if exist "%%D\python.exe" (
        set "PY_EXE=%%D\python.exe"
        goto :found_python
    )
)

:found_python
if "%PY_EXE%"=="" (
    echo [ERROR] No Python interpreter found on this system!
    echo Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

echo [INFO] Using Python: %PY_EXE%
echo [INFO] Launching Flask Backend ^& Web UI...
echo [INFO] Web UI will be accessible at: http://127.0.0.1:5000
echo.

"%PY_EXE%" api.py
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Application exited with error code %errorlevel%.
)

pause
