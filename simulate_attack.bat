@echo off
cd /d "%~dp0"
title DDoS-Guard Traffic Simulator
echo =========================================================================
echo               DDoS-Guard: Simulated Attack Traffic Generator
echo =========================================================================
echo.
echo Make sure the DDoS-Guard Web UI is running first (http://127.0.0.1:5000).
echo.
set "PY_EXE="
if exist "%~dp0.venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if "%PY_EXE%"=="" where python >nul 2>&1 && set "PY_EXE=python"
if "%PY_EXE%"=="" if exist "C:\Users\alifa\AppData\Local\Python\pythoncore-3.15-64\python.exe" set "PY_EXE=C:\Users\alifa\AppData\Local\Python\pythoncore-3.15-64\python.exe"
if "%PY_EXE%"=="" (
    echo [ERROR] No Python interpreter found!
    pause
    exit /b 1
)

"%PY_EXE%" scripts\send_traffic.py
pause

