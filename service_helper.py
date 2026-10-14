#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Windows Service Helper & Scoped UAC Elevation Manager
Enables unprivileged Flask web application to:
1. Safely query the status of DDoSGuardSnifferService without elevation.
2. Request a narrowly-scoped UAC elevation prompt *only* to start the service when stopped.
3. Gracefully handle user cancellation (Error 1223) without crashing or silent bypass.
4. Monitor startup health, IPC connectivity, and tail the service log.
"""

import os
import sys
import time
import json
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Dict, Any, Optional, List

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_FILE = PROJECT_ROOT / "ddos_guard_service.log"
SERVICE_NAME = "DDoSGuardSnifferService"
DISPLAY_NAME = "DDoS-Guard Network Sniffer Service"

# Win32 Service State Constants
SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING = 0x00000006
SERVICE_PAUSED = 0x00000007

STATE_MAP = {
    SERVICE_STOPPED: "STOPPED",
    SERVICE_START_PENDING: "START_PENDING",
    SERVICE_STOP_PENDING: "STOP_PENDING",
    SERVICE_RUNNING: "RUNNING",
    SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
    SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
    SERVICE_PAUSED: "PAUSED"
}

# Windows ShellExecuteEx Constants
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
ERROR_CANCELLED = 1223  # The operation was canceled by the user (UAC prompt declined)


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE)
    ]


def get_service_status(include_ipc: bool = True) -> Dict[str, Any]:
    """
    Queries the Windows Service status using standard unprivileged Win32 APIs.
    Does not require Administrator elevation.
    """
    result = {
        "installed": False,
        "status": "NOT_INSTALLED",
        "running": False,
        "state_code": 0,
        "pid": 0,
        "win32_exit_code": 0,
        "service_exit_code": 0,
        "ipc_online": False,
        "message": f"Service '{SERVICE_NAME}' is not registered with Windows SCM."
    }

    try:
        import win32service
        import pywintypes

        try:
            hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            hs = win32service.OpenService(hscm, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS)
            status_data = win32service.QueryServiceStatusEx(hs)
            win32service.CloseServiceHandle(hs)
            win32service.CloseServiceHandle(hscm)

            state_code = status_data.get("CurrentState", 0)
            status_str = STATE_MAP.get(state_code, f"UNKNOWN_{state_code}")
            is_running = (status_str == "RUNNING")
            ipc_active = is_service_online() if (is_running and include_ipc) else False

            result.update({
                "installed": True,
                "status": status_str,
                "running": is_running,
                "state_code": state_code,
                "pid": status_data.get("ProcessId", 0),
                "win32_exit_code": status_data.get("Win32ExitCode", 0),
                "service_exit_code": status_data.get("ServiceSpecificExitCode", 0),
                "ipc_online": ipc_active,
                "message": f"Service is currently {status_str}."
            })
            return result
        except pywintypes.error as pe:
            if pe.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return result
            result["message"] = f"Win32 SCM query error: {pe}"
            return result
    except ImportError:
        pass

    # Fallback to sc.exe query
    try:
        import subprocess
        cp = subprocess.run(
            ["sc.exe", "query", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=3.0
        )
        out = cp.stdout or ""
        if "does not exist" in out.lower() or cp.returncode != 0:
            return result

        result["installed"] = True
        if "RUNNING" in out:
            result["status"] = "RUNNING"
            result["state_code"] = SERVICE_RUNNING
            result["running"] = True
        elif "STOPPED" in out:
            result["status"] = "STOPPED"
            result["state_code"] = SERVICE_STOPPED
            result["running"] = False
        elif "START_PENDING" in out:
            result["status"] = "START_PENDING"
            result["state_code"] = SERVICE_START_PENDING
            result["running"] = False
        else:
            result["status"] = "INSTALLED"
            result["running"] = False

        if include_ipc and result["running"]:
            result["ipc_online"] = is_service_online()
        result["message"] = f"Service is currently {result['status']}."
    except Exception as e:
        result["message"] = f"Failed to query service state: {e}"

    return result


def is_service_online() -> bool:
    """Checks if the service is online and actively answering authenticated IPC pings."""
    try:
        from ipc_client import DDoSGuardIPCClient
        client = DDoSGuardIPCClient()
        return client.is_service_running()
    except Exception:
        return False


def tail_service_log(max_lines: int = 20) -> List[str]:
    """Reads the tail of ddos_guard_service.log for diagnostics."""
    if not LOG_FILE.exists():
        return []
    try:
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-max_lines:] if len(lines) > max_lines else lines
    except Exception:
        return []


def request_service_start(timeout: float = 8.0) -> Dict[str, Any]:
    """
    Prompts the user with a narrowly-scoped UAC elevation dialog to start only
    the DDoSGuardSnifferService.
    
    Returns:
    - {'status': 'already_running', 'message': ...}
    - {'status': 'not_installed', 'message': ...}
    - {'status': 'started', 'message': ...}
    - {'status': 'uac_cancelled', 'message': ...}
    - {'status': 'start_failed', 'message': ..., 'log_tail': ...}
    """
    # 1. Quick check: already running?
    if is_service_online():
        return {
            "status": "already_running",
            "message": "DDoS-Guard Windows Service is already running."
        }

    # 2. Check installation state
    svc_state = get_service_status()
    if not svc_state.get("installed"):
        return {
            "status": "not_installed",
            "message": (
                "DDoS-Guard Windows Service is not installed. "
                "Please run 'powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 Install' "
                "as Administrator once before capturing live packets."
            )
        }

    # 3. Prepare scoped UAC elevation
    # Dynamically resolve virtual environment and python paths for SCM host
    py_home = sys.base_prefix
    venv_dir = sys.prefix
    site_packages = str(Path(venv_dir) / "Lib" / "site-packages")
    win32_dir = str(Path(site_packages) / "win32")
    win32_lib = str(Path(win32_dir) / "lib")
    scripts_dir = str(Path(venv_dir) / "Scripts")
    proj_root = str(PROJECT_ROOT)
    py_path = f"{site_packages};{win32_dir};{win32_lib};{proj_root}"

    # Command ensures SCM Environment (PYTHONPATH & PYTHONHOME) is configured, then starts service
    ps_cmd = (
        f"$ErrorActionPreference='Stop'; "
        f"$svcKey='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{SERVICE_NAME}'; "
        f"$curr=(Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue).Environment; "
        f"if (-not $curr) {{ "
        f"  $envArr=@('PYTHONPATH={py_path}', 'PYTHONHOME={py_home}', 'VIRTUAL_ENV={venv_dir}', 'PATH={scripts_dir};{win32_dir};{py_home};{py_home}\\Scripts;' + $env:PATH); "
        f"  Set-ItemProperty -Path $svcKey -Name 'Environment' -Value $envArr -Type MultiString; "
        f"}}; "
        f"Start-Service -Name '{SERVICE_NAME}'; "
        f"exit 0"
    )
    params = f"-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"{ps_cmd}\""

    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"  # Triggers standard Windows UAC prompt
    sei.lpFile = "powershell.exe"
    sei.lpParameters = params
    sei.lpDirectory = str(PROJECT_ROOT)
    sei.nShow = SW_HIDE

    # Invoke elevation
    success = shell32.ShellExecuteExW(ctypes.byref(sei))
    if not success:
        err = kernel32.GetLastError()
        if err == ERROR_CANCELLED:
            return {
                "status": "uac_cancelled",
                "error_code": ERROR_CANCELLED,
                "message": (
                    "Administrator approval was cancelled by the user. "
                    "Physical network packet capture requires starting the background service. "
                    "You can still use simulated traffic via 'python send_traffic.py'."
                )
            }
        return {
            "status": "start_failed",
            "error_code": err,
            "message": f"Failed to execute elevated service startup (Win32 Error: {err})."
        }

    # Wait for the elevated PowerShell process to finish
    hProcess = sei.hProcess
    if hProcess:
        kernel32.WaitForSingleObject(hProcess, 15000)
        kernel32.CloseHandle(hProcess)

    # 4. Verify actual Windows service state and IPC health
    start_t = time.time()
    while time.time() - start_t < timeout:
        st = get_service_status()
        if st.get("status") == "RUNNING" and is_service_online():
            return {
                "status": "started",
                "message": "DDoS-Guard Windows Service started and verified online."
            }
        time.sleep(0.3)

    # If timeout occurred, check recent logs for root cause
    recent_logs = tail_service_log(15)
    return {
        "status": "start_failed",
        "message": (
            "Service was triggered, but IPC server did not respond within timeout. "
            "Inspect 'ddos_guard_service.log' for details."
        ),
        "log_tail": recent_logs
    }


if __name__ == "__main__":
    print("=" * 60)
    print("DDoS-Guard Windows Service Helper (Unprivileged)")
    print("=" * 60)
    st = get_service_status()
    print("Service Status Query:", json.dumps(st, indent=2))
    print("Service IPC Online  :", is_service_online())
    logs = tail_service_log(5)
    print(f"Recent Log Entries ({len(logs)}):")
    for l in logs:
        print("  ", l)
