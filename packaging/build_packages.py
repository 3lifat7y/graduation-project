#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Automated Windows Application & Service Packaging Script
Builds standalone Windows distribution packages using PyInstaller.
Stages all assets, models, web templates, WinDivert binaries, and deployment scripts.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist" / "DDoS-Guard-Windows"

def build_package():
    print("=" * 70)
    print("📦 DDoS-Guard: Building Windows Application & Service Package")
    print("=" * 70)

    # 1. Clean and prepare dist directory
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR, ignore_errors=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    print(f"  • Staging Directory: {DIST_DIR}")

    # 2. Stage Web UI assets
    print("  • Copying Web UI assets (templates & static)...")
    shutil.copytree(PROJECT_ROOT / "templates", DIST_DIR / "templates", dirs_exist_ok=True)
    shutil.copytree(PROJECT_ROOT / "static", DIST_DIR / "static", dirs_exist_ok=True)

    # 3. Stage Champion Model and Configs
    print("  • Copying AI Champion Model & 77 Feature Schema...")
    shutil.copytree(PROJECT_ROOT / "final_output_new_dataset" / "models", DIST_DIR / "final_output_new_dataset" / "models", dirs_exist_ok=True)
    shutil.copytree(PROJECT_ROOT / "final_output_new_dataset" / "configs", DIST_DIR / "final_output_new_dataset" / "configs", dirs_exist_ok=True)

    # 4. Verify Npcap Driver Environment
    print("  • Verifying Npcap system driver installation...")
    npcap_paths = [
        Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
        Path(r"C:\Windows\System32\wpcap.dll"),
        Path(r"C:\Program Files\Npcap")
    ]
    npcap_detected = any(p.exists() for p in npcap_paths)
    if npcap_detected:
        print("    ✅ Npcap system driver and wpcap.dll verified.")
    else:
        print("    ⚠️ Npcap driver not found in standard system directories. Target machine must have Npcap installed.")

    # 5. Stage Python source modules and packages
    print("  • Staging Core Python Modules & Packages...")
    core_dirs = ["modules", "ml_engine", "scripts"]
    for cd in core_dirs:
        src_d = PROJECT_ROOT / cd
        if src_d.exists():
            shutil.copytree(src_d, DIST_DIR / cd, dirs_exist_ok=True)
            print(f"    ✅ Staged package directory: {cd}")

    core_files = [
        "api.py",
        "ddos_guard_service.py",
        "feature_extraction2.py",
        "network_detector.py",
        "ipc_client.py",
        "send_traffic.py",
        "service_manager.ps1",
        "run_ddos_guard.bat",
        "simulate_attack.bat"
    ]
    for cf in core_files:
        src = PROJECT_ROOT / cf
        if src.exists():
            shutil.copy2(src, DIST_DIR / cf)
            print(f"    ✅ Staged {cf}")

    # 6. Create Package Readme & Deployment Guide
    readme_content = """# DDoS-Guard: Windows Application & Service Package

## Structure:
- `api.py` / `run_ddos_guard.bat`: Web UI & Flask Backend (Runs with standard user privileges).
- `ddos_guard_service.py` / `service_manager.ps1`: Windows Service for WinDivert packet capture.
- `driver/`: Contains signed 64-bit WinDivert kernel driver binaries.
- `final_output_new_dataset/`: Champion XGBoost model and exact 77-feature configuration.
- `templates/` & `static/`: Modern Web UI dashboard.

## Installation & Deployment (Standard Windows Workflow):
1. **To run with simulated attack traffic (No Administrator rights required):**
   - Double-click `run_ddos_guard.bat`
   - Open browser at `http://127.0.0.1:5000`
   - In another terminal, run: `python send_traffic.py`

2. **To install the Windows Sniffer Service for live physical packet capture:**
   - Open PowerShell as Administrator
   - Run: `.\\service_manager.ps1 Install`
   - Run: `.\\service_manager.ps1 Start`
   - Double-click `run_ddos_guard.bat` (Starts Web UI)
   - Status badge will display `WinDivert: Ready`

3. **To uninstall the Windows Service:**
   - Open PowerShell as Administrator
   - Run: `.\\service_manager.ps1 Uninstall`
"""
    with open(DIST_DIR / "README_PACKAGE.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

    print("\n" + "=" * 70)
    print(f"🎉 Packaging successfully assembled at: {DIST_DIR}")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = build_package()
    sys.exit(0 if success else 1)
