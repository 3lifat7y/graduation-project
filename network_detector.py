#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Network Interface Discovery & WinDivert Driver Health Validator
Automatically detects active network interfaces (Wi-Fi / Ethernet), validates default routing,
and checks packet capture drivers (WinDivert / pydivert, Raw Sockets) without hardcoded names or IPs.
"""

import os
import sys
import json
import socket
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def is_admin_user() -> bool:
    """Checks if the current process possesses Windows Administrator rights."""
    if os.name != 'nt':
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_tshark_path() -> Optional[str]:
    """Locates the tshark executable in PATH or standard installation directories."""
    which_path = shutil.which("tshark")
    if which_path and os.path.isfile(which_path):
        return which_path

    common_locations = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Wireshark", "tshark.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Wireshark", "tshark.exe"),
    ]
    for loc in common_locations:
        if os.path.isfile(loc):
            return loc
    return None


def get_active_routable_ip() -> Optional[str]:
    """Determines the primary local IPv4 address connected to the default gateway."""
    test_targets = [("8.8.8.8", 80), ("1.1.1.1", 80), ("208.67.222.222", 53)]
    for host, port in test_targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.connect((host, port))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                return ip
        except Exception:
            continue
    return None


def get_windows_network_adapters() -> List[Dict[str, Any]]:
    """Queries all network adapters and IPv4 addresses via Windows PowerShell with fallback."""
    adapters = []
    if os.name != 'nt':
        return adapters

    try:
        # Combined query to reduce PowerShell startup overhead and halve execution time
        ps_cmd = (
            "$a = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, InterfaceIndex, MacAddress, LinkSpeed; "
            "$b = Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, InterfaceIndex, PrefixLength; "
            "@{adapters=$a; ips=$b} | ConvertTo-Json -Compress -Depth 3"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15
        )
        if res.returncode == 0 and res.stdout.strip():
            payload = json.loads(res.stdout.strip())
            raw_adapters = payload.get("adapters", [])
            if isinstance(raw_adapters, dict):
                raw_adapters = [raw_adapters]
            raw_ips = payload.get("ips", [])
            if isinstance(raw_ips, dict):
                raw_ips = [raw_ips]

            ips_by_idx = {}
            for entry in raw_ips:
                idx = entry.get("InterfaceIndex")
                ip = entry.get("IPAddress")
                if idx and ip:
                    ips_by_idx.setdefault(idx, []).append(ip)

            for ad in raw_adapters:
                name = str(ad.get("Name", "")).strip()
                desc = str(ad.get("InterfaceDescription", "")).strip()
                status = str(ad.get("Status", "Unknown")).strip()
                idx = ad.get("InterfaceIndex", 0)
                mac = str(ad.get("MacAddress", "")).strip()
                speed = str(ad.get("LinkSpeed", "0 bps")).strip()
                ips = ips_by_idx.get(idx, [])

                # Categorize interface type
                lower_name = name.lower()
                lower_desc = desc.lower()

                if any(k in lower_name or k in lower_desc for k in ["wi-fi", "wireless", "802.11", "wlan"]):
                    adapter_type = "Wi-Fi"
                elif any(k in lower_name or k in lower_desc for k in ["ethernet", "lan", "gigabit", "fast ethernet", "i219", "realtek"]):
                    adapter_type = "Ethernet"
                elif "loopback" in lower_name or "loopback" in lower_desc:
                    adapter_type = "Loopback"
                elif any(k in lower_name or k in lower_desc for k in ["vmware", "virtualbox", "vethernet", "hyper-v"]):
                    adapter_type = "Virtual"
                else:
                    adapter_type = "Other"

                is_virtual = (adapter_type in ["Virtual", "Loopback"]) or any(k in lower_desc for k in ["vmware", "virtualbox", "hyper-v", "bluetooth"])

                adapters.append({
                    "name": name,
                    "description": desc,
                    "status": status,
                    "index": idx,
                    "mac": mac,
                    "link_speed": speed,
                    "type": adapter_type,
                    "ips": ips,
                    "is_virtual": is_virtual
                })
    except Exception as e:
        print(f"[Warning] Failed to query Windows adapters via PowerShell: {e}", file=sys.stderr)

    # Robust Fallback: If PowerShell timed out or returned no adapters, use direct socket gateway IP
    if not adapters:
        active_ip = get_active_routable_ip()
        if active_ip:
            adapters.append({
                "name": "Primary Active Adapter",
                "description": "Auto-detected routable IPv4 network interface",
                "status": "Up",
                "index": 1,
                "mac": "N/A",
                "link_speed": "N/A",
                "type": "Wi-Fi",
                "ips": [active_ip],
                "is_virtual": False
            })

    return adapters


def check_capture_drivers(tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Checks if WinDivert (pydivert) or Raw Sockets can capture packets on this machine.
    Returns status and actionable resolution instructions.
    """
    admin = is_admin_user()
    result = {
        "windivert_available": False,
        "windivert_driver_ready": False,
        "is_admin": admin,
        "npcap_installed": False,
        "raw_socket_available": False,
        "can_capture_live": False,
        "active_engine": "None",
        "error_reason": None,
        "remediation_guide": None
    }

    # 1. Test WinDivert (pydivert) capability
    try:
        import pydivert
        result["windivert_available"] = True
        
        # Test opening WinDivert if running with Administrator privileges
        if admin:
            try:
                with pydivert.WinDivert("true", flags=pydivert.Flag.SNIFF) as w:
                    result["windivert_driver_ready"] = True
                    result["can_capture_live"] = True
                    result["active_engine"] = "WinDivert"
            except Exception as e:
                result["error_reason"] = f"WinDivert initialization warning: {e}"
        else:
            result["error_reason"] = "WinDivert kernel driver requires Windows Administrator privileges."
    except ImportError:
        result["windivert_available"] = False
        result["error_reason"] = "pydivert library is not installed."
    except Exception as e:
        result["error_reason"] = f"WinDivert inspection error: {e}"

    # 2. Test Raw Socket capability (Windows Administrator check)
    try:
        active_ip = get_active_routable_ip()
        if active_ip:
            raw_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            raw_s.bind((active_ip, 0))
            raw_s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            raw_s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            raw_s.close()
            result["raw_socket_available"] = True
            if not result["can_capture_live"]:
                result["can_capture_live"] = True
                result["active_engine"] = "RawSocket"
    except Exception:
        result["raw_socket_available"] = False

    # 3. Set Remediation Guide if live capture is not available in current session
    if not result["can_capture_live"]:
        if result["windivert_available"] and not result["is_admin"]:
            result["remediation_guide"] = (
                "WinDivert is ready on Windows, but requires Administrator privileges. "
                "Please launch your command prompt, IDE, or terminal as Administrator."
            )
        else:
            result["remediation_guide"] = (
                "WinDivert packet capture engine requires 'pydivert' and Administrator privileges. "
                "Ensure 'pydivert' is installed and run terminal as Administrator."
            )

    return result


def auto_detect_primary_interface() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Selects the primary active network adapter using routing and interface health.
    Returns:
        (adapter_dict, driver_health_dict)
    """
    active_ip = get_active_routable_ip()
    adapters = get_windows_network_adapters()
    drivers = check_capture_drivers()

    selected = None

    # Priority 1: Match adapter possessing the active routable IP
    if active_ip:
        for ad in adapters:
            if active_ip in ad["ips"]:
                selected = ad
                break

    # Priority 2: Active physical adapter (Wi-Fi or Ethernet) with status 'Up' and non-APIPA IP
    if not selected:
        for ad in adapters:
            if ad["status"] == "Up" and not ad["is_virtual"] and ad["type"] in ["Wi-Fi", "Ethernet"]:
                valid_ips = [ip for ip in ad["ips"] if not ip.startswith("169.254.") and not ip.startswith("127.")]
                if valid_ips:
                    selected = ad
                    break

    # Priority 3: Any physical adapter that is 'Up'
    if not selected:
        for ad in adapters:
            if ad["status"] == "Up" and not ad["is_virtual"]:
                selected = ad
                break

    # Priority 4: Fallback to any adapter that is 'Up'
    if not selected:
        for ad in adapters:
            if ad["status"] == "Up":
                selected = ad
                break

    if not selected:
        # Build helpful diagnostic error
        err_lines = [
            "❌ No active network adapter with an active link was detected on this system!",
            "Available network adapters:"
        ]
        if adapters:
            for ad in adapters:
                ips_str = ", ".join(ad["ips"]) if ad["ips"] else "No IPv4"
                err_lines.append(f"  • {ad['name']:<25} ({ad['type']}) | Status: {ad['status']:<10} | IP: {ips_str}")
        else:
            err_lines.append("  (Could not query adapters via system APIs.)")
        err_lines.append("Please connect your device to Wi-Fi or plug in an Ethernet cable.")
        raise RuntimeError("\n".join(err_lines))

    # Enrich selected adapter
    selected["primary_ip"] = active_ip or (selected["ips"][0] if selected["ips"] else "127.0.0.1")
    selected["driver_status"] = drivers

    return selected, drivers


if __name__ == "__main__":
    print("=" * 65)
    print("      DDoS-Guard: NETWORK INTERFACE & DRIVER DIAGNOSTICS")
    print("=" * 65)
    try:
        adapter, driver_info = auto_detect_primary_interface()
        print(f"\n✅ Primary Active Network Adapter Detected:")
        print(f"   • Name             : {adapter['name']}")
        print(f"   • Type             : {adapter['type']}")
        print(f"   • Description      : {adapter['description']}")
        print(f"   • Status           : {adapter['status']}")
        print(f"   • Primary IP       : {adapter['primary_ip']}")
        print(f"   • MAC Address      : {adapter['mac']}")
        print(f"   • Link Speed       : {adapter['link_speed']}")
        print(f"\n🔍 Capture Driver Status:")
        print(f"   • WinDivert (pydivert) : {'Installed & Available' if driver_info['windivert_available'] else 'NOT Installed'}")
        print(f"   • Administrator Rights : {'Yes (Elevated)' if driver_info['is_admin'] else 'No (Standard User)'}")
        print(f"   • Driver Kernel Ready  : {'Active' if driver_info['windivert_driver_ready'] else 'Awaiting Admin'}")
        print(f"   • Raw Socket           : {'Available' if driver_info['raw_socket_available'] else 'Requires Admin'}")
        print(f"   • Can Sniff Live       : {driver_info['can_capture_live']} (Engine: {driver_info['active_engine']})")
        if not driver_info['can_capture_live']:
            print(f"\n⚠️ Action Required for Physical Live Capture:")
            print(f"   {driver_info['remediation_guide']}")
        print("\n" + "=" * 65)
    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr)
        sys.exit(1)
