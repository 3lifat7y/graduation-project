#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Network Interface Discovery & Npcap / Scapy Driver Health Validator
Automatically detects active network interfaces (Wi-Fi / Ethernet), validates default routing,
and checks packet capture drivers (Npcap, Scapy, Raw Sockets) without hardcoded names or IPs.
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


def get_scapy_interfaces_info() -> Tuple[Dict[int, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Retrieves Scapy/Npcap interface identifiers keyed by interface index and identifier/name."""
    info_by_idx: Dict[int, Dict[str, Any]] = {}
    info_by_name: Dict[str, Dict[str, Any]] = {}
    try:
        from scapy.all import conf
        if getattr(conf, "ifaces", None):
            for if_key, if_obj in conf.ifaces.items():
                idx = getattr(if_obj, "index", None)
                widx = getattr(if_obj, "win_index", None)
                guid = getattr(if_obj, "guid", None)
                net_name = getattr(if_obj, "network_name", None) or str(if_key)
                name = getattr(if_obj, "name", None)
                ip = getattr(if_obj, "ip", None)
                mac = getattr(if_obj, "mac", None)
                desc = getattr(if_obj, "description", None)
                entry = {
                    "scapy_name": name,
                    "scapy_desc": desc,
                    "guid": guid,
                    "network_name": net_name,
                    "index": idx if idx is not None else widx,
                    "ip": ip,
                    "mac": mac,
                }
                if idx is not None:
                    try:
                        info_by_idx[int(idx)] = entry
                    except (ValueError, TypeError):
                        pass
                if widx is not None:
                    try:
                        info_by_idx[int(widx)] = entry
                    except (ValueError, TypeError):
                        pass
                if guid:
                    info_by_name[str(guid).strip().lower()] = entry
                if name:
                    info_by_name[str(name).strip().lower()] = entry
    except Exception:
        pass
    return info_by_idx, info_by_name


def get_windows_network_adapters() -> List[Dict[str, Any]]:
    """
    Queries all network adapters and IPv4 addresses via Windows PowerShell
    and enriches each adapter with Scapy/Npcap device identifiers without hardcoded names or IPs.
    """
    adapters = []
    scapy_by_idx, scapy_by_name = get_scapy_interfaces_info()

    if os.name == 'nt':
        try:
            # Query PowerShell for adapters and IP assignments
            ps_cmd = (
                "$a = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, InterfaceIndex, MacAddress, LinkSpeed, PhysicalMediaType, MediaType; "
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
                    p_media = str(ad.get("PhysicalMediaType", "")).strip().lower()
                    media = str(ad.get("MediaType", "")).strip().lower()
                    ips = ips_by_idx.get(idx, [])

                    # Categorize interface type with robust hardware and NDIS media checks
                    lower_name = name.lower()
                    lower_desc = desc.lower()

                    is_virtual = (
                        any(k in lower_desc for k in ["vmware", "virtualbox", "hyper-v", "bluetooth", "wan miniport", "teredo", "isatap", "npcap loopback"]) or
                        any(k in lower_name for k in ["vmware", "virtualbox", "vethernet", "hyper-v", "bluetooth", "loopback"])
                    )

                    if "loopback" in lower_name or "loopback" in lower_desc:
                        adapter_type = "Loopback"
                    elif is_virtual:
                        adapter_type = "Virtual"
                    elif (
                        "802.11" in p_media or "native802_11" in p_media or
                        any(k in lower_name or k in lower_desc for k in ["wi-fi", "wireless", "802.11", "wlan", "wifi"])
                    ):
                        adapter_type = "Wi-Fi"
                    elif (
                        "802.3" in p_media or "802.3" in media or
                        any(k in lower_name or k in lower_desc for k in [
                            "ethernet", "lan", "gigabit", "fast ethernet", "i219", "realtek",
                            "intel(r) ethernet", "broadcom", "marvell", "qualcomm", "killer",
                            "pcie gbe", "pci-e", "gbe family", "usb ethernet", "rj45", "local area connection"
                        ])
                    ):
                        adapter_type = "Ethernet"
                    else:
                        adapter_type = "Other"

                    # Cross-reference Scapy Npcap device info
                    scapy_info = scapy_by_idx.get(idx) or scapy_by_name.get(lower_name) or {}
                    network_name = scapy_info.get("network_name")
                    guid = scapy_info.get("guid")
                    scapy_ip = scapy_info.get("ip")
                    if scapy_ip and scapy_ip not in ips and not scapy_ip.startswith("169.254."):
                        ips.append(scapy_ip)

                    adapters.append({
                        "name": name,
                        "description": desc,
                        "status": status,
                        "index": idx,
                        "mac": mac or scapy_info.get("mac", "N/A"),
                        "link_speed": speed,
                        "type": adapter_type,
                        "ips": ips,
                        "is_virtual": is_virtual,
                        "network_name": network_name,
                        "guid": guid,
                        "scapy_name": scapy_info.get("scapy_name", name)
                    })
        except Exception as e:
            print(f"[Warning] Failed to query Windows adapters via PowerShell: {e}", file=sys.stderr)

    # Scapy-Based Secondary Discovery: If PowerShell returned no adapters, query Scapy's conf.ifaces directly
    if not adapters and scapy_by_name:
        for if_name_key, s_entry in scapy_by_name.items():
            s_name = s_entry.get("scapy_name") or if_name_key
            s_desc = s_entry.get("scapy_desc") or ""
            s_ip = s_entry.get("ip")
            s_idx = s_entry.get("index") or 0
            lower_name = s_name.lower()
            lower_desc = s_desc.lower()

            is_virtual = (
                any(k in lower_desc for k in ["vmware", "virtualbox", "hyper-v", "bluetooth", "wan miniport"]) or
                any(k in lower_name for k in ["vmware", "virtualbox", "vethernet", "hyper-v", "bluetooth", "loopback"])
            )
            if "loopback" in lower_name or "loopback" in lower_desc:
                adapter_type = "Loopback"
            elif is_virtual:
                adapter_type = "Virtual"
            elif any(k in lower_name or k in lower_desc for k in ["wi-fi", "wireless", "802.11", "wlan", "wifi"]):
                adapter_type = "Wi-Fi"
            elif any(k in lower_name or k in lower_desc for k in ["ethernet", "lan", "gigabit", "i219", "realtek", "fast ethernet"]):
                adapter_type = "Ethernet"
            else:
                adapter_type = "Other"

            ips = [s_ip] if s_ip and not s_ip.startswith("169.254.") else []
            adapters.append({
                "name": s_name,
                "description": s_desc,
                "status": "Up" if ips else "Unknown",
                "index": s_idx,
                "mac": s_entry.get("mac") or "N/A",
                "link_speed": "N/A",
                "type": adapter_type,
                "ips": ips,
                "is_virtual": is_virtual,
                "network_name": s_entry.get("network_name"),
                "guid": s_entry.get("guid"),
                "scapy_name": s_name
            })

    # Robust Fallback: If no adapters discovered yet, use active routable IP without hardcoding Wi-Fi
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
                "type": "Ethernet",  # Conservative neutral physical default, never assume Wi-Fi
                "ips": [active_ip],
                "is_virtual": False,
                "network_name": None,
                "guid": None,
                "scapy_name": "Primary Active Adapter"
            })

    return adapters


def check_capture_drivers(tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Checks if Npcap + Scapy or Raw Sockets can capture packets on this machine.
    Returns status and actionable resolution instructions.
    """
    admin = is_admin_user()
    result = {
        "npcap_installed": False,
        "npcap_driver_ready": False,
        "scapy_available": False,
        "windivert_available": False,
        "windivert_driver_ready": False,
        "is_admin": admin,
        "raw_socket_available": False,
        "can_capture_live": False,
        "active_engine": "None",
        "error_reason": None,
        "remediation_guide": None
    }

    # 1. Test Npcap Driver Installation on Windows
    npcap_paths = [
        Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
        Path(r"C:\Windows\System32\wpcap.dll"),
        Path(r"C:\Program Files\Npcap"),
        Path(r"C:\Windows\System32\Npcap")
    ]
    has_npcap = any(p.exists() for p in npcap_paths)
    if not has_npcap and os.name == 'nt':
        try:
            chk = subprocess.run(
                ["sc.exe", "query", "npcap"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if "RUNNING" in chk.stdout or "STATE" in chk.stdout:
                has_npcap = True
        except Exception:
            pass

    result["npcap_installed"] = has_npcap

    # 2. Test Scapy Library Availability
    try:
        import scapy
        result["scapy_available"] = True
        result["windivert_available"] = True  # Backward compatibility alias
    except ImportError:
        result["scapy_available"] = False
        result["windivert_available"] = False
        result["error_reason"] = "scapy library is not installed. Run 'pip install scapy'."

    # 3. Determine if live capture is possible
    if result["scapy_available"] and result["npcap_installed"]:
        can_pcap = False
        try:
            from scapy.all import conf
            if conf.use_pcap and getattr(conf, "ifaces", None):
                can_pcap = True
        except Exception:
            pass

        if can_pcap or admin:
            result["npcap_driver_ready"] = True
            result["windivert_driver_ready"] = True
            result["can_capture_live"] = True
            result["active_engine"] = "Npcap/Scapy"
        else:
            result["npcap_driver_ready"] = False
            result["windivert_driver_ready"] = False
            result["error_reason"] = "Npcap kernel driver is not accessible or requires Windows Administrator privileges."
    elif not result["npcap_installed"]:
        result["error_reason"] = "Npcap driver is not installed on this machine."

    # 4. Test Raw Socket capability (fallback check)
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

    # 5. Set Remediation Guide if live capture is not available in current session
    if not result["can_capture_live"]:
        if not result["npcap_installed"]:
            result["remediation_guide"] = (
                "Npcap packet capture driver is not installed. "
                "Please download and install Npcap from https://npcap.com (ensure 'Install Npcap in WinPcap API-compatible Mode' is enabled)."
            )
        elif not result["is_admin"]:
            result["remediation_guide"] = (
                "Npcap is ready on Windows, but requires Administrator privileges. "
                "Please launch your command prompt, IDE, or terminal as Administrator."
            )
        elif not result["scapy_available"]:
            result["remediation_guide"] = (
                "Scapy packet capture engine requires 'scapy' library. "
                "Ensure 'scapy' is installed with 'pip install scapy' and run as Administrator."
            )
        else:
            result["remediation_guide"] = (
                "Packet capture engine requires Npcap driver and Administrator privileges. "
                "Verify Npcap installation and run terminal as Administrator."
            )

    return result


def auto_detect_primary_interface() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Selects the primary active network adapter using routing and interface health.
    Prioritizes connected physical Ethernet adapters over Wi-Fi, rejects disconnected/disabled
    adapters, and retrieves current IPv4, interface index, and Scapy/Npcap identifiers.
    Returns:
        (adapter_dict, driver_health_dict)
    """
    active_ip = get_active_routable_ip()
    adapters = get_windows_network_adapters()
    drivers = check_capture_drivers()

    selected = None

    # Filter physical, non-virtual adapters
    physical_adapters = [ad for ad in adapters if not ad.get("is_virtual", False)]

    def _has_valid_ip(ad_dict: Dict[str, Any]) -> bool:
        return any(
            ip and not ip.startswith("169.254.") and not ip.startswith("127.")
            for ip in ad_dict.get("ips", [])
        )

    # Priority 1: Connected physical Ethernet adapter with status 'Up' and valid non-APIPA IPv4
    for ad in physical_adapters:
        if ad.get("status") == "Up" and ad.get("type") == "Ethernet" and _has_valid_ip(ad):
            selected = ad
            break

    # Priority 2: If active routable IP matches an Up physical Ethernet adapter
    if not selected and active_ip:
        for ad in physical_adapters:
            if ad.get("status") == "Up" and ad.get("type") == "Ethernet" and active_ip in ad.get("ips", []):
                selected = ad
                break

    # Priority 3: Connected physical Wi-Fi adapter with status 'Up' and valid non-APIPA IPv4
    if not selected:
        for ad in physical_adapters:
            if ad.get("status") == "Up" and ad.get("type") == "Wi-Fi" and _has_valid_ip(ad):
                selected = ad
                break

    # Priority 4: Match active routable IP on any physical adapter that is 'Up'
    if not selected and active_ip:
        for ad in physical_adapters:
            if ad.get("status") == "Up" and active_ip in ad.get("ips", []):
                selected = ad
                break

    # Priority 5: Any physical adapter (Ethernet first, then Wi-Fi) with status 'Up'
    if not selected:
        for ad in physical_adapters:
            if ad.get("status") == "Up" and ad.get("type") == "Ethernet":
                selected = ad
                break
        if not selected:
            for ad in physical_adapters:
                if ad.get("status") == "Up" and ad.get("type") == "Wi-Fi":
                    selected = ad
                    break

    # Priority 6: Fallback to any non-virtual adapter that is 'Up'
    if not selected:
        for ad in physical_adapters:
            if ad.get("status") == "Up":
                selected = ad
                break

    if not selected:
        # Check if physical adapters exist but are down / disabled (e.g. Wi-Fi turned off or cable unplugged)
        down_physical = [ad for ad in adapters if ad.get("type") in ["Wi-Fi", "Ethernet"] and not ad.get("is_virtual", False)]
        if down_physical:
            names = ", ".join(f"{a['name']} ({a.get('status', 'Offline')})" for a in down_physical)
            raise RuntimeError(
                f"Network adapter is offline or disconnected: {names}. "
                f"Please enable Wi-Fi or connect an Ethernet cable."
            )
        else:
            raise RuntimeError(
                "No active physical network adapter detected on this system. "
                "Please connect your device to Wi-Fi or plug in an Ethernet cable."
            )

    # Determine primary IP strictly from the SELECTED adapter's own IP list
    valid_selected_ips = [
        ip for ip in selected.get("ips", [])
        if ip and not ip.startswith("169.254.") and not ip.startswith("127.")
    ]
    if active_ip and active_ip in selected.get("ips", []):
        selected_ip = active_ip
    elif valid_selected_ips:
        selected_ip = valid_selected_ips[0]
    elif selected.get("ips"):
        selected_ip = selected["ips"][0]
    else:
        selected_ip = None

    selected["primary_ip"] = selected_ip
    selected["is_connected"] = bool(selected_ip and selected.get("status") == "Up")
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
        print(f"   • Npcap Driver         : {'Installed' if driver_info['npcap_installed'] else 'NOT Installed'}")
        print(f"   • Scapy Engine         : {'Available' if driver_info['scapy_available'] else 'NOT Installed'}")
        print(f"   • Administrator Rights : {'Yes (Elevated)' if driver_info['is_admin'] else 'No (Standard User)'}")
        print(f"   • Driver Kernel Ready  : {'Active' if driver_info['npcap_driver_ready'] else 'Awaiting Admin'}")
        print(f"   • Raw Socket           : {'Available' if driver_info['raw_socket_available'] else 'Requires Admin'}")
        print(f"   • Can Sniff Live       : {driver_info['can_capture_live']} (Engine: {driver_info['active_engine']})")
        if not driver_info['can_capture_live']:
            print(f"\n⚠️ Action Required for Physical Live Capture:")
            print(f"   {driver_info['remediation_guide']}")
        print("\n" + "=" * 65)
    except Exception as ex:
        print(f"Error: {ex}", file=sys.stderr)
        sys.exit(1)
