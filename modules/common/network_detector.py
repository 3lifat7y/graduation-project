#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Network Interface Discovery & Npcap / Scapy Driver Health Validator
Automatically detects active network interfaces (Wi-Fi / Ethernet), validates default routing,
and checks packet capture drivers (Npcap, Scapy, Raw Sockets) without hardcoded names or IPs.
"""

import os
import sys
import time
import json
import re
import socket
import shutil
import threading
import ipaddress
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

OFFICIAL_WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download.html"
OFFICIAL_NPCAP_DOWNLOAD_URL = "https://npcap.com/"

# Thread-safe in-memory cache for Windows network adapter discovery
_adapter_cache_lock = threading.Lock()
_adapter_cache_time: float = 0.0
_adapter_cache_data: List[Dict[str, Any]] = []
ADAPTER_CACHE_TTL_SECONDS: float = 3.0


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


def find_wireshark_installation() -> Dict[str, Any]:
    """
    Locates Wireshark GUI or tshark executables in standard installation directories or system PATH.
    Returns:
        {
            "installed": bool,
            "path": Optional[str],
            "tshark_path": Optional[str]
        }
    """
    tshark = find_tshark_path()
    ws_candidates = [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Wireshark", "Wireshark.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Wireshark", "Wireshark.exe"),
    ]
    ws_exe = None
    for c in ws_candidates:
        if os.path.isfile(c):
            ws_exe = c
            break

    if not ws_exe:
        which_ws = shutil.which("wireshark")
        if which_ws and os.path.isfile(which_ws):
            ws_exe = which_ws
        elif tshark:
            ws_exe = tshark

    return {
        "installed": bool(ws_exe or tshark),
        "path": ws_exe or tshark,
        "tshark_path": tshark
    }


def check_packet_capture_dependencies(
    force_refresh: bool = False,
    override_npcap_installed: Optional[bool] = None,
    override_npcap_running: Optional[bool] = None,
    override_wireshark_installed: Optional[bool] = None,
    override_scapy_available: Optional[bool] = None,
    override_admin: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Performs comprehensive verification of network packet capture dependencies:
    1. Wireshark installation.
    2. Npcap driver installation, DLL presence, and kernel driver service status.
    3. Scapy library and pcap binding.
    4. Network interface capture accessibility and permissions.
    
    Accepts overrides for robust test simulation without altering system state.
    """
    admin = is_admin_user() if override_admin is None else override_admin
    ws_info = find_wireshark_installation()
    if override_wireshark_installed is not None:
        ws_info["installed"] = override_wireshark_installed
        if not override_wireshark_installed:
            ws_info["path"] = None
            ws_info["tshark_path"] = None

    # 1. Npcap DLLs and System Files
    npcap_dlls = [
        Path(r"C:\Windows\System32\Npcap\wpcap.dll"),
        Path(r"C:\Windows\System32\Npcap\Packet.dll"),
        Path(r"C:\Windows\System32\wpcap.dll"),
        Path(r"C:\Windows\System32\Packet.dll"),
        Path(r"C:\Windows\System32\drivers\npcap.sys"),
        Path(r"C:\Program Files\Npcap"),
        Path(r"C:\Program Files (x86)\Npcap"),
    ]
    dll_found = any(p.exists() for p in npcap_dlls)

    # 2. Npcap Driver Service State via Windows Service Controller
    svc_installed = False
    svc_running = False
    svc_state = "UNKNOWN"
    if os.name == 'nt':
        try:
            r = subprocess.run(
                ["sc.exe", "query", "npcap"],
                capture_output=True,
                text=True,
                timeout=3
            )
            out = r.stdout or ""
            err = r.stderr or ""
            combined = (out + " " + err).lower()
            if r.returncode == 0 or "STATE" in out:
                svc_installed = True
                m = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", out)
                if m:
                    svc_state = m.group(1)
                    svc_running = (svc_state == "RUNNING")
            elif "does not exist" in combined or "failed 1060" in combined:
                svc_installed = False
                svc_state = "NOT_INSTALLED"
        except Exception as e:
            svc_state = "ERROR"
    else:
        # Non-Windows POSIX environments (uses libpcap)
        svc_installed = True
        svc_running = True
        svc_state = "N/A"

    npcap_installed = (dll_found or svc_installed)
    if override_npcap_installed is not None:
        npcap_installed = override_npcap_installed
        dll_found = override_npcap_installed
        svc_installed = override_npcap_installed
    if override_npcap_running is not None:
        svc_running = override_npcap_running
        if not override_npcap_running and svc_state == "RUNNING":
            svc_state = "STOPPED"
        elif override_npcap_running and svc_state != "RUNNING":
            svc_state = "RUNNING"

    # 3. Scapy Library & Interface Access
    scapy_avail = False
    use_pcap = False
    iface_count = 0
    try:
        from scapy.all import conf
        scapy_avail = True
        use_pcap = bool(getattr(conf, "use_pcap", False))
        ifaces = getattr(conf, "ifaces", {})
        iface_count = len(ifaces) if ifaces else 0
    except Exception:
        pass

    if override_scapy_available is not None:
        scapy_avail = override_scapy_available
        if not override_scapy_available:
            use_pcap = False
            iface_count = 0

    # 4. Status determination & actionable guidance synthesis
    ready = False
    status_code = "READY"
    title = "Capture Engine Ready"
    message = "Packet capture driver (Npcap) and inspection engine are operational."
    remediation = None
    requires_restart = False

    if not scapy_avail:
        status_code = "SCAPY_MISSING"
        title = "Capture Engine Not Ready"
        message = "SCOUT cannot start Live Network Monitoring because the 'scapy' packet inspection library is missing."
        remediation = "Run 'pip install scapy' in your Python environment."
    elif not npcap_installed:
        if ws_info.get("installed"):
            status_code = "WIRESHARK_NO_NPCAP"
            title = "Npcap Driver Missing"
            message = (
                "SCOUT cannot start Live Network Monitoring because the required Npcap packet capture driver is missing. "
                "Wireshark is installed, but Npcap was not detected."
            )
            remediation = (
                "Please install Npcap from the official website (https://npcap.com/) with 'WinPcap API-compatible Mode' enabled, "
                "or re-run the Wireshark installer and ensure 'Install Npcap' is selected."
            )
        else:
            status_code = "NPCAP_NOT_INSTALLED"
            title = "Capture Engine Not Detected"
            message = (
                "SCOUT cannot start Live Network Monitoring because the required packet capture component is missing or unavailable. "
                "Please install Wireshark with Npcap to enable live network packet capture."
            )
            remediation = (
                "Download and install Wireshark from the official Wireshark download page. "
                "Ensure that the Npcap packet capture library component is checked during installation."
            )
    elif os.name == 'nt' and svc_installed and not svc_running:
        status_code = "NPCAP_SERVICE_NOT_RUNNING"
        title = "Packet Capture Driver Unavailable"
        message = (
            "The Npcap packet capture driver is installed, but its kernel driver service is currently not running. "
            "SCOUT cannot access physical network adapters until the driver service starts."
        )
        remediation = (
            "Start the Npcap service by running 'net start npcap' as Administrator, "
            "or restart your computer if Npcap was recently installed."
        )
        requires_restart = True
    elif os.name == 'nt' and not admin and (not use_pcap or iface_count == 0):
        status_code = "PERMISSIONS_REQUIRED"
        title = "Elevated Capture Permissions Required"
        message = (
            "The Npcap capture driver is installed, but standard user permissions cannot access network interfaces. "
            "Administrator rights are required to bind packet sniffers on Windows."
        )
        remediation = "Please launch SCOUT or your terminal with Administrator privileges ('Run as Administrator')."
    elif iface_count == 0 and not admin:
        status_code = "NO_INTERFACES"
        title = "No Network Interfaces Found"
        message = "No network adapters were discovered for packet capture. Connect an active Wi-Fi or Ethernet adapter."
        remediation = "Ensure a physical or wireless network adapter is enabled and connected to a network."
    else:
        ready = True
        status_code = "READY"
        title = "Capture Engine Ready"
        message = "Packet capture driver (Npcap) and Scapy engine are operational."

    return {
        "ready": ready,
        "status": status_code,
        "title": title,
        "message": message,
        "remediation": remediation,
        "requires_restart": requires_restart,
        "download_url": OFFICIAL_WIRESHARK_DOWNLOAD_URL,
        "npcap_url": OFFICIAL_NPCAP_DOWNLOAD_URL,
        "details": {
            "wireshark": ws_info,
            "npcap": {
                "installed": npcap_installed,
                "running": svc_running,
                "state": svc_state,
                "dll_found": dll_found
            },
            "scapy": {
                "installed": scapy_avail,
                "use_pcap": use_pcap,
                "interface_count": iface_count
            },
            "is_admin": admin
        }
    }


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


def invalidate_adapter_cache():
    """Invalidates the in-memory network adapter discovery cache."""
    global _adapter_cache_time, _adapter_cache_data
    with _adapter_cache_lock:
        _adapter_cache_time = 0.0
        _adapter_cache_data = []


def get_windows_network_adapters(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Queries all network adapters and IPv4 addresses via Windows PowerShell
    and enriches each adapter with Scapy/Npcap device identifiers without hardcoded names or IPs.
    Employs a thread-safe 3-second cache to prevent concurrent PowerShell process storms.
    """
    global _adapter_cache_time, _adapter_cache_data
    with _adapter_cache_lock:
        now = time.time()
        if not force_refresh and (now - _adapter_cache_time < ADAPTER_CACHE_TTL_SECONDS) and _adapter_cache_data:
            return [dict(ad) for ad in _adapter_cache_data]

    adapters = []
    scapy_by_idx, scapy_by_name = get_scapy_interfaces_info()

    if os.name == 'nt':
        try:
            # Query PowerShell for adapters, IP assignments, and default routes
            ps_cmd = (
                "$a = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, InterfaceIndex, MacAddress, LinkSpeed, PhysicalMediaType, MediaType; "
                "$b = Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, InterfaceIndex, PrefixLength; "
                "$c = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, NextHop; "
                "@{adapters=$a; ips=$b; routes=$c} | ConvertTo-Json -Compress -Depth 3"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            if res.returncode == 0 and res.stdout.strip():
                payload = json.loads(res.stdout.strip())
                raw_adapters = payload.get("adapters", [])
                if isinstance(raw_adapters, dict):
                    raw_adapters = [raw_adapters]
                raw_ips = payload.get("ips", [])
                if isinstance(raw_ips, dict):
                    raw_ips = [raw_ips]
                raw_routes = payload.get("routes", [])
                if isinstance(raw_routes, dict):
                    raw_routes = [raw_routes]

                ips_by_idx: Dict[int, List[str]] = {}
                prefixes_by_idx: Dict[int, List[int]] = {}
                for entry in raw_ips:
                    idx = entry.get("InterfaceIndex")
                    ip = entry.get("IPAddress")
                    prefix = entry.get("PrefixLength", 24)
                    if idx and ip:
                        ips_by_idx.setdefault(int(idx), []).append(str(ip).strip())
                        try:
                            prefixes_by_idx.setdefault(int(idx), []).append(int(prefix))
                        except (ValueError, TypeError):
                            prefixes_by_idx.setdefault(int(idx), []).append(24)

                routes_by_idx: Dict[int, str] = {}
                for entry in raw_routes:
                    r_idx = entry.get("InterfaceIndex")
                    hop = entry.get("NextHop")
                    if r_idx and hop and hop != "0.0.0.0":
                        routes_by_idx[int(r_idx)] = str(hop).strip()

                for ad in raw_adapters:
                    name = str(ad.get("Name", "")).strip()
                    desc = str(ad.get("InterfaceDescription", "")).strip()
                    status = str(ad.get("Status", "Unknown")).strip()
                    idx = int(ad.get("InterfaceIndex", 0))
                    mac = str(ad.get("MacAddress", "")).strip()
                    speed = str(ad.get("LinkSpeed", "0 bps")).strip()
                    p_media = str(ad.get("PhysicalMediaType", "")).strip().lower()
                    media = str(ad.get("MediaType", "")).strip().lower()
                    ips = ips_by_idx.get(idx, [])
                    gateway = routes_by_idx.get(idx)

                    # Categorize interface type with robust hardware and NDIS media checks
                    lower_name = name.lower()
                    lower_desc = desc.lower()

                    is_virtual = (
                        any(k in lower_desc for k in ["vmware", "virtualbox", "hyper-v", "bluetooth", "wan miniport", "teredo", "isatap", "npcap loopback"]) or
                        any(k in lower_name for k in ["vmware", "virtualbox", "vethernet", "hyper-v", "bluetooth", "loopback"])
                    )

                    if "virtualbox" in lower_name or "virtualbox" in lower_desc:
                        adapter_type = "VirtualBox"
                    elif "loopback" in lower_name or "loopback" in lower_desc:
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

                    valid_ips = [ip for ip in ips if ip and not ip.startswith("169.254.") and not ip.startswith("127.")]
                    primary_ip = valid_ips[0] if valid_ips else (ips[0] if ips else None)
                    has_ipv4 = bool(valid_ips)
                    is_enabled = status.lower() != "disabled"
                    is_connected = status.lower() == "up" and has_ipv4
                    can_capture = bool(network_name)

                    # Calculate subnet mask, prefix, and CIDR
                    prefix_list = prefixes_by_idx.get(idx, [24])
                    prefix_len = prefix_list[0] if prefix_list else 24
                    subnet_cidr = None
                    subnet_mask = None
                    if primary_ip:
                        try:
                            # Clamp prefix between /8 and /32
                            safe_prefix = min(max(prefix_len, 8), 32)
                            iface_net = ipaddress.IPv4Interface(f"{primary_ip}/{safe_prefix}").network
                            subnet_cidr = str(iface_net)
                            subnet_mask = str(iface_net.netmask)
                        except Exception:
                            pass

                    adapters.append({
                        "name": name,
                        "description": desc,
                        "status": status,
                        "index": idx,
                        "mac": mac or scapy_info.get("mac", "N/A"),
                        "link_speed": speed,
                        "type": adapter_type,
                        "ips": ips,
                        "primary_ip": primary_ip,
                        "has_ipv4": has_ipv4,
                        "is_enabled": is_enabled,
                        "is_connected": is_connected,
                        "can_capture": can_capture,
                        "gateway": gateway,
                        "prefix_length": prefix_len,
                        "subnet_mask": subnet_mask,
                        "subnet_cidr": subnet_cidr,
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
            primary_ip = ips[0] if ips else None
            subnet_cidr = None
            subnet_mask = None
            if primary_ip:
                try:
                    iface_net = ipaddress.IPv4Interface(f"{primary_ip}/24").network
                    subnet_cidr = str(iface_net)
                    subnet_mask = str(iface_net.netmask)
                except Exception:
                    pass

            adapters.append({
                "name": s_name,
                "description": s_desc,
                "status": "Up" if ips else "Unknown",
                "index": s_idx,
                "mac": s_entry.get("mac") or "N/A",
                "link_speed": "N/A",
                "type": adapter_type,
                "ips": ips,
                "primary_ip": primary_ip,
                "has_ipv4": bool(ips),
                "is_enabled": True,
                "is_connected": bool(ips),
                "can_capture": bool(s_entry.get("network_name")),
                "gateway": None,
                "prefix_length": 24,
                "subnet_mask": subnet_mask,
                "subnet_cidr": subnet_cidr,
                "is_virtual": is_virtual,
                "network_name": s_entry.get("network_name"),
                "guid": s_entry.get("guid"),
                "scapy_name": s_name
            })

    # Robust Fallback: If no adapters discovered yet, use active routable IP without hardcoding Wi-Fi
    if not adapters:
        active_ip = get_active_routable_ip()
        if active_ip:
            subnet_cidr = None
            subnet_mask = None
            try:
                iface_net = ipaddress.IPv4Interface(f"{active_ip}/24").network
                subnet_cidr = str(iface_net)
                subnet_mask = str(iface_net.netmask)
            except Exception:
                pass

            adapters.append({
                "name": "Primary Active Adapter",
                "description": "Auto-detected routable IPv4 network interface",
                "status": "Up",
                "index": 1,
                "mac": "N/A",
                "link_speed": "N/A",
                "type": "Ethernet",  # Conservative neutral physical default, never assume Wi-Fi
                "ips": [active_ip],
                "primary_ip": active_ip,
                "has_ipv4": True,
                "is_enabled": True,
                "is_connected": True,
                "can_capture": False,
                "gateway": None,
                "prefix_length": 24,
                "subnet_mask": subnet_mask,
                "subnet_cidr": subnet_cidr,
                "is_virtual": False,
                "network_name": None,
                "guid": None,
                "scapy_name": "Primary Active Adapter"
            })

    # Store discovered adapters in memory cache
    with _adapter_cache_lock:
        _adapter_cache_time = time.time()
        _adapter_cache_data = [dict(ad) for ad in adapters]

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
    deps = check_packet_capture_dependencies()
    result["dependency_details"] = deps
    result["download_url"] = deps.get("download_url", OFFICIAL_WIRESHARK_DOWNLOAD_URL)
    result["npcap_url"] = deps.get("npcap_url", OFFICIAL_NPCAP_DOWNLOAD_URL)

    if not result["can_capture_live"]:
        if deps.get("remediation"):
            result["remediation_guide"] = deps["remediation"]
        elif not result["npcap_installed"]:
            result["remediation_guide"] = (
                f"Npcap packet capture driver is not installed. "
                f"Please install Wireshark with Npcap ({OFFICIAL_WIRESHARK_DOWNLOAD_URL}) or download Npcap ({OFFICIAL_NPCAP_DOWNLOAD_URL})."
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


def auto_detect_interface_with_rationale(adapters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Selects the primary active network adapter using routing and interface health.
    Prioritizes connected physical Ethernet adapters with default gateways over Wi-Fi,
    rejects disconnected/disabled adapters, and provides human-readable selection rationale
    alongside candidate summaries.
    Returns:
        {
            "adapter": adapter_dict,
            "driver_status": driver_health_dict,
            "selection_rationale": rationale_str,
            "candidates": [candidate_dicts]
        }
    """
    active_ip = get_active_routable_ip()
    if adapters is None:
        adapters = get_windows_network_adapters()
    drivers = check_capture_drivers()

    # Discover candidate connected adapters
    candidates = []
    for ad in adapters:
        if ad.get("status") == "Up" and ad.get("has_ipv4"):
            candidates.append(ad)

    candidate_summaries = []
    for ad in candidates:
        candidate_summaries.append({
            "name": ad.get("name"),
            "type": ad.get("type"),
            "ip": ad.get("primary_ip"),
            "gateway": ad.get("gateway"),
            "is_virtual": ad.get("is_virtual", False),
            "description": ad.get("description", "")
        })

    selected = None
    rationale = ""

    # Priority 1: Connected physical Ethernet adapter with status 'Up', valid IPv4, and default gateway
    for ad in candidates:
        if not ad.get("is_virtual") and ad.get("type") == "Ethernet" and ad.get("gateway"):
            selected = ad
            rationale = (
                f"Auto-selected '{ad.get('name')}' ({ad.get('primary_ip')}): Operational physical Ethernet "
                f"adapter with active default gateway ({ad.get('gateway')}). Preferred for high-throughput, "
                f"low-latency live packet capture."
            )
            break

    # Priority 2: Connected physical Wi-Fi adapter with status 'Up', valid IPv4, and default gateway
    if not selected:
        for ad in candidates:
            if not ad.get("is_virtual") and ad.get("type") == "Wi-Fi" and ad.get("gateway"):
                selected = ad
                eth_down = [a for a in adapters if a.get("type") == "Ethernet" and not a.get("is_virtual")]
                eth_note = f" (Physical Ethernet '{eth_down[0].get('name')}' is currently {eth_down[0].get('status', 'Disconnected')})" if eth_down else ""
                rationale = (
                    f"Auto-selected '{ad.get('name')}' ({ad.get('primary_ip')}): Operational physical Wi-Fi "
                    f"adapter with active default gateway ({ad.get('gateway')}){eth_note}."
                )
                break

    # Priority 3: Connected physical adapter matching active_ip (the active outbound route)
    if not selected and active_ip:
        for ad in candidates:
            if not ad.get("is_virtual") and any(ip == active_ip for ip in ad.get("ips", [])):
                selected = ad
                rationale = (
                    f"Auto-selected '{ad.get('name')}' ({ad.get('primary_ip')}): Operational physical {ad.get('type')} "
                    f"adapter matching active internet-routed IP ({active_ip})."
                )
                break

    # Priority 4: Connected physical Ethernet on local subnet (without gateway)
    if not selected:
        for ad in candidates:
            if not ad.get("is_virtual") and ad.get("type") == "Ethernet":
                selected = ad
                rationale = (
                    f"Auto-selected '{ad.get('name')}' ({ad.get('primary_ip')}): Operational physical Ethernet "
                    f"adapter on local subnet."
                )
                break

    # Priority 5: Connected physical Wi-Fi with valid IPv4
    if not selected:
        for ad in candidates:
            if not ad.get("is_virtual") and ad.get("type") == "Wi-Fi":
                selected = ad
                rationale = f"Auto-selected '{ad.get('name')}' ({ad.get('primary_ip')}): Operational wireless adapter on local subnet."
                break

    # Priority 5: Any physical adapter (Ethernet first, then Wi-Fi) with status 'Up'
    if not selected:
        for ad in adapters:
            if not ad.get("is_virtual") and ad.get("status") == "Up" and ad.get("type") == "Ethernet":
                selected = ad
                rationale = f"Auto-selected '{ad.get('name')}': Operational physical Ethernet interface."
                break
        if not selected:
            for ad in adapters:
                if not ad.get("is_virtual") and ad.get("status") == "Up" and ad.get("type") == "Wi-Fi":
                    selected = ad
                    rationale = f"Auto-selected '{ad.get('name')}': Operational physical Wi-Fi interface."
                    break

    # Priority 6: Any physical adapter with status 'Up'
    if not selected:
        for ad in adapters:
            if not ad.get("is_virtual") and ad.get("status") == "Up":
                selected = ad
                rationale = f"Auto-selected '{ad.get('name')}': Available physical network interface."
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

    selected_copy = dict(selected)
    selected_copy["primary_ip"] = selected_ip
    selected_copy["is_connected"] = bool(selected_ip and selected_copy.get("status") == "Up")
    selected_copy["driver_status"] = drivers

    return {
        "adapter": selected_copy,
        "driver_status": drivers,
        "selection_rationale": rationale,
        "candidates": candidate_summaries
    }


def auto_detect_primary_interface() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Backward compatibility wrapper returning (adapter_dict, driver_health_dict)."""
    res = auto_detect_interface_with_rationale()
    return res["adapter"], res["driver_status"]



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
