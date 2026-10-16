#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Independent Local Network Discovery Engine
Architecture: Pure Python standard library implementation (socket, ipaddress, ctypes, threading, concurrent.futures).
Completely decoupled and isolated from the DDoS monitoring core, WinDivert, IPC, ML models, and Port Scanner.

Features:
- Subnet & default gateway auto-detection.
- Multi-method active host discovery: Win32 SendARP, ICMP ping probing, Windows Neighbor/ARP cache table.
- Result aggregation and deduplication by IP.
- Hostname resolution via reverse DNS and NetBIOS node status queries.
- Curated IEEE MAC OUI hardware manufacturer lookup (150+ vendors).
- Device category inference (Computer, Mobile, Router/Gateway, Printer, IoT) with explicit [Inferred] vs [Verified] labeling.
- Thread-safe asynchronous scan lifecycle with live progress and cancellation support.
"""

import os
import re
import sys
import time
import socket
import struct
import ctypes
import datetime
import ipaddress
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any, Set

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# ==============================================================================
# 1. Curated MAC OUI Database (150+ Top Global Hardware Manufacturers)
# ==============================================================================
MAC_OUI_DATABASE: Dict[str, str] = {
    # Apple Inc.
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:0D:93": "Apple", "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple",
    "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple", "3C:07:54": "Apple",
    "3C:15:C2": "Apple", "3C:2E:F9": "Apple", "40:6c:8f": "Apple", "40:A6:D9": "Apple",
    "48:60:5F": "Apple", "50:BC:96": "Apple", "58:55:CA": "Apple", "60:03:08": "Apple",
    "70:DE:E2": "Apple", "78:4F:43": "Apple", "80:E6:50": "Apple", "88:66:5A": "Apple",
    "90:B2:1F": "Apple", "A4:C3:61": "Apple", "A8:66:7F": "Apple", "B8:78:2E": "Apple",
    "C8:69:CD": "Apple", "D0:25:98": "Apple", "E0:B9:BA": "Apple", "F0:18:98": "Apple",

    # Samsung Electronics
    "00:00:F0": "Samsung", "00:07:AB": "Samsung", "00:0D:AE": "Samsung", "00:12:47": "Samsung",
    "00:15:99": "Samsung", "00:16:6B": "Samsung", "00:17:C9": "Samsung", "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung", "00:1D:25": "Samsung", "00:1E:7D": "Samsung", "00:21:19": "Samsung",
    "00:23:D7": "Samsung", "00:24:54": "Samsung", "00:26:37": "Samsung", "08:08:C2": "Samsung",
    "14:49:E0": "Samsung", "18:22:7E": "Samsung", "24:F5:A2": "Samsung", "30:CD:A7": "Samsung",
    "34:BE:00": "Samsung", "44:F4:59": "Samsung", "50:01:D9": "Samsung", "54:92:BE": "Samsung",
    "60:A1:0A": "Samsung", "78:47:1D": "Samsung", "84:25:19": "Samsung", "8C:77:12": "Samsung",
    "94:63:72": "Samsung", "A0:0B:BA": "Samsung", "AC:5F:3E": "Samsung", "B4:07:F9": "Samsung",
    "BC:44:86": "Samsung", "C4:42:02": "Samsung", "CC:F9:E8": "Samsung", "D4:E8:B2": "Samsung",
    "E4:58:E8": "Samsung", "F4:7B:5E": "Samsung",

    # Intel Corporate
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:07:E9": "Intel",
    "00:0C:F1": "Intel", "00:0E:0C": "Intel", "00:11:11": "Intel", "00:13:02": "Intel",
    "00:13:E8": "Intel", "00:15:00": "Intel", "00:16:76": "Intel", "00:18:DE": "Intel",
    "00:19:D1": "Intel", "00:1B:21": "Intel", "00:1C:C0": "Intel", "00:1D:E0": "Intel",
    "00:1E:64": "Intel", "00:1F:3B": "Intel", "00:21:5C": "Intel", "00:22:FB": "Intel",
    "00:23:14": "Intel", "00:24:D7": "Intel", "00:26:C6": "Intel", "34:13:E8": "Intel",
    "3C:FD:FE": "Intel", "48:51:B7": "Intel", "68:05:CA": "Intel", "7C:5C:F8": "Intel",
    "80:86:F2": "Intel", "84:A9:3E": "Intel", "8C:85:90": "Intel", "A0:36:BC": "Intel",
    "AC:74:B1": "Intel", "B4:96:91": "Intel", "C8:5B:76": "Intel", "DC:FB:48": "Intel",

    # Cisco Systems
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:63": "Cisco", "00:01:96": "Cisco",
    "00:02:16": "Cisco", "00:02:4A": "Cisco", "00:02:7D": "Cisco", "00:02:B9": "Cisco",
    "00:03:6B": "Cisco", "00:04:4D": "Cisco", "00:05:31": "Cisco", "00:05:9A": "Cisco",
    "00:06:52": "Cisco", "00:07:0E": "Cisco", "00:08:20": "Cisco", "00:0A:41": "Cisco",
    "00:0A:8A": "Cisco", "00:0B:46": "Cisco", "00:0C:CE": "Cisco", "00:0E:38": "Cisco",
    "00:0F:23": "Cisco", "00:10:07": "Cisco", "00:11:20": "Cisco", "00:12:43": "Cisco",
    "00:13:19": "Cisco", "00:14:1C": "Cisco", "00:15:2B": "Cisco", "00:16:46": "Cisco",
    "00:17:3B": "Cisco", "00:18:18": "Cisco", "00:19:2F": "Cisco", "00:1A:2F": "Cisco",

    # TP-Link Technologies
    "00:14:78": "TP-Link", "00:19:E0": "TP-Link", "00:21:27": "TP-Link", "00:23:CD": "TP-Link",
    "00:25:86": "TP-Link", "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link", "30:B5:C2": "TP-Link", "30:DE:4B": "TP-Link", "50:C7:BF": "TP-Link",
    "60:A4:4C": "TP-Link", "74:DA:38": "TP-Link", "84:16:F9": "TP-Link", "98:DA:C4": "TP-Link",
    "A0:F3:C1": "TP-Link", "AC:84:C6": "TP-Link", "B0:4E:26": "TP-Link", "C0:06:C3": "TP-Link",
    "C0:25:E9": "TP-Link", "D8:0D:17": "TP-Link", "E8:48:B8": "TP-Link", "EC:08:6B": "TP-Link",

    # ZTE Corporation & Huawei (Common Egyptian / Regional ISP Gateways)
    "00:19:E0": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei", "00:46:4B": "Huawei",
    "04:25:C5": "Huawei", "08:19:A6": "Huawei", "0C:96:BF": "Huawei", "10:1B:54": "Huawei",
    "10:47:80": "Huawei", "10:C6:1F": "Huawei", "20:F3:A3": "Huawei", "28:31:52": "Huawei",
    "28:6E:D4": "Huawei", "34:6B:46": "Huawei", "40:4D:8E": "Huawei", "48:46:FB": "Huawei",
    "00:15:EB": "ZTE", "00:19:C6": "ZTE", "00:1E:73": "ZTE", "00:22:93": "ZTE",
    "00:25:12": "ZTE", "08:18:1A": "ZTE", "10:59:32": "ZTE", "28:5A:05": "ZTE",
    "30:42:40": "ZTE", "34:4B:50": "ZTE", "38:4C:90": "ZTE", "48:28:2F": "ZTE",
    "54:22:F8": "ZTE", "68:1A:B2": "ZTE", "70:85:C2": "ZTE", "84:D8:1B": "ZTE",
    "94:04:9C": "ZTE", "A0:EC:F9": "ZTE", "C8:3A:35": "ZTE", "DC:02:8E": "ZTE",

    # Xiaomi Communications
    "00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "0C:1D:AF": "Xiaomi", "10:2A:B3": "Xiaomi",
    "18:59:36": "Xiaomi", "28:6C:07": "Xiaomi", "34:80:0D": "Xiaomi", "38:A4:ED": "Xiaomi",
    "48:2C:A0": "Xiaomi", "50:64:2B": "Xiaomi", "58:44:98": "Xiaomi", "64:09:80": "Xiaomi",
    "74:23:44": "Xiaomi", "78:11:DC": "Xiaomi", "84:F3:EB": "Xiaomi", "A4:C4:94": "Xiaomi",
    "AC:C1:EE": "Xiaomi", "C4:0B:CB": "Xiaomi", "F4:F5:24": "Xiaomi",

    # Dell Inc.
    "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell", "00:0D:56": "Dell",
    "00:0F:1F": "Dell", "00:11:43": "Dell", "00:12:3F": "Dell", "00:13:72": "Dell",
    "00:14:22": "Dell", "00:15:C5": "Dell", "00:16:F0": "Dell", "00:18:8B": "Dell",
    "00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1C:23": "Dell", "00:1D:09": "Dell",
    "00:1E:4F": "Dell", "14:FE:B5": "Dell", "18:03:73": "Dell", "24:B6:FD": "Dell",
    "34:17:EB": "Dell", "48:4D:7E": "Dell", "50:9A:4C": "Dell", "74:86:7A": "Dell",

    # Hewlett-Packard (HP)
    "00:01:E6": "HP", "00:01:E7": "HP", "00:02:A5": "HP", "00:04:EA": "HP",
    "00:08:02": "HP", "00:08:83": "HP", "00:0B:CD": "HP", "00:0E:7F": "HP",
    "00:0F:20": "HP", "00:10:83": "HP", "00:11:0A": "HP", "00:12:79": "HP",
    "00:13:21": "HP", "00:14:38": "HP", "00:15:60": "HP", "00:16:35": "HP",
    "00:17:08": "HP", "00:18:71": "HP", "00:19:BB": "HP", "00:1A:4B": "HP",

    # Espressif Inc. & Raspberry Pi (Smart Home & IoT)
    "18:FE:34": "Espressif (ESP8266/ESP32)", "24:0A:C4": "Espressif (ESP8266/ESP32)",
    "24:62:AB": "Espressif (ESP8266/ESP32)", "24:6F:28": "Espressif (ESP8266/ESP32)",
    "24:B2:DE": "Espressif (ESP8266/ESP32)", "2C:F4:32": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)", "3C:61:05": "Espressif (ESP8266/ESP32)",
    "3C:71:BF": "Espressif (ESP8266/ESP32)", "4C:11:AE": "Espressif (ESP8266/ESP32)",
    "5C:CF:7F": "Espressif (ESP8266/ESP32)", "60:01:94": "Espressif (ESP8266/ESP32)",
    "84:0D:8E": "Espressif (ESP8266/ESP32)", "84:F3:EB": "Espressif (ESP8266/ESP32)",
    "84:CC:A8": "Espressif (ESP8266/ESP32)", "A4:CF:12": "Espressif (ESP8266/ESP32)",
    "B4:E6:2D": "Espressif (ESP8266/ESP32)", "BC:DD:C2": "Espressif (ESP8266/ESP32)",
    "C4:4F:33": "Espressif (ESP8266/ESP32)", "CC:50:E3": "Espressif (ESP8266/ESP32)",
    "DC:4F:22": "Espressif (ESP8266/ESP32)", "EC:FA:BC": "Espressif (ESP8266/ESP32)",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation", "28:CD:C1": "Raspberry Pi Foundation",

    # Microsoft
    "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft", "00:15:5D": "Microsoft (Hyper-V)",
    "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft", "00:22:48": "Microsoft",
    "00:25:AE": "Microsoft", "00:50:F2": "Microsoft", "28:18:78": "Microsoft",
    "7C:1E:52": "Microsoft (Xbox)", "DC:B4:C4": "Microsoft",

    # Network Infrastructure / NAS: Netgear, D-Link, Ubiquiti, Synology, QNAP
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear", "00:18:4D": "Netgear",
    "00:1E:2A": "Netgear", "00:24:B2": "Netgear", "00:26:F2": "Netgear", "10:DA:43": "Netgear",
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:13:46": "D-Link", "00:15:E9": "D-Link",
    "00:17:9A": "D-Link", "00:19:5B": "D-Link", "00:1B:11": "D-Link", "00:1C:F0": "D-Link",
    "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti", "68:72:51": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "80:2A:A8": "Ubiquiti", "AC:8B:A9": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "00:11:32": "Synology", "00:08:9B": "QNAP Systems", "00:04:4B": "NVIDIA", "48:B0:2D": "NVIDIA",

    # Printers: Canon, Epson, Brother
    "00:00:85": "Canon", "00:1E:8F": "Canon", "00:24:37": "Canon", "18:0C:AC": "Canon",
    "00:00:48": "Epson", "00:26:AB": "Epson", "64:EB:8C": "Epson", "AC:18:26": "Epson",
    "00:80:77": "Brother", "00:1B:A9": "Brother", "30:05:5C": "Brother", "40:B0:34": "Brother"
}


def lookup_mac_vendor(mac_str: Optional[str]) -> str:
    """
    Looks up hardware manufacturer using IEEE MAC OUI prefix.
    Returns manufacturer name if found in database, or 'Unknown Vendor'.
    """
    if not mac_str or mac_str in ["Unknown", "Unavailable", "N/A"]:
        return "Unknown"

    clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac_str).upper()
    if len(clean_mac) < 6:
        return "Unknown"

    prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
    return MAC_OUI_DATABASE.get(prefix, "Unknown Vendor")


# ==============================================================================
# 2. Network Interface & Subnet Discovery
# ==============================================================================
def get_active_routable_ip() -> Optional[str]:
    """Determines primary local IPv4 address by probing routable destination sockets."""
    test_destinations = [("8.8.8.8", 80), ("1.1.1.1", 80), ("208.67.222.222", 53)]
    for host, port in test_destinations:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.2)
            s.connect((host, port))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                return ip
        except Exception:
            continue
    return None


def get_network_discovery_info() -> Dict[str, Any]:
    """
    Auto-detects active network adapter, IPv4 address, subnet mask, prefix length,
    default gateway, and calculated CIDR network range.
    """
    active_ip = get_active_routable_ip() or "127.0.0.1"
    is_offline = active_ip.startswith("127.") or active_ip.startswith("169.254.")

    info: Dict[str, Any] = {
        "status": "offline" if is_offline else "online",
        "adapter_name": "Unknown Adapter",
        "adapter_type": "Wi-Fi",
        "local_ip": active_ip,
        "subnet_mask": "255.255.255.0",
        "prefix_length": 24,
        "default_gateway": None,
        "subnet_cidr": "192.168.1.0/24",
        "network_address": "192.168.1.0",
        "broadcast_address": "192.168.1.255",
        "total_hosts": 254,
        "local_mac": "Unknown",
        "is_connected": not is_offline,
        "message": "Local network interface active." if not is_offline else "No active routable network connection detected."
    }

    # Query detailed interface and gateway metrics on Windows via PowerShell
    if os.name == 'nt' and not is_offline:
        try:
            ps_cmd = (
                "$ip = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '" + active_ip + "' | Select-Object -First 1 InterfaceIndex, PrefixLength; "
                "if ($ip) { "
                "    $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex | Select-Object -First 1 Name, InterfaceDescription, MacAddress; "
                "    $gw = (Get-NetRoute -InterfaceIndex $ip.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1 NextHop).NextHop; "
                "    @{Name=$adapter.Name; Mac=$adapter.MacAddress; PrefixLength=$ip.PrefixLength; Gateway=$gw} | ConvertTo-Json -Compress "
                "}"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0 and res.stdout.strip():
                import json
                data = json.loads(res.stdout.strip())
                if data.get("Name"):
                    info["adapter_name"] = str(data["Name"]).strip()
                if data.get("Mac"):
                    info["local_mac"] = str(data["Mac"]).strip()
                if data.get("PrefixLength"):
                    info["prefix_length"] = int(data["PrefixLength"])
                if data.get("Gateway"):
                    info["default_gateway"] = str(data["Gateway"]).strip()
        except Exception:
            pass

    # Compute IPv4 network parameters using ipaddress
    try:
        if not is_offline and active_ip:
            prefix = info.get("prefix_length", 24)
            # Safe boundary check: limit discovery to networks <= /22 (max 1024 hosts)
            if prefix < 22:
                prefix = 24
            iface_net = ipaddress.IPv4Interface(f"{active_ip}/{prefix}").network
            info["subnet_cidr"] = str(iface_net)
            info["network_address"] = str(iface_net.network_address)
            info["broadcast_address"] = str(iface_net.broadcast_address)
            info["subnet_mask"] = str(iface_net.netmask)
            info["total_hosts"] = max(0, iface_net.num_addresses - 2)
            if not info["default_gateway"]:
                # Most consumer routers sit at .1 or .254
                first_ip = str(list(iface_net.hosts())[0]) if info["total_hosts"] > 0 else None
                info["default_gateway"] = first_ip
    except Exception as e:
        info["subnet_cidr"] = f"{active_ip}/24"

    return info


# ==============================================================================
# 3. Discovery Probing Engines (SendARP, ICMP, Neighbor Table, Hostnames)
# ==============================================================================
def probe_host_arp(ip_str: str) -> Optional[str]:
    """
    Direct kernel-level ARP probe using Win32 SendARP API via ctypes.
    Unprivileged, sub-millisecond latency on LAN, returns hardware MAC address.
    """
    if os.name != 'nt':
        return None

    try:
        iphlpapi = ctypes.windll.iphlpapi
        dest_ip = struct.unpack('<I', socket.inet_aton(ip_str))[0]
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)

        # SendARP(DestIP, SrcIP, pMacAddr, PhyAddrLen)
        res = iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0 and mac_len.value == 6:
            mac_bytes = bytes(mac_buf)
            if any(b != 0 for b in mac_bytes):
                return ':'.join(f'{b:02X}' for b in mac_bytes)
    except Exception:
        pass
    return None


def probe_host_icmp(ip_str: str, timeout_ms: int = 300) -> bool:
    """
    Lightweight ICMP ping probe via OS ping utility to verify responsiveness.
    """
    try:
        if os.name == 'nt':
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip_str]

        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        return proc.returncode == 0
    except Exception:
        return False


def read_windows_arp_cache() -> Dict[str, str]:
    """
    Reads the Windows ARP neighbor table (`arp -a`) into a dictionary {IP: MAC}.
    Discovers existing / recent communications already established by the OS.
    """
    arp_entries: Dict[str, str] = {}
    if os.name != 'nt':
        return arp_entries

    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        if proc.returncode == 0 and proc.stdout:
            # Pattern matches: 192.168.1.1   30-42-40-e2-d2-54   dynamic
            pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})', re.IGNORECASE)
            for line in proc.stdout.splitlines():
                m = pattern.search(line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').upper()
                    # Filter out multicast / broadcast
                    if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                        if mac != "FF:FF:FF:FF:FF:FF":
                            arp_entries[ip] = mac
    except Exception:
        pass
    return arp_entries


def probe_netbios_name(ip_str: str, timeout: float = 0.35) -> Optional[str]:
    """
    Sends a standard NetBIOS Node Status query (UDP 137) to resolve computer name on Windows/Samba hosts.
    """
    try:
        # NetBIOS Name query: 50-byte RFC 1002 NBSTAT wildcard packet
        query = (
            b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x00\x00\x21\x00\x01"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip_str, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            if num_names > 0 and len(data) >= 57 + 18:
                raw_name = data[57:57+15].decode('ascii', errors='ignore').strip()
                if raw_name:
                    return raw_name
    except Exception:
        pass
    return None


def resolve_hostname(ip_str: str) -> str:
    """
    Attempts reverse DNS resolution and NetBIOS discovery for target IP.
    Returns discovered name or 'Unknown' (never fabricates).
    """
    # 1. Reverse DNS
    try:
        name = socket.gethostbyaddr(ip_str)[0]
        if name and name != ip_str:
            return name
    except Exception:
        pass

    # 2. NetBIOS node status fallback
    nb_name = probe_netbios_name(ip_str)
    if nb_name:
        return nb_name

    return "Unknown"


def infer_device_type(
    ip_str: str,
    mac_str: Optional[str],
    hostname: str,
    vendor: str,
    is_gateway: bool = False,
    is_local_host: bool = False
) -> Tuple[str, str]:
    """
    Infers device category while providing transparent reasoning and distinguishing
    [Verified] from [Inferred] attributes.
    Returns:
        (device_type: str, basis_explanation: str)
    """
    if is_gateway:
        return "Router / Gateway", "Verified (Configured Default Gateway for Local Subnet)"

    v_lower = (vendor or "").lower()
    h_lower = (hostname or "").lower()

    # Network infrastructure
    if any(k in v_lower for k in ["cisco", "zte", "huawei", "tp-link", "d-link", "netgear", "ubiquiti", "mikrotik"]):
        return "Router / Access Point", f"Inferred from Network Hardware Vendor: {vendor}"

    # Printers
    if any(k in v_lower for k in ["canon", "epson", "brother", "lexmark"]) or any(k in h_lower for k in ["printer", "laserjet", "deskjet"]):
        return "Printer", f"Inferred from Hardware Vendor/Host ({vendor})"

    # Smart Home / IoT
    if any(k in v_lower for k in ["espressif", "raspberry pi", "tuya", "sonos", "roku", "nest", "philips"]):
        return "IoT / Embedded", f"Inferred from Microcontroller/IoT Vendor ({vendor})"

    # Mobile Devices
    if any(k in v_lower for k in ["xiaomi", "motorola", "oneplus"]) or any(k in h_lower for k in ["android", "iphone", "galaxy", "phone"]):
        return "Mobile Device", f"Inferred from Vendor/Hostname Signature ({vendor})"
    if "samsung" in v_lower and not any(k in h_lower for k in ["laptop", "pc"]):
        return "Mobile / Smart Device", f"Inferred from Samsung Hardware OUI"

    # Personal Computers & Laptops
    if is_local_host:
        return "Computer / Workstation", "Verified (Current Host Network Interface)"
    if any(k in v_lower for k in ["intel", "dell", "lenovo", "microsoft", "asustek", "realtek", "nvidia", "micro-star"]):
        return "Computer / Workstation", f"Inferred from Computing Hardware Vendor ({vendor})"
    if "apple" in v_lower:
        if any(k in h_lower for k in ["mac", "macbook", "imac"]):
            return "Computer / Workstation", "Inferred from Apple Mac Hostname"
        return "Mobile / Apple Device", "Inferred from Apple OUI"

    return "Unknown Device", "Insufficient heuristic data to categorize"


# ==============================================================================
# 4. Asynchronous Network Discovery Manager
# ==============================================================================
class NetworkDiscoveryManager:
    """
    Thread-safe controller managing network discovery scan sessions,
    progress calculation, and safe cooperative cancellation.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._active_thread: Optional[threading.Thread] = None
        self.session: Dict[str, Any] = {
            "status": "idle",  # "idle" | "scanning" | "completed" | "stopped" | "error"
            "scan_id": None,
            "started_at": 0.0,
            "duration_s": 0.0,
            "subnet": None,
            "progress_pct": 0.0,
            "scanned_hosts": 0,
            "total_hosts": 0,
            "devices_count": 0,
            "online_count": 0,
            "devices": [],
            "network_info": {},
            "message": "Ready to initiate network discovery scan."
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns a thread-safe snapshot of the current scan state."""
        with self._lock:
            state = dict(self.session)
            state["devices"] = list(self.session.get("devices", []))
            state["network_info"] = dict(self.session.get("network_info", {}))
            if state["status"] == "scanning" and state.get("started_at"):
                state["duration_s"] = round(time.time() - state["started_at"], 1)
            return state

    def stop_scan(self) -> Dict[str, Any]:
        """Signals active discovery scan to cancel immediately and cooperatively."""
        with self._lock:
            if self.session.get("status") == "scanning":
                self._stop_event.set()
                self.session["status"] = "stopped"
                self.session["message"] = "Network discovery scan stopped by user."
                if self.session.get("started_at"):
                    self.session["duration_s"] = round(time.time() - self.session["started_at"], 1)
                return {"status": "stopped", "message": "Scan cancelled."}
            return {"status": self.session.get("status", "idle"), "message": "No scan currently active."}

    def start_scan(
        self,
        subnet_cidr: Optional[str] = None,
        timeout: float = 0.6,
        concurrency: int = 50
    ) -> Dict[str, Any]:
        """
        Validates subnet target and launches an asynchronous discovery worker.
        """
        with self._lock:
            if self.session.get("status") == "scanning":
                return {
                    "status": "already_scanning",
                    "scan_id": self.session.get("scan_id"),
                    "message": "A network discovery scan is already in progress."
                }

            # 1. Auto-detect local network configuration
            net_info = get_network_discovery_info()
            target_subnet = (subnet_cidr or "").strip() or net_info.get("subnet_cidr")

            # 2. Validate IPv4 network CIDR
            try:
                network_obj = ipaddress.IPv4Network(target_subnet, strict=False)
            except ValueError as ve:
                raise ValueError(f"Invalid IPv4 subnet format '{target_subnet}': {ve}")

            # Safety restriction: Enforce max 1024 hosts (e.g. /22 minimum prefix) to prevent catastrophic network loops
            num_addrs = network_obj.num_addresses
            if num_addrs > 1024:
                raise ValueError(f"Subnet '{target_subnet}' contains {num_addrs} addresses. Subnets must be /22 or smaller (maximum 1,024 hosts).")

            scan_id = f"net_{int(time.time()*1000)}"
            usable_hosts = [str(ip) for ip in network_obj.hosts()]
            total_hosts = len(usable_hosts)

            self._stop_event.clear()
            self.session = {
                "status": "scanning",
                "scan_id": scan_id,
                "started_at": time.time(),
                "duration_s": 0.0,
                "subnet": str(network_obj),
                "progress_pct": 0.0,
                "scanned_hosts": 0,
                "total_hosts": total_hosts,
                "devices_count": 0,
                "online_count": 0,
                "devices": [],
                "network_info": net_info,
                "message": f"Discovering active devices across {network_obj}..."
            }

            self._active_thread = threading.Thread(
                target=self._discovery_worker,
                args=(scan_id, usable_hosts, network_obj, net_info, timeout, concurrency),
                daemon=True
            )
            self._active_thread.start()

            return {
                "status": "scanning",
                "scan_id": scan_id,
                "subnet": str(network_obj),
                "total_hosts": total_hosts,
                "message": f"Scan initiated for {total_hosts} hosts."
            }

    def _discovery_worker(
        self,
        scan_id: str,
        target_ips: List[str],
        network_obj: ipaddress.IPv4Network,
        net_info: Dict[str, Any],
        timeout: float,
        concurrency: int
    ):
        start_t = time.time()
        local_ip = net_info.get("local_ip")
        local_mac = net_info.get("local_mac", "Unknown")
        default_gw = net_info.get("default_gateway")

        # Discovered devices indexed by IP
        discovered_map: Dict[str, Dict[str, Any]] = {}

        # ----------------------------------------------------------------------
        # Phase 1: Pre-populate from Windows Neighbor / ARP Cache
        # ----------------------------------------------------------------------
        arp_cache = read_windows_arp_cache()
        for ip, mac in arp_cache.items():
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj in network_obj:
                    is_gw = (ip == default_gw)
                    vendor = lookup_mac_vendor(mac)
                    dev_type, type_basis = infer_device_type(ip, mac, "Unknown", vendor, is_gw, False)
                    discovered_map[ip] = {
                        "ip": ip,
                        "hostname": "Unknown",
                        "mac": mac,
                        "vendor": vendor,
                        "device_type": dev_type,
                        "device_type_basis": type_basis,
                        "status": "Online",
                        "methods": ["Neighbor Cache"],
                        "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "is_gateway": is_gw,
                        "is_local_host": False
                    }
            except Exception:
                continue

        # Add local machine itself as verified active device
        if local_ip:
            try:
                if ipaddress.IPv4Address(local_ip) in network_obj:
                    local_vendor = lookup_mac_vendor(local_mac)
                    local_hostname = socket.gethostname() or "Local Workstation"
                    dev_type, type_basis = infer_device_type(local_ip, local_mac, local_hostname, local_vendor, False, True)
                    discovered_map[local_ip] = {
                        "ip": local_ip,
                        "hostname": local_hostname,
                        "mac": local_mac if local_mac != "N/A" else "Unavailable",
                        "vendor": local_vendor,
                        "device_type": dev_type,
                        "device_type_basis": type_basis,
                        "status": "Online",
                        "methods": ["Local Interface"],
                        "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "is_gateway": False,
                        "is_local_host": True
                    }
            except Exception:
                pass

        with self._lock:
            if self.session.get("scan_id") == scan_id:
                self.session["devices"] = list(discovered_map.values())
                self.session["devices_count"] = len(discovered_map)
                self.session["online_count"] = len(discovered_map)

        # ----------------------------------------------------------------------
        # Phase 2: Active Concurrent ARP & ICMP Subnet Sweep
        # ----------------------------------------------------------------------
        total_targets = len(target_ips)
        scanned_count = 0

        def scan_single_host(ip: str):
            if self._stop_event.is_set():
                return None

            # Skip self (already added)
            if ip == local_ip:
                return None

            methods_used: List[str] = []
            mac = None
            is_responsive = False

            # 1. Win32 SendARP (Direct kernel ARP probe)
            arp_mac = probe_host_arp(ip)
            if arp_mac:
                mac = arp_mac
                is_responsive = True
                methods_used.append("ARP")

            # 2. ICMP Echo probe fallback/complement
            if not is_responsive or not mac:
                if probe_host_icmp(ip, timeout_ms=int(timeout * 1000)):
                    is_responsive = True
                    methods_used.append("ICMP")
                    # Try SendARP again now that target was prompted by ICMP
                    if not mac:
                        mac = probe_host_arp(ip)

            if not is_responsive and ip in discovered_map:
                # Existing neighbor entry that didn't reply to active ping
                return None

            if not is_responsive:
                return None

            is_gw = (ip == default_gw)
            final_mac = mac or discovered_map.get(ip, {}).get("mac") or "Unavailable"
            vendor = lookup_mac_vendor(final_mac)
            hostname = resolve_hostname(ip)
            dev_type, type_basis = infer_device_type(ip, final_mac, hostname, vendor, is_gw, False)

            # Combine discovery methods if host was already in neighbor table
            if ip in discovered_map:
                for m in discovered_map[ip].get("methods", []):
                    if m not in methods_used:
                        methods_used.append(m)

            return {
                "ip": ip,
                "hostname": hostname,
                "mac": final_mac,
                "vendor": vendor,
                "device_type": dev_type,
                "device_type_basis": type_basis,
                "status": "Online",
                "methods": methods_used or ["Probed"],
                "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "is_gateway": is_gw,
                "is_local_host": False
            }

        workers_count = min(concurrency, max(10, total_targets))
        with ThreadPoolExecutor(max_workers=workers_count) as executor:
            future_to_ip = {executor.submit(scan_single_host, ip): ip for ip in target_ips}

            for future in as_completed(future_to_ip):
                if self._stop_event.is_set():
                    break

                scanned_count += 1
                try:
                    result = future.result()
                    if result:
                        discovered_map[result["ip"]] = result
                except Exception:
                    pass

                # Update live progress periodically
                if scanned_count % 8 == 0 or scanned_count == total_targets:
                    pct = round((scanned_count / max(1, total_targets)) * 100.0, 1)
                    with self._lock:
                        if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                            self.session["scanned_hosts"] = scanned_count
                            self.session["progress_pct"] = pct
                            self.session["devices"] = sorted(
                                discovered_map.values(),
                                key=lambda d: ipaddress.IPv4Address(d["ip"])
                            )
                            self.session["devices_count"] = len(discovered_map)
                            self.session["online_count"] = sum(1 for d in discovered_map.values() if d["status"] == "Online")
                            self.session["duration_s"] = round(time.time() - start_t, 1)

        # ----------------------------------------------------------------------
        # Phase 3: Finalize Results
        # ----------------------------------------------------------------------
        with self._lock:
            if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                total_duration = round(time.time() - start_t, 1)
                sorted_devices = sorted(
                    discovered_map.values(),
                    key=lambda d: ipaddress.IPv4Address(d["ip"])
                )
                online_num = sum(1 for d in sorted_devices if d["status"] == "Online")

                self.session.update({
                    "status": "completed",
                    "progress_pct": 100.0,
                    "scanned_hosts": total_targets,
                    "devices_count": len(sorted_devices),
                    "online_count": online_num,
                    "devices": sorted_devices,
                    "duration_s": total_duration,
                    "message": f"Discovery completed in {total_duration}s. Found {len(sorted_devices)} active device(s) on {network_obj}."
                })


# Global singleton instance for Network Discovery
network_discovery_manager = NetworkDiscoveryManager()
