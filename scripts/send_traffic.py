#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard / SocNet: Cross-Device Traffic Generator & Connectivity Diagnostic Tool
Generates bounded, benign network traffic (HTTP / TCP / UDP) across an authorized local Ethernet network
from the Sender Computer to the Monitoring Computer without synthetic feature injection, or streams
pre-extracted dataset flow features to the Monitoring Flask API for inference evaluation.
"""

import os
import sys
import json
import time
import socket
import argparse
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def get_project_root() -> Path:
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / ".git").exists() or (p / "requirements.txt").exists() or (p / "api.py").exists():
            return p
        p = p.parent
    return Path(__file__).resolve().parent.parent


BASE_DIR = get_project_root()
TEST_SET_PATH = str(BASE_DIR / "features_by_label.json")

# ==================== USER CONFIGURATION ====================

TARGET_HOST = "192.168.1.12"
TARGET_PORT = 8080
API_PORT = 5000

# Workflow Configuration: Dataset Replay is the DEFAULT
DEFAULT_WORKFLOW = "dataset"
ENABLE_DATASET_MODE = True

# Dataset Replay settings
DATASET_LABEL: Optional[str] = None         # None = prompt user interactively to choose
DATASET_RECORD_COUNT: Optional[int] = None # None = continuous until Ctrl+C; or int for bounded
DATASET_CONTINUOUS = True                   # Continuous replay by default
DATASET_INTERVAL_SECONDS = 0.5              # Delay between replay requests

# Real Wire Traffic settings (USED ONLY when --wire-traffic or --probe is explicitly specified)
TRAFFIC_PROTOCOL = "http"                   # http, tcp, or udp
TRAFFIC_COUNT = 200                         # Count when real wire traffic is explicitly chosen
TRAFFIC_INTERVAL_SECONDS = 0.5              # Delay between real traffic transmissions
CONNECT_TIMEOUT_SECONDS = 3
CONNECTIVITY_CHECK_INTERVAL_SECONDS = 5
CONTINUOUS_MODE = False
TRAFFIC_PAYLOAD_SIZE_BYTES = 256

# ============================================================

# Backward compatibility aliases for existing external module imports
DEFAULT_MONITORING_HOST: str = TARGET_HOST
DEFAULT_BENIGN_TRAFFIC_PORT: int = TARGET_PORT
DEFAULT_API_PORT: int = API_PORT


# ==============================================================================
# VALIDATION & PRE-FLIGHT CONNECTIVITY CHECKS
# ==============================================================================

def validate_ip_or_host(host: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates host string format and resolves DNS if hostname.
    Returns: (is_valid, resolved_ip, error_message)
    """
    clean_host = str(host).strip()
    if not clean_host:
        return False, "", "Target host address cannot be empty."

    # Try literal IP address parsing first (IPv4 / IPv6)
    try:
        ip = ipaddress.ip_address(clean_host)
        return True, str(ip), None
    except ValueError:
        pass

    # Try hostname resolution
    try:
        resolved_ip = socket.gethostbyname(clean_host)
        return True, resolved_ip, None
    except socket.gaierror as ge:
        return False, "", f"Unable to resolve host '{clean_host}': {ge}"
    except Exception as ex:
        return False, "", f"Invalid host or IP address '{clean_host}': {ex}"


def check_destination_service(
    host: str,
    port: int,
    protocol: str = "tcp",
    timeout: float = 3.0,
    check_http_endpoint: bool = False,
    http_path: str = "/api/health"
) -> Tuple[bool, Optional[str]]:
    """
    Performs real network connectivity check against intended destination service/port.
    - For TCP/HTTP: verifies TCP connect.
    - For UDP: verifies route & socket assignment (with clear connectionless semantics).
    - If check_http_endpoint: verifies HTTP status on endpoint.
    Returns: (is_reachable, failure_reason)
    """
    valid, resolved_ip, err = validate_ip_or_host(host)
    if not valid:
        return False, f"Host validation failed for '{host}': {err}"

    proto_lower = protocol.lower()

    if proto_lower == "udp":
        # UDP is connectionless: test routing table & local interface binding
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((resolved_ip, port))
            return True, None
        except Exception as ex:
            return False, f"UDP destination route to {resolved_ip}:{port} failed: {ex}"

    # For TCP / HTTP: attempt TCP handshake to destination port
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((resolved_ip, port))
            if res != 0:
                return False, f"Connection refused on {resolved_ip}:{port} (errno {res})"
    except socket.timeout:
        return False, f"Connection timed out after {timeout:.1f}s connecting to {resolved_ip}:{port}"
    except Exception as ex:
        return False, f"Network error connecting to {resolved_ip}:{port}: {ex}"

    # If HTTP endpoint verification requested (e.g. for API mode)
    if check_http_endpoint:
        try:
            url = f"http://{resolved_ip}:{port}{http_path}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SocNet-PreflightCheck/2.5"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 204, 301, 302):
                    return False, f"HTTP endpoint returned unexpected status code: {resp.status}"
        except urllib.error.HTTPError as he:
            # Server answered with HTTP error code, meaning HTTP service is running
            pass
        except urllib.error.URLError as ue:
            return False, f"HTTP endpoint unreachable on {resolved_ip}:{port}{http_path}: {ue.reason}"
        except Exception as ex:
            return False, f"HTTP check error on {resolved_ip}:{port}: {ex}"

    return True, None


def check_remote_connectivity(host: str, traffic_port: int, api_port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Backward-compatible diagnostics function testing reachability of both ports
    with actionable error diagnoses and remediation instructions.
    """
    results: Dict[str, Any] = {
        "host": host,
        "traffic_port": traffic_port,
        "api_port": api_port,
        "host_resolvable": False,
        "api_port_open": False,
        "traffic_port_open": False,
        "api_online": False,
        "api_health": None,
        "error_reason": None,
        "remediation": None
    }

    valid, resolved_ip, err = validate_ip_or_host(host)
    if not valid:
        results["error_reason"] = f"Host resolution failed for '{host}': {err}"
        results["remediation"] = (
            f"Could not resolve host '{host}'. Verify the IP address is correct.\n"
            f"When connecting over an Ethernet cable, use the Monitoring Computer's Ethernet IPv4 address (e.g. 192.168.1.X)."
        )
        return results

    results["resolved_ip"] = resolved_ip
    results["host_resolvable"] = True

    # 1. API Port Check
    api_probe, _ = check_destination_service(resolved_ip, api_port, protocol="tcp", timeout=timeout)
    results["api_port_open"] = api_probe
    if api_probe:
        try:
            req = urllib.request.Request(
                f"http://{resolved_ip}:{api_port}/api/health",
                headers={"User-Agent": "SocNet-TrafficSender/2.5"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    results["api_online"] = True
                    results["api_health"] = json.loads(resp.read().decode('utf-8'))
        except Exception:
            pass

    # 2. Traffic Port Check
    traffic_probe, traffic_err = check_destination_service(resolved_ip, traffic_port, protocol="tcp", timeout=timeout)
    results["traffic_port_open"] = traffic_probe
    if not traffic_probe:
        results["traffic_errno"] = 10060 if "timed out" in str(traffic_err).lower() else 10035

    # 3. Actionable Diagnostics
    if not results["api_port_open"] and not results["traffic_port_open"]:
        if host in ("127.0.0.1", "localhost"):
            results["error_reason"] = (
                f"Connection refused on 127.0.0.1:{traffic_port} and 127.0.0.1:{api_port}. "
                f"You are currently targeting localhost on the Sender Computer."
            )
            results["remediation"] = (
                "When running send_traffic.py on a separate Sender Computer, you MUST specify the Monitoring "
                "Computer's Ethernet IPv4 address (not 127.0.0.1).\n"
                "Example: python scripts/send_traffic.py --host 192.168.1.11 --port 8080\n"
                "Or set TARGET_HOST at the top of scripts/send_traffic.py."
            )
        else:
            results["error_reason"] = f"Unable to establish TCP connection to {host} on ports {api_port} or {traffic_port}."
            results["remediation"] = (
                f"Troubleshooting checklist for connecting to {host}:\n"
                f" 1. Physical Layer : Ensure the Ethernet cable is securely connected to both computers and link LEDs are active.\n"
                f" 2. Subnet Config  : Confirm both computers share the same IPv4 subnet (e.g. Sender: 192.168.1.X, Monitor: 192.168.1.Y).\n"
                f" 3. Service Status : On the Monitoring Computer, ensure 'python api.py' is running.\n"
                f" 4. Firewall Rule  : On the Monitoring Computer, configure Windows Firewall to permit inbound TCP on ports {api_port} and {traffic_port}.\n"
                f"    Run as Administrator on Monitor: 'powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 ConfigureFirewall'"
            )
    elif results["api_port_open"] and not results["traffic_port_open"]:
        results["error_reason"] = f"API port {api_port} is reachable, but traffic sink port {traffic_port} is not responding."
        results["remediation"] = (
            f"The Flask API is active on {host}:{api_port}, but benign traffic service on port {traffic_port} is closed.\n"
            f"Ensure api.py was started with benign traffic service enabled (default: port 8080)."
        )

    return results


# ==============================================================================
# CONFIGURATION RESOLUTION & ARGUMENT PARSING
# ==============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="SocNet / DDoS-Guard: Cross-Device Traffic Generator & Pre-flight Diagnostics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
===============================================================================
INSTRUCTIONS FOR TWO-COMPUTER ETHERNET DEPLOYMENT:
===============================================================================
1. On the MONITORING COMPUTER:
   a. Connect the Ethernet cable and identify its IPv4 address (e.g. {TARGET_HOST}).
   b. Configure Windows Firewall (run as Administrator once):
      powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 ConfigureFirewall
   c. Start the monitoring server:
      python api.py
   d. In your web browser, open http://127.0.0.1:{API_PORT} and click 'Start Monitoring'.

2. On the SENDER COMPUTER:
   a. Connect the Ethernet cable on the same subnet (e.g. 192.168.1.X).
   b. Run pre-flight connectivity check:
      python scripts/send_traffic.py --host {TARGET_HOST} --check-only
   c. Send real HTTP benign network traffic (20 packets, 256 bytes payload):
      python scripts/send_traffic.py --host {TARGET_HOST} --port {TARGET_PORT} --protocol http --count 20
   d. Or stream dataset flow feature records for API model inference:
      python scripts/send_traffic.py --host {TARGET_HOST} --api-port {API_PORT} --label BENIGN --count 20

NOTE:
- Default settings can be changed once at the top of scripts/send_traffic.py under USER CONFIGURATION.
- CLI arguments override file defaults.
- The sender NEVER silently falls back to 127.0.0.1 or an unconfigured destination.
===============================================================================
        """
    )
    # Destination Options
    p.add_argument(
        '--host', '-H', type=str, default=None,
        help=f"Target Monitoring Computer Ethernet IPv4 address (default: {TARGET_HOST}, env: SOCNET_HOST)"
    )
    p.add_argument(
        '--target', '-t', type=str, default=None,
        help=f"Target server URL or host:port (e.g. http://{TARGET_HOST}:{TARGET_PORT}, env: SOCNET_TARGET)"
    )
    p.add_argument(
        '--port', '-p', type=int, default=None,
        help=f"Target port for real traffic sink on Monitoring Computer (default: {TARGET_PORT}, env: SOCNET_TRAFFIC_PORT)"
    )
    p.add_argument(
        '--api-port', type=int, default=None,
        help=f"Target Flask API port on Monitoring Computer (default: {API_PORT}, env: SOCNET_PORT)"
    )

    # Traffic Flow Controls
    p.add_argument(
        '--protocol', type=str, default=None, choices=['http', 'tcp', 'udp'],
        help=f"Transport / application protocol for real network traffic (default: {TRAFFIC_PROTOCOL})"
    )
    p.add_argument(
        '--count', '-c', type=int, default=None,
        help="Number of transmissions or records to send (default: 20; use --continuous for unlimited)"
    )
    p.add_argument(
        '--continuous', dest='continuous', action='store_const', const=True, default=None,
        help="Send continuously until stopped by user (Ctrl+C)"
    )
    p.add_argument(
        '--no-continuous', dest='continuous', action='store_const', const=False,
        help="Disable continuous mode and use bounded count"
    )
    p.add_argument(
        '--interval', '-i', type=float, default=None,
        help="Seconds between transmissions (default: 0.5s)"
    )
    p.add_argument(
        '--timeout', type=float, default=None,
        help=f"Socket / HTTP connection timeout in seconds (default: {CONNECT_TIMEOUT_SECONDS}s)"
    )
    p.add_argument(
        '--payload-size', type=int, default=None,
        help=f"Traffic payload size in bytes for real traffic mode (default: {TRAFFIC_PAYLOAD_SIZE_BYTES})"
    )
    p.add_argument(
        '--check-interval', type=float, default=None,
        help=f"Periodic connectivity check interval in seconds during continuous mode (default: {CONNECTIVITY_CHECK_INTERVAL_SECONDS}s)"
    )
    p.add_argument(
        '--check-only', action='store_true',
        help="Run pre-flight connectivity diagnostics then exit"
    )

    # Mode Selection & Dataset Options
    p.add_argument(
        '--dataset-mode', '--dataset-replay', dest='dataset_mode', action='store_true',
        help="Dataset Replay mode (DEFAULT): stream pre-extracted 77-feature flow records to /api/replay-feature"
    )
    p.add_argument(
        '--wire-traffic', '--real-traffic', dest='wire_traffic', action='store_true',
        help="Explicit real network traffic mode: transmit genuine Layer-4/Layer-7 network packets across the wire"
    )
    p.add_argument(
        '--probe', dest='probe', action='store_true',
        help="Legacy alias for --wire-traffic: transmit genuine Layer-4/Layer-7 network packets"
    )
    p.add_argument(
        '--label', '-l', type=str, default=None,
        help="Target dataset traffic label name or 1-based index (e.g. 'Benign', 'DDoS', or '2')"
    )
    p.add_argument(
        '--dataset', type=str, default=None,
        help="Path to feature dataset JSON file (default: features_by_label.json)"
    )
    p.add_argument(
        '--list-labels', action='store_true',
        help="List available traffic labels in the dataset JSON with record counts, then exit"
    )
    p.add_argument(
        '--yes', '-y', dest='auto_confirm', action='store_true',
        help="Automatically confirm transmission prompts without interactive prompt"
    )

    # Backward Compatibility Aliases
    p.add_argument('--simulate-dataset', dest='simulate_dataset', action='store_true', help="Legacy alias for dataset feature streaming")
    p.add_argument('--attack', '-a', type=str, default=None, help="Legacy alias for --label: attack label name or index")
    p.add_argument('--list', action='store_true', help="Alias for --list-labels: list available labels then exit")

    return p.parse_args()


def _safe_get(obj: Any, attr: str, expected_type: Any = None, default: Any = None) -> Any:
    val = getattr(obj, attr, default)
    if val is None or hasattr(val, '_mock_name'):
        return default
    if expected_type is not None:
        if not isinstance(val, expected_type):
            try:
                val = expected_type(val)
            except (ValueError, TypeError):
                return default
    return val


def resolve_effective_config(args) -> Dict[str, Any]:
    """
    Resolves the single consistent source of truth by applying precedence:
    CLI Arguments > Environment Variables > File-Level USER CONFIGURATION.
    Validates all parameters before execution.
    """
    # 1. Target Host Resolution
    host = _safe_get(args, "host", str, default=None)
    target_arg = _safe_get(args, "target", str, default=None)
    if not host and target_arg:
        if "://" in target_arg:
            host = urlparse(target_arg).hostname
        else:
            host = target_arg.split(":")[0]
    if not host:
        host = os.environ.get("SOCNET_HOST")
    if not host:
        host = TARGET_HOST

    host = str(host).strip()
    if not host:
        raise ValueError("Target host cannot be empty.")

    valid_host, resolved_ip, host_err = validate_ip_or_host(host)
    if not valid_host:
        raise ValueError(f"Invalid target host '{host}': {host_err}")

    # 2. Traffic Port Resolution
    traffic_port = _safe_get(args, "port", int, default=None)
    if traffic_port is None and target_arg and ":" in target_arg:
        try:
            traffic_port = int(urlparse(target_arg).port or target_arg.split(":")[-1].split("/")[0])
        except (ValueError, TypeError):
            pass
    if traffic_port is None:
        env_traffic_port = os.environ.get("SOCNET_TRAFFIC_PORT")
        if env_traffic_port:
            try:
                traffic_port = int(env_traffic_port)
            except ValueError:
                pass
    if traffic_port is None:
        traffic_port = TARGET_PORT

    if not (1 <= traffic_port <= 65535):
        raise ValueError(f"Invalid traffic port {traffic_port}. Must be between 1 and 65535.")

    # 3. API Port Resolution
    api_port = _safe_get(args, "api_port", int, default=None)
    if api_port is None:
        env_api_port = os.environ.get("SOCNET_PORT")
        if env_api_port:
            try:
                api_port = int(env_api_port)
            except ValueError:
                pass
    if api_port is None:
        api_port = API_PORT

    if not (1 <= api_port <= 65535):
        raise ValueError(f"Invalid API port {api_port}. Must be between 1 and 65535.")

    # 4. Mode Selection
    wire_flag = bool(
        _safe_get(args, "wire_traffic", bool, default=False) or
        _safe_get(args, "real_traffic", bool, default=False) or
        _safe_get(args, "probe", bool, default=False)
    )
    dataset_flag = bool(
        _safe_get(args, "dataset_mode", bool, default=False) or
        _safe_get(args, "dataset_replay", bool, default=False) or
        _safe_get(args, "simulate_dataset", bool, default=False)
    )
    label_arg = _safe_get(args, "label", str, default=None) or _safe_get(args, "attack", str, default=None)
    dataset_arg = _safe_get(args, "dataset", str, default=None)

    # Real wire traffic is ONLY selected if explicitly requested via wire flags,
    # and no dataset flags or arguments were provided
    if wire_flag and not (dataset_flag or label_arg or dataset_arg):
        mode = "real_traffic"
    else:
        # DEFAULT WORKFLOW IS ALWAYS DATASET REPLAY
        mode = "dataset"

    # 5. Continuous Mode Resolution
    continuous_arg = _safe_get(args, "continuous", bool, default=None)
    count_arg = _safe_get(args, "count", int, default=None)

    if mode == "dataset":
        if continuous_arg is True:
            is_continuous = True
            count = None
        elif continuous_arg is False:
            is_continuous = False
            count = max(1, int(count_arg)) if count_arg is not None else 20
        elif count_arg is not None:
            # Explicit --count provided on CLI -> bounded test
            is_continuous = False
            count = max(1, int(count_arg))
        elif DATASET_RECORD_COUNT is not None:
            is_continuous = False
            count = max(1, int(DATASET_RECORD_COUNT))
        else:
            # Default for Dataset Replay: CONTINUOUS (indefinitely until Ctrl+C)
            is_continuous = True
            count = None
    else:
        # Real wire traffic mode
        if continuous_arg is not None:
            is_continuous = bool(continuous_arg)
        else:
            is_continuous = bool(CONTINUOUS_MODE)

        if is_continuous:
            count = None
        elif count_arg is not None:
            count = max(0, int(count_arg))
        else:
            count = max(0, int(TRAFFIC_COUNT))

    # 6. Count Resolution (already handled above for both modes)

    # 7. Interval Resolution
    interval_arg = _safe_get(args, "interval", float, default=None)
    if interval_arg is not None:
        interval = max(0.001, float(interval_arg))
    elif mode == "dataset":
        interval = max(0.001, float(DATASET_INTERVAL_SECONDS))
    else:
        interval = max(0.001, float(TRAFFIC_INTERVAL_SECONDS))

    # 8. Protocol Resolution (for real traffic mode)
    proto_arg = _safe_get(args, "protocol", str, default=None)
    if proto_arg is not None:
        protocol = str(proto_arg).strip().lower()
    else:
        protocol = str(TRAFFIC_PROTOCOL).strip().lower()
    if protocol not in ("http", "tcp", "udp"):
        raise ValueError(f"Unsupported protocol '{protocol}'. Choose from 'http', 'tcp', or 'udp'.")

    # 9. Payload Size Resolution (for real traffic mode)
    payload_arg = _safe_get(args, "payload_size", int, default=None)
    if payload_arg is not None:
        payload_size = max(1, min(65507, int(payload_arg)))
    else:
        payload_size = max(1, min(65507, int(TRAFFIC_PAYLOAD_SIZE_BYTES)))

    # 10. Timeout & Connectivity Check Interval
    timeout_arg = _safe_get(args, "timeout", float, default=None)
    if timeout_arg is not None:
        timeout = max(0.1, float(timeout_arg))
    else:
        timeout = max(0.1, float(CONNECT_TIMEOUT_SECONDS))

    check_interval_arg = _safe_get(args, "check_interval", float, default=None)
    if check_interval_arg is not None:
        check_interval = max(0.5, float(check_interval_arg))
    else:
        check_interval = max(0.5, float(CONNECTIVITY_CHECK_INTERVAL_SECONDS))

    # 11. Dataset Label Resolution
    label = label_arg
    if not label and mode == "dataset" and DATASET_LABEL:
        label = DATASET_LABEL

    auto_confirm = bool(_safe_get(args, "auto_confirm", bool, default=False))

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "traffic_port": traffic_port,
        "api_port": api_port,
        "mode": mode,
        "protocol": protocol,
        "continuous": is_continuous,
        "count": count,
        "interval": interval,
        "payload_size": payload_size,
        "timeout": timeout,
        "check_interval": check_interval,
        "label": label,
        "dataset_path": dataset_arg,
        "auto_confirm": auto_confirm,
        "check_only": bool(_safe_get(args, "check_only", bool, default=False)),
        "list_labels": bool(_safe_get(args, "list_labels", bool, default=False) or _safe_get(args, "list", bool, default=False))
    }


def resolve_target_config(args) -> Tuple[str, int, int]:
    """Backward compatibility wrapper returning (host, traffic_port, api_port)."""
    cfg = resolve_effective_config(args)
    return cfg["host"], cfg["traffic_port"], cfg["api_port"]


# ==============================================================================
# REAL NETWORK TRAFFIC GENERATOR (HTTP / TCP / UDP)
# ==============================================================================

def run_benign_traffic_generator(
    host: str,
    port: int,
    protocol: str = 'http',
    interval: float = 0.5,
    count: Optional[int] = 20,
    timeout: float = 3.0,
    payload_size: int = 256,
    check_interval: float = 5.0
):
    """
    Transmits genuine, bounded Layer-4/Layer-7 network traffic to the target host and port.
    Uses ordinary HTTP POST/GET requests or TCP/UDP probe datagrams.
    Periodically checks target connectivity during continuous transmission.
    """
    is_continuous = (count is None or count <= 0)
    count_desc = "Continuous (Ctrl+C to stop)" if is_continuous else f"{count}"

    print("\n" + "=" * 75)
    print("      SOCNET: REAL BENIGN NETWORK TRAFFIC GENERATOR (WIRE FRAMES)")
    print("=" * 75)
    print(f"  Target Destination   : {host}:{port}")
    print(f"  Transport Protocol   : {protocol.upper()}")
    print(f"  Payload Size         : {payload_size} bytes")
    print(f"  Transmission Count   : {count_desc}")
    print(f"  Transmission Interval: {interval}s")
    print(f"  Connect Timeout      : {timeout}s")
    if is_continuous:
        print(f"  Periodic Re-check    : Every {check_interval}s")
    print("=" * 75)
    if protocol.lower() == "udp":
        print("  NOTICE: UDP is a connectionless transport protocol. Datagrams are emitted")
        print("          onto the wire; transmission success indicates local dispatch.")
        print("=" * 75)
    print(f"Transmitting genuine {protocol.upper()} network frames across the wire to {host}:{port}...\n")

    sent = 0
    successful = 0
    failed = 0
    latencies = []
    start_time = time.time()
    last_check_time = time.time()

    try:
        while True:
            # Periodic reachability check during continuous transmission
            now = time.time()
            if is_continuous and (now - last_check_time) >= check_interval:
                last_check_time = now
                is_alive, check_err = check_destination_service(
                    host, port, protocol=protocol, timeout=min(timeout, 2.0)
                )
                if not is_alive:
                    print(f"\n[STOP] Target is no longer reachable ({check_err}). Transmission stopped.")
                    break

            frame_start = time.time()
            success = False
            status_desc = ""
            duration_ms = 0.0

            if protocol.lower() == 'http':
                target_url = f"http://{host}:{port}/test?frame={sent + 1}&t={int(time.time() * 1000)}"
                body_bytes = b"X" * max(0, payload_size)
                req = urllib.request.Request(
                    target_url,
                    data=body_bytes,
                    headers={
                        "User-Agent": "SocNet-BenignTrafficProbe/2.5 (CrossDevice-Ethernet-Test)",
                        "Content-Type": "application/octet-stream",
                        "Accept": "application/json, text/plain, */*",
                        "Connection": "close"
                    },
                    method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        duration_ms = (time.time() - frame_start) * 1000
                        latencies.append(duration_ms)
                        status_desc = f"HTTP {resp.status} OK"
                        success = True
                except urllib.error.HTTPError as he:
                    duration_ms = (time.time() - frame_start) * 1000
                    latencies.append(duration_ms)
                    status_desc = f"HTTP {he.code}"
                    success = True  # Reached target HTTP service
                except urllib.error.URLError as ue:
                    status_desc = f"Connection Error: {ue.reason}"
                except Exception as ex:
                    status_desc = f"Error: {ex}"

            elif protocol.lower() == 'tcp':
                # Layer 4 TCP SYN Handshake & payload probe
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        res = s.connect_ex((host, port))
                        duration_ms = (time.time() - frame_start) * 1000
                        if res == 0:
                            payload = f"SOCNET_PROBE_{sent + 1}_".encode('utf-8')
                            payload = payload.ljust(payload_size, b'#')[:payload_size]
                            s.sendall(payload)
                            latencies.append(duration_ms)
                            status_desc = f"TCP Handshake OK ({len(payload)}B)"
                            success = True
                        else:
                            status_desc = f"TCP Refused (Errno {res})"
                except Exception as ex:
                    status_desc = f"TCP Error: {ex}"

            else:  # UDP
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(timeout)
                        payload = f"SOCNET_UDP_PROBE_{sent + 1}_{time.time()}".encode('utf-8')
                        payload = payload.ljust(payload_size, b'#')[:payload_size]
                        s.sendto(payload, (host, port))
                        duration_ms = (time.time() - frame_start) * 1000
                        latencies.append(duration_ms)
                        status_desc = f"Datagram Transmitted ({len(payload)}B)"
                        success = True
                except Exception as ex:
                    status_desc = f"UDP Error: {ex}"

            sent += 1
            limit_total = count_desc if is_continuous else f"{count}"
            progress_str = f"{sent}/{limit_total}"

            if protocol.lower() == 'udp':
                if success:
                    successful += 1
                    print(f"[SEND] {progress_str:>8} | Result=transmitted (unconfirmed delivery) | Size={payload_size}B")
                else:
                    failed += 1
                    print(f"[SEND] {progress_str:>8} | Result=failed | Error={status_desc}")
            else:
                if success:
                    successful += 1
                    print(f"[SEND] {progress_str:>8} | Result=success | Latency={duration_ms:.1f}ms [{status_desc}]")
                else:
                    failed += 1
                    print(f"[SEND] {progress_str:>8} | Result=failed  | Error={status_desc}")

            if not is_continuous and count is not None and sent >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[STOP] Traffic generation stopped cleanly by user (Ctrl+C).")

    total_duration = max(0.001, round(time.time() - start_time, 2))
    achieved_rate = round(sent / total_duration, 2)
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

    print("\n" + "=" * 75)
    print("                 TRAFFIC GENERATION SUMMARY")
    print("=" * 75)
    print(f"  Target Destination : {host}:{port} ({protocol.upper()})")
    print(f"  Frames Transmitted : {sent}")
    print(f"  Successful Sends   : {successful}")
    print(f"  Failed Sends       : {failed}")
    print(f"  Success Rate       : {round((successful / sent) * 100, 1) if sent > 0 else 0.0}%")
    print(f"  Total Elapsed Time : {total_duration}s")
    print(f"  Achieved Rate      : {achieved_rate} packets/sec")
    if latencies and protocol.lower() != 'udp':
        print(f"  Average Latency    : {avg_latency} ms (Min: {round(min(latencies), 1)}ms, Max: {round(max(latencies), 1)}ms)")
    if protocol.lower() == 'udp':
        print("  Delivery Notice    : UDP datagrams were dispatched across the network interface.")
        print("                       Remote arrival cannot be confirmed without an application-layer reply.")
    print("=" * 75)
    if successful > 0:
        print("✅ Traffic frames successfully transmitted across the wire.")
        print("   Verify the packet counter on the Monitoring Computer dashboard increments.\n")
    else:
        print("⚠️ No traffic frames were successfully transmitted.")
        print("   Review the pre-flight connectivity check diagnostics above.\n")


# ==============================================================================
# DATASET FEATURE STREAMING (MODEL INFERENCE API)
# ==============================================================================

def resolve_dataset_path(custom_path: Optional[str] = None) -> Path:
    """Locates dataset JSON file."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Specified dataset file '{custom_path}' does not exist.")

    candidates = [
        BASE_DIR / "features_by_label.json",
        BASE_DIR / "scripts" / "features_by_label.json",
        BASE_DIR / "features_by_label_test.json",
        BASE_DIR / "scripts" / "features_by_label_test.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return BASE_DIR / "features_by_label.json"


def load_dataset_records(dataset_path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Tuple[str, int]]]:
    """Loads and groups records by Label from JSON dataset."""
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file '{dataset_path}' not found.")

    with open(dataset_path, "r", encoding="utf-8") as f:
        try:
            raw_data = json.load(f)
        except Exception as ex:
            raise ValueError(f"Corrupted or invalid JSON format in '{dataset_path}': {ex}")

    if isinstance(raw_data, dict) and "all_data" in raw_data:
        records = raw_data["all_data"]
    elif isinstance(raw_data, list):
        records = raw_data
    elif isinstance(raw_data, dict):
        records_by_label = raw_data
        counts = [(k, len(v)) for k, v in records_by_label.items() if isinstance(v, list)]
        counts.sort(key=lambda x: (x[0].lower() != "benign", -x[1], x[0]))
        return records_by_label, counts
    else:
        raise ValueError(f"Unsupported dataset structure in '{dataset_path}'. Expected JSON list or dict with 'all_data'.")

    if not records:
        raise ValueError(f"Dataset file '{dataset_path}' contains zero records.")

    records_by_label: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        lbl = str(r.get("Label", "Unknown")).strip()
        if lbl not in records_by_label:
            records_by_label[lbl] = []
        records_by_label[lbl].append(r)

    counts = [(lbl, len(rec_list)) for lbl, rec_list in records_by_label.items()]
    counts.sort(key=lambda x: (x[0].lower() != "benign", -x[1], x[0]))
    return records_by_label, counts


def select_dataset_label_interactively(sorted_label_counts: List[Tuple[str, int]]) -> Optional[str]:
    """Displays terminal menu listing available labels and prompts user selection."""
    print("\n" + "=" * 75)
    print("           SOCNET SENDER: DYNAMIC DATASET LABELS DISCOVERED")
    print("=" * 75)
    print(f" {'#':<4} | {'Label Name':<30} | {'Available Records':<18}")
    print("-" * 75)
    for idx, (lbl, count) in enumerate(sorted_label_counts, start=1):
        is_attack_marker = " [Attack]" if lbl.lower() not in ["benign", "safe", "normal"] else " [Baseline]"
        print(f" {idx:<4} | {lbl + is_attack_marker:<30} | {count:>6} records")
    print("=" * 75)

    while True:
        try:
            choice = input(f"\nSelect label by number (1-{len(sorted_label_counts)}) or name [q to cancel]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[CANCELLED] Selection aborted by user.")
            return None

        if not choice:
            continue
        if choice.lower() in ['q', 'quit', 'exit', 'cancel']:
            print("[CANCELLED] Operation cancelled by user.")
            return None

        try:
            num = int(choice)
            if 1 <= num <= len(sorted_label_counts):
                return sorted_label_counts[num - 1][0]
            else:
                print(f"Invalid selection: '{choice}'. Enter a number between 1 and {len(sorted_label_counts)}.")
                continue
        except ValueError:
            pass

        choice_clean = choice.lower().replace("-", " ").replace("_", " ").strip()
        matches = [lbl for lbl, _ in sorted_label_counts if lbl.lower().replace("-", " ").replace("_", " ").strip() == choice_clean]
        if len(matches) == 1:
            return matches[0]

        partials = [lbl for lbl, _ in sorted_label_counts if choice_clean in lbl.lower().replace("-", " ").replace("_", " ")]
        if len(partials) == 1:
            return partials[0]

        print(f"Invalid label: '{choice}'. Please pick a valid number (1-{len(sorted_label_counts)}) or label name from above.")


def resolve_label_argument(label_arg: str, sorted_label_counts: List[Tuple[str, int]]) -> Optional[str]:
    """Resolves label argument to exact label name in dataset."""
    clean = str(label_arg).strip()
    try:
        num = int(clean)
        if 1 <= num <= len(sorted_label_counts):
            return sorted_label_counts[num - 1][0]
    except ValueError:
        pass

    clean_norm = clean.lower().replace("-", " ").replace("_", " ").strip()
    for lbl, _ in sorted_label_counts:
        if lbl.lower().replace("-", " ").replace("_", " ").strip() == clean_norm:
            return lbl

    partials = [lbl for lbl, _ in sorted_label_counts if clean_norm in lbl.lower().replace("-", " ").replace("_", " ")]
    if len(partials) == 1:
        return partials[0]

    return None


def confirm_replay_transmission(
    label: str,
    target_url: str,
    record_count: int,
    is_continuous: bool = True,
    interval: float = 0.5,
    auto_confirm: bool = False
) -> bool:
    """
    Displays the selected label and session details and requires explicit
    user confirmation before any dataset replay transmission begins.
    """
    if auto_confirm:
        return True

    count_desc = "Continuous (Ctrl+C to stop)" if is_continuous else f"{record_count} records"

    print("\n" + "=" * 75)
    print("                 CONFIRMATION REQUIRED: DATASET REPLAY")
    print("=" * 75)
    print(f"  Target Destination    : {target_url.rstrip('/')}/api/replay-feature")
    print(f"  Selected Label        : {label}")
    print(f"  Available Records     : {record_count}")
    print(f"  Transmission Mode     : {count_desc}")
    print(f"  Transmission Interval : {interval}s")
    print(f"  Workflow Architecture : Layer-7 Feature Replay (Dedicated ML Evaluation)")
    print("=" * 75)

    try:
        confirm = input(f"Start replaying '{label}' dataset records to {target_url}? [y/N]: ").strip().lower()
        if confirm in ['y', 'yes']:
            return True
        else:
            print(f"\n[CANCELLED] Replay of '{label}' cancelled by user.")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\n[CANCELLED] Operation aborted by user.")
        return False


def confirm_attack_transmission(label: str, target_url: str, record_count: int) -> bool:
    """Legacy helper: prompts for user confirmation before sending attack-labelled records."""
    if label.lower() in ["benign", "safe", "normal"]:
        return True

    print("\n" + "!" * 75)
    print(f"⚠️  SECURITY CONFIRMATION REQUIRED: ATTACK DATASET SELECTED")
    print("!" * 75)
    print(f"  Target Destination : {target_url} (Monitoring API)")
    print(f"  Selected Vector    : '{label}'")
    print(f"  Records to Send    : {record_count}")
    print(f"  Safety Policy      : Bounded test transmission to authorized monitoring endpoint.")
    print("!" * 75)

    try:
        confirm = input(f"Are you sure you want to transmit '{label}' attack records to {target_url}? [y/N]: ").strip().lower()
        if confirm in ['y', 'yes']:
            return True
        else:
            print(f"[CANCELLED] Transmission of '{label}' aborted by user.")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\n[CANCELLED] Transmission aborted by user.")
        return False


def run_dataset_feature_stream(
    records: List[Dict[str, Any]],
    label: str,
    target_api_url: str,
    interval: float = 0.5,
    count: Optional[int] = 20,
    continuous: bool = False,
    timeout: float = 3.0,
    check_interval: float = 5.0
):
    """
    Streams pre-extracted flow feature JSON records directly to /api/replay-feature
    for real-time ML model classification and precision evaluation.
    Periodically checks API connectivity during continuous transmission.
    """
    import random

    endpoint = f"{target_api_url.rstrip('/')}/api/replay-feature"
    total_available = len(records)
    count_desc = "Continuous (Ctrl+C to stop)" if (continuous or count is None or count <= 0) else f"{count}"

    parsed_url = urlparse(target_api_url)
    api_host = parsed_url.hostname or "127.0.0.1"
    api_port = parsed_url.port or 5000

    print("\n" + "=" * 75)
    print("        SOCNET: DATASET REPLAY & INFERENCE EVALUATION WORKFLOW")
    print("=" * 75)
    print(f"  Target Destination    : {endpoint}")
    print(f"  Selected Label        : {label} ({total_available} records available)")
    print(f"  Payload Architecture  : Pre-extracted 77-feature flow JSON + Ground Truth")
    print(f"                          (Real-time ML Model Evaluation, NOT raw wire L2/L3 packets)")
    print(f"  Transmission Count    : {count_desc}")
    print(f"  Transmission Interval : {interval}s")
    print(f"  Request Timeout       : {timeout}s")
    if continuous or count is None or count <= 0:
        print(f"  Periodic Re-check     : Every {check_interval}s")
    print("=" * 75)
    print(f"Replaying '{label}' flow records to {endpoint}...\n")

    sent = 0
    successful_inferences = 0
    correct_predictions = 0
    mismatched_predictions = 0
    failed_requests = 0
    consecutive_errors = 0
    latencies = []
    start_time = time.time()
    last_check_time = time.time()
    is_continuous = (continuous or count is None or count <= 0)

    try:
        while True:
            # Periodic reachability check during continuous transmission
            now = time.time()
            if is_continuous and (now - last_check_time) >= check_interval:
                last_check_time = now
                is_alive, check_err = check_destination_service(
                    api_host, api_port, protocol="tcp", timeout=min(timeout, 2.0), check_http_endpoint=True, http_path="/api/health"
                )
                if not is_alive:
                    print(f"\n[STOP] Target is no longer reachable ({check_err}). Replay stopped.")
                    break

            pkt = random.choice(records)
            features = {k: v for k, v in pkt.items() if k != "Label"}
            record_label = str(pkt.get("Label", label)).strip()
            payload = {
                "features": features,
                "ground_truth": record_label
            }
            frame_start = time.time()

            req_bytes = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                endpoint,
                data=req_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SocNet-DatasetReplayStreamer/2.5"
                },
                method="POST"
            )

            seq_num = sent + 1
            seq_str = f"#{seq_num}" if (is_continuous or count is None) else f"#{seq_num}/{count}"

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    dur_ms = (time.time() - frame_start) * 1000
                    resp_bytes = resp.read()
                    try:
                        resp_data = json.loads(resp_bytes.decode('utf-8'))
                    except Exception:
                        resp_data = {}

                    status = resp_data.get("status")
                    if status == "success" and ("predicted_label" in resp_data or "prediction" in resp_data):
                        sent += 1
                        successful_inferences += 1
                        consecutive_errors = 0
                        latencies.append(dur_ms)

                        pred_label = resp_data.get("predicted_label", "Unknown")
                        truth_label = resp_data.get("ground_truth", record_label)
                        conf = float(resp_data.get("confidence", 0.0))
                        match = bool(resp_data.get("match", False))

                        if match:
                            correct_predictions += 1
                            match_str = "YES"
                        else:
                            mismatched_predictions += 1
                            match_str = "NO "

                        print(f"[REPLAY] {seq_str:>8} | Truth={truth_label:<14} | Prediction={pred_label:<14} | Confidence={conf:>5.1f}% | Match={match_str} | Latency={dur_ms:.1f}ms")
                    else:
                        sent += 1
                        failed_requests += 1
                        consecutive_errors += 1
                        err_msg = resp_data.get("error", "Invalid inference response from receiver")
                        print(f"[REPLAY] {seq_str:>8} | Truth={record_label:<14} | Result=invalid_response | Error={err_msg}")

            except urllib.error.HTTPError as he:
                dur_ms = (time.time() - frame_start) * 1000
                sent += 1
                failed_requests += 1
                consecutive_errors += 1
                err_body = ""
                try:
                    raw_err = he.read().decode('utf-8', errors='replace')
                    err_json = json.loads(raw_err)
                    err_body = err_json.get("error", raw_err)
                except Exception:
                    pass
                print(f"[REPLAY] {seq_str:>8} | Truth={record_label:<14} | Result=failed  | Error=HTTP {he.code}: {err_body or he.reason}")

            except Exception as ex:
                dur_ms = (time.time() - frame_start) * 1000
                sent += 1
                failed_requests += 1
                consecutive_errors += 1
                print(f"[REPLAY] {seq_str:>8} | Truth={record_label:<14} | Result=failed  | Error={ex}")

            if consecutive_errors >= 10:
                print(f"\n[STOP] Reached 10 consecutive transmission errors. Replay stopped cleanly.")
                break

            if not is_continuous and count is not None and sent >= count:
                break
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[STOP] Replay stopped cleanly by user (Ctrl+C).")

    elapsed = max(0.001, round(time.time() - start_time, 2))
    throughput = round(sent / elapsed, 2)
    avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
    acc_pct = round((correct_predictions / successful_inferences) * 100, 1) if successful_inferences > 0 else 0.0
    mismatch_pct = round((mismatched_predictions / successful_inferences) * 100, 1) if successful_inferences > 0 else 0.0

    print("\n" + "=" * 75)
    print("                  DATASET REPLAY INFERENCE SUMMARY")
    print("=" * 75)
    print(f"  Target Destination    : {endpoint}")
    print(f"  Replayed Label        : {label}")
    print(f"  Total Requests Sent   : {sent}")
    print(f"  Successful Inferences : {successful_inferences}")
    print(f"  Correct Predictions   : {correct_predictions} ({acc_pct}%)")
    print(f"  Prediction Mismatches : {mismatched_predictions} ({mismatch_pct}%)")
    print(f"  Failed Requests       : {failed_requests}")
    print(f"  Total Elapsed Time    : {elapsed}s")
    print(f"  Measured Throughput   : {throughput} records/sec")
    if latencies:
        print(f"  Average Latency       : {avg_lat} ms (Min: {round(min(latencies), 1)}ms, Max: {round(max(latencies), 1)}ms)")
    print("=" * 75)
    if successful_inferences > 0:
        print(f"✅ Successfully evaluated {successful_inferences} '{label}' records against AI model.")
        print(f"   Model Accuracy on Session: {acc_pct}%\n")
    else:
        print("⚠️ No inference results were successfully obtained from the Monitoring API.")
        print(f"   Confirm that api.py is running on {target_api_url}.\n")


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

def main():
    args = parse_args()

    # 1. Resolve Effective Configuration
    try:
        cfg = resolve_effective_config(args)
    except Exception as ex:
        print(f"\n❌ CONFIGURATION ERROR: {ex}\n")
        sys.exit(1)

    host = cfg["host"]
    target_api_url = f"http://{host}:{cfg['api_port']}"

    # 2. Dataset Discovery (if dataset mode or label listing requested)
    dataset_file = None
    records_by_label = {}
    sorted_label_counts = []
    dataset_error = None

    if cfg["mode"] == "dataset" or cfg["list_labels"]:
        try:
            dataset_file = resolve_dataset_path(cfg["dataset_path"])
            records_by_label, sorted_label_counts = load_dataset_records(dataset_file)
        except Exception as ex:
            dataset_error = str(ex)

    # 3. Handle --list-labels
    if cfg["list_labels"]:
        if dataset_error:
            print(f"\n❌ Error discovering dataset labels: {dataset_error}\n")
            sys.exit(1)
        print("\n" + "=" * 75)
        print(f"   SOCNET: AVAILABLE TRAFFIC LABELS IN DATASET ({dataset_file.name})")
        print("=" * 75)
        print(f" {'#':<4} | {'Label Name':<30} | {'Available Records':<18}")
        print("-" * 75)
        for idx, (lbl, count) in enumerate(sorted_label_counts, start=1):
            is_attack_marker = " [Attack]" if lbl.lower() not in ["benign", "safe", "normal"] else " [Baseline]"
            print(f" {idx:<4} | {lbl + is_attack_marker:<30} | {count:>6} records")
        print("=" * 75 + "\n")
        sys.exit(0)

    # 4. Handle check-only diagnostics
    if cfg["check_only"]:
        target_check_port = cfg["api_port"] if cfg["mode"] == "dataset" else cfg["traffic_port"]
        proto = "tcp" if cfg["mode"] == "dataset" else cfg["protocol"]
        chk_http = (cfg["mode"] == "dataset")
        http_pth = "/api/replay-status" if cfg["mode"] == "dataset" else "/api/health"
        print(f"\n[CHECK] Pre-flight connectivity check to {host}:{target_check_port}...")
        reachable, err_reason = check_destination_service(
            host, target_check_port, protocol=proto, timeout=cfg["timeout"], check_http_endpoint=chk_http, http_path=http_pth
        )
        if reachable:
            print(f"✅ Pre-flight connectivity check passed ({host}:{target_check_port}).")
            sys.exit(0)
        else:
            print(f"❌ Pre-flight check failed ({host}:{target_check_port}): {err_reason}")
            sys.exit(1)

    # 5. Workflow Execution
    if cfg["mode"] == "real_traffic":
        # REAL WIRE TRAFFIC (Explicitly requested via --wire-traffic or --probe)
        count_desc = "Continuous" if cfg["continuous"] else f"{cfg['count']}"
        target_service_str = f"{host}:{cfg['traffic_port']} ({cfg['protocol'].upper()})"

        print("=" * 75)
        print("        SOCNET SENDER: TARGET & CONNECTIVITY INITIALIZATION")
        print("=" * 75)
        print(f"  Target Host Address  : {host} (Resolved: {cfg['resolved_ip']})")
        print(f"  Selected Workflow    : Real Wire Traffic ({cfg['protocol'].upper()})")
        print(f"  Destination Service  : {target_service_str}")
        print(f"  Transmission Count   : {count_desc}")
        print(f"  Transmission Interval: {cfg['interval']}s")
        print(f"  Payload Size         : {cfg['payload_size']} bytes")
        print("=" * 75)

        print(f"\n[CHECK] Checking target {host}:{cfg['traffic_port']} (Protocol: {cfg['protocol'].upper()})...")
        reachable, err_reason = check_destination_service(
            host, cfg["traffic_port"], protocol=cfg["protocol"], timeout=cfg["timeout"], check_http_endpoint=False
        )
        if not reachable:
            print("\n" + "!" * 75)
            print(f"❌ TARGET SERVICE UNREACHABLE: {host}:{cfg['traffic_port']} ({cfg['protocol'].upper()})")
            print(f"   Reason: {err_reason}")
            print("!" * 75)
            print("\n[STOP] Preflight check failed. Absolutely no network traffic will be transmitted.")
            sys.exit(1)

        print("[OK] Target service is reachable.")
        run_benign_traffic_generator(
            host=host,
            port=cfg["traffic_port"],
            protocol=cfg["protocol"],
            interval=cfg["interval"],
            count=cfg["count"],
            timeout=cfg["timeout"],
            payload_size=cfg["payload_size"],
            check_interval=cfg["check_interval"]
        )

    else:
        # DATASET REPLAY WORKFLOW (DEFAULT)
        if dataset_error:
            print(f"\n❌ DATASET FILE ERROR: {dataset_error}\n")
            sys.exit(1)

        # 5a. Label selection: prompt interactively if not passed on CLI
        selected_label = None
        if cfg["label"]:
            selected_label = resolve_label_argument(cfg["label"], sorted_label_counts)
            if not selected_label:
                print(f"\n❌ INVALID LABEL ARGUMENT: '{cfg['label']}' was not found in dataset {dataset_file.name}.")
                print("Available labels:")
                for idx, (lbl, cnt) in enumerate(sorted_label_counts, start=1):
                    print(f"  {idx:>2}. {lbl:<25} ({cnt} records)")
                sys.exit(1)

        if not selected_label:
            selected_label = select_dataset_label_interactively(sorted_label_counts)
            if not selected_label:
                # User cancelled, exited, or entered invalid selection -> send NOTHING
                sys.exit(0)

        records_to_send = records_by_label.get(selected_label, [])
        if not records_to_send:
            print(f"\n❌ Error: Selected label '{selected_label}' has zero available records.")
            sys.exit(1)

        # 5b. Explicit confirmation before starting
        auto_confirm = bool(cfg.get("auto_confirm", False))
        confirmed = confirm_replay_transmission(
            label=selected_label,
            target_url=target_api_url,
            record_count=len(records_to_send),
            is_continuous=cfg["continuous"],
            interval=cfg["interval"],
            auto_confirm=auto_confirm
        )
        if not confirmed:
            sys.exit(0)

        # 5c. Target Reachability Check (against Replay API endpoint, NOT port 8080)
        print(f"\n[CHECK] Checking target {host}:{cfg['api_port']} (Replay API Endpoint)...")
        reachable, err_reason = check_destination_service(
            host, cfg["api_port"], protocol="tcp", timeout=cfg["timeout"], check_http_endpoint=True, http_path="/api/replay-status"
        )
        if not reachable:
            print("\n" + "!" * 75)
            print(f"❌ TARGET REPLAY API SERVICE UNREACHABLE: {host}:{cfg['api_port']}")
            print(f"   Reason: {err_reason}")
            print("!" * 75)
            print("\n[STOP] Preflight check failed. Absolutely no feature records will be transmitted.")
            print(f"Verify that api.py is running on {host} and port {cfg['api_port']} is accessible.")
            print("Troubleshooting checklist:")
            print(" 1. Physical Layer: Ensure Ethernet cable is connected between Sender and Monitor.")
            print(" 2. Service Status: On Monitor, confirm 'python api.py' is running.")
            print(f" 3. Firewall Rule : On Monitor, ensure inbound TCP port {cfg['api_port']} is permitted.\n")
            sys.exit(1)

        print("[OK] Target Replay API is reachable.")

        # 5d. Launch Replay Stream
        run_dataset_feature_stream(
            records=records_to_send,
            label=selected_label,
            target_api_url=target_api_url,
            interval=cfg["interval"],
            count=cfg["count"],
            continuous=cfg["continuous"],
            timeout=cfg["timeout"],
            check_interval=cfg["check_interval"]
        )


if __name__ == '__main__':
    main()
