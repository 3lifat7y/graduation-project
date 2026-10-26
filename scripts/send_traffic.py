#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT: Dedicated Dataset / API Testing & Model Evaluation Script
================================================================
Streams pre-extracted flow feature records from the test dataset (`test_set.csv`)
over the network to the Receiver's dedicated `/api/replay-feature` endpoint.

Validates model inference accuracy, class prediction distribution, and confidence scores
without generating raw network packets or injecting synthetic traffic onto the physical wire.

Key Principles:
- Uses `test_set.csv` (or configured dataset) as the source of pre-extracted features.
- Never sends the ground-truth label as an input feature (strictly excludes 'Label' key).
- Sends feature records exclusively to `/api/replay-feature` on the Receiver API.
- Displays real-time prediction feedback: Ground Truth, Prediction, Confidence, Match, Latency.
- Provides comprehensive summary statistics (Accuracy %, Mismatches, Latency, Throughput).
- Completely independent from live network packet generation (`scripts/send_live_traffic.py`).
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
DEFAULT_CSV_DATASET = BASE_DIR / "final_output_new_dataset" / "datasets" / "test_set.csv"
DEFAULT_JSON_DATASET = BASE_DIR / "features_by_label.json"

TEST_SET_PATH = str(DEFAULT_CSV_DATASET if DEFAULT_CSV_DATASET.exists() else DEFAULT_JSON_DATASET)

# ==================== USER CONFIGURATION ====================

TARGET_HOST = "192.168.1.12"
TARGET_PORT = 8080                          # Traffic sink port (for backward compatibility)
API_PORT = 5000                             # Monitoring API port

# Workflow Configuration: Dataset Replay is the DEFAULT
DEFAULT_WORKFLOW = "dataset"
ENABLE_DATASET_MODE = True

# Dataset Replay settings
DATASET_LABEL: Optional[str] = None         # None = prompt user interactively to choose
DATASET_RECORD_COUNT: Optional[int] = None # None = continuous until Ctrl+C; or int for bounded
DATASET_CONTINUOUS = True                   # Continuous replay by default
DATASET_INTERVAL_SECONDS = 0.5              # Delay between replay requests

# Real Wire Traffic settings (BACKWARD COMPATIBILITY ONLY: Use send_live_traffic.py instead)
TRAFFIC_PROTOCOL = "http"                   # http, tcp, or udp
TRAFFIC_COUNT = 200                         # Count when real wire traffic is explicitly chosen
TRAFFIC_INTERVAL_SECONDS = 0.5              # Delay between real traffic transmissions
CONNECT_TIMEOUT_SECONDS = 3.0
CONNECTIVITY_CHECK_INTERVAL_SECONDS = 5.0
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
                headers={"User-Agent": "SCOUT-PreflightCheck/3.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 204, 301, 302):
                    return False, f"HTTP endpoint returned unexpected status code: {resp.status}"
        except urllib.error.HTTPError:
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
                headers={"User-Agent": "SCOUT-TrafficSender/3.0"}
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
                "Example: python scripts/send_traffic.py --host 192.168.1.11 --api-port 5000\n"
                "Or set TARGET_HOST at the top of scripts/send_traffic.py."
            )
        else:
            results["error_reason"] = f"Unable to establish TCP connection to {host} on ports {api_port} or {traffic_port}."
            results["remediation"] = (
                f"Troubleshooting checklist for connecting to {host}:\n"
                f" 1. Physical Layer : Ensure the Ethernet cable is securely connected to both computers and link LEDs are active.\n"
                f" 2. Subnet Config  : Confirm both computers share the same IPv4 subnet (e.g. Sender: 192.168.1.X, Monitor: 192.168.1.Y).\n"
                f" 3. Service Status : On the Monitoring Computer, ensure 'python api.py' is running.\n"
                f" 4. Firewall Rule  : On the Monitoring Computer, configure Windows Firewall to permit inbound TCP on ports {api_port} and {traffic_port}."
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
    parser = argparse.ArgumentParser(
        description="SCOUT: Dedicated Dataset Feature Replay & Model Inference Evaluation Tool."
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help=f"Target Monitoring Computer host or IP address (default: {TARGET_HOST})."
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=None,
        help=f"Monitoring Flask API port (default: {API_PORT})."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Traffic sink port (backward compatibility; default: {TARGET_PORT})."
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path to CSV test dataset file (default: final_output_new_dataset/datasets/test_set.csv) or JSON."
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Dataset traffic label to replay (e.g. 'Benign', 'DDoS', 'PortScan'). If omitted, interactive menu opens."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of records to replay. If omitted, replays continuously until Ctrl+C."
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        default=None,
        help="Replay dataset records continuously in random loop until Ctrl+C."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help=f"Delay between replay transmissions in seconds (default: {DATASET_INTERVAL_SECONDS}s)."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"HTTP request timeout in seconds (default: {CONNECT_TIMEOUT_SECONDS}s)."
    )
    parser.add_argument(
        "--check-interval",
        type=float,
        default=None,
        help=f"Target connectivity check interval during continuous stream (default: {CONNECTIVITY_CHECK_INTERVAL_SECONDS}s)."
    )
    parser.add_argument(
        "--list-labels", "--list",
        action="store_true",
        help="Discover and display available labels and record counts in dataset, then exit."
    )
    parser.add_argument(
        "--check-only", "--check",
        action="store_true",
        help="Run pre-flight connectivity check to target API and exit."
    )
    parser.add_argument(
        "-y", "--yes",
        dest="auto_confirm",
        action="store_true",
        help="Bypass interactive user confirmation prompt."
    )

    # Backward-compatibility flags (for legacy wire traffic tests):
    parser.add_argument(
        "--wire-traffic",
        action="store_true",
        help="[Compatibility] Switch to wire traffic generation (prefer scripts/send_live_traffic.py)."
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="[Compatibility] Alias for wire traffic probe."
    )
    parser.add_argument(
        "--protocol",
        type=str,
        default=None,
        help="[Compatibility] Transport protocol for wire traffic ('http', 'tcp', 'udp')."
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=None,
        help="[Compatibility] Wire packet payload size in bytes."
    )

    return parser.parse_args()


def _safe_get(obj: Any, attr: str, expected_type: Any = None, default: Any = None) -> Any:
    val = getattr(obj, attr, default)
    if val is None or hasattr(val, '_mock_name') or type(val).__name__ in ('MagicMock', 'Mock'):
        return default
    if expected_type is not None:
        try:
            return expected_type(val)
        except (ValueError, TypeError):
            return default
    return val


def resolve_effective_config(args) -> Dict[str, Any]:
    """
    Consolidates CLI arguments, environment variables, and file-level defaults
    into a validated configuration dictionary.
    """
    # 1. Target URL parsing (e.g. --target http://192.168.1.99:9090)
    target_url_arg = _safe_get(args, "target", str, default=None)
    target_url_host = None
    target_url_port = None
    if target_url_arg:
        t_clean = str(target_url_arg).strip()
        if "://" not in t_clean:
            t_clean = f"http://{t_clean}"
        p_parsed = urlparse(t_clean)
        if p_parsed.hostname:
            target_url_host = p_parsed.hostname
        if p_parsed.port:
            target_url_port = p_parsed.port

    # 2. Host Resolution
    host_arg = _safe_get(args, "host", str, default=None)
    if host_arg is not None and str(host_arg).strip():
        host = str(host_arg).strip()
    elif target_url_host:
        host = target_url_host
    elif os.environ.get("SOCNET_TARGET_HOST"):
        host = os.environ["SOCNET_TARGET_HOST"].strip()
    elif TARGET_HOST:
        host = str(TARGET_HOST).strip()
    else:
        raise ValueError("Target host is not configured. Provide --host <IP> or set TARGET_HOST.")

    valid, resolved_ip, err = validate_ip_or_host(host)
    if not valid:
        raise ValueError(f"Invalid host address '{host}': {err}")

    # 3. Port Resolutions
    api_port_arg = _safe_get(args, "api_port", int, default=None)
    if api_port_arg is not None:
        api_port = int(api_port_arg)
    elif os.environ.get("SOCNET_API_PORT"):
        api_port = int(os.environ["SOCNET_API_PORT"])
    else:
        api_port = int(API_PORT)

    traffic_port_arg = _safe_get(args, "port", int, default=None)
    if traffic_port_arg is not None:
        traffic_port = int(traffic_port_arg)
    elif target_url_port is not None:
        traffic_port = int(target_url_port)
    elif os.environ.get("SOCNET_TRAFFIC_PORT"):
        traffic_port = int(os.environ["SOCNET_TRAFFIC_PORT"])
    else:
        traffic_port = int(TARGET_PORT)

    # 4. Mode Resolution: Dataset Replay is default
    is_wire_traffic = bool(_safe_get(args, "wire_traffic", bool, default=False) or _safe_get(args, "probe", bool, default=False))
    mode = "real_traffic" if is_wire_traffic else "dataset"

    # 4. Dataset Path Resolution
    dataset_arg = _safe_get(args, "dataset", str, default=None)

    # 5. Continuous vs Bounded Count Resolution
    continuous_arg = _safe_get(args, "continuous", bool, default=None)
    count_arg = _safe_get(args, "count", int, default=None)
    label_arg = _safe_get(args, "label", str, default=None)

    if mode == "dataset":
        if continuous_arg is True:
            is_continuous = True
            count = None
        elif count_arg is not None:
            is_continuous = False
            count = max(1, int(count_arg))
        elif DATASET_RECORD_COUNT is not None:
            is_continuous = False
            count = max(1, int(DATASET_RECORD_COUNT))
        else:
            is_continuous = True
            count = None
    else:
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

    # 6. Interval Resolution
    interval_arg = _safe_get(args, "interval", float, default=None)
    if interval_arg is not None:
        interval = max(0.001, float(interval_arg))
    elif mode == "dataset":
        interval = max(0.001, float(DATASET_INTERVAL_SECONDS))
    else:
        interval = max(0.001, float(TRAFFIC_INTERVAL_SECONDS))

    # 7. Protocol Resolution (for wire traffic mode)
    proto_arg = _safe_get(args, "protocol", str, default=None)
    if proto_arg is not None:
        protocol = str(proto_arg).strip().lower()
    else:
        protocol = str(TRAFFIC_PROTOCOL).strip().lower()
    if protocol not in ("http", "tcp", "udp"):
        raise ValueError(f"Unsupported protocol '{protocol}'. Choose from 'http', 'tcp', or 'udp'.")

    # 8. Payload Size Resolution (for wire traffic mode)
    payload_arg = _safe_get(args, "payload_size", int, default=None)
    if payload_arg is not None:
        payload_size = max(1, min(65507, int(payload_arg)))
    else:
        payload_size = max(1, min(65507, int(TRAFFIC_PAYLOAD_SIZE_BYTES)))

    # 9. Timeout & Connectivity Check Interval
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
# DATASET RESOLUTION & PARSING (CSV / JSON)
# ==============================================================================

def resolve_dataset_path(custom_path: Optional[str] = None) -> Path:
    """Locates primary test dataset file (defaults to test_set.csv)."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Specified dataset file '{custom_path}' does not exist.")

    candidates = [
        BASE_DIR / "final_output_new_dataset" / "datasets" / "test_set.csv",
        BASE_DIR / "features_by_label.json",
        BASE_DIR / "scripts" / "features_by_label.json",
        BASE_DIR / "features_by_label_test.json",
        BASE_DIR / "scripts" / "features_by_label_test.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return BASE_DIR / "final_output_new_dataset" / "datasets" / "test_set.csv"


def load_dataset_records(dataset_path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Tuple[str, int]]]:
    """
    Loads and groups pre-extracted records by Label from CSV (test_set.csv) or JSON dataset.
    Preserves all 77 numerical flow feature keys while retaining 'Label' for evaluation.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file '{dataset_path}' not found.")

    ext = dataset_path.suffix.lower()

    # 1. Handle CSV Datasets (test_set.csv)
    if ext == ".csv":
        try:
            import pandas as pd
            df = pd.read_csv(dataset_path, low_memory=False)
            df.columns = df.columns.str.strip()

            if "Label" not in df.columns:
                raise ValueError(f"Dataset CSV '{dataset_path}' is missing required 'Label' column.")

            # Replace NaNs/Infs with zero defaults to preserve clean numeric types
            df = df.replace([float('inf'), float('-inf')], float('nan')).fillna(0.0)

            records_by_label: Dict[str, List[Dict[str, Any]]] = {}
            for lbl, grp in df.groupby("Label"):
                lbl_clean = str(lbl).strip()
                records_by_label[lbl_clean] = grp.to_dict(orient="records")

            counts = [(lbl, len(rec_list)) for lbl, rec_list in records_by_label.items()]
            counts.sort(key=lambda x: (x[0].lower() != "benign", -x[1], x[0]))
            return records_by_label, counts
        except Exception as ex:
            raise ValueError(f"Failed to parse CSV dataset '{dataset_path}': {ex}")

    # 2. Handle JSON Datasets (features_by_label.json)
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
        raise ValueError(f"Unsupported dataset structure in '{dataset_path}'. Expected CSV or JSON list/dict with 'all_data'.")

    if not records:
        raise ValueError(f"Dataset file '{dataset_path}' contains zero records.")

    records_by_label = {}
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
    print("\n" + "=" * 78)
    print("           SCOUT SENDER: DYNAMIC DATASET LABELS DISCOVERED")
    print("=" * 78)
    print(f" {'#':<4} | {'Label Name':<32} | {'Available Records':<18}")
    print("-" * 78)
    for idx, (lbl, count) in enumerate(sorted_label_counts, start=1):
        is_attack_marker = " [Attack]" if lbl.lower() not in ["benign", "safe", "normal"] else " [Baseline]"
        print(f" {idx:<4} | {lbl + is_attack_marker:<32} | {count:>6} records")
    print("=" * 78)

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
    """Displays the selected label and session details and prompts for confirmation."""
    if auto_confirm:
        return True

    count_desc = "Continuous (Ctrl+C to stop)" if is_continuous else f"{record_count} records"

    print("\n" + "=" * 78)
    print("                 CONFIRMATION REQUIRED: DATASET REPLAY")
    print("=" * 78)
    print(f"  Target Destination    : {target_url.rstrip('/')}/api/replay-feature")
    print(f"  Selected Label        : {label}")
    print(f"  Available Records     : {record_count}")
    print(f"  Transmission Mode     : {count_desc}")
    print(f"  Transmission Interval : {interval}s")
    print(f"  Workflow Architecture : Layer-7 Feature Replay (Dedicated ML Evaluation)")
    print("=" * 78)

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

    print("\n" + "!" * 78)
    print(f"⚠️  SECURITY CONFIRMATION REQUIRED: ATTACK DATASET SELECTED")
    print("!" * 78)
    print(f"  Target Destination : {target_url} (Monitoring API)")
    print(f"  Selected Vector    : '{label}'")
    print(f"  Records to Send    : {record_count}")
    print(f"  Safety Policy      : Bounded test transmission to authorized monitoring endpoint.")
    print("!" * 78)

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


# ==============================================================================
# DATASET FEATURE STREAMING (MODEL INFERENCE API)
# ==============================================================================

def run_dataset_feature_stream(
    records: List[Dict[str, Any]],
    label: str,
    target_api_url: str,
    interval: float = 0.5,
    count: Optional[int] = 20,
    continuous: bool = False,
    timeout: float = 3.0,
    check_interval: float = 5.0
) -> Dict[str, Any]:
    """
    Streams pre-extracted flow feature JSON records directly to /api/replay-feature
    for real-time ML model classification and evaluation.

    Strict Requirements:
    - Never passes the 'Label' column as an input feature (strictly excludes 'Label' key).
    - Sends ground truth exclusively under the 'ground_truth' key for receiver comparison.
    - Captures and displays real-time prediction, confidence score, and match status.
    - Computes and prints comprehensive evaluation metrics at conclusion.
    """
    import random

    endpoint = f"{target_api_url.rstrip('/')}/api/replay-feature"
    total_available = len(records)
    count_desc = "Continuous (Ctrl+C to stop)" if (continuous or count is None or count <= 0) else f"{count}"

    parsed_url = urlparse(target_api_url)
    api_host = parsed_url.hostname or "127.0.0.1"
    api_port = parsed_url.port or 5000

    print("\n" + "=" * 78)
    print("        SCOUT: DATASET REPLAY & INFERENCE EVALUATION WORKFLOW")
    print("=" * 78)
    print(f"  Target Destination    : {endpoint}")
    print(f"  Selected Label        : {label} ({total_available} records available)")
    print(f"  Payload Architecture  : Pre-extracted 77-feature flow JSON + Ground Truth")
    print(f"                          (Real-time ML Model Evaluation, NOT raw wire L2/L3 packets)")
    print(f"  Transmission Count    : {count_desc}")
    print(f"  Transmission Interval : {interval}s")
    print(f"  Request Timeout       : {timeout}s")
    if continuous or count is None or count <= 0:
        print(f"  Periodic Health Check : Every {check_interval}s")
    print("=" * 78)
    print(f"Replaying '{label}' flow records to {endpoint}...\n")

    sent = 0
    successful_inferences = 0
    correct_predictions = 0
    mismatched_predictions = 0
    failed_requests = 0
    consecutive_errors = 0
    latencies: List[float] = []
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
            # NEVER send ground truth label as an input feature
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
                    "User-Agent": "SCOUT-DatasetReplayStreamer/3.0"
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

    print("\n" + "=" * 78)
    print("                  DATASET REPLAY INFERENCE SUMMARY")
    print("=" * 78)
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
    print("=" * 78)
    if successful_inferences > 0:
        print(f"✅ Successfully evaluated {successful_inferences} '{label}' records against AI model.")
        print(f"   Model Accuracy on Session: {acc_pct}%\n")
    else:
        print("⚠️ No inference results were successfully obtained from the Monitoring API.")
        print(f"   Confirm that api.py is running on {target_api_url}.\n")

    return {
        "sent": sent,
        "successful_inferences": successful_inferences,
        "correct_predictions": correct_predictions,
        "mismatches": mismatched_predictions,
        "failed_requests": failed_requests,
        "accuracy_pct": acc_pct,
        "elapsed_seconds": elapsed,
        "throughput": throughput,
        "avg_latency_ms": avg_lat
    }


# ==============================================================================
# BACKWARD COMPATIBILITY: WIRE TRAFFIC GENERATOR DELEGATION
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
    Backward compatibility shim delegating real network traffic generation
    to scripts.send_live_traffic.run_live_traffic_generator.
    """
    try:
        from scripts.send_live_traffic import run_live_traffic_generator
        return run_live_traffic_generator(
            host=host,
            port=port,
            protocol=protocol,
            interval=interval,
            count=count,
            timeout=timeout,
            payload_size=payload_size,
            check_interval=check_interval
        )
    except ImportError:
        # Standalone inline fallback if send_live_traffic is not yet in path
        from send_live_traffic import run_live_traffic_generator
        return run_live_traffic_generator(
            host=host,
            port=port,
            protocol=protocol,
            interval=interval,
            count=count,
            timeout=timeout,
            payload_size=payload_size,
            check_interval=check_interval
        )


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
        print("\n" + "=" * 78)
        print(f"   SCOUT: AVAILABLE TRAFFIC LABELS IN DATASET ({dataset_file.name})")
        print("=" * 78)
        print(f" {'#':<4} | {'Label Name':<32} | {'Available Records':<18}")
        print("-" * 78)
        for idx, (lbl, count) in enumerate(sorted_label_counts, start=1):
            is_attack_marker = " [Attack]" if lbl.lower() not in ["benign", "safe", "normal"] else " [Baseline]"
            print(f" {idx:<4} | {lbl + is_attack_marker:<32} | {count:>6} records")
        print("=" * 78 + "\n")
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

    # 5. Workflow Execution: Real Wire Traffic (Backward Compatibility)
    if cfg["mode"] == "real_traffic":
        count_desc = "Continuous" if cfg["continuous"] else f"{cfg['count']}"
        target_service_str = f"{host}:{cfg['traffic_port']} ({cfg['protocol'].upper()})"

        print("=" * 78)
        print("        SOCNET SENDER: TARGET & CONNECTIVITY INITIALIZATION")
        print("=" * 78)
        print(f"  Target Host Address  : {host} (Resolved: {cfg['resolved_ip']})")
        print(f"  Selected Workflow    : Real Wire Traffic ({cfg['protocol'].upper()})")
        print(f"  Destination Service  : {target_service_str}")
        print(f"  Transmission Count   : {count_desc}")
        print(f"  Transmission Interval: {cfg['interval']}s")
        print(f"  Payload Size         : {cfg['payload_size']} bytes")
        print("=" * 78)

        print(f"\n[CHECK] Checking target {host}:{cfg['traffic_port']} (Protocol: {cfg['protocol'].upper()})...")
        reachable, err_reason = check_destination_service(
            host, cfg["traffic_port"], protocol=cfg["protocol"], timeout=cfg["timeout"], check_http_endpoint=False
        )
        if not reachable:
            print("\n" + "!" * 78)
            print(f"❌ TARGET SERVICE UNREACHABLE: {host}:{cfg['traffic_port']} ({cfg['protocol'].upper()})")
            print(f"   Reason: {err_reason}")
            print("!" * 78)
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
        return

    # 6. Workflow Execution: Primary Dataset Replay
    if dataset_error:
        print(f"\n❌ DATASET INITIALIZATION ERROR: {dataset_error}\n")
        sys.exit(1)

    selected_label = None
    if cfg["label"]:
        selected_label = resolve_label_argument(cfg["label"], sorted_label_counts)
        if not selected_label:
            print(f"\n❌ Specified label '{cfg['label']}' was not found in dataset '{dataset_file.name}'.")
            print("   Run with '--list-labels' to view all available traffic classes.\n")
            sys.exit(1)
    else:
        selected_label = select_dataset_label_interactively(sorted_label_counts)
        if not selected_label:
            sys.exit(0)

    label_records = records_by_label.get(selected_label, [])
    if not label_records:
        print(f"\n❌ Zero records found for label '{selected_label}' in '{dataset_file.name}'.\n")
        sys.exit(1)

    # 7. User Confirmation Prompt (Prompt before probing network)
    if not confirm_replay_transmission(
        label=selected_label,
        target_url=target_api_url,
        record_count=len(label_records),
        is_continuous=cfg["continuous"],
        interval=cfg["interval"],
        auto_confirm=cfg["auto_confirm"]
    ):
        sys.exit(0)

    # 8. Pre-flight check to Replay API endpoint
    print(f"\n[CHECK] Checking target {host}:{cfg['api_port']} (Replay API Endpoint)...")
    reachable, err_reason = check_destination_service(
        host, cfg["api_port"], protocol="tcp", timeout=cfg["timeout"], check_http_endpoint=True, http_path="/api/health"
    )
    if not reachable:
        print("\n" + "!" * 78)
        print(f"❌ RECEIVER REPLAY API UNREACHABLE: {host}:{cfg['api_port']}")
        print(f"   Reason: {err_reason}")
        print("!" * 78)
        print("\n[STOP] Preflight check failed. Ensure api.py is running on the Receiver.")
        sys.exit(1)

    print("[OK] Target Replay API is reachable.")

    # 9. Execute Replay Stream
    run_dataset_feature_stream(
        records=label_records,
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
