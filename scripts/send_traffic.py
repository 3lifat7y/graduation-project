 #!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard / SocNet: Cross-Device Traffic Generator & Connectivity Diagnostic Tool
Generates bounded, benign network traffic (HTTP / TCP / UDP) across an authorized local Ethernet network
from the Sender Computer to the Monitoring Computer without synthetic feature injection.
"""

import os
import sys
import json
import time
import socket
import argparse
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

# ==============================================================================
# SENDER CONFIGURATION: TARGET MONITORING COMPUTER
#
# Configure default destination in this SINGLE central location.
# Change DEFAULT_MONITORING_HOST to your Monitoring Computer's Ethernet IPv4 address
# (e.g. 192.168.1.11), or override it dynamically on the command line via:
#   python scripts/send_traffic.py --host 192.168.1.11 --port 8080
# or via the SOCNET_HOST environment variable.
# ==============================================================================
DEFAULT_MONITORING_HOST: str = os.environ.get("SOCNET_HOST", "192.168.1.11")
DEFAULT_BENIGN_TRAFFIC_PORT: int = int(os.environ.get("SOCNET_TRAFFIC_PORT", 8080))
DEFAULT_API_PORT: int = int(os.environ.get("SOCNET_PORT", 5000))


def parse_args():
    p = argparse.ArgumentParser(
        description="SocNet / DDoS-Guard: Cross-Device Benign Network Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
===============================================================================
INSTRUCTIONS FOR TWO-COMPUTER ETHERNET DEPLOYMENT:
===============================================================================
1. On the MONITORING COMPUTER:
   a. Connect the Ethernet cable and identify its IPv4 address (e.g. {DEFAULT_MONITORING_HOST}).
   b. Configure Windows Firewall (run as Administrator once):
      powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 ConfigureFirewall
   c. Start the monitoring server:
      python api.py
   d. In your web browser, open http://127.0.0.1:5000 and click 'Start Monitoring'.

2. On the SENDER COMPUTER:
   a. Connect the Ethernet cable on the same subnet (e.g. 192.168.1.X).
   b. Run pre-flight connectivity check:
      python scripts/send_traffic.py --host {DEFAULT_MONITORING_HOST} --check-only
   c. Send 20 bounded, benign HTTP test packets:
      python scripts/send_traffic.py --host {DEFAULT_MONITORING_HOST} --port {DEFAULT_BENIGN_TRAFFIC_PORT} --count 20
   d. Or send continuous traffic at 0.5s intervals:
      python scripts/send_traffic.py --host {DEFAULT_MONITORING_HOST} --port {DEFAULT_BENIGN_TRAFFIC_PORT} --continuous

NOTE:
- The target host can be customized in one place by changing DEFAULT_MONITORING_HOST
  at the top of scripts/send_traffic.py, or overridden dynamically using --host.
- The sender NEVER silently falls back to 127.0.0.1 when a remote target is configured.
===============================================================================
        """
    )
    # Destination Options
    p.add_argument(
        '--host', '-H', type=str, default=None,
        help=f"Target Monitoring Computer Ethernet IPv4 address (default: {DEFAULT_MONITORING_HOST}, env: SOCNET_HOST)"
    )
    p.add_argument(
        '--target', '-t', type=str, default=None,
        help=f"Target server URL or host (e.g. http://{DEFAULT_MONITORING_HOST}:{DEFAULT_BENIGN_TRAFFIC_PORT}, env: SOCNET_TARGET)"
    )
    p.add_argument(
        '--port', '-p', type=int, default=None,
        help=f"Target port for benign traffic on Monitoring Computer (default: {DEFAULT_BENIGN_TRAFFIC_PORT}, env: SOCNET_TRAFFIC_PORT)"
    )
    p.add_argument(
        '--api-port', type=int, default=None,
        help=f"Target Flask API port on Monitoring Computer for health check (default: {DEFAULT_API_PORT}, env: SOCNET_PORT)"
    )

    # Traffic Flow Controls
    p.add_argument(
        '--protocol', type=str, default='http', choices=['http', 'tcp', 'udp'],
        help="Transport / application protocol for benign probe (default: http)"
    )
    p.add_argument(
        '--count', '-c', type=int, default=20,
        help="Number of benign requests/packets to send (default: 20; use --continuous for unlimited)"
    )
    p.add_argument(
        '--continuous', action='store_true',
        help="Send continuously until stopped by user (Ctrl+C)"
    )
    p.add_argument(
        '--interval', '-i', type=float, default=0.5,
        help="Seconds between sends (default: 0.5s)"
    )
    p.add_argument(
        '--timeout', type=float, default=2.0,
        help="Socket / HTTP connection timeout in seconds (default: 2.0s)"
    )
    p.add_argument(
        '--check-only', action='store_true',
        help="Run pre-flight connectivity diagnostics then exit"
    )

    # Dynamic JSON Label Selection & Dataset Options
    p.add_argument(
        '--label', '-l', type=str, default=None,
        help="Target dataset traffic label name or 1-based index (e.g. 'DDoS', 'Benign', or '2')"
    )
    p.add_argument(
        '--dataset', type=str, default=None,
        help="Path to feature dataset JSON file (default: looks for features_by_label_test.json or features_by_label.json)"
    )
    p.add_argument(
        '--list-labels', action='store_true',
        help="List available traffic labels in the dataset JSON with record counts, then exit"
    )

    # Backward Compatibility Options
    p.add_argument('--probe', action='store_true', help="Explicit wire probing mode: transmit Layer-4/Layer-7 network packets instead of streaming dataset records")
    p.add_argument('--simulate-dataset', action='store_true', help="Legacy alias for dataset feature streaming")
    p.add_argument('--attack', '-a', type=str, default=None, help="Legacy alias for --label: attack label name or index")
    p.add_argument('--list', action='store_true', help="Alias for --list-labels: list available labels then exit")

    return p.parse_args()


def resolve_target_config(args) -> Tuple[str, int, int]:
    """
    Resolves target host, traffic port, and API port using CLI flags, environment variables,
    and the central DEFAULT_MONITORING_HOST configuration variable.
    Ensures that a remote target configuration is strictly honored and never silently reverts to 127.0.0.1.
    """
    # Priority 1: Direct --host CLI argument
    host = args.host

    # Priority 2: Extract from --target URL if passed
    if not host and args.target:
        if "://" in args.target:
            parsed = urlparse(args.target)
            host = parsed.hostname
        else:
            host = args.target.split(":")[0]

    # Priority 3: Central default configuration variable (or SOCNET_HOST env variable)
    if not host:
        host = DEFAULT_MONITORING_HOST

    # Validate that host is clean and non-empty
    host = str(host).strip()
    if not host:
        host = "192.168.1.11"

    # Traffic port resolution: CLI -> --target URL -> central default
    traffic_port = args.port
    if traffic_port is None and args.target and ":" in args.target:
        try:
            traffic_port = int(urlparse(args.target).port or args.target.split(":")[-1].split("/")[0])
        except (ValueError, TypeError):
            pass
    if traffic_port is None:
        traffic_port = DEFAULT_BENIGN_TRAFFIC_PORT

    # API port resolution: CLI -> central default
    api_port = args.api_port
    if api_port is None:
        api_port = DEFAULT_API_PORT

    return host, traffic_port, api_port


def check_remote_connectivity(host: str, traffic_port: int, api_port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Performs comprehensive pre-flight network diagnostics against the Monitoring Computer.
    Tests TCP reachability on both the API port and traffic sink port
    with actionable error diagnoses for refused connections, timeouts, and unreachable hosts.
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

    # 1. Test Host Resolution & Basic IP Format
    try:
        resolved_ip = socket.gethostbyname(host)
        results["resolved_ip"] = resolved_ip
        results["host_resolvable"] = True
    except socket.gaierror as ge:
        results["error_reason"] = f"Host resolution failed for '{host}': {ge}"
        results["remediation"] = (
            f"Could not resolve host '{host}'. Verify the IP address is correct.\n"
            f"When connecting over an Ethernet cable, use the Monitoring Computer's Ethernet IPv4 address (e.g. 192.168.1.X)."
        )
        return results

    # 2. Test API Port Reachability (e.g. Port 5000)
    api_probe = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, api_port))
            if res == 0:
                api_probe = True
    except Exception:
        api_probe = False

    results["api_port_open"] = api_probe

    # If API port is open, query /api/health for deep diagnosis
    if api_probe:
        try:
            req = urllib.request.Request(
                f"http://{host}:{api_port}/api/health",
                headers={"User-Agent": "SocNet-TrafficSender/2.4"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    health_data = json.loads(resp.read().decode('utf-8'))
                    results["api_online"] = True
                    results["api_health"] = health_data
        except Exception:
            # Fallback to home page probe
            try:
                req = urllib.request.Request(f"http://{host}:{api_port}/")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        results["api_online"] = True
            except Exception:
                pass

    # 3. Test Traffic Port Reachability (e.g. Port 8080)
    traffic_probe = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, traffic_port))
            if res == 0:
                traffic_probe = True
            else:
                results["traffic_errno"] = res
    except socket.timeout:
        results["traffic_errno"] = 10060
    except Exception as ex:
        results["traffic_errno"] = getattr(ex, "errno", -1)

    results["traffic_port_open"] = traffic_probe

    # 4. Formulate Actionable Diagnostics
    if not results["api_port_open"] and not results["traffic_port_open"]:
        if host == "127.0.0.1":
            results["error_reason"] = (
                f"Connection refused on 127.0.0.1:{traffic_port} and 127.0.0.1:{api_port}. "
                f"You are currently targeting localhost on the Sender Computer."
            )
            results["remediation"] = (
                "When running send_traffic.py on a separate Sender Computer, you MUST specify the Monitoring "
                "Computer's Ethernet IPv4 address (not 127.0.0.1).\n"
                "Example: python scripts/send_traffic.py --host 192.168.1.11 --port 8080\n"
                "Or set DEFAULT_MONITORING_HOST at the top of scripts/send_traffic.py."
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


def run_benign_traffic_generator(
    host: str,
    port: int,
    protocol: str = 'http',
    interval: float = 0.5,
    count: Optional[int] = 20,
    timeout: float = 2.0
):
    """
    Transmits real, bounded, benign network traffic across the Ethernet cable to the Monitoring Computer.
    Uses ordinary HTTP requests (or raw TCP/UDP probes) to trigger real packet capture and 77-feature extraction.
    """
    is_continuous = (count is None or count <= 0)
    limit_str = "Continuous (Press Ctrl+C to stop)" if is_continuous else f"{count} packets"

    print("\n" + "=" * 70)
    print("      SOCNET: CROSS-DEVICE BENIGN TRAFFIC GENERATOR (ETHERNET)")
    print("=" * 70)
    print(f"  Target Host         : {host}")
    print(f"  Target Port         : {port}")
    print(f"  Application Protocol: {protocol.upper()}")
    print(f"  Transmission Rate   : 1 frame every {interval}s")
    print(f"  Transmission Limit  : {limit_str}")
    print(f"  Socket Timeout      : {timeout}s")
    print("=" * 70)
    print(f"Emitting genuine benign {protocol.upper()} network frames across the wire to {host}:{port}...\n")

    sent = 0
    successful = 0
    failed = 0
    latencies = []
    start_time = time.time()

    try:
        while True:
            t_str = time.strftime('%H:%M:%S')
            success = False
            status_desc = ""
            frame_start = time.time()

            if protocol.lower() == 'http':
                # Ordinary Benign HTTP GET request
                target_url = f"http://{host}:{port}/test?frame={sent + 1}&t={int(time.time() * 1000)}"
                req = urllib.request.Request(
                    target_url,
                    headers={
                        "User-Agent": "SocNet-BenignTrafficProbe/2.4 (CrossDevice-Ethernet-Test)",
                        "Accept": "application/json, text/plain, */*",
                        "Connection": "close"
                    }
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        duration_ms = (time.time() - frame_start) * 1000
                        latencies.append(duration_ms)
                        status_desc = f"HTTP {resp.status} OK ({duration_ms:.1f}ms)"
                        success = True
                except urllib.error.HTTPError as he:
                    duration_ms = (time.time() - frame_start) * 1000
                    status_desc = f"HTTP {he.code} ({duration_ms:.1f}ms)"
                    success = True  # Layer-4 and Layer-7 packets reached and exchanged
                except urllib.error.URLError as ue:
                    status_desc = f"Connection Error: {ue.reason}"
                except Exception as ex:
                    status_desc = f"Error: {ex}"

            elif protocol.lower() == 'tcp':
                # Layer 4 TCP SYN Handshake probe
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        res = s.connect_ex((host, port))
                        duration_ms = (time.time() - frame_start) * 1000
                        if res == 0:
                            s.sendall(b"SOCNET_BENIGN_PROBE_TCP\r\n")
                            latencies.append(duration_ms)
                            status_desc = f"TCP Handshake OK ({duration_ms:.1f}ms)"
                            success = True
                        else:
                            status_desc = f"TCP Refused (Errno {res})"
                except Exception as ex:
                    status_desc = f"TCP Error: {ex}"

            else:  # UDP
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(timeout)
                        payload = f"SOCNET_BENIGN_UDP_PROBE_{sent + 1}_{time.time()}".encode('utf-8')
                        s.sendto(payload, (host, port))
                        duration_ms = (time.time() - frame_start) * 1000
                        latencies.append(duration_ms)
                        status_desc = f"UDP Datagram Transmitted ({len(payload)} bytes)"
                        success = True
                except Exception as ex:
                    status_desc = f"UDP Error: {ex}"

            sent += 1
            if success:
                successful += 1
                print(f"[{t_str}] Frame #{sent:>3} transmitted on wire → {host}:{port} [{status_desc}]")
            else:
                failed += 1
                print(f"[{t_str}] Frame #{sent:>3} transmission failed   → {host}:{port} [{status_desc}]")

            if not is_continuous and sent >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[STOP] Traffic generation stopped cleanly by user.")

    total_duration = round(time.time() - start_time, 2)
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

    print("\n" + "=" * 70)
    print("                 TRAFFIC GENERATION SUMMARY")
    print("=" * 70)
    print(f"  Target Destination : {host}:{port} ({protocol.upper()})")
    print(f"  Frames Transmitted : {sent}")
    print(f"  Successful Probes  : {successful}")
    print(f"  Failed Probes      : {failed}")
    print(f"  Success Rate       : {round((successful / sent) * 100, 1) if sent > 0 else 0.0}%")
    if latencies:
        print(f"  Average Latency    : {avg_latency} ms (Min: {round(min(latencies), 1)}ms, Max: {round(max(latencies), 1)}ms)")
    print(f"  Total Duration     : {total_duration}s")
    print("=" * 70)
    if successful > 0:
        print("✅ Real packets successfully transmitted across the wire.")
        print("   Verify the packet counter on the Monitoring Computer dashboard increments.\n")
    else:
        print("⚠️ No packets successfully reached the destination.")
        print("   Review the pre-flight connectivity check diagnostics above.\n")


def resolve_dataset_path(custom_path: Optional[str] = None) -> Path:
    """
    Locates the dataset JSON file in order of preference:
    1. Explicit custom path passed via --dataset
    2. features_by_label_test.json in workspace or scripts/ directory
    3. features_by_label.json in workspace or scripts/ directory
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Specified dataset file '{custom_path}' does not exist.")

    candidates = [
        BASE_DIR / "features_by_label_test.json",
        BASE_DIR / "scripts" / "features_by_label_test.json",
        BASE_DIR / "features_by_label.json",
        BASE_DIR / "scripts" / "features_by_label.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return BASE_DIR / "features_by_label.json"


def load_dataset_records(dataset_path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Tuple[str, int]]]:
    """
    Dynamically loads and groups records by Label from the given JSON dataset.
    Discovers all unique labels present and counts available records per label.
    Returns:
        (records_by_label_dict, sorted_label_counts_list)
    """
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
        # Already grouped by label dictionary
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

    # Sort labels: "Benign" first if present, then by count descending
    counts = [(lbl, len(rec_list)) for lbl, rec_list in records_by_label.items()]
    counts.sort(key=lambda x: (x[0].lower() != "benign", -x[1], x[0]))
    return records_by_label, counts


def select_dataset_label_interactively(sorted_label_counts: List[Tuple[str, int]]) -> Optional[str]:
    """
    Displays an interactive terminal menu listing available labels and prompts the user
    to select a label by number or name.
    """
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

        # 1. Try numeric selection
        try:
            num = int(choice)
            if 1 <= num <= len(sorted_label_counts):
                return sorted_label_counts[num - 1][0]
            else:
                print(f"Invalid selection: '{choice}'. Enter a number between 1 and {len(sorted_label_counts)}.")
                continue
        except ValueError:
            pass

        # 2. Try exact/normalized string match
        choice_clean = choice.lower().replace("-", " ").replace("_", " ").strip()
        matches = [lbl for lbl, _ in sorted_label_counts if lbl.lower().replace("-", " ").replace("_", " ").strip() == choice_clean]
        if len(matches) == 1:
            return matches[0]

        # 3. Try unique partial match
        partials = [lbl for lbl, _ in sorted_label_counts if choice_clean in lbl.lower().replace("-", " ").replace("_", " ")]
        if len(partials) == 1:
            return partials[0]

        print(f"Invalid label: '{choice}'. Please pick a valid number (1-{len(sorted_label_counts)}) or label name from above.")


def resolve_label_argument(label_arg: str, sorted_label_counts: List[Tuple[str, int]]) -> Optional[str]:
    """
    Resolves CLI --label or --attack argument to an exact label name in the dataset.
    """
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


def confirm_attack_transmission(label: str, target_url: str, record_count: int) -> bool:
    """
    Requires explicit user confirmation before attempting to transmit attack-labelled data.
    Keeps traffic generation bounded and safe.
    """
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
    timeout: float = 3.0
):
    """
    Streams pre-extracted flow feature JSON records directly to /api/receive-packet on the Monitoring Computer.
    Reports telemetry, latency, and transmission results transparently.
    """
    import random
    import urllib.request
    import urllib.error

    endpoint = f"{target_api_url.rstrip('/')}/api/receive-packet"
    total_available = len(records)
    limit_desc = f"{count} records" if (count and not continuous) else "Continuous (Ctrl+C to stop)"

    print("\n" + "=" * 75)
    print("           SOCNET: DATASET FEATURE STREAMING WORKFLOW")
    print("=" * 75)
    print(f"  Target Destination   : {endpoint}")
    print(f"  Selected Label       : {label} ({total_available} records available)")
    print(f"  Payload Architecture : Pre-extracted 77-feature flow JSON via HTTP POST")
    print(f"                         (API inference evaluation, NOT raw wire L2/L3 packets)")
    print(f"  Transmission Limit   : {limit_desc}")
    print(f"  Transmission Interval: {interval}s ({round(1.0/interval, 1) if interval > 0 else 'max'} rec/s)")
    print("=" * 75)
    print(f"Streaming '{label}' flow records to {endpoint}...\n")

    sent = 0
    successful = 0
    failed = 0
    latencies = []
    start_time = time.time()

    try:
        while True:
            pkt = random.choice(records)
            payload = {k: v for k, v in pkt.items() if k != "Label"}
            t_str = time.strftime('%H:%M:%S')
            frame_start = time.time()

            req_bytes = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                endpoint,
                data=req_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SocNet-DatasetStreamer/2.5"
                },
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    dur_ms = (time.time() - frame_start) * 1000
                    latencies.append(dur_ms)
                    _ = resp.read()
                    status_desc = f"HTTP {resp.status} OK ({dur_ms:.1f}ms)"
                    sent += 1
                    successful += 1
                    print(f"[{t_str}] Record #{sent:>3} streamed → {label} [{status_desc}]")
            except urllib.error.HTTPError as he:
                dur_ms = (time.time() - frame_start) * 1000
                sent += 1
                failed += 1
                print(f"[{t_str}] Record #{sent:>3} failed   → HTTP {he.code}: {he.reason} ({dur_ms:.1f}ms)")
            except Exception as ex:
                dur_ms = (time.time() - frame_start) * 1000
                sent += 1
                failed += 1
                print(f"[{t_str}] Record #{sent:>3} failed   → Error: {ex}")

            if count and sent >= count and not continuous:
                break
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[STOP] Streaming stopped cleanly by user.")

    elapsed = round(time.time() - start_time, 2)
    avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

    print("\n" + "=" * 75)
    print("                   STREAMING SUMMARY")
    print("=" * 75)
    print(f"  Target Destination : {endpoint}")
    print(f"  Streamed Label     : {label}")
    print(f"  Total Streamed     : {sent}")
    print(f"  Successful Posts   : {successful}")
    print(f"  Failed Posts       : {failed}")
    print(f"  Success Rate       : {round((successful / sent) * 100, 1) if sent > 0 else 0.0}%")
    if latencies:
        print(f"  Average Latency    : {avg_lat} ms (Min: {round(min(latencies), 1)}ms, Max: {round(max(latencies), 1)}ms)")
    print(f"  Total Duration     : {elapsed}s")
    print("=" * 75)
    if successful > 0:
        print(f"✅ Successfully streamed {successful} '{label}' records.")
        print("   Verify the prediction and confidence updates on the Monitoring Computer dashboard.\n")
    else:
        print("⚠️ No records were successfully received by the Monitoring API.")
        print(f"   Confirm that api.py is running on {target_api_url}.\n")


def main():
    args = parse_args()
    host, traffic_port, api_port = resolve_target_config(args)
    target_api_url = f"http://{host}:{api_port}"

    # 1. Dataset Resolution & Discovery
    dataset_file = None
    records_by_label = {}
    sorted_label_counts = []
    dataset_error = None

    try:
        dataset_file = resolve_dataset_path(args.dataset)
        records_by_label, sorted_label_counts = load_dataset_records(dataset_file)
    except Exception as ex:
        dataset_error = str(ex)

    # 2. List Labels mode
    if args.list or args.list_labels:
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

    # 3. Early CLI Label Validation
    selected_label = None
    label_input = args.label or args.attack
    if label_input:
        if dataset_error:
            print(f"\n❌ DATASET FILE ERROR: {dataset_error}\n")
            sys.exit(1)
        selected_label = resolve_label_argument(label_input, sorted_label_counts)
        if not selected_label:
            print("\n" + "!" * 75)
            print(f"❌ INVALID LABEL ARGUMENT: '{label_input}' was not found in dataset {dataset_file.name}.")
            print("!" * 75)
            print("Available labels:")
            for idx, (lbl, cnt) in enumerate(sorted_label_counts, start=1):
                print(f"  {idx:>2}. {lbl:<25} ({cnt} records)")
            print("\nSpecify a valid label name or numeric index (1-15).")
            sys.exit(1)

    # 4. Pre-flight Connectivity & Health Verification
    print("=" * 75)
    print("        SOCNET SENDER: TARGET & CONNECTIVITY INITIALIZATION")
    print("=" * 75)
    print(f"  Configured Target IP : {host}")
    print(f"  Benign Traffic Port  : {traffic_port}")
    print(f"  Monitoring API Port  : {api_port} ({target_api_url})")
    print("=" * 75)
    print(f"\n[PRE-FLIGHT] Testing network connectivity to Monitoring Computer ({host})...")
    conn = check_remote_connectivity(host, traffic_port=traffic_port, api_port=api_port, timeout=args.timeout)

    print(f"  • Target IPv4 Address   : {host} (Resolved: {conn.get('resolved_ip', 'Failed')})")
    print(f"  • Monitoring API Probe  : Port {api_port} -> {'REACHABLE [OK]' if conn['api_port_open'] else 'NOT RESPONDING'}")
    if conn.get("api_health"):
        h = conn["api_health"]
        primary_ad = h.get("primary_adapter", {})
        print(f"    - Remote Adapter Name : {primary_ad.get('name')} ({primary_ad.get('type')})")
        print(f"    - Remote IP Reported  : {primary_ad.get('ip')}")
        print(f"    - Capture Driver Ready: {h.get('can_capture_live')}")
        print(f"    - Active Monitoring   : {h.get('monitoring')}")
    traffic_status = 'OPEN [OK]' if conn['traffic_port_open'] else f"FAILED (Errno {conn.get('traffic_errno', 'N/A')})"
    print(f"  • Benign Test Port Probe: Port {traffic_port} -> {traffic_status}")

    # Strict Validation: If connectivity check failed, output actionable guidance and abort
    # NEVER silently fall back to 127.0.0.1 when a remote target is configured!
    if conn.get("error_reason"):
        print("\n" + "!" * 75)
        print(f"❌ CONNECTIVITY ERROR TO TARGET {host}:")
        print(f"   {conn['error_reason']}")
        print("!" * 75)
        if conn.get("remediation"):
            print(f"\nActionable Remediation:\n{conn['remediation']}")
        print("!" * 75 + "\n")
        print(f"CRITICAL: Traffic transmission aborted. The sender will NOT fall back to 127.0.0.1.")
        print(f"Verify the Monitoring Computer ({host}) is reachable and api.py is running.")
        sys.exit(1)

    if args.check_only:
        print("\n✅ Pre-flight connectivity check passed successfully.")
        sys.exit(0)

    # 5. Mode Determination: Explicit Wire Probing (--probe) vs. Dynamic Dataset Label Streaming
    if args.probe:
        print("\n[MODE: REAL WIRE PACKET PROBING]")
        print("Transmitting genuine Layer-4/Layer-7 network packets across the wire to benign sink port.\n")
        effective_count = None if args.continuous else args.count
        run_benign_traffic_generator(
            host=host,
            port=traffic_port,
            protocol=args.protocol,
            interval=args.interval,
            count=effective_count,
            timeout=args.timeout
        )
        return

    # 6. Dynamic Dataset Label Selection Workflow
    if dataset_error:
        print("\n" + "!" * 75)
        print(f"❌ DATASET FILE ERROR: {dataset_error}")
        print("!" * 75)
        print("Please verify 'features_by_label_test.json' or 'features_by_label.json' exists in the project root.")
        sys.exit(1)

    # If label was not passed on CLI, display Interactive Terminal Menu
    if not selected_label:
        selected_label = select_dataset_label_interactively(sorted_label_counts)
        if not selected_label:
            # User cancelled or exited
            sys.exit(0)

    records_to_send = records_by_label.get(selected_label, [])
    if not records_to_send:
        print(f"\n❌ Error: Selected label '{selected_label}' has zero available records.")
        sys.exit(1)

    effective_count = None if args.continuous else args.count
    count_desc = f"{effective_count} records" if effective_count else "Continuous"

    # 7. Safety Confirmation Gate for Attack Data
    confirmed = confirm_attack_transmission(selected_label, target_api_url, len(records_to_send))
    if not confirmed:
        sys.exit(0)

    # 8. Stream Records to Monitoring API
    run_dataset_feature_stream(
        records=records_to_send,
        label=selected_label,
        target_api_url=target_api_url,
        interval=args.interval,
        count=effective_count,
        continuous=args.continuous,
        timeout=args.timeout
    )


if __name__ == '__main__':
    main()
