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
from typing import Optional, Tuple, Dict, Any

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


def parse_args():
    p = argparse.ArgumentParser(
        description="SocNet / DDoS-Guard: Cross-Device Benign Network Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send 20 benign HTTP test packets across Ethernet to Monitoring Computer:
  python scripts/send_traffic.py --host 192.168.1.11 --port 8080 --count 20

  # Send continuous benign HTTP traffic at 0.5s interval until Ctrl+C:
  python scripts/send_traffic.py --host 192.168.1.11 --port 8080 --continuous

  # Check connectivity to Monitoring Computer API and test port without transmitting:
  python scripts/send_traffic.py --host 192.168.1.11 --check-only

  # Send TCP SYN frames to verify layer-4 capture:
  python scripts/send_traffic.py --host 192.168.1.11 --port 8080 --protocol tcp --count 30
        """
    )
    # Destination Options
    p.add_argument(
        '--host', '-H', type=str, default=None,
        help="Target Monitoring Computer Ethernet IPv4 address (e.g. 192.168.1.11, env: SOCNET_HOST)"
    )
    p.add_argument(
        '--target', '-t', type=str, default=None,
        help="Target server URL or host (e.g. http://192.168.1.11:8080, env: SOCNET_TARGET)"
    )
    p.add_argument(
        '--port', '-p', type=int, default=None,
        help="Target port for real benign traffic on Monitoring Computer (default: 8080, env: SOCNET_TRAFFIC_PORT)"
    )
    p.add_argument(
        '--api-port', type=int, default=None,
        help="Target Flask API port on Monitoring Computer for health check (default: 5000, env: SOCNET_PORT)"
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

    # Backward Compatibility Options
    p.add_argument('--probe', action='store_true', help="Alias for real packet probing mode (active by default)")
    p.add_argument('--simulate-dataset', action='store_true', help="Legacy Track 1: Stream pre-extracted flow JSON to /api/receive-packet")
    p.add_argument('--attack', '-a', type=str, help="Legacy: Attack label name or index for dataset simulation")
    p.add_argument('--list', action='store_true', help="Legacy: List available attack labels in dataset then exit")

    return p.parse_args()


def resolve_target_config(args) -> Tuple[str, int, int]:
    """
    Resolves target host, traffic port, and API port using CLI flags, environment variables,
    and sensible defaults without hardcoded IP addresses.
    """
    host = args.host

    # Priority 2: Extract from --target URL if passed
    if not host and args.target:
        if "://" in args.target:
            parsed = urlparse(args.target)
            host = parsed.hostname
        else:
            host = args.target.split(":")[0]

    # Priority 3: Environment variables
    if not host:
        host = os.environ.get("SOCNET_HOST") or os.environ.get("SOCNET_TARGET") or os.environ.get("MONITORING_HOST")

    # Priority 4: Default localhost (with explicit remote warning)
    if not host:
        host = "127.0.0.1"

    # Traffic port resolution
    traffic_port = args.port
    if traffic_port is None:
        env_traffic_port = os.environ.get("SOCNET_TRAFFIC_PORT")
        if env_traffic_port:
            try:
                traffic_port = int(env_traffic_port)
            except ValueError:
                pass
    if traffic_port is None and args.target and ":" in args.target:
        try:
            traffic_port = int(urlparse(args.target).port or args.target.split(":")[-1].split("/")[0])
        except (ValueError, TypeError):
            pass
    if traffic_port is None:
        traffic_port = 8080

    # API port resolution
    api_port = args.api_port
    if api_port is None:
        env_api_port = os.environ.get("SOCNET_PORT")
        if env_api_port:
            try:
                api_port = int(env_api_port)
            except ValueError:
                pass
    if api_port is None:
        api_port = 5000

    return host, traffic_port, api_port


def check_remote_connectivity(host: str, traffic_port: int, api_port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Performs comprehensive pre-flight network diagnostics against the Monitoring Computer.
    Tests TCP reachability on both the API port (5000) and traffic sink port (8080)
    with actionable error diagnoses for refused connections, timeouts, and unreachable hosts.
    """
    results: Dict[str, Any] = {
        "host": host,
        "traffic_port": traffic_port,
        "api_port": api_port,
        "host_resolvable": False,
        "api_online": False,
        "traffic_port_open": False,
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
            f"Could not resolve host '{host}'. Verify the IP address is correct. "
            f"If connecting over an Ethernet cable, use the Monitoring Computer's Ethernet IPv4 address (e.g. 192.168.1.X)."
        )
        return results

    # 2. Test API Port Reachability (Port 5000)
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
                "Example: python scripts/send_traffic.py --host 192.168.1.11 --port 8080"
            )
        else:
            results["error_reason"] = f"Unable to establish TCP connection to {host} on ports {api_port} or {traffic_port}."
            results["remediation"] = (
                f"Troubleshooting checklist for connecting to {host}:\n"
                f" 1. Physical Layer : Ensure the Ethernet cable is securely connected to both computers and link LEDs are active.\n"
                f" 2. Subnet Config  : Confirm both computers share the same IPv4 subnet (e.g. Sender: 192.168.1.X, Monitor: 192.168.1.Y).\n"
                f" 3. Service Status : On the Monitoring Computer, ensure 'python api.py' is running.\n"
                f" 4. Firewall Rule  : On the Monitoring Computer, configure Windows Firewall to permit inbound TCP on ports {api_port} and {traffic_port}.\n"
                f"    Run as Administrator on Monitor: 'powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 Configure-Firewall'"
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


def run_legacy_dataset_simulation(args, target_url: str):
    """
    Legacy Track 1: Streams pre-extracted flow feature JSON from features_by_label.json
    directly to /api/receive-packet for backward compatibility and offline validation.
    """
    import random
    import requests

    print(f"\n[LEGACY SIMULATION] Loading feature dataset from {TEST_SET_PATH}...")
    if not Path(TEST_SET_PATH).exists():
        print(f"Error: Dataset file {TEST_SET_PATH} not found.")
        sys.exit(1)

    with open(TEST_SET_PATH, 'r', encoding='utf-8') as f:
        dataset = json.load(f).get("all_data", [])

    labels = {}
    for p in dataset:
        lbl = p.get("Label", "Unknown")
        labels[lbl] = labels.get(lbl, 0) + 1

    sorted_labels = sorted(labels.items(), key=lambda x: x[1], reverse=True)

    print("=" * 65)
    print("           AVAILABLE ATTACK TYPES")
    print("=" * 65)
    for i, (label, count) in enumerate(sorted_labels, 1):
        print(f"  {i}. {label:<22} → {count:>5} samples")
    print("=" * 65)

    if args.list:
        sys.exit(0)

    selected = None
    if args.attack:
        try:
            choice_num = int(args.attack)
            if 1 <= choice_num <= len(sorted_labels):
                selected = sorted_labels[choice_num - 1][0]
        except ValueError:
            for lbl, _ in sorted_labels:
                if lbl.lower() == args.attack.lower():
                    selected = lbl
                    break

    while selected is None:
        choice_raw = input(f"\nSelect attack by number or name (1-{len(sorted_labels)}): ").strip()
        if not choice_raw:
            continue
        try:
            choice = int(choice_raw)
            if 1 <= choice <= len(sorted_labels):
                selected = sorted_labels[choice - 1][0]
                break
        except ValueError:
            matches = [lbl for lbl, _cnt in sorted_labels if lbl.lower() == choice_raw.lower()]
            if len(matches) == 1:
                selected = matches[0]
                break

    packets = [{k: v for k, v in p.items() if k != "Label"} for p in dataset if p.get("Label") == selected]
    if not packets:
        print(f"No packets found for label '{selected}'.")
        sys.exit(1)

    api_endpoint = f"{target_url.rstrip('/')}/api/receive-packet"
    print(f"\nStreaming {selected} feature records to {api_endpoint} (interval={args.interval}s)...")
    sent = 0
    try:
        while True:
            pkt = random.choice(packets)
            try:
                requests.post(api_endpoint, json=pkt, timeout=3.0)
                print(f"[{time.strftime('%H:%M:%S')}] Streamed Record #{sent + 1} → {selected}")
            except Exception as ex:
                print(f"[{time.strftime('%H:%M:%S')}] Record #{sent + 1} failed: {ex}")
            sent += 1
            if args.count and sent >= args.count and not args.continuous:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nSimulation stopped. Total records streamed: {sent}.")


def main():
    args = parse_args()
    host, traffic_port, api_port = resolve_target_config(args)

    # Legacy Track 1 explicit invocation
    if args.simulate_dataset or args.attack or args.list:
        target_server = args.target or f"http://{host}:{api_port}"
        run_legacy_dataset_simulation(args, target_server)
        return

    # Pre-flight Connectivity & Health Verification
    print(f"\n[PRE-FLIGHT] Testing network connectivity to Monitoring Computer ({host})...")
    conn = check_remote_connectivity(host, traffic_port=traffic_port, api_port=api_port, timeout=args.timeout)

    if conn["host_resolvable"]:
        print(f"  • Host IP Resolution     : {conn['resolved_ip']} [OK]")
    else:
        print(f"  • Host IP Resolution     : Failed ({host})")

    if conn["api_port_open"]:
        print(f"  • Monitoring API (Port {api_port}) : Reachable [OK]")
        if conn.get("api_health"):
            h = conn["api_health"]
            primary_ad = h.get("primary_adapter", {})
            print(f"    - Monitoring Interface : {primary_ad.get('name')} ({primary_ad.get('type')}) - IP: {primary_ad.get('ip')}")
            print(f"    - Capture Driver Ready : {h.get('can_capture_live')}")
            print(f"    - Active Monitoring    : {h.get('monitoring')}")
    else:
        print(f"  • Monitoring API (Port {api_port}) : Not Responding")

    if conn["traffic_port_open"]:
        print(f"  • Benign Test Port ({traffic_port}) : Open & Acknowledging [OK]")
    else:
        print(f"  • Benign Test Port ({traffic_port}) : Not Responding (Errno {conn.get('traffic_errno', 'N/A')})")

    # If connectivity check failed completely, output actionable guidance
    if conn.get("error_reason"):
        print("\n" + "!" * 70)
        print(f"❌ CONNECTIVITY ERROR: {conn['error_reason']}")
        print("!" * 70)
        if conn.get("remediation"):
            print(f"\nActionable Remediation:\n{conn['remediation']}")
        print("!" * 70 + "\n")
        if args.check_only:
            sys.exit(1)
        # Ask or confirm before attempting transmission
        if not conn["traffic_port_open"] and not conn["api_port_open"]:
            print("Cannot transmit traffic: Host is unreachable or target ports are closed.")
            sys.exit(1)

    if args.check_only:
        print("\n✅ Pre-flight connectivity check passed successfully.")
        sys.exit(0)

    # Primary Workflow: Real Benign Network Traffic Generation
    effective_count = None if args.continuous else args.count
    run_benign_traffic_generator(
        host=host,
        port=traffic_port,
        protocol=args.protocol,
        interval=args.interval,
        count=effective_count,
        timeout=args.timeout
    )


if __name__ == '__main__':
    main()