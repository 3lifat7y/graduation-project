#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT: Dedicated Live Network Traffic Generator
===============================================
Generates genuine Layer-4 (TCP/UDP) and Layer-7 (HTTP) network packets across an
authorized local network (e.g., Ethernet link) from the Sender Computer to the
Receiver (Monitoring) Computer.

Designed specifically to test the Receiver's live packet capture engine (Npcap/Scapy)
and real-time monitoring dashboard by generating actual wire traffic.

Key Principles:
- Generates genuine, wire-level network packets (HTTP requests, UDP datagrams, TCP probes).
- Transmits across the physical network interface to the Receiver's actual LAN IP address.
- Rejects 127.0.0.1 / loopback by default to prevent accidental local-only testing.
- Does NOT send pre-extracted 77-feature JSON vectors to the API.
- Does NOT use /api/replay-feature as a substitute for real network packets.
- Provides strict bounds, rate limiting, and safe shutdown controls.
"""

import os
import sys
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

# ==================== DEFAULT CONFIGURATION ====================

TARGET_HOST = "192.168.1.12"
TARGET_PORT = 8080                          # Benign traffic sink port on Receiver
TRAFFIC_PROTOCOL = "http"                   # http, tcp, or udp
DEFAULT_PACKET_COUNT = 100                  # Default bounded packet count
DEFAULT_INTERVAL_SECONDS = 0.2              # 5 packets per second
DEFAULT_PAYLOAD_SIZE_BYTES = 256            # Size of packet body
CONNECT_TIMEOUT_SECONDS = 3.0
CONNECTIVITY_CHECK_INTERVAL_SECONDS = 5.0
ALLOW_LOOPBACK_DEFAULT = False

# ===============================================================


def validate_destination_host(
    host: str,
    allow_loopback: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """
    Validates host format, resolves DNS, and enforces non-loopback policy for cross-device testing.
    Returns: (is_valid, resolved_ip, error_message)
    """
    clean_host = str(host).strip()
    if not clean_host:
        return False, "", "Destination host address cannot be empty."

    resolved_ip = ""
    # Try parsing as IP literal
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        resolved_ip = str(ip_obj)
        is_loopback = ip_obj.is_loopback
    except ValueError:
        # Try DNS hostname resolution
        try:
            resolved_ip = socket.gethostbyname(clean_host)
            is_loopback = ipaddress.ip_address(resolved_ip).is_loopback
        except socket.gaierror as ge:
            return False, "", f"Unable to resolve host '{clean_host}': {ge}"
        except Exception as ex:
            return False, "", f"Invalid host '{clean_host}': {ex}"

    if is_loopback and not allow_loopback:
        return False, resolved_ip, (
            f"Target address '{clean_host}' resolves to loopback ({resolved_ip}).\n"
            f"   For cross-device testing, you MUST specify the Receiver Computer's actual LAN/Ethernet IPv4\n"
            f"   address (e.g., 192.168.1.X) so packets traverse the physical network interface.\n"
            f"   (If conducting single-machine development testing, pass --allow-loopback to override)."
        )

    return True, resolved_ip, None


def check_destination_service(
    host: str,
    port: int,
    protocol: str = "http",
    timeout: float = 3.0
) -> Tuple[bool, Optional[str]]:
    """
    Preflight check to verify that the target destination host and port are reachable.
    - For TCP/HTTP: checks TCP handshake connection to destination port.
    - For UDP: checks routing and socket assignment with clear connectionless semantics.
    """
    proto_lower = protocol.lower()

    if proto_lower == "udp":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
            return True, None
        except Exception as ex:
            return False, f"UDP destination route to {host}:{port} failed: {ex}"

    # TCP / HTTP check
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            if res != 0:
                return False, f"Connection refused on {host}:{port} (errno {res}). Ensure api.py or traffic service is running on the Receiver."
    except socket.timeout:
        return False, f"Connection timed out after {timeout:.1f}s connecting to {host}:{port}."
    except Exception as ex:
        return False, f"Network error connecting to {host}:{port}: {ex}"

    return True, None


def run_live_traffic_generator(
    host: str,
    port: int = 8080,
    protocol: str = 'http',
    interval: float = 0.2,
    count: Optional[int] = 100,
    timeout: float = 3.0,
    payload_size: int = 256,
    check_interval: float = 5.0,
    max_duration: Optional[float] = None
) -> Dict[str, Any]:
    """
    Transmits genuine, bounded Layer-4/Layer-7 network traffic to the target host and port.
    Packets traverse the network interface, where the Receiver's capture engine (Npcap/Scapy)
    intercepts them, extracts 77 flow features, and feeds them into the live monitoring pipeline.
    """
    is_continuous = (count is None or count <= 0)
    count_desc = "Continuous (Ctrl+C to stop)" if is_continuous else f"{count} packets"

    print("\n" + "=" * 78)
    print("      SCOUT: DEDICATED LIVE NETWORK TRAFFIC GENERATOR (WIRE FRAMES)")
    print("=" * 78)
    print(f"  Target Destination    : {host}:{port}")
    print(f"  Transport Protocol    : {protocol.upper()}")
    print(f"  Payload Size          : {payload_size} bytes")
    print(f"  Transmission Count    : {count_desc}")
    print(f"  Transmission Interval : {interval}s ({round(1.0 / max(0.001, interval), 1)} pkts/sec)")
    print(f"  Connect Timeout       : {timeout}s")
    if max_duration:
        print(f"  Max Duration Limit    : {max_duration}s")
    if is_continuous:
        print(f"  Periodic Health Check : Every {check_interval}s")
    print("=" * 78)
    if protocol.lower() == "udp":
        print("  NOTICE: UDP is a connectionless transport protocol. Datagrams are emitted")
        print("          onto the wire; transmission success indicates local dispatch.")
        print("=" * 78)
    print(f"Transmitting genuine {protocol.upper()} network frames across the wire to {host}:{port}...\n")

    sent = 0
    successful = 0
    failed = 0
    latencies: List[float] = []
    start_time = time.time()
    last_check_time = time.time()

    try:
        while True:
            now = time.time()

            # Duration check
            if max_duration and (now - start_time) >= max_duration:
                print(f"\n[STOP] Maximum test duration limit ({max_duration}s) reached.")
                break

            # Periodic reachability check during continuous transmission
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

            # 1. HTTP Mode (Layer 7)
            if protocol.lower() == 'http':
                target_url = f"http://{host}:{port}/test?frame={sent + 1}&t={int(time.time() * 1000)}"
                body_bytes = b"X" * max(0, payload_size)
                req = urllib.request.Request(
                    target_url,
                    data=body_bytes,
                    headers={
                        "User-Agent": "SCOUT-LiveTrafficGenerator/3.0 (CrossDevice-Ethernet-Test)",
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
                    success = True  # Packet reached target HTTP service and was answered
                except urllib.error.URLError as ue:
                    status_desc = f"Connection Error: {ue.reason}"
                except Exception as ex:
                    status_desc = f"Error: {ex}"

            # 2. TCP Mode (Layer 4)
            elif protocol.lower() == 'tcp':
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        res = s.connect_ex((host, port))
                        duration_ms = (time.time() - frame_start) * 1000
                        if res == 0:
                            payload = f"SCOUT_PROBE_{sent + 1}_".encode('utf-8')
                            payload = payload.ljust(payload_size, b'#')[:payload_size]
                            s.sendall(payload)
                            latencies.append(duration_ms)
                            status_desc = f"TCP Handshake OK ({len(payload)}B)"
                            success = True
                        else:
                            status_desc = f"TCP Refused (Errno {res})"
                except Exception as ex:
                    status_desc = f"TCP Error: {ex}"

            # 3. UDP Mode (Layer 4)
            else:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(timeout)
                        payload = f"SCOUT_UDP_PROBE_{sent + 1}_{time.time()}".encode('utf-8')
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
                    print(f"[LIVE] {progress_str:>10} | Protocol=UDP  | Result=transmitted (unconfirmed delivery) | Size={payload_size}B")
                else:
                    failed += 1
                    print(f"[LIVE] {progress_str:>10} | Protocol=UDP  | Result=failed | Error={status_desc}")
            else:
                if success:
                    successful += 1
                    print(f"[LIVE] {progress_str:>10} | Protocol={protocol.upper():<4} | Result=success | Latency={duration_ms:.1f}ms [{status_desc}]")
                else:
                    failed += 1
                    print(f"[LIVE] {progress_str:>10} | Protocol={protocol.upper():<4} | Result=failed  | Error={status_desc}")

            if not is_continuous and count is not None and sent >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[STOP] Traffic generation stopped cleanly by user (Ctrl+C).")

    total_duration = max(0.001, round(time.time() - start_time, 2))
    achieved_rate = round(sent / total_duration, 2)
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

    print("\n" + "=" * 78)
    print("                 LIVE TRAFFIC GENERATION SUMMARY")
    print("=" * 78)
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
        print("  Delivery Notice    : UDP datagrams were dispatched onto the network interface.")
        print("                       Remote arrival cannot be confirmed without an application-layer reply.")
    print("=" * 78)
    if successful > 0:
        print("✅ Real network traffic frames were successfully transmitted across the wire.")
        print("   Verify on the Receiver Machine:")
        print("   1. In Web UI (http://<Receiver-IP>:5000), packet counter on the Live Monitoring card increments.")
        print("   2. Flow aggregation and 77-feature extraction updates the live classification display.\n")
    else:
        print("⚠️ No traffic frames were successfully transmitted.")
        print("   Review the preflight check diagnostics and ensure the Receiver's service is running.\n")

    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "sent": sent,
        "successful": successful,
        "failed": failed,
        "duration": total_duration,
        "achieved_rate": achieved_rate,
        "avg_latency": avg_latency
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="SCOUT: Dedicated Live Network Traffic Generator for Cross-Device Testing."
    )
    parser.add_argument(
        "--host",
        type=str,
        default=TARGET_HOST,
        help=f"Receiver Computer LAN IP address (default: {TARGET_HOST}). Do not use 127.0.0.1 for cross-device tests."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=TARGET_PORT,
        help=f"Receiver destination port (default: {TARGET_PORT}, Receiver's benign traffic sink)."
    )
    parser.add_argument(
        "--protocol",
        choices=["http", "tcp", "udp"],
        default=TRAFFIC_PROTOCOL,
        help=f"Transport protocol to generate (default: {TRAFFIC_PROTOCOL})."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_PACKET_COUNT,
        help=f"Total number of packets to transmit (default: {DEFAULT_PACKET_COUNT})."
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuously until stopped with Ctrl+C (overrides --count)."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"Delay between packet transmissions in seconds (default: {DEFAULT_INTERVAL_SECONDS}s)."
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=None,
        help="Target transmission rate in packets per second (e.g., --rate 10 = 0.1s interval)."
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Maximum test duration in seconds before automatic termination."
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=DEFAULT_PAYLOAD_SIZE_BYTES,
        help=f"Payload size in bytes per packet (default: {DEFAULT_PAYLOAD_SIZE_BYTES})."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=CONNECT_TIMEOUT_SECONDS,
        help=f"Socket connect timeout in seconds (default: {CONNECT_TIMEOUT_SECONDS}s)."
    )
    parser.add_argument(
        "--allow-loopback",
        action="store_true",
        default=ALLOW_LOOPBACK_DEFAULT,
        help="Permit loopback address (127.0.0.1/localhost) for single-machine local testing."
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Perform preflight connectivity check to target destination port and exit."
    )
    parser.add_argument(
        "-y", "--yes",
        dest="auto_confirm",
        action="store_true",
        help="Bypass interactive user confirmation prompt."
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # 1. Validate Target Host
    valid, resolved_ip, err_msg = validate_destination_host(
        args.host,
        allow_loopback=args.allow_loopback
    )
    if not valid:
        print("\n" + "!" * 78)
        print("❌ DESTINATION HOST CONFIGURATION ERROR:")
        print(f"   {err_msg}")
        print("!" * 78 + "\n")
        sys.exit(1)

    effective_interval = args.interval
    if args.rate and args.rate > 0:
        effective_interval = round(1.0 / args.rate, 4)

    packet_count = None if args.continuous else args.count

    # 2. Check-only mode
    if args.check_only:
        print(f"\n[CHECK] Pre-flight connectivity check to {args.host}:{args.port} (Protocol: {args.protocol.upper()})...")
        alive, reason = check_destination_service(
            args.host, args.port, protocol=args.protocol, timeout=args.timeout
        )
        if alive:
            print(f"✅ Pre-flight connectivity check passed: {args.host}:{args.port} is reachable.")
            sys.exit(0)
        else:
            print(f"❌ Pre-flight check failed: {reason}")
            sys.exit(1)

    # 3. Interactive confirmation (if not auto-confirmed)
    count_desc = "Continuous (Ctrl+C to stop)" if args.continuous or packet_count is None else f"{packet_count} packets"
    if not args.auto_confirm:
        print("\n" + "=" * 78)
        print("            SCOUT: LIVE NETWORK TRAFFIC GENERATION CONFIRMATION")
        print("=" * 78)
        print(f"  Target Destination : {args.host}:{args.port} (Resolved: {resolved_ip})")
        print(f"  Transport Protocol : {args.protocol.upper()}")
        print(f"  Packet Count       : {count_desc}")
        print(f"  Transmission Rate  : {effective_interval}s interval ({round(1.0 / max(0.001, effective_interval), 1)} pkts/sec)")
        print(f"  Payload Size       : {args.payload_size} bytes")
        print(f"  Operation Mode     : Genuine Wire Frames (Captured by Npcap/Scapy on Receiver)")
        print("=" * 78)
        try:
            confirm = input(f"Begin transmitting genuine {args.protocol.upper()} network frames to {args.host}:{args.port}? [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("\n[CANCELLED] Operation aborted by user.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\n[CANCELLED] Operation aborted by user.")
            sys.exit(0)

    # 4. Preflight connectivity probe
    print(f"\n[CHECK] Probing target {args.host}:{args.port} (Protocol: {args.protocol.upper()})...")
    reachable, check_err = check_destination_service(
        args.host, args.port, protocol=args.protocol, timeout=args.timeout
    )
    if not reachable:
        print("\n" + "!" * 78)
        print(f"❌ TARGET DESTINATION SERVICE UNREACHABLE: {args.host}:{args.port} ({args.protocol.upper()})")
        print(f"   Reason: {check_err}")
        print("!" * 78)
        print("\n[STOP] Preflight check failed. Zero network traffic was transmitted.")
        print("       Ensure api.py is running on the Receiver and firewall allows incoming TCP/UDP.")
        sys.exit(1)

    print(f"[OK] Target destination service is reachable.")

    # 5. Run Generator
    run_live_traffic_generator(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        interval=effective_interval,
        count=packet_count,
        timeout=args.timeout,
        payload_size=args.payload_size,
        check_interval=CONNECTIVITY_CHECK_INTERVAL_SECONDS,
        max_duration=args.duration
    )


if __name__ == '__main__':
    main()
