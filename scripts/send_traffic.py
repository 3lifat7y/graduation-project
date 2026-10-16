import json
import random
import time
import requests
import argparse
import socket
import sys
from urllib.parse import urlparse
from pathlib import Path

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
TARGET_SERVER = "http://127.0.0.1:5000"
SEND_INTERVAL = 0.5

def parse_args():
    p = argparse.ArgumentParser(description='Network Security System Traffic Simulator')
    p.add_argument('--interval', '-i', type=float, help='Seconds between sends (default: 0.5)')
    p.add_argument('--target', '-t', type=str, help='Target server URL for API simulation (default: http://127.0.0.1:5000)')
    p.add_argument('--count', '-c', type=int, help='Number of packets/probes to send (default: infinite)')
    p.add_argument('--attack', '-a', type=str, help='Attack type by name or number (skips interactive menu)')
    p.add_argument('--list', action='store_true', help='List available attack types then exit')
    
    # Real Packet Probing (Track 2 for physical WinDivert packet capture)
    p.add_argument('--probe', action='store_true', help='Track 2: Generate safe real network packets across the LAN to test WinDivert')
    p.add_argument('--host', type=str, default=None, help='Target host IP for real packet probe (e.g. Receiver LAN IP)')
    p.add_argument('--port', '-p', type=int, default=8080, help='Target port for real packet probe (default: 8080, non-excluded)')
    p.add_argument('--protocol', type=str, default='tcp', choices=['tcp', 'udp'], help='Transport protocol for probe (default: tcp)')
    return p.parse_args()

def load_dataset():
    with open(TEST_SET_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)["all_data"]

def run_real_packet_probe(host: str, port: int, protocol: str, interval: float, count: int = None):
    """Track 2: Generates safe real network packets across the LAN to test WinDivert packet capture."""
    print("=" * 68)
    print("       REAL NETWORK PACKET CAPTURE TEST (TRACK 2: WINDIVERT)")
    print("=" * 68)
    print(f"  Target Host:     {host}")
    print(f"  Target Port:     {port}")
    print(f"  Transport:       {protocol.upper()}")
    print(f"  Send Interval:   {interval}s")
    print(f"  Packet Limit:    {f'{count} packets' if count else 'Continuous (Press Ctrl+C to stop)'}")
    print("=" * 68)
    print(f"Emitting safe {protocol.upper()} network frames across the wire to {host}:{port}...\n")

    sent = 0
    try:
        while True:
            t_str = time.strftime('%H:%M:%S')
            success = False
            if protocol.lower() == 'udp':
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(1.0)
                        payload = f"NSS_SAFE_PROBE_{sent}_{time.time()}".encode()
                        s.sendto(payload, (host, port))
                        success = True
                except Exception as ex:
                    print(f"[{t_str}] [PROBE ERROR] {ex}")
            else:  # TCP
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        # connect_ex emits a physical TCP SYN packet onto the wire
                        s.connect_ex((host, port))
                        success = True
                except Exception as ex:
                    print(f"[{t_str}] [PROBE ERROR] {ex}")

            sent += 1
            if success:
                print(f"[{t_str}] Frame #{sent} transmitted on physical wire → {host}:{port} [{protocol.upper()}]")
            else:
                print(f"[{t_str}] Frame #{sent} failed to transmit")

            if count and sent >= count:
                print(f"\n[DONE] Successfully transmitted {sent} packets to {host}:{port}.")
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\nProbing stopped by user. Total packets transmitted: {sent}.")

def main():
    args = parse_args()
    global SEND_INTERVAL, TARGET_SERVER
    if args.interval:
        SEND_INTERVAL = args.interval
    if args.target:
        TARGET_SERVER = args.target

    # =========================================================================
    # Track 2: Real Network Packet Probing (Tests WinDivert on Receiver NIC)
    # =========================================================================
    if args.probe:
        target_host = args.host
        if not target_host and args.target:
            parsed = urlparse(args.target)
            target_host = parsed.hostname or args.target
        if not target_host:
            target_host = "127.0.0.1"

        probe_port = args.port
        if probe_port in (5000, 50505):
            print(f"[WARNING] Port {probe_port} is excluded from WinDivert filters to isolate Web UI/IPC.")
            print(f"          Auto-switching probe port to 8080 to ensure WinDivert captures the traffic.")
            probe_port = 8080

        run_real_packet_probe(
            host=target_host,
            port=probe_port,
            protocol=args.protocol,
            interval=args.interval or SEND_INTERVAL,
            count=args.count
        )
        return

    # =========================================================================
    # Track 1: API Feature Simulation (Streams pre-extracted flow JSON to Flask)
    # =========================================================================
    print(f"Loading attack packets... (send interval={SEND_INTERVAL}s, target={TARGET_SERVER})")
    dataset = load_dataset()
    print(f"Loaded {len(dataset):,} packets\n")

    labels = {}
    for p in dataset:
        lbl = p.get("Label", "Unknown")
        labels[lbl] = labels.get(lbl, 0) + 1

    sorted_labels = sorted(labels.items(), key=lambda x: x[1], reverse=True)

    print("="*65)
    print("           AVAILABLE ATTACK TYPES")
    print("="*65)
    for i, (label, count) in enumerate(sorted_labels, 1):
        print(f"  {i}. {label:<18} → {count:>5} samples")
    print("="*65)

    if args.list:
        print("Attack types listed above.")
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
        choice_raw = input(f"\nSelect attack by number or name (1-{len(sorted_labels)}): ")
        if not choice_raw:
            print("Please choose a valid number or label name.")
            continue
        try:
            choice = int(choice_raw)
            if 1 <= choice <= len(sorted_labels):
                selected = sorted_labels[choice-1][0]
                break
            else:
                print(f"Invalid number: choose 1-{len(sorted_labels)}")
                continue
        except ValueError:
            matches = [lbl for lbl, _cnt in sorted_labels if lbl.lower() == choice_raw.lower()]
            if len(matches) == 1:
                selected = matches[0]
                break
            else:
                print("No matching label found. Try exact label name or choose a number.")
                continue

    packets = [{k: v for k, v in p.items() if k != "Label"}
            for p in dataset if p.get("Label") == selected]

    if len(packets) == 0:
        print(f"\nNo packets for selected label ({selected}).")
        sys.exit(1)

    print(f"\nStarting {selected} attack - {len(packets)} packets ready")
    print(f"Sending one packet every {SEND_INTERVAL} seconds → Press Ctrl+C to stop\n")

    sent = 0
    try:
        while True:
            packet = random.choice(packets)
            try:
                requests.post(f"{TARGET_SERVER}/api/receive-packet", json=packet, timeout=3)
                print(f"[{time.strftime('%H:%M:%S')}] Sent → {selected}")
            except Exception:
                print(f"[{time.strftime('%H:%M:%S')}] Failed")
            sent += 1
            if args.count and sent >= args.count:
                print(f"\nSent {sent} packets as requested. Stopping.")
                break
            time.sleep(SEND_INTERVAL)
    except KeyboardInterrupt:
        print("\n\nAttack stopped.")

if __name__ == "__main__":
    main()