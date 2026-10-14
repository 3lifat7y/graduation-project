#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Windows Service & Secure Local IPC Capture Engine
Runs in the background (as LocalSystem or elevated service) to open WinDivert
kernel filters strictly in MONITOR-ONLY mode (pydivert.Flag.SNIFF).
Exposes a secure local IPC interface (127.0.0.1 / Named Pipe) restricted to
authorized local processes (Flask Backend).

Security Constraints Enforced:
1. Monitor-Only Mode: pydivert.Flag.SNIFF enforced - no packet modification or dropping.
2. Least Privilege Control: Accepts only safe telemetry/scan commands (PING, STATUS, START_SCAN, GET_STATUS, STOP_SCAN).
3. No Remote Control: Binds exclusively to 127.0.0.1 with local token validation.
4. Standalone & Service Modes: Can run as native Windows Service or CLI worker (--standalone / --debug).
"""

import os
import sys
import json
import time
import socket
import secrets
import threading
import hmac
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from feature_extraction2 import FlowStatsCollector, parse_windivert_packet, OFFICIAL_77_FEATURES
from network_detector import auto_detect_primary_interface, is_admin_user

try:
    import pydivert
    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

IPC_HOST = "127.0.0.1"
IPC_PORT = 50505
PRIMARY_TOKEN_FILE = PROJECT_ROOT / ".ipc_auth.token"
LEGACY_TOKEN_FILE = PROJECT_ROOT / "scratch" / "ipc_auth.token"
TOKEN_FILE = PRIMARY_TOKEN_FILE


class CaptureWorker:
    """Manages windowed live packet capture using WinDivert in monitor-only mode."""

    def __init__(self):
        self.lock = threading.Lock()
        self.is_capturing = False
        self.stop_requested = False
        self.active_scan_id = None
        self.current_result: Dict[str, Any] = {
            "status": "ready",
            "message": "Capture engine ready."
        }
        self.total_packets_seen = 0

    def start_window(self, scan_id: str, duration: float = 3.0, min_packets: int = 3, filter_str: str = "true"):
        with self.lock:
            if self.is_capturing:
                return {"status": "error", "message": "Capture already in progress", "scan_id": self.active_scan_id}
            self.is_capturing = True
            self.stop_requested = False
            self.active_scan_id = scan_id
            self.current_result = {
                "status": "scanning",
                "scan_id": scan_id,
                "started_at": time.time(),
                "duration": duration,
                "min_packets": min_packets,
                "packets_captured": 0,
                "message": f"Capturing traffic for {duration}s in monitor-only mode..."
            }

        thread = threading.Thread(
            target=self._capture_loop,
            args=(scan_id, duration, min_packets, filter_str),
            daemon=True
        )
        thread.start()
        return {"status": "scanning", "scan_id": scan_id}

    def stop_window(self):
        with self.lock:
            self.stop_requested = True
            self.is_capturing = False
            self.current_result["status"] = "stopped"
            self.current_result["message"] = "Scan cancelled by client."
        return {"status": "stopped"}

    def get_status(self, scan_id: Optional[str] = None):
        with self.lock:
            return dict(self.current_result)

    def _capture_loop(self, scan_id: str, duration: float, min_packets: int, filter_str: str):
        collector = FlowStatsCollector()
        start_t = time.time()

        if not HAS_PYDIVERT:
            with self.lock:
                self.is_capturing = False
                self.current_result = {
                    "status": "error",
                    "error_type": "ModuleMissing",
                    "message": "pydivert library not found.",
                    "scan_id": scan_id
                }
            return

        try:
            # Strictly enforce Flag.SNIFF (monitor-only, non-dropping)
            with pydivert.WinDivert(filter_str, flags=pydivert.Flag.SNIFF) as w:
                while True:
                    with self.lock:
                        if self.stop_requested or not self.is_capturing:
                            break
                    elapsed = time.time() - start_t
                    if elapsed >= duration:
                        break
                    time_left = max(0.05, duration - elapsed)
                    try:
                        packet = w.recv(timeout=min(time_left, 0.3))
                        if packet:
                            pkt_dict = parse_windivert_packet(packet)
                            if pkt_dict:
                                collector.add_packet(pkt_dict)
                                self.total_packets_seen += 1
                                with self.lock:
                                    self.current_result["packets_captured"] = collector.packet_count
                    except TimeoutError:
                        continue
                    except Exception:
                        break
        except PermissionError as pe:
            with self.lock:
                self.is_capturing = False
                self.current_result = {
                    "status": "error",
                    "error_type": "DriverPermissionError",
                    "message": f"Kernel driver permission denied: {pe}",
                    "scan_id": scan_id
                }
            return
        except Exception as e:
            with self.lock:
                self.is_capturing = False
                self.current_result = {
                    "status": "error",
                    "error_type": "WinDivertError",
                    "message": str(e),
                    "scan_id": scan_id
                }
            return

        actual_duration = round(time.time() - start_t, 2)
        pkt_count = collector.packet_count

        with self.lock:
            self.is_capturing = False
            if pkt_count < min_packets:
                self.current_result = {
                    "status": "insufficient_traffic",
                    "scan_id": scan_id,
                    "packets_captured": pkt_count,
                    "min_required": min_packets,
                    "duration": actual_duration,
                    "message": f"Only {pkt_count} packet(s) captured in {actual_duration}s."
                }
            else:
                features = collector.compute_77_features()
                self.current_result = {
                    "status": "captured",
                    "scan_id": scan_id,
                    "packets_captured": pkt_count,
                    "duration": actual_duration,
                    "features": features,
                    "message": f"Successfully captured {pkt_count} packets."
                }


class SecureIPCServer:
    """Listens on 127.0.0.1:50505 for local commands from the Flask application."""

    def __init__(self, capture_worker: CaptureWorker, host: str = IPC_HOST, port: int = IPC_PORT, auth_token: Optional[str] = None):
        self.worker = capture_worker
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.auth_token = auth_token or self._init_auth_token()

    def _sync_token_files(self, token: str):
        """Writes token securely across primary and legacy paths with restrictive permissions."""
        targets = [PRIMARY_TOKEN_FILE, LEGACY_TOKEN_FILE]
        env_file = os.environ.get("DDOS_GUARD_TOKEN_FILE")
        if env_file:
            targets.append(Path(env_file))

        for target in targets:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(token, encoding="utf-8")
                try:
                    os.chmod(target, 0o600)
                except Exception:
                    pass
            except Exception as e:
                print(f"[Warning] Failed to write token to {target}: {e}", file=sys.stderr)

    def _init_auth_token(self) -> str:
        """
        Securely provisions or loads the IPC authentication secret.
        1. Checks DDOS_GUARD_IPC_TOKEN environment variable.
        2. Checks PRIMARY_TOKEN_FILE (.ipc_auth.token) or LEGACY_TOKEN_FILE (scratch/ipc_auth.token).
           If an existing valid secret (>= 32 chars) is found, LOADS IT to preserve synchronization.
        3. Only if no valid secret exists, generates a new 256-bit random hex secret (secrets.token_hex(32))
           and persists it with restricted file permissions.
        """
        env_token = os.environ.get("DDOS_GUARD_IPC_TOKEN", "").strip()
        if env_token and len(env_token) >= 32:
            return env_token

        candidates = []
        env_file = os.environ.get("DDOS_GUARD_TOKEN_FILE")
        if env_file:
            candidates.append(Path(env_file))
        candidates.extend([PRIMARY_TOKEN_FILE, LEGACY_TOKEN_FILE])

        for p in candidates:
            if p.exists():
                try:
                    content = p.read_text(encoding="utf-8").strip()
                    if len(content) >= 32:
                        self._sync_token_files(content)
                        return content
                except Exception:
                    continue

        new_token = secrets.token_hex(32)
        self._sync_token_files(new_token)
        return new_token

    def _is_authorized(self, req_token: Optional[str]) -> bool:
        """Constant-time token validation against timing attacks."""
        if not req_token or not self.auth_token:
            return False
        return hmac.compare_digest(str(req_token).strip(), str(self.auth_token).strip())

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"🔒 Secure IPC Server listening on {self.host}:{self.port}")

        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_sock, client_addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[IPC Error] Accept error: {e}", file=sys.stderr)
                break

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(5.0)
            data = b""
            while not data.endswith(b"\n"):
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:  # Prevent buffer overflow
                    break

            if not data:
                client_sock.close()
                return

            req = json.loads(data.decode("utf-8").strip())
            cmd = req.get("cmd", "")

            # Verify token for mutating commands
            req_token = req.get("token")
            if cmd not in ["PING", "STATUS"] and not self._is_authorized(req_token):
                resp = {"status": "error", "message": "Unauthorized IPC request."}
                client_sock.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                client_sock.close()
                return

            resp = self._dispatch_command(cmd, req)
            client_sock.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception as e:
            err_resp = {"status": "error", "message": f"IPC dispatch error: {e}"}
            try:
                client_sock.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _dispatch_command(self, cmd: str, req: Dict[str, Any]) -> Dict[str, Any]:
        if cmd == "PING":
            admin = is_admin_user()
            return {
                "status": "ok",
                "pong": True,
                "service": "DDoSGuardSnifferService",
                "is_admin": admin,
                "windivert_available": HAS_PYDIVERT,
                "total_packets": self.worker.total_packets_seen
            }

        elif cmd == "STATUS":
            admin = is_admin_user()
            return {
                "status": "ok",
                "service_running": True,
                "is_admin": admin,
                "total_packets": self.worker.total_packets_seen,
                "scan_state": self.worker.get_status()
            }

        elif cmd == "START_SCAN":
            duration = float(req.get("duration", 3.0))
            min_packets = int(req.get("min_packets", 3))
            scan_id = req.get("scan_id", f"srv_scan_{int(time.time()*1000)}")
            return self.worker.start_window(scan_id=scan_id, duration=duration, min_packets=min_packets)

        elif cmd == "GET_SCAN_STATUS":
            scan_id = req.get("scan_id")
            return self.worker.get_status(scan_id=scan_id)

        elif cmd == "STOP_SCAN":
            return self.worker.stop_window()

        else:
            return {"status": "error", "message": f"Unknown command: '{cmd}'"}


class DDoSGuardWindowsService(win32serviceutil.ServiceFramework if HAS_WIN32 else object):
    """Native Windows Service implementation for DDoS-Guard Network Sniffer."""
    _svc_name_ = "DDoSGuardSnifferService"
    _svc_display_name_ = "DDoS-Guard Network Sniffer Service"
    _svc_description_ = "DDoS-Guard kernel packet capture engine running WinDivert in monitor-only mode."

    def __init__(self, args):
        if HAS_WIN32:
            super().__init__(args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.worker = CaptureWorker()
        self.ipc_server = SecureIPCServer(self.worker)

    def SvcStop(self):
        if HAS_WIN32:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
        self.ipc_server.stop()
        self.worker.stop_window()

    def SvcDoRun(self):
        if HAS_WIN32:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
        server_thread = threading.Thread(target=self.ipc_server.start, daemon=True)
        server_thread.start()
        if HAS_WIN32:
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        else:
            server_thread.join()


def main():
    if "--standalone" in sys.argv or not HAS_WIN32:
        import argparse
        parser = argparse.ArgumentParser(description="DDoS-Guard: Windows Sniffer Service")
        parser.add_argument("--standalone", action="store_true", help="Run IPC capture server in standalone console mode")
        parser.add_argument("--port", type=int, default=IPC_PORT, help=f"IPC port (default: {IPC_PORT})")
        args, unknown = parser.parse_known_args()

        print("=" * 65)
        print("   DDoS-Guard: SECURE IPC PACKET CAPTURE WORKER (STANDALONE)")
        print("=" * 65)
        admin = is_admin_user()
        print(f"  • Process Administrator Rights: {'Elevated (Admin)' if admin else 'Standard User'}")
        print(f"  • WinDivert Engine Status     : {'Installed' if HAS_PYDIVERT else 'Missing'}")
        print(f"  • Monitor-Only Enforcement    : Active (Flag.SNIFF)")
        print(f"  • IPC Local Port              : {args.port}")

        worker = CaptureWorker()
        server = SecureIPCServer(worker, port=args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            print("\nShutting down IPC server...")
            server.stop()
    elif len(sys.argv) == 1 and HAS_WIN32:
        # Invoked directly by Windows Service Control Manager (SCM) with no arguments
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(DDoSGuardWindowsService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception:
            win32serviceutil.HandleCommandLine(DDoSGuardWindowsService)
    else:
        # CLI management commands: install, remove, start, stop, restart, debug
        win32serviceutil.HandleCommandLine(DDoSGuardWindowsService)


if __name__ == "__main__":
    main()
