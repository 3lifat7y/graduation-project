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
import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

LOG_FILE = PROJECT_ROOT / "ddos_guard_service.log"

def get_service_logger() -> logging.Logger:
    logger = logging.getLogger("DDoSGuardService")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        try:
            fh = logging.handlers.RotatingFileHandler(
                str(LOG_FILE), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] [PID:%(process)d/TID:%(thread)d] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception:
            pass
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(ch)
    return logger

logger = get_service_logger()

from feature_extraction2 import FlowStatsCollector, parse_windivert_packet, OFFICIAL_77_FEATURES, validate_flow_features
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
SERVICE_VERSION = "2.2-isolated-traffic"
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

    def start_window(
        self,
        scan_id: str,
        duration: float = 3.0,
        min_packets: int = 3,
        filter_str: Optional[str] = None,
        interface_name: Optional[str] = None,
        interface_index: Optional[int] = None
    ):
        with self.lock:
            if self.is_capturing:
                # Signal previous window to stop cleanly so new scan can proceed
                self.stop_requested = True
                self.is_capturing = False
            self.is_capturing = True
            self.stop_requested = False
            self.active_scan_id = scan_id
            self.current_result = {
                "status": "scanning",
                "scan_id": scan_id,
                "started_at": time.time(),
                "duration": duration,
                "min_packets": min_packets,
                "interface_name": interface_name,
                "interface_index": interface_index,
                "packets_captured": 0,
                "last_packet_time": None,
                "features": None,
                "message": f"Capturing traffic on [{interface_name or 'Network Adapter'}] for {duration}s in monitor-only mode..."
            }

        thread = threading.Thread(
            target=self._capture_loop,
            args=(scan_id, duration, min_packets, filter_str, interface_name, interface_index),
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
            # Prevent stale result poisoning: if scan_id specified, ensure current_result matches
            if scan_id is not None:
                cur_id = self.current_result.get("scan_id")
                if cur_id != scan_id and self.active_scan_id != scan_id:
                    return {
                        "status": "waiting",
                        "scan_id": scan_id,
                        "packets_captured": 0,
                        "message": f"Scan '{scan_id}' has not recorded results yet."
                    }
            return dict(self.current_result)

    def _capture_loop(
        self,
        scan_id: str,
        duration: float,
        min_packets: int,
        filter_str: Optional[str],
        interface_name: Optional[str],
        interface_index: Optional[int]
    ):
        collector = FlowStatsCollector(target_interface_index=interface_index)
        start_t = time.time()

        if not HAS_PYDIVERT:
            with self.lock:
                if self.active_scan_id == scan_id:
                    self.is_capturing = False
                    self.current_result = {
                        "status": "error",
                        "error_type": "ModuleMissing",
                        "message": "pydivert library not found.",
                        "scan_id": scan_id
                    }
            return

        # Build safe WinDivert kernel filter strictly excluding loopback and management ports
        if not filter_str or filter_str.strip() == "true":
            base_exclude = "!loopback && (ip || ipv6) && (!tcp || (tcp.SrcPort != 5000 && tcp.DstPort != 5000 && tcp.SrcPort != 50505 && tcp.DstPort != 50505))"
            if interface_index is not None and int(interface_index) > 0:
                effective_filter = f"ifIdx == {int(interface_index)} && {base_exclude}"
            else:
                effective_filter = base_exclude
        else:
            effective_filter = filter_str

        logger.info(
            f"[SCAN_START] scan_id={scan_id} | adapter={interface_name} (idx={interface_index}) | "
            f"duration={duration}s | min_pkts={min_packets} | filter='{effective_filter}'"
        )

        try:
            # Strictly enforce Flag.SNIFF (monitor-only, non-dropping)
            with pydivert.WinDivert(effective_filter, flags=pydivert.Flag.SNIFF) as w:
                while True:
                    with self.lock:
                        if self.stop_requested or not self.is_capturing or self.active_scan_id != scan_id:
                            break
                    elapsed = time.time() - start_t
                    if elapsed >= duration:
                        break
                    time_left = max(0.05, duration - elapsed)
                    try:
                        packet = w.recv(timeout=min(time_left, 0.3))
                        if packet:
                            pkt_dict = parse_windivert_packet(packet, target_if_idx=interface_index)
                            if pkt_dict:
                                collector.add_packet(pkt_dict)
                                self.total_packets_seen += 1
                                with self.lock:
                                    if self.active_scan_id == scan_id:
                                        self.current_result["packets_captured"] = collector.packet_count
                                        self.current_result["last_packet_time"] = collector.last_packet_time
                    except TimeoutError:
                        continue
                    except Exception:
                        break
        except PermissionError as pe:
            with self.lock:
                if self.active_scan_id == scan_id:
                    self.is_capturing = False
                    self.current_result = {
                        "status": "error",
                        "error_type": "DriverPermissionError",
                        "message": f"Kernel driver permission denied: {pe}",
                        "scan_id": scan_id
                    }
            logger.error(f"[SCAN_ERROR] scan_id={scan_id} | PermissionError: {pe}")
            return
        except Exception as e:
            with self.lock:
                if self.active_scan_id == scan_id:
                    self.is_capturing = False
                    self.current_result = {
                        "status": "error",
                        "error_type": "WinDivertError",
                        "message": str(e),
                        "scan_id": scan_id
                    }
            logger.error(f"[SCAN_ERROR] scan_id={scan_id} | WinDivertError: {e}")
            return

        actual_duration = round(time.time() - start_t, 2)
        pkt_count = collector.packet_count
        last_pkt_time = collector.last_packet_time

        with self.lock:
            if self.active_scan_id != scan_id:
                return
            self.is_capturing = False
            if self.stop_requested:
                self.current_result = {
                    "status": "stopped",
                    "scan_id": scan_id,
                    "packets_captured": pkt_count,
                    "duration": actual_duration,
                    "message": "Scan cancelled."
                }
                logger.info(f"[SCAN_CANCELLED] scan_id={scan_id}")
            elif pkt_count == 0:
                self.current_result = {
                    "status": "no_traffic",
                    "scan_id": scan_id,
                    "packets_captured": 0,
                    "min_required": min_packets,
                    "duration": actual_duration,
                    "interface_name": interface_name,
                    "last_packet_time": None,
                    "message": f"No traffic detected on [{interface_name or 'Network Adapter'}]. 0 packets intercepted."
                }
                logger.info(
                    f"[SCAN_END] scan_id={scan_id} | adapter={interface_name} | new_pkts=0 | "
                    f"state=no_traffic | duration={actual_duration}s"
                )
            elif pkt_count < min_packets:
                self.current_result = {
                    "status": "insufficient_traffic",
                    "scan_id": scan_id,
                    "packets_captured": pkt_count,
                    "min_required": min_packets,
                    "duration": actual_duration,
                    "interface_name": interface_name,
                    "last_packet_time": last_pkt_time,
                    "message": f"Only {pkt_count} packet(s) captured in {actual_duration}s (min: {min_packets}). Insufficient data."
                }
                logger.info(
                    f"[SCAN_END] scan_id={scan_id} | adapter={interface_name} | new_pkts={pkt_count} | "
                    f"last_pkt_time={last_pkt_time} | state=insufficient_traffic | duration={actual_duration}s"
                )
            else:
                features = collector.compute_77_features()
                is_valid, val_reason = validate_flow_features(features, min_packets=min_packets)
                if not is_valid:
                    self.current_result = {
                        "status": "error",
                        "scan_id": scan_id,
                        "error_type": "InvalidFlowFeatures",
                        "packets_captured": pkt_count,
                        "duration": actual_duration,
                        "message": f"Flow validation failed: {val_reason}"
                    }
                    logger.warning(f"[SCAN_INVALID] scan_id={scan_id} | validation_failed={val_reason}")
                else:
                    self.current_result = {
                        "status": "captured",
                        "scan_id": scan_id,
                        "packets_captured": pkt_count,
                        "duration": actual_duration,
                        "interface_name": interface_name,
                        "last_packet_time": last_pkt_time,
                        "features": features,
                        "message": f"Successfully captured {pkt_count} packets."
                    }
                    logger.info(
                        f"[SCAN_END] scan_id={scan_id} | adapter={interface_name} | new_pkts={pkt_count} | "
                        f"last_pkt_time={last_pkt_time} | state=captured | duration={actual_duration}s"
                    )


class SecureIPCServer:
    """Listens on 127.0.0.1:50505 for local commands from the Flask application."""

    def __init__(self, capture_worker: CaptureWorker, host: str = IPC_HOST, port: int = IPC_PORT, auth_token: Optional[str] = None, stop_callback: Optional[Any] = None):
        self.worker = capture_worker
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.stop_callback = stop_callback
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
            logger.debug(f"[IPC] Request: cmd={cmd}, scan_id={req.get('scan_id')}")

            # Verify token for mutating commands
            req_token = req.get("token")
            if cmd not in ["PING", "STATUS"] and not self._is_authorized(req_token):
                logger.warning(f"[IPC] Unauthorized request rejected for cmd={cmd}")
                resp = {"status": "error", "message": "Unauthorized IPC request."}
                client_sock.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                client_sock.close()
                return

            resp = self._dispatch_command(cmd, req)
            logger.debug(f"[IPC] Response for {cmd}: status={resp.get('status')}, scan_id={resp.get('scan_id')}")
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
                "service_version": SERVICE_VERSION,
                "service_pid": os.getpid(),
                "capabilities": ["loopback_exclusion", "iface_binding", "dynamic_filter"],
                "is_admin": admin,
                "windivert_available": HAS_PYDIVERT,
                "total_packets": self.worker.total_packets_seen
            }

        elif cmd == "STATUS":
            admin = is_admin_user()
            return {
                "status": "ok",
                "service_running": True,
                "service_version": SERVICE_VERSION,
                "service_pid": os.getpid(),
                "is_admin": admin,
                "total_packets": self.worker.total_packets_seen,
                "scan_state": self.worker.get_status()
            }

        elif cmd == "START_SCAN":
            duration = float(req.get("duration", 3.0))
            min_packets = int(req.get("min_packets", 3))
            scan_id = req.get("scan_id", f"srv_scan_{int(time.time()*1000)}")
            interface_name = req.get("interface_name")
            interface_index = req.get("interface_index")
            filter_str = req.get("filter_str")
            return self.worker.start_window(
                scan_id=scan_id,
                duration=duration,
                min_packets=min_packets,
                filter_str=filter_str,
                interface_name=interface_name,
                interface_index=interface_index
            )

        elif cmd == "GET_SCAN_STATUS":
            scan_id = req.get("scan_id")
            return self.worker.get_status(scan_id=scan_id)

        elif cmd == "STOP_SCAN":
            return self.worker.stop_window()

        elif cmd == "STOP_SERVICE":
            logger.info(f"[IPC] STOP_SERVICE command received from authorized client (PID: {os.getpid()})")
            def _delayed_stop():
                time.sleep(0.4)
                if self.stop_callback:
                    try:
                        self.stop_callback()
                    except Exception as ex:
                        logger.error(f"stop_callback exception: {ex}")
                else:
                    sys.exit(0)
            threading.Thread(target=_delayed_stop, daemon=True).start()
            return {"status": "stopping", "message": f"DDoSGuardSnifferService (PID: {os.getpid()}) is stopping."}

        else:
            return {"status": "error", "message": f"Unknown command: '{cmd}'"}


class DDoSGuardWindowsService(win32serviceutil.ServiceFramework if HAS_WIN32 else object):
    """Native Windows Service implementation for DDoS-Guard Network Sniffer."""
    _svc_name_ = "DDoSGuardSnifferService"
    _svc_display_name_ = "DDoS-Guard Network Sniffer Service"
    _svc_description_ = "DDoS-Guard kernel packet capture engine running WinDivert in monitor-only mode."
    _exe_name_ = str(PROJECT_ROOT / ".venv" / "pythonservice.exe")
    _exe_path_ = str(PROJECT_ROOT / ".venv" / "pythonservice.exe")

    def __init__(self, args):
        logger.info(f"DDoSGuardWindowsService.__init__ called (PID: {os.getpid()})")
        try:
            if HAS_WIN32:
                super().__init__(args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.worker = CaptureWorker()
            self.ipc_server = SecureIPCServer(
                self.worker,
                host=IPC_HOST,
                port=IPC_PORT,
                stop_callback=self._request_service_exit
            )
            self.server_thread = None
            logger.info("DDoSGuardWindowsService instance initialized successfully.")
        except Exception as e:
            logger.exception(f"FATAL Exception in DDoSGuardWindowsService.__init__: {e}")
            raise

    def _request_service_exit(self):
        logger.info("Service exit triggered via authorized IPC.")
        if HAS_WIN32 and hasattr(self, 'hWaitStop'):
            win32event.SetEvent(self.hWaitStop)
        else:
            sys.exit(0)

    def SvcStop(self):
        logger.info("SvcStop signal received. Initiating graceful shutdown...")
        try:
            if HAS_WIN32:
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.hWaitStop)
            if self.ipc_server:
                self.ipc_server.stop()
            if self.worker:
                self.worker.stop_window()
            logger.info("SvcStop completed successfully.")
        except Exception as e:
            logger.exception(f"Exception during SvcStop: {e}")

    def SvcDoRun(self):
        logger.info(f"SvcDoRun started for {self._svc_name_} (PID: {os.getpid()})")
        try:
            if HAS_WIN32:
                # 1. Immediately report SERVICE_START_PENDING to prevent SCM 7000/7009 timeouts
                self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
                try:
                    servicemanager.LogMsg(
                        servicemanager.EVENTLOG_INFORMATION_TYPE,
                        servicemanager.PYS_SERVICE_STARTED,
                        (self._svc_name_, "")
                    )
                except Exception:
                    pass

            # 2. Ensure sys.path includes PROJECT_ROOT and virtual environment site-packages
            if str(PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(PROJECT_ROOT))
            site_packages = PROJECT_ROOT / ".venv" / "Lib" / "site-packages"
            if site_packages.exists() and str(site_packages) not in sys.path:
                sys.path.insert(1, str(site_packages))

            # 3. Start IPC server in dedicated daemon thread
            logger.info(f"Starting SecureIPCServer on {IPC_HOST}:{IPC_PORT}...")
            self.server_thread = threading.Thread(
                target=self._run_ipc_server,
                daemon=True,
                name="IPCServerThread"
            )
            self.server_thread.start()

            # 4. Wait briefly to ensure server bound successfully
            time.sleep(0.4)
            if not self.ipc_server or not self.ipc_server.running:
                raise RuntimeError(f"IPC Server failed to bind to {IPC_HOST}:{IPC_PORT}.")

            # 5. CRITICAL: Report SERVICE_RUNNING to Windows SCM
            if HAS_WIN32:
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            logger.info(f"Reported SERVICE_RUNNING to Windows SCM. {self._svc_name_} is now ACTIVE.")

            # 6. Block until service stop event is signaled
            if HAS_WIN32:
                win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            else:
                self.server_thread.join()

            logger.info("Service stop event signaled. Exiting SvcDoRun loop.")
        except Exception as e:
            logger.exception(f"FATAL Exception in SvcDoRun: {e}")
            if HAS_WIN32:
                try:
                    self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                except Exception:
                    pass
            raise
        finally:
            if HAS_WIN32:
                try:
                    self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                except Exception:
                    pass
            logger.info(f"SvcDoRun finished: Reported SERVICE_STOPPED for {self._svc_name_}.")

    def _run_ipc_server(self):
        try:
            self.ipc_server.start()
        except Exception as e:
            logger.exception(f"IPC server thread crashed: {e}")


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
        except Exception as e:
            logger.exception(f"SCM Dispatcher exception: {e}")
            win32serviceutil.HandleCommandLine(DDoSGuardWindowsService)
    else:
        # CLI management commands: install, remove, start, stop, restart, debug
        win32serviceutil.HandleCommandLine(DDoSGuardWindowsService)


if __name__ == "__main__":
    main()
