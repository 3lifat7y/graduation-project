#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Secure Local IPC Client
Used by Flask Backend (api.py) to communicate with DDoSGuardWindowsService.
Sends requests to 127.0.0.1:50505 with token authentication.
Provides graceful fallbacks if the service is offline or not installed.
"""

import os
import sys
import json
import socket
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent
PRIMARY_TOKEN_FILE = PROJECT_ROOT / ".ipc_auth.token"
LEGACY_TOKEN_FILE = PROJECT_ROOT / "scratch" / "ipc_auth.token"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50505


def get_candidate_token_files() -> List[Path]:
    """Returns candidate paths for the IPC auth token file in priority order."""
    candidates: List[Path] = []
    env_file = os.environ.get("DDOS_GUARD_TOKEN_FILE")
    if env_file:
        candidates.append(Path(env_file))
    candidates.append(PRIMARY_TOKEN_FILE)
    candidates.append(LEGACY_TOKEN_FILE)
    return candidates


def load_provisioned_token() -> Tuple[Optional[str], float]:
    """
    Loads provisioned IPC secret from environment or candidate token files.
    Returns (token_str, max_mtime).
    """
    # 1. Environment variable override
    env_token = os.environ.get("DDOS_GUARD_IPC_TOKEN", "").strip()
    if env_token:
        return env_token, 0.0

    # 2. File-based resolution
    candidates = get_candidate_token_files()
    max_mtime = 0.0
    for path in candidates:
        if path.exists():
            try:
                mtime = path.stat().st_mtime
                if mtime > max_mtime:
                    max_mtime = mtime
                token = path.read_text(encoding="utf-8").strip()
                if token:
                    return token, max_mtime
            except Exception:
                continue

    return None, max_mtime


class DDoSGuardIPCClient:
    """Thread-safe IPC client to query the Windows Sniffer Service."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._cached_token: Optional[str] = None
        self._last_token_mtime: float = 0.0

    def _get_token(self, force_refresh: bool = False) -> Optional[str]:
        """
        Retrieves the auth token.
        Detects file modification time (mtime) or force_refresh to ensure
        the client stays synchronized if the service rotates or writes a new secret.
        """
        if not force_refresh and self._cached_token:
            current_max_mtime = 0.0
            for p in get_candidate_token_files():
                if p.exists():
                    try:
                        current_max_mtime = max(current_max_mtime, p.stat().st_mtime)
                    except Exception:
                        pass
            if current_max_mtime <= self._last_token_mtime:
                return self._cached_token

        token, mtime = load_provisioned_token()
        if token:
            self._cached_token = token
            self._last_token_mtime = mtime
            return token

        return self._cached_token

    def reload_token(self) -> Optional[str]:
        """Explicitly reloads and returns the latest provisioned token."""
        return self._get_token(force_refresh=True)

    def _send_command(
        self,
        cmd: str,
        extra_args: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        _allow_retry: bool = True
    ) -> Dict[str, Any]:
        req = {"cmd": cmd}
        if extra_args:
            req.update(extra_args)

        token = self._get_token()
        if not token:
            token = self._get_token(force_refresh=True)
        if token:
            req["token"] = token

        t = timeout or self.timeout
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            s.connect((self.host, self.port))
            msg = json.dumps(req) + "\n"
            s.sendall(msg.encode("utf-8"))

            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 131072:
                    break
            s.close()

            if not buf:
                return {"status": "error", "message": "Empty response from service."}

            resp = json.loads(buf.decode("utf-8").strip())

            # Self-healing: if server rejected with Unauthorized IPC request,
            # invalidate cache, reload from disk/env, and retry once.
            if _allow_retry and resp.get("status") == "error" and "Unauthorized IPC request" in str(resp.get("message", "")):
                refreshed_token = self._get_token(force_refresh=True)
                if refreshed_token and (refreshed_token != token or not token):
                    return self._send_command(cmd, extra_args=extra_args, timeout=timeout, _allow_retry=False)

            return resp
        except ConnectionRefusedError:
            return {
                "status": "service_unavailable",
                "connected": False,
                "message": f"DDoS-Guard Windows Service is not running on {self.host}:{self.port}."
            }
        except socket.timeout:
            return {
                "status": "timeout",
                "connected": False,
                "message": "Timed out waiting for response from DDoS-Guard Windows Service."
            }
        except Exception as e:
            return {
                "status": "error",
                "connected": False,
                "message": f"IPC communication error: {e}"
            }

    def ping(self) -> Dict[str, Any]:
        """Probes service availability with a rapid 0.6s probe."""
        return self._send_command("PING", timeout=0.6)

    def is_service_running(self) -> bool:
        res = self.ping()
        return bool(res.get("pong", False))

    def get_status(self) -> Dict[str, Any]:
        return self._send_command("STATUS")

    def start_scan(self, duration: float = 3.0, min_packets: int = 3, scan_id: Optional[str] = None) -> Dict[str, Any]:
        args = {
            "duration": duration,
            "min_packets": min_packets,
            "scan_id": scan_id or f"scan_{int(time.time()*1000)}"
        }
        return self._send_command("START_SCAN", args)

    def get_scan_status(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        args = {"scan_id": scan_id} if scan_id else None
        return self._send_command("GET_SCAN_STATUS", args)

    def stop_scan(self) -> Dict[str, Any]:
        return self._send_command("STOP_SCAN")


if __name__ == "__main__":
    print("Testing DDoS-Guard IPC Client...")
    client = DDoSGuardIPCClient()
    resp = client.ping()
    print("Ping Response:", json.dumps(resp, indent=2))
    tok = client._get_token()
    print("Provisioned Token Discovered:", f"{tok[:8]}...{tok[-8:]}" if tok else "None")

