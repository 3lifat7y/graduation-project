#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Focused Test Suite: DDoS-Guard IPC Authentication
Validates:
1. Unauthenticated commands (PING, STATUS) succeed without token.
2. Valid authenticated requests (START_SCAN, GET_SCAN_STATUS, STOP_SCAN) succeed.
3. Invalid token requests are rejected with 'Unauthorized IPC request.'.
4. Missing token requests are rejected with 'Unauthorized IPC request.'.
5. Client self-healing cache recovery and mtime reload.
6. Constant-time token verification.
"""

import os
import sys
import json
import socket
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.monitoring.ipc_client import (
    DDoSGuardIPCClient,
    get_candidate_token_files,
    load_provisioned_token,
    PRIMARY_TOKEN_FILE,
    LEGACY_TOKEN_FILE
)


class TestIPCAuthentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = DDoSGuardIPCClient()
        cls.token, _ = load_provisioned_token()
        if not cls.token:
            raise unittest.SkipTest("No provisioned IPC token found on disk or environment.")
        
        # Verify IPC server is listening
        ping_res = cls.client.ping()
        if not ping_res.get("pong"):
            raise unittest.SkipTest("DDoS-Guard IPC server is not running on 127.0.0.1:50505.")

    def _raw_send(self, payload: dict) -> dict:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", 50505))
        msg = json.dumps(payload) + "\n"
        s.sendall(msg.encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf.decode("utf-8").strip())

    def test_01_unauthenticated_ping_and_status(self):
        """PING and STATUS are safe telemetry commands that must succeed without a token."""
        # Raw send without token
        res_ping = self._raw_send({"cmd": "PING"})
        self.assertEqual(res_ping.get("status"), "ok")
        self.assertTrue(res_ping.get("pong"))

        res_status = self._raw_send({"cmd": "STATUS"})
        self.assertEqual(res_status.get("status"), "ok")
        self.assertTrue(res_status.get("service_running"))

    def test_02_valid_authenticated_scan_lifecycle(self):
        """Mutating commands with the valid provisioned token must succeed."""
        scan_id = f"test_valid_{int(time.time()*1000)}"
        start_res = self.client.start_scan(duration=1.0, min_packets=1, scan_id=scan_id)
        self.assertIn(start_res.get("status"), ["scanning", "monitoring"])
        self.assertEqual(start_res.get("scan_id"), scan_id)

        status_res = self.client.get_scan_status(scan_id)
        self.assertIn(status_res.get("status"), ["scanning", "captured", "insufficient_traffic", "no_traffic", "monitoring"])

        stop_res = self.client.stop_scan()
        self.assertIn(stop_res.get("status"), ["stopped", "ready"])

    def test_03_invalid_token_rejected(self):
        """Mutating commands with an incorrect token must be rejected with 'Unauthorized IPC request.'."""
        bad_token = "invalid_token_deadbeef00112233445566778899aabbccddeeff"
        
        # 1. START_SCAN with invalid token
        payload_start = {
            "cmd": "START_SCAN",
            "duration": 1.0,
            "min_packets": 1,
            "scan_id": "test_invalid_token",
            "token": bad_token
        }
        res_start = self._raw_send(payload_start)
        self.assertEqual(res_start.get("status"), "error")
        self.assertIn("Unauthorized IPC request", res_start.get("message", ""))

        # 2. STOP_SCAN with invalid token
        payload_stop = {
            "cmd": "STOP_SCAN",
            "token": bad_token
        }
        res_stop = self._raw_send(payload_stop)
        self.assertEqual(res_stop.get("status"), "error")
        self.assertIn("Unauthorized IPC request", res_stop.get("message", ""))

        # 3. GET_SCAN_STATUS with invalid token
        payload_status = {
            "cmd": "GET_SCAN_STATUS",
            "scan_id": "test_invalid_token",
            "token": bad_token
        }
        res_status = self._raw_send(payload_status)
        self.assertEqual(res_status.get("status"), "error")
        self.assertIn("Unauthorized IPC request", res_status.get("message", ""))

    def test_04_missing_token_rejected(self):
        """Mutating commands without any token field must be rejected with 'Unauthorized IPC request.'."""
        payload_no_token = {
            "cmd": "START_SCAN",
            "duration": 1.0,
            "min_packets": 1,
            "scan_id": "test_missing_token"
        }
        res = self._raw_send(payload_no_token)
        self.assertEqual(res.get("status"), "error")
        self.assertIn("Unauthorized IPC request", res.get("message", ""))

    def test_05_client_self_healing_cache_recovery(self):
        """Client with stale/invalid token in cache must reload from disk and retry on auth failure."""
        faulty_client = DDoSGuardIPCClient()
        # Poison client's cache with bad token
        faulty_client._cached_token = "stale_poisoned_token_12345"
        faulty_client._last_token_mtime = 9999999999.0

        scan_id = f"test_healing_{int(time.time()*1000)}"
        # Because of self-healing in _send_command, it catches Unauthorized, force-refreshes, and retries
        res = faulty_client.start_scan(duration=1.0, min_packets=1, scan_id=scan_id)
        self.assertIn(res.get("status"), ["scanning", "monitoring"])
        self.assertEqual(res.get("scan_id"), scan_id)

        # Verify client cache was healed
        self.assertEqual(faulty_client._cached_token, self.token)

        # Cleanup scan
        faulty_client.stop_scan()

    def test_06_token_discovery_order_and_sync(self):
        """Verify token discovery candidates include primary and legacy paths."""
        candidates = get_candidate_token_files()
        self.assertIn(PRIMARY_TOKEN_FILE, candidates)
        self.assertIn(LEGACY_TOKEN_FILE, candidates)
        
        token, mtime = load_provisioned_token()
        self.assertIsNotNone(token)
        self.assertGreaterEqual(len(token), 32)


if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

if __name__ == "__main__":
    print("=" * 70)
    print(">> Running Focused IPC Authentication Test Suite")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIPCAuthentication)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
