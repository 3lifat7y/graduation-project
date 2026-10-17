#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Focused Test Suite: Complete DDoS-Guard Frontend-to-Backend Scan Execution Flow
Tests all 7 scenarios specified in requirements:
1. Service stopped -> click Scan -> UAC elevation requested.
2. Approve UAC -> service starts -> IPC connects -> fresh scan runs.
3. Cancel UAC -> no scan success is reported (status="uac_cancelled", prediction=None).
4. Service already running -> no UAC prompt -> fresh scan runs directly.
5. API request failure -> meaningful error returned.
6. Service stops or fails during capture -> scan fails clearly without fake results.
7. Repeated scans -> each has unique scan_id, fresh packet counters, and stale results rejected.
"""

import sys
import time
import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import api
from api import app, current_scan_session, scan_session_lock, run_scan_worker
from modules.monitoring.service import CaptureWorker
from modules.monitoring.capture_engine import OFFICIAL_77_FEATURES


class TestScanExecutionFlow(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        with scan_session_lock:
            api.is_monitoring = False
            current_scan_session.update({
                "status": "ready",
                "scan_id": None,
                "started_at": None,
                "duration": 3.0,
                "min_packets": 3,
                "packets_captured": 0,
                "interface": None,
                "driver_status": None,
                "prediction": None,
                "label": None,
                "is_attack": False,
                "confidence": 0.0,
                "flow_summary": {},
                "error": None,
                "message": "Ready to scan network traffic."
            })

    def tearDown(self):
        try:
            self.client.post("/api/scan-stop")
        except Exception:
            pass
        with scan_session_lock:
            api.is_monitoring = False
            current_scan_session.update({
                "status": "ready",
                "scan_id": None
            })

    def test_01_service_stopped_triggers_uac_elevation(self):
        """Scenario 1: Service stopped -> click Scan -> UAC elevation is requested."""
        mock_stopped_svc = {
            "installed": True,
            "status": "STOPPED",
            "running": False,
            "ipc_online": False,
            "pid": 0
        }
        with patch("api.get_service_status", return_value=mock_stopped_svc), \
             patch("api.request_service_start", return_value={"status": "started", "message": "Service started."}) as mock_uac, \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "type": "Wi-Fi"}, {"can_capture_live": True})):
            res = self.client.post("/api/scan", json={"duration": 1.0, "min_packets": 1})
            self.assertEqual(res.status_code, 200)
            mock_uac.assert_called_once()
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertIsNotNone(data.get("scan_id"))
        print("  [PASS] Scenario 1: Service stopped -> UAC elevation correctly requested.")

    def test_02_approve_uac_starts_service_and_initiates_scan(self):
        """Scenario 2: Approve UAC -> service starts -> fresh scan session created."""
        mock_stopped = {"installed": True, "status": "STOPPED", "running": False, "ipc_online": False}
        mock_started = {"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 4321}

        # Sequence: First query is STOPPED, second query after UAC approval is RUNNING
        def fake_get_status(*args, **kwargs):
            if not hasattr(fake_get_status, "called"):
                fake_get_status.called = True
                return mock_stopped
            return mock_started

        with patch("api.get_service_status", side_effect=fake_get_status), \
             patch("api.request_service_start", return_value={"status": "started", "message": "Service started."}) as mock_start, \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Ethernet", "type": "Ethernet"}, {"can_capture_live": True})):
            res = self.client.post("/api/scan", json={"duration": 1.0, "min_packets": 2})
            self.assertEqual(res.status_code, 200)
            mock_start.assert_called_once()
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertTrue(data.get("scan_id").startswith("scan_"))
            self.assertEqual(data.get("packets_captured"), 0)
            self.assertIsNone(data.get("prediction"))
        print("  [PASS] Scenario 2: Approve UAC -> service started, clean fresh scan session initialized.")

    def test_03_cancel_uac_reports_no_scan_success(self):
        """Scenario 3: Cancel UAC -> no scan success is reported (status='uac_cancelled')."""
        mock_stopped = {"installed": True, "status": "STOPPED", "running": False, "ipc_online": False}
        with patch("api.get_service_status", return_value=mock_stopped), \
             patch("api.request_service_start", return_value={
                 "status": "uac_cancelled",
                 "error_code": 1223,
                 "message": "Administrator approval was cancelled by the user."
             }):
            res = self.client.post("/api/scan", json={"duration": 2.0})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "uac_cancelled")
            self.assertEqual(data.get("error_type"), "UAC_CANCELLED")
            self.assertIsNone(data.get("prediction"), "Prediction must NOT exist when UAC is cancelled.")
            with scan_session_lock:
                self.assertEqual(current_scan_session.get("status"), "uac_cancelled")
                self.assertIsNone(current_scan_session.get("prediction"))
        print("  [PASS] Scenario 3: Cancel UAC -> status='uac_cancelled', zero fake predictions reported.")

    def test_04_service_already_running_bypasses_uac(self):
        """Scenario 4: Service already running -> no UAC prompt -> fresh scan runs directly."""
        mock_running_svc = {
            "installed": True,
            "status": "RUNNING",
            "running": True,
            "ipc_online": True,
            "pid": 9999
        }
        with patch("api.get_service_status", return_value=mock_running_svc), \
             patch("api.request_service_start") as mock_uac, \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "type": "Wi-Fi"}, {"can_capture_live": True})):
            res = self.client.post("/api/scan", json={"duration": 1.0})
            self.assertEqual(res.status_code, 200)
            mock_uac.assert_not_called()  # UAC MUST NOT be called!
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertIsNotNone(data.get("scan_id"))
        print("  [PASS] Scenario 4: Service already running -> UAC bypassed, fresh scan session started.")

    def test_05_api_request_failure_returns_meaningful_error(self):
        """Scenario 5: API request failure -> meaningful error returned."""
        mock_running_svc = {
            "installed": True,
            "status": "RUNNING",
            "running": True,
            "ipc_online": True,
            "pid": 9999
        }
        with patch("api.get_service_status", return_value=mock_running_svc), \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", side_effect=RuntimeError("No active network adapter found.")):
            res = self.client.post("/api/scan", json={"duration": 1.0})
            self.assertIn(res.status_code, [200, 500])
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertIn("No active network adapter", data.get("error"))
        print("  [PASS] Scenario 5: Adapter discovery failure returns meaningful 500 error.")

    def test_06_service_stops_during_capture_fails_without_fake_prediction(self):
        """Scenario 6: Service stops during capture -> scan fails clearly without fake results."""
        scan_id = "test_scan_disconnect"
        adapter_info = {"name": "Wi-Fi", "type": "Wi-Fi"}
        driver_info = {"can_capture_live": False}

        # Simulate service available when scan started, then IPC error during capture
        with patch.object(api.ipc_client, "is_service_running", return_value=True), \
             patch.object(api.ipc_client, "start_scan", return_value={"status": "scanning", "scan_id": scan_id}), \
             patch.object(api.ipc_client, "get_scan_status", return_value={
                 "status": "service_unavailable",
                 "scan_id": scan_id,
                 "message": "DDoS-Guard Windows Service connection lost."
             }):
            with scan_session_lock:
                current_scan_session.update({
                    "status": "scanning",
                    "scan_id": scan_id,
                    "continuous": False,
                    "packets_captured": 0
                })

            run_scan_worker(scan_id, adapter_info, driver_info, duration=0.5, min_packets=2, continuous=False)

            with scan_session_lock:
                self.assertEqual(current_scan_session.get("status"), "error")
                self.assertIsNone(current_scan_session.get("prediction"), "Must not generate a prediction on disconnect.")
                self.assertIn("connection lost", current_scan_session.get("error", "").lower())
        print("  [PASS] Scenario 6: Service disconnection during capture fails clearly with zero fake results.")

    def test_07_capture_worker_rejects_stale_scan_id_and_repeated_scans(self):
        """Scenario 7: Repeated scans -> unique IDs, fresh packet counters, and stale results rejected."""
        worker = CaptureWorker()
        with patch.object(worker, "_capture_loop"):
            # Initial scan
            res1 = worker.start_window(scan_id="scan_A", duration=0.1, min_packets=1)
            self.assertIn(res1.get("status"), ["scanning", "monitoring"])
            self.assertEqual(res1.get("scan_id"), "scan_A")

            # Simulate scan_A completion
            with worker.lock:
                worker.active_scan_id = "scan_A"
                worker.is_capturing = False
                worker.current_result = {
                    "status": "captured",
                    "scan_id": "scan_A",
                    "packets_captured": 55,
                    "features": {f: 1.0 for f in OFFICIAL_77_FEATURES}
                }

            # Querying status for scan_A returns captured
            st_a = worker.get_status(scan_id="scan_A")
            self.assertEqual(st_a.get("status"), "captured")
            self.assertEqual(st_a.get("packets_captured"), 55)

            # Querying status for brand new scan_B MUST NOT return scan_A's captured result!
            st_b = worker.get_status(scan_id="scan_B")
            self.assertEqual(st_b.get("status"), "waiting", "Querying new scan_id must not return stale captured result!")
            self.assertNotEqual(st_b.get("scan_id"), "scan_A")

            # Starting scan_B resets state completely
            res2 = worker.start_window(scan_id="scan_B", duration=0.1, min_packets=1)
            self.assertIn(res2.get("status"), ["scanning", "monitoring"])
            self.assertEqual(res2.get("scan_id"), "scan_B")
            
            st_b_active = worker.get_status(scan_id="scan_B")
            self.assertIn(st_b_active.get("status"), ["scanning", "monitoring", "no_traffic"])
            self.assertEqual(st_b_active.get("packets_captured"), 0, "New scan session must start with 0 packets.")
            print("  [PASS] Scenario 7: Stale scan results strictly rejected; repeated scans get fresh 0-packet state.")

    def test_08_authenticated_ipc_failure_aborts_scan_clearly(self):
        """Scenario 8: Service running but authenticated IPC health check fails -> reports IPC_AUTH_FAILED error cleanly."""
        mock_running = {"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 1111}
        with patch("api.get_service_status", return_value=mock_running), \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(False, "Unauthorized IPC token rejected by service.")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "type": "Wi-Fi"}, {"can_capture_live": True})):
            res = self.client.post("/api/scan", json={"duration": 1.0})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error_type"), "IPC_AUTH_FAILED")
            self.assertIn("Unauthorized IPC token", data.get("error"))
            self.assertIsNone(data.get("prediction"), "Prediction must be None on IPC auth failure.")
            with scan_session_lock:
                self.assertEqual(current_scan_session.get("status"), "error")
                self.assertIsNone(current_scan_session.get("prediction"))
        print("  [PASS] Scenario 8: Authenticated IPC failure halts scan cleanly with zero fake predictions.")

    def test_09_start_pending_waits_for_running_without_uac(self):
        """Scenario 9: Service in START_PENDING -> polls until RUNNING without prompting UAC."""
        mock_pending = {"installed": True, "status": "START_PENDING", "running": False, "ipc_online": False}
        mock_running = {"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 5555}

        # Sequence: First SCM query is START_PENDING, second after brief wait is RUNNING
        def fake_get_status(*args, **kwargs):
            if not hasattr(fake_get_status, "called"):
                fake_get_status.called = True
                return mock_pending
            return mock_running

        with patch("api.get_service_status", side_effect=fake_get_status), \
             patch("api.request_service_start") as mock_uac, \
             patch.object(api.ipc_client, "verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "type": "Wi-Fi"}, {"can_capture_live": True})):
            res = self.client.post("/api/scan", json={"duration": 1.0})
            self.assertEqual(res.status_code, 200)
            mock_uac.assert_not_called()  # Must NOT call UAC for START_PENDING!
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertIsNotNone(data.get("scan_id"))
        print("  [PASS] Scenario 9: START_PENDING transitions to RUNNING without unnecessary UAC prompt.")

    def test_10_service_startup_failed_returns_error_and_log_tail(self):
        """Scenario 10: Service startup failure / timeout returns SERVICE_START_FAILED with log_tail."""
        mock_stopped = {"installed": True, "status": "STOPPED", "running": False, "ipc_online": False}
        with patch("api.get_service_status", return_value=mock_stopped), \
             patch("api.request_service_start", return_value={
                 "status": "start_failed",
                 "error_code": 1,
                 "message": "Elevated service startup failed.",
                 "log_tail": ["[ERROR] pythonservice.exe failed to start"]
             }):
            res = self.client.post("/api/scan", json={"duration": 1.0})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error_type"), "SERVICE_START_FAILED")
            self.assertIn("startup failed", data.get("error").lower())
            self.assertIn("log_tail", data)
            self.assertIsNone(data.get("prediction"), "Prediction must be None on startup failure.")
            with scan_session_lock:
                self.assertEqual(current_scan_session.get("status"), "error")
                self.assertIsNone(current_scan_session.get("prediction"))
        print("  [PASS] Scenario 10: Service startup failure returns actionable error, log_tail, and zero predictions.")


if __name__ == "__main__":
    print("=" * 70)
    print(">> Running Complete DDoS-Guard Scan Flow Scenarios Test Suite")
    print("=" * 70)
    unittest.main()
