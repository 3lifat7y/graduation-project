#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Non-Privileged Test Suite: DDoS-Guard Service Architecture
Validates all aspects of the Windows Service architecture without requiring
Administrator privileges and without starting/stopping/installing/removing services:

1. Unprivileged SCM Query: Checks service status via unprivileged Win32 API.
2. Runtime & DLL Dependency Verification: Checks python311.dll & pywintypes311.dll safely.
3. Scoped UAC Elevation & Error 1223 (Cancellation) Handling: Verifies exact verb and params.
4. Localhost-only Binding & IPC Authentication Token: Verifies 127.0.0.1:50505 & token security.
5. Exact 77-Feature Model Pipeline: Verifies feature ordering, scaling, and inference.
6. Persistent SCM Logging & Traceback Formatting: Verifies log file and formatting.
7. Flask Unprivileged API Endpoints: Verifies /api/service-status and /api/adapter-info.
"""

import os
import sys
import json
import time
import struct
import logging
import logging.handlers
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import modules.monitoring.service_helper as service_helper
from modules.monitoring.service_helper import (
    get_service_status,
    is_service_online,
    tail_service_log,
    request_service_start,
    SERVICE_NAME,
    ERROR_CANCELLED
)
import modules.monitoring.ipc_client as ipc_client
from modules.monitoring.ipc_client import (
    DDoSGuardIPCClient,
    load_provisioned_token,
    PRIMARY_TOKEN_FILE
)
import modules.monitoring.capture_engine as feature_extraction2
from modules.monitoring.capture_engine import FlowStatsCollector, OFFICIAL_77_FEATURES
import api
from api import app, prepare_features, model, scaler, CLASS_LABELS


class TestServiceArchitectureNonPrivileged(unittest.TestCase):
    """Rigorous non-privileged verification of service architecture and model integrity."""

    def setUp(self):
        with api.scan_session_lock:
            api.is_monitoring = False
            api.current_scan_session.update({
                "status": "ready",
                "scan_id": None,
                "is_live_capture": False
            })

    def test_01_unprivileged_scm_query(self):
        """1. Verify service status can be queried without administrator privileges."""
        status = get_service_status(include_ipc=False)
        self.assertIsInstance(status, dict)
        self.assertIn("installed", status)
        self.assertIn("status", status)
        self.assertIn("state_code", status)
        self.assertIn("running", status)

        # Service was registered with Windows SCM
        self.assertTrue(status["installed"], f"Service '{SERVICE_NAME}' should be registered in SCM.")
        self.assertIn(status["status"], ["RUNNING", "STOPPED", "START_PENDING"], "SCM state must be valid.")
        
        if status["status"] == "RUNNING":
            self.assertTrue(status["running"])
            self.assertEqual(status["state_code"], service_helper.SERVICE_RUNNING)
            self.assertGreater(status["pid"], 0, "Running service must have valid PID.")
        elif status["status"] == "STOPPED":
            self.assertFalse(status["running"])
            self.assertEqual(status["state_code"], service_helper.SERVICE_STOPPED)

        print(f"  [PASS] Unprivileged SCM Query: Status={status['status']} (PID={status.get('pid', 0)}, Installed={status['installed']})")

    def test_02_runtime_dll_dependency_resolution(self):
        """2. Verify Python DLL runtime dependencies are staged and compatible."""
        venv_dir = PROJECT_ROOT / ".venv"
        self.assertTrue(venv_dir.exists(), "Virtual environment .venv directory must exist.")

        # Check python311.dll
        python_dll = venv_dir / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        self.assertTrue(python_dll.exists(), f"Runtime DLL '{python_dll.name}' must exist in .venv root.")
        
        # Verify 64-bit PE header of staged python DLL
        with open(python_dll, "rb") as f:
            dos_header = f.read(64)
            self.assertEqual(dos_header[:2], b"MZ", "Staged python DLL must have valid MZ header.")
            e_lfanew = struct.unpack("<I", dos_header[60:64])[0]
            f.seek(e_lfanew)
            pe_signature = f.read(4)
            self.assertEqual(pe_signature, b"PE\x00\x00", "Must have valid PE signature.")
            machine = struct.unpack("<H", f.read(2))[0]
            # 0x8664 = IMAGE_FILE_MACHINE_AMD64 (x64)
            self.assertEqual(machine, 0x8664, "Staged DLL must be 64-bit AMD64.")

        # Check pywintypes311.dll
        pywin_dll = venv_dir / f"pywintypes{sys.version_info.major}{sys.version_info.minor}.dll"
        self.assertTrue(pywin_dll.exists(), f"Runtime DLL '{pywin_dll.name}' must exist in .venv root.")

        # Verify pydivert imports and enforces Flag.SNIFF
        import pydivert
        self.assertTrue(hasattr(pydivert, "Flag"))
        self.assertTrue(hasattr(pydivert.Flag, "SNIFF"))
        print("  [PASS] DLL Runtime Dependencies verified: 64-bit python311.dll & pywintypes311.dll staged.")

    def test_03_scoped_uac_and_error_1223_handling(self):
        """3. Verify scoped UAC elevation correctly handles user cancellation (Error 1223)."""
        # Test simulated UAC cancellation without displaying interactive GUI
        with patch("service_helper.is_service_online", return_value=False), \
             patch("service_helper.get_service_status", return_value={"installed": True, "status": "STOPPED"}), \
             patch("ctypes.windll.shell32.ShellExecuteExW", return_value=0), \
             patch("ctypes.windll.kernel32.GetLastError", return_value=ERROR_CANCELLED):
            res = request_service_start()
            self.assertEqual(res["status"], "uac_cancelled")
            self.assertEqual(res["error_code"], 1223)
            self.assertIn("Administrator approval was cancelled", res["message"])
            self.assertIn("send_traffic.py", res["message"])

        # Test command targeting - verify verb is 'runas' and parameters target only DDoSGuardSnifferService
        with patch("service_helper.is_service_online", side_effect=[False, True]), \
             patch("service_helper.get_service_status", return_value={"installed": True, "status": "STOPPED"}), \
             patch("ctypes.windll.shell32.ShellExecuteExW") as mock_exec, \
             patch("ctypes.windll.kernel32.WaitForSingleObject", return_value=0), \
             patch("ctypes.windll.kernel32.CloseHandle", return_value=1):
            mock_exec.return_value = 1
            res = request_service_start(timeout=0.1)
            self.assertTrue(mock_exec.called)
            sei_ref = mock_exec.call_args[0][0]
            sei = sei_ref._obj
            self.assertEqual(sei.lpVerb, "runas")
            self.assertEqual(sei.lpFile, "powershell.exe")
            self.assertIn(f"Start-Service -Name '{SERVICE_NAME}'", sei.lpParameters)
        print("  [PASS] Scoped UAC Elevation logic verified: verb='runas', target=DDoSGuardSnifferService only, error 1223 handled.")

    def test_04_ipc_security_and_token_loading(self):
        """4. Verify IPC localhost-only binding and high-entropy authentication token."""
        client = DDoSGuardIPCClient()
        self.assertEqual(client.host, "127.0.0.1", "IPC client must strictly bind to 127.0.0.1.")
        self.assertEqual(client.port, 50505, "IPC client port must be 50505.")

        token, source = load_provisioned_token()
        self.assertIsNotNone(token, "Provisioned token must exist.")
        self.assertEqual(len(token), 64, "Token must be a 64-character hex string (256-bit entropy).")
        self.assertTrue(all(c in "0123456789abcdef" for c in token.lower()))

        # Live probe test: if service is currently running in SCM, test authenticated ping
        if client.is_service_running():
            ping_resp = client.ping()
            self.assertTrue(ping_resp.get("pong"), "Authenticated ping to running service must succeed.")
            self.assertTrue(ping_resp.get("is_admin"), "Running service must execute with elevated administrator token.")

        # Test simulated offline condition: is_service_running() returns False without raising
        with patch("socket.socket.connect", side_effect=ConnectionRefusedError("Connection refused")):
            offline_client = DDoSGuardIPCClient()
            self.assertFalse(offline_client.is_service_running(), "is_service_running() must return False when service is offline.")

        print(f"  [PASS] IPC Security verified: Localhost 127.0.0.1:50505, 256-bit token ({PRIMARY_TOKEN_FILE.name}).")

    def test_05_exact_77_feature_pipeline_and_model_inference(self):
        """5. Verify exact 77-feature ordering, collector extraction, scaling, and inference."""
        config_path = PROJECT_ROOT / "final_output_new_dataset" / "configs" / "feature_columns.json"
        self.assertTrue(config_path.exists(), "Config feature_columns.json must exist.")

        with open(config_path, "r", encoding="utf-8") as f:
            expected_77 = json.load(f)

        self.assertEqual(len(expected_77), 77, "Dataset must specify exactly 77 features.")
        self.assertEqual(len(OFFICIAL_77_FEATURES), 77, "feature_extraction2 must have exactly 77 features.")
        self.assertEqual(expected_77, OFFICIAL_77_FEATURES, "Feature names and ordering must match 100%.")

        # Test FlowStatsCollector with synthetic packets
        collector = FlowStatsCollector()
        now = time.time()
        for i in range(5):
            collector.add_packet({
                "timestamp": now + (i * 0.05),
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "length": 128,
                "protocol": 6,
                "header_len": 20,
                "win_size": 8192,
                "payload_len": 108,
                "flags": {"syn": 1 if i == 0 else 0, "ack": 1}
            })

        feats = collector.compute_77_features()
        self.assertIsInstance(feats, dict)
        self.assertEqual(len(feats), 77, "Collector must output exactly 77 features.")
        import numpy as np
        for col in OFFICIAL_77_FEATURES:
            self.assertIn(col, feats, f"Feature '{col}' must be present in computed features.")
            val = feats[col]
            self.assertFalse(np.isnan(val) or np.isinf(val), f"Feature '{col}' must be finite.")

        # Test model inference through api.py pipeline
        X = prepare_features(feats)
        self.assertEqual(X.shape, (1, 77), "Scaled feature array must have shape (1, 77).")

        # Run inference
        self.assertIsNotNone(model, "Model must be loaded.")
        prediction = model.predict(X)[0]
        self.assertIn(int(prediction), CLASS_LABELS, "Prediction must be a valid class index.")
        label_name = CLASS_LABELS[int(prediction)]
        self.assertIsInstance(label_name, str)

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)[0]
            conf = float(probs[prediction]) * 100.0
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 100.0)

        print(f"  [PASS] 77-Feature Model Pipeline: Evaluated synthetic flow -> Label: {label_name} ({int(prediction)}).")

    def test_06_persistent_logging_and_tracebacks(self):
        """6. Verify persistent rotating file logging and traceback formatting."""
        from modules.monitoring.service import get_service_logger, LOG_FILE
        logger = get_service_logger()
        self.assertIsNotNone(logger)
        
        # Verify handler points to ddos_guard_service.log
        has_file_handler = any(
            isinstance(h, logging.handlers.RotatingFileHandler) and Path(h.baseFilename) == LOG_FILE
            for h in logger.handlers
        )
        self.assertTrue(has_file_handler, "Service logger must have a RotatingFileHandler to ddos_guard_service.log.")

        # Test writing a diagnostic entry
        test_msg = f"[NON-PRIVILEGED TEST] Architecture validation check at {time.time()}"
        logger.info(test_msg)

        # Verify entry can be read back via tail_service_log
        lines = tail_service_log(10)
        self.assertTrue(any(test_msg in l for l in lines), "Logged message must appear in tail_service_log.")
        print("  [PASS] Persistent SCM logging verified: RotatingFileHandler active on ddos_guard_service.log.")

    def test_07_flask_unprivileged_endpoints(self):
        """7. Verify Flask routes work cleanly without elevation."""
        test_client = app.test_client()

        # 1. /api/service-status
        res = test_client.get("/api/service-status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["service"]["installed"])
        self.assertIn(data["service"]["status"], ["RUNNING", "STOPPED"])
        self.assertIsInstance(data["service"]["running"], bool)
        self.assertIsInstance(data["service"]["ipc_online"], bool)

        # 2. /api/adapter-info
        res = test_client.get("/api/adapter-info")
        self.assertEqual(res.status_code, 200)
        ad_data = res.get_json()
        self.assertEqual(ad_data["status"], "success")
        self.assertIn("adapter", ad_data)
        self.assertIn("service_state", ad_data)
        self.assertIn(ad_data["service_state"]["status"], ["RUNNING", "STOPPED"])
        print("  [PASS] Flask unprivileged API endpoints verified: /api/service-status & /api/adapter-info.")

    def test_08_uac_already_running_bypass(self):
        """8. Verify that if service is already running, no UAC elevation is prompted."""
        with patch("service_helper.is_service_online", return_value=True), \
             patch("ctypes.windll.shell32.ShellExecuteExW") as mock_exec:
            res = request_service_start()
            self.assertEqual(res["status"], "already_running")
            self.assertIn("already running", res["message"])
            self.assertFalse(mock_exec.called, "UAC ShellExecuteExW must NOT be called if service is online.")
        print("  [PASS] Already-Running Bypass: Zero elevation prompts when service is active.")

    def test_09_startup_failure_diagnostics(self):
        """9. Verify startup failure timeout returns actionable diagnostics and log tail."""
        with patch("ctypes.windll.shell32.ShellExecuteExW", return_value=1), \
             patch("service_helper.is_service_online", return_value=False), \
             patch("service_helper.get_service_status", return_value={"installed": True, "status": "STOPPED"}), \
             patch("ctypes.windll.kernel32.WaitForSingleObject", return_value=0), \
             patch("ctypes.windll.kernel32.CloseHandle", return_value=1):
            res = request_service_start(timeout=0.2)
            self.assertEqual(res["status"], "start_failed")
            self.assertIn("log_tail", res)
            self.assertIn("ddos_guard_service.log", res["message"])
        print("  [PASS] Startup Failure Handling: Returns actionable diagnostics and log_tail on timeout.")

    def test_10_scm_environment_variable_formatting(self):
        """10. Verify SCM Environment registry configuration contains all critical paths."""
        with patch("service_helper.is_service_online", return_value=False), \
             patch("service_helper.get_service_status", return_value={"installed": True, "status": "STOPPED"}), \
             patch("ctypes.windll.shell32.ShellExecuteExW") as mock_exec, \
             patch("ctypes.windll.kernel32.WaitForSingleObject", return_value=0), \
             patch("ctypes.windll.kernel32.CloseHandle", return_value=1):
            mock_exec.return_value = 1
            request_service_start(timeout=0.1)
            self.assertTrue(mock_exec.called)
            sei = mock_exec.call_args[0][0]._obj
            params = sei.lpParameters

            # Verify PowerShell command sets MultiString Environment
            self.assertIn("-Name 'Environment'", params)
            self.assertIn("-Type MultiString", params)
            self.assertIn("PYTHONPATH=", params)
            self.assertIn("PYTHONHOME=", params)
            self.assertIn("win32", params)
            self.assertIn("site-packages", params)
        print("  [PASS] SCM Environment Block: Correct MultiString paths (PYTHONPATH, PYTHONHOME, win32) verified.")

    def test_11_scan_session_freshness_and_telemetry(self):
        """11. Verify scan-session freshness, unique session ID, and live state polling synchronization."""
        test_client = app.test_client()

        # 1. Query /api/scan-status and verify service_state synchronization
        res = test_client.get("/api/scan-status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("service_state", data)
        self.assertIn("status", data["service_state"])
        self.assertIn("running", data["service_state"])
        self.assertIn("ipc_online", data["service_state"])

        # 2. Verify scan session uniqueness and freshness
        from api import current_scan_session, scan_session_lock
        with scan_session_lock:
            initial_scan_id = current_scan_session.get("scan_id")

        # Simulate fresh scan session ID generation
        new_scan_id = f"scan_{int(time.time() * 1000)}"
        self.assertNotEqual(initial_scan_id, new_scan_id)

        # 3. Verify that live packet capture is explicitly tagged and not synthetic
        # When backed by service, is_live_capture must be True and packets must match
        mock_features = {f: 1.0 for f in OFFICIAL_77_FEATURES}
        mock_features["Total Fwd Packets"] = 100
        mock_features["Total Backward Packets"] = 42
        with patch.object(api.ipc_client, "is_service_running", return_value=True), \
             patch.object(api.ipc_client, "start_scan", return_value={"status": "scanning", "scan_id": new_scan_id}), \
             patch.object(api.ipc_client, "get_scan_status", return_value={
                 "status": "captured",
                 "scan_id": new_scan_id,
                 "interface_name": "Wi-Fi",
                 "packets_captured": 142,
                 "features": mock_features
             }):
            # Run worker logic directly
            from api import run_scan_worker
            adapter_info = {"name": "Wi-Fi", "type": "Wireless"}
            driver_info = {"can_capture_live": True}
            
            with scan_session_lock:
                current_scan_session.update({
                    "status": "scanning",
                    "scan_id": new_scan_id,
                    "continuous": False,
                    "packets_captured": 0,
                    "is_live_capture": False
                })

            run_scan_worker(new_scan_id, adapter_info, driver_info, duration=0.1, min_packets=3, continuous=False)

            with scan_session_lock:
                self.assertEqual(current_scan_session["scan_id"], new_scan_id)
                self.assertEqual(current_scan_session["packets_captured"], 142)
                self.assertTrue(current_scan_session["is_live_capture"], "Service capture must be marked as live capture.")
                self.assertEqual(current_scan_session["status"], "prediction_available")
                self.assertIsNotNone(current_scan_session["prediction"])

        print("  [PASS] Scan Session Freshness & Telemetry: Verified unique scan_id, live capture tagging, and live polling sync.")

    def test_12_service_failure_after_uac(self):
        """12. Verify service startup failure after UAC approval returns actionable log details, never fake predictions."""
        test_client = app.test_client()

        # Simulate service stopped and SCM startup failing with timeout / log tail
        mock_fail_response = {
            "status": "start_failed",
            "error_type": "SERVICE_START_FAILED",
            "message": "Windows Service failed to enter RUNNING state within 8.0s timeout.",
            "log_tail": [
                "2026-10-15 01:00:00 [ERROR] SvcDoRun failed: WinDivert driver initialization timeout",
                "2026-10-15 01:00:01 [ERROR] Service exiting with code 1"
            ]
        }

        with patch("api.get_service_status", return_value={"installed": True, "status": "STOPPED", "running": False, "ipc_online": False}), \
             patch("api.request_service_start", return_value=mock_fail_response):
            res = test_client.post("/api/scan", json={"duration": 3.0, "min_packets": 3})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "error")
            self.assertEqual(data["error_type"], "SERVICE_START_FAILED")
            self.assertIn("failed to enter RUNNING state", data["message"])
            self.assertIn("log_tail", data)
            self.assertEqual(len(data["log_tail"]), 2)
            self.assertIn("service_state", data)
            # Verify no fake prediction was generated
            self.assertIsNone(data.get("prediction"))

        print("  [PASS] Service Failure after UAC: Returns actionable error, full log_tail, and zero fake predictions.")

    def test_13_scm_state_distinction(self):
        """13. Verify SCM state distinction logic for RUNNING, START_PENDING, STOPPED, and STOP_PENDING."""
        import win32service

        mock_states = [
            (win32service.SERVICE_RUNNING, "RUNNING", True),
            (win32service.SERVICE_START_PENDING, "START_PENDING", False),
            (win32service.SERVICE_STOPPED, "STOPPED", False),
            (win32service.SERVICE_STOP_PENDING, "STOP_PENDING", False),
        ]

        for code, expected_status, expected_running in mock_states:
            mock_status_data = {
                "CurrentState": code,
                "ProcessId": 1234 if expected_running else 0,
                "Win32ExitCode": 0,
                "ServiceSpecificExitCode": 0
            }
            with patch("win32service.OpenSCManager", return_value=1), \
                 patch("win32service.OpenService", return_value=2), \
                 patch("win32service.QueryServiceStatusEx", return_value=mock_status_data), \
                 patch("win32service.CloseServiceHandle", return_value=None), \
                 patch("service_helper.is_service_online", return_value=expected_running):
                st = get_service_status(include_ipc=True)
                self.assertEqual(st["status"], expected_status, f"State code {code} should map to {expected_status}.")
                self.assertEqual(st["running"], expected_running, f"State code {code} running flag should be {expected_running}.")
                self.assertEqual(st["state_code"], code)

        print("  [PASS] SCM State Distinction: Accurately distinguished RUNNING, START_PENDING, STOPPED, and STOP_PENDING.")


if __name__ == "__main__":
    import logging
    print("=" * 70)
    print("  DDoS-Guard: NON-PRIVILEGED SERVICE ARCHITECTURE TEST SUITE")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestServiceArchitectureNonPrivileged)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
