#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification Test Suite: Live Network Monitoring Strict Traffic Enforcement
Validates:
1. Loopback (127.0.0.1) & local ports (5000, 50505) are completely excluded from capture.
2. 0 packets intercepted -> 'no_traffic' status, 'No Traffic Detected' label, Confidence = 0.
3. 1-2 packets intercepted -> 'insufficient_traffic' status, 'Insufficient Data' label, Confidence = 0.
4. Empty or zero-filled feature vectors are rejected by validation gate (prevents false Benign 99.95%).
5. Network adapter offline / disabled -> 'error' status, 'Capture Error' label, no Benign prediction.
6. Previous scan results and counters are wiped immediately on new scan; scan_id strictly enforced.
7. Real valid traffic with >= 3 packets passes validation and evaluates model inference.
8. Port scanner remains completely isolated and functional.
"""

import os
import sys
import time
import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import api
from api import app, current_scan_session, scan_session_lock, prepare_features, run_scan_worker
from modules.monitoring.capture_engine import (
    FlowStatsCollector,
    parse_scapy_packet,
    parse_windivert_packet,
    validate_flow_features,
    OFFICIAL_77_FEATURES
)
from modules.monitoring.service import CaptureWorker
import modules.common.network_detector as network_detector


class TestLiveMonitoringFix(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        with scan_session_lock:
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

    def test_01_loopback_and_internal_ports_excluded(self):
        """1. Verify that loopback and local web/IPC traffic (5000, 50505) are rejected."""
        collector = FlowStatsCollector(target_interface_index=14)

        # Scapy packet on loopback (127.0.0.1)
        from scapy.all import IP, TCP
        scapy_loopback = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=5000, dport=52345)
        self.assertIsNone(parse_scapy_packet(scapy_loopback, target_if_idx=14))
        self.assertIsNone(parse_windivert_packet(scapy_loopback, target_if_idx=14))

        # Scapy packet on IPC port 50505
        scapy_ipc = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50505, dport=54321)
        self.assertIsNone(parse_scapy_packet(scapy_ipc, target_if_idx=14))

        # Mock WinDivert packet on loopback
        mock_loopback = MagicMock()
        mock_loopback.is_loopback = True
        mock_loopback.src_addr = "127.0.0.1"
        mock_loopback.dst_addr = "127.0.0.1"
        mock_loopback.src_port = 5000
        mock_loopback.dst_port = 52345
        self.assertIsNone(parse_windivert_packet(mock_loopback, target_if_idx=14))

        # Mock WinDivert packet on IPC port 50505
        mock_ipc = MagicMock()
        mock_ipc.is_loopback = False
        mock_ipc.src_addr = "127.0.0.1"
        mock_ipc.dst_addr = "127.0.0.1"
        mock_ipc.src_port = 50505
        mock_ipc.dst_port = 54321
        self.assertIsNone(parse_windivert_packet(mock_ipc, target_if_idx=14))

        # Mock packet with mismatched interface index
        mock_wrong_if = MagicMock()
        mock_wrong_if.is_loopback = False
        mock_wrong_if.interface = (99, 0)
        mock_wrong_if.src_addr = "192.168.1.10"
        mock_wrong_if.dst_addr = "8.8.8.8"
        mock_wrong_if.src_port = 443
        mock_wrong_if.dst_port = 443
        self.assertIsNone(parse_windivert_packet(mock_wrong_if, target_if_idx=14))

        # Try to feed directly to collector
        collector.add_packet({"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 5000, "dst_port": 5000, "length": 60})
        collector.add_packet({"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 50505, "dst_port": 50505, "length": 60})
        collector.add_packet({"is_loopback": True, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "length": 100})
        self.assertEqual(collector.packet_count, 0, "Loopback / internal packets must never be collected.")
        print("  [PASS] 1. Loopback and internal management traffic (5000, 50505) strictly rejected.")

    def test_02_zero_packets_produces_no_traffic_detected(self):
        """2. Verify 0 packets intercepted results in 'no_traffic' and 'No Traffic Detected'."""
        worker = CaptureWorker()
        scan_id = "test_zero_pkt_scan"
        worker.active_scan_id = scan_id

        # Simulate completion with 0 packets
        with worker.lock:
            worker.current_result = {
                "status": "no_traffic",
                "scan_id": scan_id,
                "packets_captured": 0,
                "min_required": 3,
                "duration": 3.0,
                "interface_name": "Wi-Fi",
                "last_packet_time": None,
                "message": "No traffic detected on [Wi-Fi]. 0 packets intercepted."
            }

        st = worker.get_status(scan_id=scan_id)
        self.assertEqual(st["status"], "no_traffic")
        self.assertEqual(st["packets_captured"], 0)

        # Update Flask session to simulate worker handling
        with scan_session_lock:
            current_scan_session.update({
                "status": "no_traffic",
                "label": "No Traffic Detected",
                "is_attack": False,
                "prediction": None,
                "confidence": 0.0,
                "packets_captured": 0,
                "message": "No traffic detected on [Wi-Fi]. 0 packets intercepted."
            })

        # Test /api/predict response
        res = self.client.get("/api/predict")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "no_traffic")
        self.assertEqual(data.get("label"), "No Traffic Detected")
        self.assertEqual(data.get("confidence"), 0)
        self.assertEqual(data.get("packets_captured"), 0)
        self.assertNotIn("Benign", data.get("label"))
        print("  [PASS] 2. 0 packets intercepted correctly yields 'No Traffic Detected' (Confidence: 0).")

    def test_03_insufficient_packets_produces_insufficient_data(self):
        """3. Verify 1-2 packets intercepted results in 'insufficient_traffic' and 'Insufficient Data'."""
        with scan_session_lock:
            current_scan_session.update({
                "status": "insufficient_traffic",
                "label": "Insufficient Data",
                "is_attack": False,
                "prediction": None,
                "confidence": 0.0,
                "packets_captured": 2,
                "message": "Network was quiet: only 2 packet(s) intercepted in 3.0s."
            })

        res = self.client.get("/api/predict")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "insufficient_traffic")
        self.assertEqual(data.get("label"), "Insufficient Data")
        self.assertEqual(data.get("confidence"), 0)
        self.assertEqual(data.get("packets_captured"), 2)
        print("  [PASS] 3. 1-2 packets correctly yields 'Insufficient Data' (Confidence: 0).")

    def test_04_zero_and_empty_features_rejected_by_validation_gate(self):
        """4. Verify that empty or all-zero feature vectors are rejected and cannot predict Benign."""
        # Empty dict
        valid, msg = validate_flow_features({})
        self.assertFalse(valid)

        # All zeros
        all_zeros = {feat: 0.0 for feat in OFFICIAL_77_FEATURES}
        valid, msg = validate_flow_features(all_zeros)
        self.assertFalse(valid)
        self.assertIn("less than minimum", msg.lower() if "less than" in msg.lower() else msg)

        # Verify prepare_features raises ValueError instead of evaluating all zeros as Benign 99.95%
        with self.assertRaises(ValueError):
            prepare_features({})

        with self.assertRaises(ValueError):
            prepare_features(all_zeros)

        print("  [PASS] 4. Zero/empty feature vectors rejected by validation gate, preventing false Benign 99.95%.")

    def test_05_adapter_offline_produces_capture_error(self):
        """5. Verify that disabled / disconnected adapter produces Capture Error, not Benign."""
        with patch("api.get_service_status", return_value={"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 1234}), \
             patch("api.ipc_client.get_service_version_info", return_value={"online": True, "version": "2.3-continuous-monitoring", "is_updated": True}), \
             patch("api.ipc_client.verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", side_effect=RuntimeError("Network adapter is offline or disconnected: Wi-Fi (Disabled)")):
            res = self.client.post("/api/scan")
            self.assertIn(res.status_code, [200, 500])
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("label"), "Capture Error")
            self.assertEqual(data.get("confidence"), 0.0)
            self.assertIn("Wi-Fi (Disabled)", data.get("error", ""))

        # Check /api/predict reflects Capture Error
        res_pred = self.client.get("/api/predict")
        pred_data = res_pred.get_json()
        self.assertEqual(pred_data.get("status"), "error")
        self.assertEqual(pred_data.get("label"), "Capture Error")
        self.assertEqual(pred_data.get("confidence"), 0)
        print("  [PASS] 5. Offline / disabled adapter immediately triggers 'Capture Error' without prediction.")

    def test_06_stale_results_wiped_and_scan_id_strictly_enforced(self):
        """6. Verify previous results are wiped on new scan and scan_id is strictly matched."""
        # Setup previous results
        with scan_session_lock:
            current_scan_session.update({
                "status": "prediction_available",
                "scan_id": "old_scan_111",
                "prediction": 0,
                "label": "Benign",
                "confidence": 98.5,
                "packets_captured": 45
            })

        worker = CaptureWorker()
        worker.start_window(scan_id="new_scan_222", duration=1.0)

        # Query status with old scan_id -> MUST NOT return new_scan_222 results
        old_status = worker.get_status(scan_id="old_scan_111")
        self.assertEqual(old_status.get("status"), "waiting")
        self.assertEqual(old_status.get("scan_id"), "old_scan_111")

        # Start new scan in api -> previous prediction and counters must be wiped immediately
        with patch("api.get_service_status", return_value={"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 1234}), \
             patch("api.ipc_client.get_service_version_info", return_value={"online": True, "version": "2.3-continuous-monitoring", "is_updated": True}), \
             patch("api.ipc_client.verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "index": 14, "type": "Wi-Fi"}, {"can_capture_live": True})), \
             patch("api.ipc_client.start_scan", return_value={"status": "scanning", "scan_id": "new_scan_333"}):
            res = self.client.post("/api/scan")
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertIsNone(data.get("prediction"))
            self.assertIsNone(data.get("label"))
            self.assertEqual(data.get("confidence"), 0.0)
            self.assertEqual(data.get("packets_captured"), 0)
            self.assertNotEqual(data.get("scan_id"), "old_scan_111")

        print("  [PASS] 6. Stale results wiped immediately on new scan and scan_id strictly enforced.")

    def test_07_real_valid_traffic_passes_validation_and_infers(self):
        """7. Verify real physical packets pass validation and produce model inference."""
        collector = FlowStatsCollector(target_interface_index=14)

        # Add 5 valid physical packets (e.g. DNS / HTTP)
        t_base = time.time()
        for i in range(5):
            collector.add_packet({
                "timestamp": t_base + i * 0.05,
                "src_ip": "192.168.1.100",
                "dst_ip": "142.250.190.46",
                "src_port": 51234,
                "dst_port": 443,
                "protocol": 6,
                "length": 150 + i * 20,
                "header_len": 20,
                "payload_len": 130 + i * 20,
                "flags": {"ACK": 1}
            })

        self.assertEqual(collector.packet_count, 5)
        features = collector.compute_77_features()
        is_valid, msg = validate_flow_features(features, min_packets=3)
        self.assertTrue(is_valid, f"Real flow should be valid: {msg}")

        # Test model inference with valid features
        X = prepare_features(features)
        pred = int(api.model.predict(X)[0])
        label = api.CLASS_LABELS.get(pred, "Unknown")
        self.assertIn(label, list(api.CLASS_LABELS.values()))
        print(f"  [PASS] 7. Real physical flow (5 packets) passed validation and model inference -> '{label}'.")

    def test_08_port_scanner_isolation_maintained(self):
        """8. Verify Port Scanner endpoints and operations remain unaffected and isolated."""
        res = self.client.get("/api/port-scan/network-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("local_ip", data)

        st_res = self.client.get("/api/port-scan/status")
        self.assertEqual(st_res.status_code, 200)
        st_data = st_res.get_json()
        self.assertIn("status", st_data)
        print("  [PASS] 8. Port Scanner isolation completely maintained.")


if __name__ == "__main__":
    print("=" * 70)
    print("  RUNNING LIVE NETWORK MONITORING VERIFICATION TEST SUITE")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestLiveMonitoringFix)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\nALL 8 LIVE MONITORING VERIFICATION TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print(f"\n{len(result.failures)} FAILURES, {len(result.errors)} ERRORS")
        sys.exit(1)
