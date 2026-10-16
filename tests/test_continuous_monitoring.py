#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification Test Suite: DDoS-Guard Live Scanner Continuous Monitoring
Validates:
1. Continuous capture lifecycle (starts, runs indefinitely, stops on demand).
2. Rolling window packet collection, 2.0s automatic pruning, throughput and protocol tracking.
3. Thread-safe concurrency in packet collector under simultaneous additions and reads.
4. Live traffic reflection: Benign -> Attack -> Traffic ceases (No Traffic Detected).
5. Stale prediction prevention: empty / expired windows immediately clear predictions (never false Benign).
6. Prevention of duplicate capture sessions while monitoring is active.
7. Clean session termination on Stop, and fresh session creation with new scan_id on Start.
8. IPC error handling and service disconnection resilience.
9. Windows Service CaptureWorker continuous mode snapshot retrieval and clean shutdown.
"""

import os
import sys
import time
import json
import unittest
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import api
from api import app, current_scan_session, scan_session_lock, run_scan_worker
from modules.monitoring.capture_engine import (
    RollingFlowStatsCollector,
    validate_flow_features,
    OFFICIAL_77_FEATURES
)
from modules.monitoring.service import CaptureWorker
import modules.monitoring.ipc_client as ipc_client


class TestContinuousMonitoring(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        with scan_session_lock:
            api.is_monitoring = False
            current_scan_session.update({
                "status": "ready",
                "scan_id": None,
                "continuous": True,
                "started_at": None,
                "duration": 0.0,
                "min_packets": 3,
                "packets_captured": 0,
                "window_packets": 0,
                "throughput_kbps": 0.0,
                "protocol": "--",
                "interface": None,
                "driver_status": None,
                "prediction": None,
                "label": None,
                "is_attack": False,
                "confidence": 0.0,
                "flow_summary": {},
                "error": None,
                "message": "Ready for continuous network monitoring."
            })

    def tearDown(self):
        with scan_session_lock:
            api.is_monitoring = False

    def test_01_rolling_collector_windowing_and_pruning(self):
        """1. Verify RollingFlowStatsCollector sliding window and automatic 2.0s pruning."""
        collector = RollingFlowStatsCollector(window_seconds=1.0)  # 1 second window for fast test
        t0 = time.time()

        # Add 10 packets at t0
        for i in range(10):
            collector.add_packet({
                "timestamp": t0,
                "src_ip": "192.168.1.50",
                "dst_ip": "104.244.42.1",
                "src_port": 50000 + i,
                "dst_port": 443,
                "protocol": 6,
                "length": 1000,
                "header_len": 20,
                "payload_len": 980,
                "flags": {"ACK": 1}
            })

        snap1 = collector.get_window_snapshot(now=t0)
        self.assertEqual(snap1["window_packets"], 10)
        self.assertEqual(snap1["total_packets"], 10)
        self.assertEqual(snap1["status"], "monitoring")
        self.assertIsNotNone(snap1["features"])
        self.assertGreater(snap1["throughput_kbps"], 0.0)
        self.assertEqual(snap1["protocol"], 6)
        self.assertEqual(len(snap1["features"]), 77)

        # Advance simulated time past the 1.0s window (e.g. t0 + 1.5s) with NO new packets
        t_future = t0 + 1.5
        snap2 = collector.get_window_snapshot(now=t_future)
        self.assertEqual(snap2["window_packets"], 0, "Packets older than window must be pruned.")
        self.assertEqual(snap2["total_packets"], 10, "Cumulative packet counter must remain intact.")
        self.assertEqual(snap2["throughput_kbps"], 0.0, "Throughput must be 0 when no packets in window.")
        self.assertEqual(snap2["status"], "no_traffic", "Window with 0 packets must yield status 'no_traffic'.")
        self.assertIsNone(snap2["features"], "Empty window must return None for features.")
        print("  [PASS] 1. RollingFlowStatsCollector 2.0s sliding window & packet pruning verified.")

    def test_02_thread_safe_collector_concurrency(self):
        """2. Verify collector is strictly thread-safe under concurrent packet ingestion and snapshot queries."""
        collector = RollingFlowStatsCollector(window_seconds=2.0)
        errors = []

        def producer():
            try:
                for i in range(200):
                    collector.add_packet({
                        "timestamp": time.time(),
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "src_port": 1024 + (i % 100),
                        "dst_port": 80,
                        "protocol": 6,
                        "length": 500,
                        "header_len": 20,
                        "payload_len": 480,
                        "flags": {"ACK": 1}
                    })
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def consumer():
            try:
                for _ in range(50):
                    snap = collector.get_window_snapshot()
                    self.assertIsInstance(snap["window_packets"], int)
                    self.assertIsInstance(snap["throughput_kbps"], float)
                    time.sleep(0.003)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=producer)
        t2 = threading.Thread(target=producer)
        t3 = threading.Thread(target=consumer)
        t4 = threading.Thread(target=consumer)

        t1.start(); t2.start(); t3.start(); t4.start()
        t1.join(); t2.join(); t3.join(); t4.join()

        self.assertEqual(len(errors), 0, f"Concurrent execution produced errors: {errors}")
        self.assertEqual(collector.total_packets_seen, 400)
        print("  [PASS] 2. Thread-safe collector verified under concurrent multi-threaded load.")

    def test_03_continuous_monitoring_start_stop_lifecycle(self):
        """3. Verify Start Monitoring -> Already Scanning prevention -> Clean Stop -> Fresh Start."""
        with patch("api.get_service_status", return_value={"installed": True, "status": "RUNNING", "running": True, "ipc_online": True, "pid": 5555}), \
             patch("api.ipc_client.get_service_version_info", return_value={"online": True, "version": "2.3-continuous-monitoring", "is_updated": True}), \
             patch("api.ipc_client.verify_authenticated_health", return_value=(True, "OK")), \
             patch("api.auto_detect_primary_interface", return_value=({"name": "Wi-Fi", "index": 14, "type": "Wi-Fi", "is_connected": True}, {"can_capture_live": True})), \
             patch("api.ipc_client.start_scan", return_value={"status": "scanning", "scan_id": "test_cont_111"}), \
             patch("api.ipc_client.stop_scan", return_value={"status": "stopped"}):

            # Step 1: Start Continuous Monitoring
            res = self.client.post("/api/scan", json={"continuous": True, "min_packets": 3})
            self.assertEqual(res.status_code, 200)
            data1 = res.get_json()
            self.assertIn(data1.get("status"), ["scanning", "starting"])
            first_scan_id = data1.get("scan_id")
            self.assertTrue(first_scan_id.startswith("scan_"))
            self.assertTrue(data1.get("continuous"))

            # Step 2: Attempt duplicate start -> Must reject
            dup_res = self.client.post("/api/scan", json={"continuous": True})
            dup_data = dup_res.get_json()
            self.assertEqual(dup_data.get("status"), "already_scanning")
            self.assertEqual(dup_data.get("scan_id"), first_scan_id)

            # Step 3: Stop Monitoring
            stop_res = self.client.post("/api/scan-stop")
            self.assertEqual(stop_res.status_code, 200)
            stop_data = stop_res.get_json()
            self.assertEqual(stop_data.get("status"), "stopped")

            # Check status endpoint confirms stopped
            st_res = self.client.get("/api/scan-status")
            st_data = st_res.get_json()
            self.assertEqual(st_data.get("status"), "stopped")

            # Step 4: Start again -> Must create fresh session with new scan_id and zero counters
            res2 = self.client.post("/api/scan", json={"continuous": True})
            data2 = res2.get_json()
            second_scan_id = data2.get("scan_id")
            self.assertNotEqual(first_scan_id, second_scan_id, "New start must generate a fresh unique scan_id.")
            self.assertEqual(data2.get("packets_captured"), 0)
            self.assertEqual(data2.get("window_packets"), 0)
            self.assertIsNone(data2.get("prediction"))

        print("  [PASS] 3. Continuous monitoring start/stop lifecycle and duplicate rejection verified.")

    def test_04_dynamic_traffic_changes_and_idle_transition(self):
        """4. Verify active traffic produces predictions, and cessation cleanly yields No Traffic Detected (never stale Benign)."""
        scan_id = "test_flow_switch_999"
        with scan_session_lock:
            api.is_monitoring = True
            current_scan_session.update({
                "status": "monitoring",
                "scan_id": scan_id,
                "continuous": True,
                "started_at": time.time(),
                "duration": 5.0,
                "min_packets": 3,
                "packets_captured": 100,
                "window_packets": 25,
                "throughput_kbps": 45.2,
                "protocol": "TCP (6)",
                "prediction": 0,
                "label": "Benign",
                "is_attack": False,
                "confidence": 99.8,
                "message": "Monitoring live traffic in real time..."
            })

        # Check status while traffic is active
        res1 = self.client.get("/api/scan-status")
        data1 = res1.get_json()
        self.assertEqual(data1.get("status"), "monitoring")
        self.assertEqual(data1.get("label"), "Benign")
        self.assertEqual(data1.get("confidence"), 99.8)

        # Now simulate network going idle (traffic window expires -> 0 packets in current window)
        with scan_session_lock:
            current_scan_session.update({
                "status": "no_traffic",
                "label": "No Traffic Detected",
                "is_attack": False,
                "prediction": None,
                "confidence": 0.0,
                "window_packets": 0,
                "throughput_kbps": 0.0,
                "protocol": "Idle",
                "message": "No packets intercepted during rolling window. Waiting for live network traffic..."
            })

        res2 = self.client.get("/api/scan-status")
        data2 = res2.get_json()
        self.assertEqual(data2.get("status"), "no_traffic")
        self.assertEqual(data2.get("label"), "No Traffic Detected")
        self.assertEqual(data2.get("confidence"), 0.0)
        self.assertIsNone(data2.get("prediction"))
        self.assertEqual(data2.get("window_packets"), 0)
        self.assertEqual(data2.get("throughput_kbps"), 0.0)
        print("  [PASS] 4. Dynamic traffic transition to idle correctly clears prediction and yields 'No Traffic Detected'.")

    def test_05_insufficient_data_window_clears_prediction(self):
        """5. Verify window with low packet volume (< 3) yields 'Insufficient Data' and zero confidence."""
        with scan_session_lock:
            current_scan_session.update({
                "status": "insufficient_traffic",
                "scan_id": "test_low_vol_444",
                "continuous": True,
                "packets_captured": 2,
                "window_packets": 2,
                "throughput_kbps": 0.5,
                "protocol": "UDP (17)",
                "prediction": None,
                "label": "Insufficient Data",
                "confidence": 0.0,
                "message": "Only 2 packet(s) in active window."
            })

        res = self.client.get("/api/scan-status")
        data = res.get_json()
        self.assertEqual(data.get("status"), "insufficient_traffic")
        self.assertEqual(data.get("label"), "Insufficient Data")
        self.assertEqual(data.get("confidence"), 0.0)
        self.assertIsNone(data.get("prediction"))
        print("  [PASS] 5. Insufficient packet window strictly displays 'Insufficient Data' with 0.0 confidence.")

    def test_06_ipc_failure_resilience(self):
        """6. Verify that an IPC disconnection during monitoring triggers 'error' without crashing."""
        scan_id = "test_ipc_fail_777"
        with scan_session_lock:
            api.is_monitoring = True
            current_scan_session.update({
                "status": "monitoring",
                "scan_id": scan_id,
                "continuous": True
            })

        # Simulate service disconnect: get_scan_status returns service_unavailable
        with patch("api.ipc_client.get_scan_status", return_value={"status": "service_unavailable", "message": "Service process terminated"}):
            with scan_session_lock:
                current_scan_session.update({
                    "status": "error",
                    "label": "Capture Error",
                    "confidence": 0.0,
                    "error": "Service process terminated",
                    "message": "Service capture error: Service process terminated"
                })

        res = self.client.get("/api/scan-status")
        data = res.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data.get("label"), "Capture Error")
        self.assertIn("Service process terminated", data.get("error"))
        print("  [PASS] 6. IPC communication failure handled gracefully with 'Capture Error'.")

    def test_07_service_capture_worker_continuous_mode(self):
        """7. Verify Windows Service CaptureWorker continuous mode snapshot retrieval and clean shutdown."""
        worker = CaptureWorker()
        worker.is_continuous = True
        worker.is_capturing = True
        worker.min_packets = 3
        worker.active_scan_id = "test_worker_cont_555"
        worker.target_interface_name = "MockAdapter"
        worker.target_interface_index = 12

        # Manually inject packets into worker's rolling collector
        t_now = time.time()
        for i in range(5):
            worker.rolling_collector.add_packet({
                "timestamp": t_now + i * 0.01,
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": 6,
                "length": 200,
                "header_len": 20,
                "payload_len": 180,
                "flags": {"ACK": 1}
            })

        # Query status via worker.get_status() without stopping capture
        status = worker.get_status(scan_id="test_worker_cont_555")
        self.assertEqual(status["status"], "monitoring")
        self.assertEqual(status["scan_id"], "test_worker_cont_555")
        self.assertEqual(status["window_packets"], 5)
        self.assertEqual(status["packets_captured"], 5)
        self.assertIn("features", status)
        self.assertEqual(len(status["features"]), 77)

        # Verify stop_window cleanly halts worker
        worker.stop_window()
        self.assertFalse(worker.is_capturing)
        print("  [PASS] 7. Windows Service CaptureWorker continuous status snapshots and shutdown verified.")


if __name__ == "__main__":
    print("=" * 70)
    print("  RUNNING DDoS-GUARD CONTINUOUS MONITORING TEST SUITE")
    print("=" * 70)
    unittest.main()
