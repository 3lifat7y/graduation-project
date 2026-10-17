#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Scapy + Npcap Capture Engine Comprehensive Offline Test Suite
Validates:
1. Packet parsing: synthetic TCP, UDP, IPv4, and IPv6 Scapy packets.
2. Loopback and internal management traffic exclusion (127.0.0.1, ::1, ports 5000 & 50505).
3. Exact 8-bit RFC 793 TCP flag bitmask extraction (FIN, SYN, RST, PSH, ACK, URG, ECE, CWE).
4. Exact 77 CIC-IDS2017 flow feature schema, naming, microsecond units, and ordering.
5. Champion ML model and StandardScaler pipeline compatibility without schema drift.
6. RollingFlowStatsCollector sliding window, time-based pruning, throughput & protocol tracking.
7. Active interface resolution for Wi-Fi and Ethernet adapters.
8. Driver diagnostics and error remediation for Npcap and Administrator privileges.
9. Offline capture window lifecycle and backward-compatibility aliases.
"""

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, IPv6, TCP, UDP, Raw, conf
from modules.monitoring.capture_engine import (
    FlowStatsCollector,
    RollingFlowStatsCollector,
    parse_scapy_packet,
    parse_windivert_packet,
    capture_window_scapy,
    capture_window_windivert,
    resolve_scapy_interface,
    validate_flow_features,
    OFFICIAL_77_FEATURES
)
from modules.common.network_detector import check_capture_drivers
import api
from api import prepare_features, model, scaler


class TestScapyNpcapEngine(unittest.TestCase):
    """Offline test suite for DDoS-Guard Npcap + Scapy packet capture and flow extraction."""

    def setUp(self):
        with api.scan_session_lock:
            api.current_scan_session["status"] = "idle"
            api.current_scan_session["scan_id"] = None
            api.is_monitoring = False

    def tearDown(self):
        with api.scan_session_lock:
            api.current_scan_session["status"] = "idle"
            api.current_scan_session["scan_id"] = None
            api.is_monitoring = False

    def test_01_parse_scapy_tcp_packet(self):
        """1. Verify Scapy TCP packet parsing: headers, window, payload, and ports."""
        raw_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packet = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(
            sport=49152, dport=80, flags="PA", seq=1000, window=65535
        ) / Raw(load=raw_payload)

        parsed = parse_scapy_packet(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "192.168.1.50")
        self.assertEqual(parsed["dst_ip"], "93.184.216.34")
        self.assertEqual(parsed["src_port"], 49152)
        self.assertEqual(parsed["dst_port"], 80)
        self.assertEqual(parsed["protocol"], 6)
        self.assertEqual(parsed["win_size"], 65535)
        self.assertGreaterEqual(parsed["header_len"], 20)
        self.assertEqual(parsed["payload_len"], len(raw_payload))
        self.assertEqual(parsed["flags"]["PSH"], 1)
        self.assertEqual(parsed["flags"]["ACK"], 1)
        self.assertEqual(parsed["flags"]["SYN"], 0)
        self.assertEqual(parsed["flags"]["FIN"], 0)
        self.assertFalse(parsed["is_loopback"])
        print("  [PASS] 1. Scapy TCP packet parsing and field extraction verified.")

    def test_02_parse_scapy_udp_packet(self):
        """2. Verify Scapy UDP packet parsing: DNS query inspection."""
        dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        packet = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=53535, dport=53) / Raw(load=dns_query)

        parsed = parse_scapy_packet(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "10.0.0.5")
        self.assertEqual(parsed["dst_ip"], "8.8.8.8")
        self.assertEqual(parsed["src_port"], 53535)
        self.assertEqual(parsed["dst_port"], 53)
        self.assertEqual(parsed["protocol"], 17)
        self.assertEqual(parsed["header_len"], 8)
        self.assertEqual(parsed["payload_len"], len(dns_query))
        self.assertFalse(parsed["is_loopback"])
        print("  [PASS] 2. Scapy UDP packet parsing verified.")

    def test_03_parse_scapy_ipv6_packet(self):
        """3. Verify IPv6 Scapy packet parsing."""
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1024, dport=443, flags="S", window=32768)
        parsed = parse_scapy_packet(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "2001:db8::1")
        self.assertEqual(parsed["dst_ip"], "2001:db8::2")
        self.assertEqual(parsed["protocol"], 6)
        self.assertEqual(parsed["flags"]["SYN"], 1)
        print("  [PASS] 3. Scapy IPv6 packet parsing verified.")

    def test_04_loopback_and_internal_management_exclusion(self):
        """4. Verify strict exclusion of loopback (127.0.0.0/8, ::1) and local ports (5000, 50505)."""
        # 127.0.0.1
        pkt_loopback = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=55555, dport=80)
        self.assertIsNone(parse_scapy_packet(pkt_loopback))

        # 127.0.0.2
        pkt_loopback_subnet = IP(src="127.0.0.2", dst="192.168.1.1") / UDP(sport=1234, dport=53)
        self.assertIsNone(parse_scapy_packet(pkt_loopback_subnet))

        # IPv6 loopback ::1
        pkt_v6_loopback = IPv6(src="::1", dst="::1") / TCP(sport=55555, dport=80)
        self.assertIsNone(parse_scapy_packet(pkt_v6_loopback))

        # Local web UI port 5000 (Source)
        pkt_flask_src = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5000, dport=54321)
        self.assertIsNone(parse_scapy_packet(pkt_flask_src))

        # Local web UI port 5000 (Destination)
        pkt_flask_dst = IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=54321, dport=5000)
        self.assertIsNone(parse_scapy_packet(pkt_flask_dst))

        # Local IPC port 50505 (Source)
        pkt_ipc_src = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50505, dport=54321)
        self.assertIsNone(parse_scapy_packet(pkt_ipc_src))

        # Local IPC port 50505 (Destination)
        pkt_ipc_dst = IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=54321, dport=50505)
        self.assertIsNone(parse_scapy_packet(pkt_ipc_dst))

        print("  [PASS] 4. Loopback and management traffic (5000, 50505) strictly rejected.")

    def test_05_tcp_flags_rfc793_bitmask(self):
        """5. Verify all 8 TCP flags via exact RFC 793 bitmask extraction."""
        test_flags = [
            ("F", {"FIN": 1, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0}),
            ("S", {"FIN": 0, "SYN": 1, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0}),
            ("R", {"FIN": 0, "SYN": 0, "RST": 1, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0}),
            ("P", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 1, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0}),
            ("A", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 1, "URG": 0, "ECE": 0, "CWE": 0}),
            ("U", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 1, "ECE": 0, "CWE": 0}),
            ("E", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 1, "CWE": 0}),
            ("C", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 1}),
            ("SA", {"FIN": 0, "SYN": 1, "RST": 0, "PSH": 0, "ACK": 1, "URG": 0, "ECE": 0, "CWE": 0}),
            ("FA", {"FIN": 1, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 1, "URG": 0, "ECE": 0, "CWE": 0}),
            ("PA", {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 1, "ACK": 1, "URG": 0, "ECE": 0, "CWE": 0}),
        ]

        for flag_str, expected in test_flags:
            pkt = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=80, flags=flag_str)
            parsed = parse_scapy_packet(pkt)
            self.assertIsNotNone(parsed)
            for flag_name, expected_val in expected.items():
                self.assertEqual(
                    parsed["flags"].get(flag_name, 0),
                    expected_val,
                    f"Flag '{flag_name}' for '{flag_str}' expected {expected_val} but got {parsed['flags'].get(flag_name)}"
                )

        print("  [PASS] 5. RFC 793 TCP flags (FIN/SYN/RST/PSH/ACK/URG/ECE/CWE) bitmask verified.")

    def test_06_exact_77_features_and_ordering_preservation(self):
        """6. Verify FlowStatsCollector preserves all 77 CIC-IDS2017 features in exact order."""
        collector = FlowStatsCollector()
        t0 = 1700000000.0

        # Simulate synthetic two-way TCP flow with Scapy packets
        # Packet 1 (SYN) Fwd
        p1 = IP(src="192.168.1.100", dst="142.250.190.46") / TCP(sport=50001, dport=443, flags="S", window=64240)
        p1.time = t0
        collector.add_packet(parse_scapy_packet(p1))

        # Packet 2 (SYN-ACK) Bwd
        p2 = IP(src="142.250.190.46", dst="192.168.1.100") / TCP(sport=443, dport=50001, flags="SA", window=65535)
        p2.time = t0 + 0.025
        collector.add_packet(parse_scapy_packet(p2))

        # Packet 3 (ACK) Fwd
        p3 = IP(src="192.168.1.100", dst="142.250.190.46") / TCP(sport=50001, dport=443, flags="A", window=64240)
        p3.time = t0 + 0.030
        collector.add_packet(parse_scapy_packet(p3))

        # Packet 4 (DATA) Fwd
        p4 = IP(src="192.168.1.100", dst="142.250.190.46") / TCP(sport=50001, dport=443, flags="PA", window=64240) / Raw(load=b"TLS_CLIENT_HELLO_DATA")
        p4.time = t0 + 0.050
        collector.add_packet(parse_scapy_packet(p4))

        # Packet 5 (ACK) Bwd
        p5 = IP(src="142.250.190.46", dst="192.168.1.100") / TCP(sport=443, dport=50001, flags="A", window=65535)
        p5.time = t0 + 0.075
        collector.add_packet(parse_scapy_packet(p5))

        self.assertEqual(collector.packet_count, 5)

        features = collector.compute_77_features()
        self.assertEqual(len(features), 77)

        # Strict feature schema ordering check
        feature_names = list(features.keys())
        self.assertEqual(feature_names, OFFICIAL_77_FEATURES, "77 features must strictly follow OFFICIAL_77_FEATURES ordering.")

        # Check key calculated values
        self.assertEqual(features["Protocol"], 6.0)
        self.assertEqual(features["Total Fwd Packets"], 3.0)
        self.assertEqual(features["Total Backward Packets"], 2.0)
        self.assertGreater(features["Flow Duration"], 0.0)
        self.assertEqual(features["Init Fwd Win Bytes"], 64240.0)
        self.assertEqual(features["Init Bwd Win Bytes"], 65535.0)
        self.assertEqual(features["SYN Flag Count"], 2.0)
        self.assertEqual(features["ACK Flag Count"], 4.0)
        self.assertEqual(features["PSH Flag Count"], 1.0)

        # Validation gate check
        is_valid, reason = validate_flow_features(features, min_packets=3)
        self.assertTrue(is_valid, f"Validation gate failed: {reason}")
        print("  [PASS] 6. Exact 77 CIC-IDS2017 features, ordering, and calculations verified.")

    def test_07_model_and_scaler_compatibility(self):
        """7. Verify model and StandardScaler pipeline process Scapy-extracted features seamlessly."""
        collector = FlowStatsCollector()
        t0 = 1700000000.0
        for i in range(10):
            p = IP(src="192.168.1.200", dst="1.1.1.1") / TCP(
                sport=40000 + i, dport=443, flags="A", window=64000
            ) / Raw(load=b"X" * 100)
            p.time = t0 + (i * 0.01)
            collector.add_packet(parse_scapy_packet(p))

        feats = collector.compute_77_features()
        payload = {"features": feats}

        # prepare_features validates and transforms using StandardScaler
        X = prepare_features(payload)
        self.assertEqual(X.shape, (1, 77), "Scaled feature array must have shape (1, 77)")

        # Run inference through loaded model
        pred = model.predict(X)
        probs = model.predict_proba(X)
        self.assertEqual(len(pred), 1)
        self.assertEqual(probs.shape[1], 15, "Model must evaluate across all 15 trained classes.")
        print(f"  [PASS] 7. ML Model Pipeline: Evaluated Scapy flow -> Class={pred[0]}, Confidence={probs[0][pred[0]]:.4f}.")

    def test_08_rolling_flow_collector_windowing_with_scapy(self):
        """8. Verify RollingFlowStatsCollector sliding window with Scapy packets."""
        collector = RollingFlowStatsCollector(window_seconds=1.5)
        t_base = time.time()

        for i in range(6):
            p = IP(src="10.10.10.10", dst="20.20.20.20") / UDP(sport=50000 + i, dport=53) / Raw(load=b"data")
            p.time = t_base + (i * 0.1)
            collector.add_packet(parse_scapy_packet(p))

        snap = collector.get_window_snapshot(now=t_base + 0.6, min_packets=3)
        self.assertEqual(snap["status"], "monitoring")
        self.assertEqual(snap["window_packets"], 6)
        self.assertEqual(snap["protocol"], 17)
        self.assertGreater(snap["throughput_kbps"], 0.0)
        self.assertEqual(len(snap["features"]), 77)
        print("  [PASS] 8. RollingFlowStatsCollector sliding window with Scapy verified.")

    def test_09_interface_selection_resolution(self):
        """9. Verify resolve_scapy_interface resolves friendly names and handles fallbacks."""
        # Friendly name
        res_wifi = resolve_scapy_interface("Wi-Fi")
        self.assertIsNotNone(res_wifi)

        res_eth = resolve_scapy_interface("Ethernet")
        self.assertIsNotNone(res_eth)

        # None input
        res_none = resolve_scapy_interface(None)
        self.assertIsNone(res_none)

        # Unknown interface returns None strictly to prevent default substitution
        res_custom = resolve_scapy_interface("NonExistentAdapterXYZ")
        self.assertIsNone(res_custom, "Unresolvable interface must return None, never default interface.")
        print("  [PASS] 9. Interface selection and resolution verified.")

    def test_10_driver_health_and_remediation_diagnostics(self):
        """10. Verify check_capture_drivers reports Npcap/Scapy readiness and actionable errors."""
        # Test current system detection
        drivers = check_capture_drivers()
        self.assertTrue(drivers["scapy_available"], "Scapy must be reported as available.")
        self.assertIn("npcap_installed", drivers)
        self.assertIn("can_capture_live", drivers)

        # Test simulated missing Npcap driver
        with patch("modules.common.network_detector.Path.exists", return_value=False), \
             patch("subprocess.run", side_effect=Exception("Driver not found")):
            sim_drivers = check_capture_drivers()
            self.assertFalse(sim_drivers["npcap_installed"])
            self.assertIn("https://npcap.com", sim_drivers["remediation_guide"])

        # Test simulated restricted driver without admin or pcap access
        orig_pcap = getattr(conf, "use_pcap", None)
        try:
            conf.use_pcap = False
            with patch("modules.common.network_detector.is_admin_user", return_value=False):
                sim_drivers_nonadmin = check_capture_drivers()
                self.assertFalse(sim_drivers_nonadmin["is_admin"])
                if sim_drivers_nonadmin["npcap_installed"]:
                    self.assertFalse(sim_drivers_nonadmin["can_capture_live"])
                    self.assertIn("Administrator", sim_drivers_nonadmin["remediation_guide"])
        finally:
            if orig_pcap is not None:
                conf.use_pcap = orig_pcap

        print("  [PASS] 10. Driver health and actionable remediation diagnostics verified.")

    def test_11_backward_compatibility_aliases(self):
        """11. Verify WinDivert aliases point directly to Scapy implementations."""
        self.assertIs(parse_windivert_packet, parse_scapy_packet)
        self.assertIs(capture_window_windivert, capture_window_scapy)
        print("  [PASS] 11. Backward compatibility aliases verified.")

    def test_12_interface_propagation_in_scan_request(self):
        """12. Verify selected Wi-Fi/Ethernet interface propagates from /api/scan into adapter_info."""
        import api
        client = api.app.test_client()
        mock_svc = {"installed": False, "status": "NOT_INSTALLED", "running": False, "ipc_online": False}

        with patch("api.get_service_status", return_value=mock_svc), \
             patch("api.check_capture_drivers", return_value={"can_capture_live": True}), \
             patch("api.run_scan_worker") as mock_worker:
            res = client.post("/api/scan", json={
                "interface_name": "Wi-Fi",
                "interface_index": 8,
                "continuous": True
            })
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertEqual(data["interface"]["name"], "Wi-Fi")
            mock_worker.assert_called_once()
            args = mock_worker.call_args[0]
            # args: (scan_id, adapter_info, driver_info, duration, min_packets, continuous)
            self.assertEqual(args[1]["name"], "Wi-Fi")
            self.assertEqual(args[1]["index"], 8)
        print("  [PASS] 12. Interface propagation from /api/scan to worker verified.")

    def test_13_missing_interface_explicit_error(self):
        """13. Verify requested non-existent interface returns explicit InterfaceNotFound error."""
        import api
        client = api.app.test_client()
        res = client.post("/api/scan", json={
            "interface_name": "Ghost_Interface_DoesNotExist_9999",
            "interface_index": 99999
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data.get("error_type"), "InterfaceNotFound")
        self.assertIn("could not be resolved", data.get("error", ""))
        print("  [PASS] 13. Missing interface explicit rejection without substitution verified.")

    def test_14_capture_window_missing_interface(self):
        """14. Verify capture_window_scapy aborts immediately when interface cannot be resolved."""
        status, feats = capture_window_scapy(interface_name="FakeAdapter123", interface_index=88888)
        self.assertEqual(status.get("status"), "error")
        self.assertEqual(status.get("error_type"), "InterfaceNotFound")
        self.assertEqual(status.get("packets_captured"), 0)
        print("  [PASS] 14. capture_window_scapy missing interface rejection verified.")

    def test_15_permission_error_handling_and_traceback(self):
        """15. Verify PermissionError logs full traceback and returns DriverPermissionError with zero predictions."""
        with patch("scapy.all.sniff", side_effect=PermissionError("[WinError 5] Access is denied")):
            status, feats = capture_window_scapy(interface_name="Wi-Fi", interface_index=8)
            self.assertEqual(status.get("status"), "error")
            self.assertEqual(status.get("error_type"), "DriverPermissionError")
            self.assertIn("PermissionError", status.get("message", ""))
            self.assertIn("traceback", status)
            self.assertIn("Access is denied", status["traceback"])
        print("  [PASS] 15. PermissionError handling with full traceback verified.")

    def test_16_service_capture_worker_permission_and_traceback(self):
        """16. Verify CaptureWorker handles PermissionError with clean state and traceback."""
        from modules.monitoring.service import CaptureWorker
        worker = CaptureWorker()
        with patch("scapy.all.AsyncSniffer.start", side_effect=PermissionError("[WinError 5] Access is denied")):
            res = worker.start_window(
                scan_id="test_perm_scan",
                duration=1.0,
                min_packets=1,
                interface_name="Wi-Fi",
                interface_index=8,
                continuous=True
            )
            t0 = time.time()
            while worker.is_capturing and (time.time() - t0) < 3.0:
                time.sleep(0.05)
            st = worker.get_status("test_perm_scan")
            self.assertEqual(st.get("status"), "error")
            self.assertEqual(st.get("error_type"), "DriverPermissionError")
            self.assertIn("traceback", st)
        print("  [PASS] 16. Service CaptureWorker PermissionError handling verified.")

    def test_17_callback_execution_and_counter_updates(self):
        """17. Verify Scapy packet callback runs, increments total_packets_seen, and updates status snapshots."""
        from modules.monitoring.service import CaptureWorker
        worker = CaptureWorker()
        scan_id = "test_cb_counter_scan"

        # CaptureWorker starts in ready state
        self.assertEqual(worker.get_status(scan_id).get("status"), "waiting")

        # Simulate AsyncSniffer.start capturing actual packets via the prn callback
        captured_callbacks = []
        def fake_sniffer_init(*args, **kwargs):
            if "prn" in kwargs:
                captured_callbacks.append(kwargs["prn"])
            mock_sniff = MagicMock()
            mock_sniff.start = MagicMock()
            mock_sniff.stop = MagicMock()
            return mock_sniff

        with patch("modules.monitoring.service.AsyncSniffer", side_effect=fake_sniffer_init):
            res = worker.start_window(
                scan_id=scan_id,
                duration=3.0,
                min_packets=3,
                interface_name="Wi-Fi",
                interface_index=8,
                continuous=True
            )
            self.assertEqual(res.get("status"), "scanning")
            for _ in range(50):
                if captured_callbacks:
                    break
                time.sleep(0.02)
            self.assertTrue(len(captured_callbacks) > 0, "Packet callback prn must be registered with AsyncSniffer.")
            prn_callback = captured_callbacks[0]

            # Before any packet arrives, status must be no_traffic with 0 packets (never marked monitoring prematurely)
            init_status = worker.get_status(scan_id)
            self.assertEqual(init_status.get("status"), "no_traffic")
            self.assertEqual(init_status.get("packets_captured"), 0)

            # Feed 2 synthetic packets (below min_packets=3)
            p1 = IP(src="192.168.1.9", dst="142.250.190.46") / TCP(sport=54321, dport=443, flags="A")
            p2 = IP(src="142.250.190.46", dst="192.168.1.9") / TCP(sport=443, dport=54321, flags="PA") / Raw(b"DATA")
            prn_callback(p1)
            prn_callback(p2)

            # Status should be insufficient_traffic with 2 packets
            low_status = worker.get_status(scan_id)
            self.assertEqual(low_status.get("status"), "insufficient_traffic")
            self.assertEqual(low_status.get("packets_captured"), 2)
            self.assertEqual(low_status.get("window_packets"), 2)

            # Feed 3rd and 4th packets (meeting min_packets=3)
            p3 = IP(src="192.168.1.9", dst="142.250.190.46") / TCP(sport=54321, dport=443, flags="A")
            p4 = IP(src="142.250.190.46", dst="192.168.1.9") / TCP(sport=443, dport=54321, flags="A")
            prn_callback(p3)
            prn_callback(p4)

            # Status should now transition to monitoring with exact 77 features
            ready_status = worker.get_status(scan_id)
            self.assertEqual(ready_status.get("status"), "monitoring")
            self.assertEqual(ready_status.get("packets_captured"), 4)
            self.assertEqual(ready_status.get("window_packets"), 4)
            self.assertIn("features", ready_status)
            self.assertEqual(len(ready_status["features"]), 77)

            # Halt worker
            worker.stop_window()
            self.assertFalse(worker.is_capturing)
        print("  [PASS] 17. Packet callback execution, counter increments, and status transitions verified.")

    def test_18_ui_api_telemetry_propagation_and_status_transitions(self):
        """18. Verify API telemetry reflects true packet counts and status transitions without premature monitoring."""
        client = api.app.test_client()
        mock_svc = {"installed": False, "status": "NOT_INSTALLED", "running": False, "ipc_online": False}

        # Simulate start_scan with 0 initial packets
        with patch("api.get_service_status", return_value=mock_svc), \
             patch("api.check_capture_drivers", return_value={"can_capture_live": True}), \
             patch("api.run_scan_worker"):
            res = client.post("/api/scan", json={
                "interface_name": "Wi-Fi",
                "interface_index": 8,
                "continuous": True,
                "min_packets": 3
            })
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            # Must NOT be marked monitoring before capture is confirmed
            self.assertEqual(data.get("status"), "scanning")
            self.assertEqual(data.get("packets_captured"), 0)
            self.assertIsNone(data.get("prediction"))

            # Simulate worker polling status with no traffic
            with api.scan_session_lock:
                api.current_scan_session.update({
                    "status": "no_traffic",
                    "label": "No Traffic Detected",
                    "packets_captured": 0,
                    "window_packets": 0,
                    "throughput_kbps": 0.0
                })
            poll_res = client.get("/api/scan-status")
            poll_data = poll_res.get_json()
            self.assertEqual(poll_data.get("status"), "no_traffic")
            self.assertEqual(poll_data.get("packets_captured"), 0)
            self.assertIsNone(poll_data.get("prediction"))

            # Simulate worker receiving real traffic and updating session
            with api.scan_session_lock:
                api.current_scan_session.update({
                    "status": "monitoring",
                    "label": "Benign",
                    "prediction": 0,
                    "confidence": 99.8,
                    "packets_captured": 56,
                    "window_packets": 14,
                    "throughput_kbps": 12.4,
                    "protocol": "TCP (6)"
                })
            active_poll = client.get("/api/scan-status")
            active_data = active_poll.get_json()
            self.assertEqual(active_data.get("status"), "monitoring")
            self.assertEqual(active_data.get("packets_captured"), 56)
            self.assertEqual(active_data.get("window_packets"), 14)
            self.assertEqual(active_data.get("throughput_kbps"), 12.4)
            self.assertEqual(active_data.get("label"), "Benign")
            self.assertEqual(active_data.get("confidence"), 99.8)

            # Test stopping scan
            stop_res = client.post("/api/scan-stop")
            self.assertEqual(stop_res.status_code, 200)
            stopped_data = client.get("/api/scan-status").get_json()
            self.assertEqual(stopped_data.get("status"), "stopped")
            self.assertEqual(stopped_data.get("packets_captured"), 56)

        print("  [PASS] 18. API telemetry propagation, exact packet count tracking, and clean stop verified.")


if __name__ == "__main__":
    unittest.main()

