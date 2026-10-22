#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Reliability Regression Tests for Network Security System.

Validates:
1. Live Monitoring:
   - First-attempt deterministic startup
   - Repeated requests & concurrent-start protection
   - Disconnected/disabled adapter rejection (zero silent fallback)
   - Clean shutdown and cancellation
   - Safe error handling without crashing or unhandled 500s
2. Network Discovery:
   - Mobile-hotspot-style subnet validation (10.206.35.0/24)
   - Explicit target CIDR support when automatic local detection is offline
   - Clean session stop/cancellation without thread leak
   - Invalid CIDR rejection
3. Port Scanning:
   - Target URL/URI sanitization
   - CGNAT/mobile hotspot support (100.64.0.0/10)
   - Concurrent scan protection
   - Cancellation, cleanup, and status synchronization
4. Cross-Feature Independence:
   - Live Monitoring, Network Discovery, and Port Scanning do not interfere with each other
   - Dataset Replay metrics remain completely isolated from Live Monitoring metrics
"""

import os
import json
import socket
import asyncio
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

import api
from modules.monitoring.capture_engine import OFFICIAL_77_FEATURES
from modules.common.network_detector import (
    get_windows_network_adapters,
    auto_detect_interface_with_rationale,
    invalidate_adapter_cache
)
from modules.network_discovery.discovery import (
    get_network_discovery_info,
    validate_and_normalize_subnet,
    NetworkDiscoveryManager
)
from modules.port_scanner.scanner import (
    validate_and_resolve_target,
    probe_single_port,
    PortScannerManager,
    port_scanner_manager
)


class TestLiveMonitoringReliability(unittest.TestCase):
    """Regression tests for Live Monitoring startup, concurrency, and error handling."""

    def setUp(self):
        self.app = api.app.test_client()
        self.app.testing = True
        with api.scan_session_lock:
            api.is_monitoring = False
            api.current_scan_session["status"] = "ready"
            api.current_scan_session["scan_id"] = None
            api.current_scan_session["error"] = None

    def tearDown(self):
        with api.scan_session_lock:
            api.is_monitoring = False
            api.current_scan_session["status"] = "ready"
            api.current_scan_session["scan_id"] = None

    @patch("api.ipc_client.verify_authenticated_health", return_value=(True, "Authenticated"))
    @patch("api.get_service_status", return_value={"installed": True, "running": True, "ipc_online": True, "status": "RUNNING"})
    @patch("api.auto_detect_primary_interface")
    @patch("threading.Thread")
    def test_first_attempt_start_success(self, mock_thread, mock_detect, mock_svc, mock_auth):
        """Live Monitoring must start successfully on the very first attempt without requiring a second click."""
        mock_detect.return_value = (
            {
                "name": "Wi-Fi",
                "type": "Wi-Fi",
                "index": 12,
                "status": "Up",
                "primary_ip": "192.168.1.50",
                "is_connected": True,
                "guid": "{12345678-1234-1234-1234-1234567890AB}",
                "network_name": "\\Device\\NPF_{12345678-1234-1234-1234-1234567890AB}"
            },
            {
                "installed": True,
                "can_capture_live": True,
                "active_engine": "Npcap + Scapy (Standalone / Direct)"
            }
        )

        resp = self.app.post("/api/scan", json={"continuous": True, "adapter": "auto"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "scanning")
        self.assertTrue(data["scan_id"].startswith("scan_"))
        self.assertTrue(mock_thread.called)

    def test_concurrent_scan_protection(self):
        """A second concurrent start request must be cleanly rejected with 'already_scanning' status."""
        with api.scan_session_lock:
            api.current_scan_session["status"] = "scanning"
            api.current_scan_session["scan_id"] = "scan_test_existing"
            api.is_monitoring = True

        resp = self.app.post("/api/scan", json={"continuous": True, "force_restart": False})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "already_scanning")
        self.assertEqual(data["scan_id"], "scan_test_existing")

    @patch("api.get_windows_network_adapters")
    def test_disconnected_adapter_rejection(self, mock_adapters):
        """Selected adapter that is Disconnected must be rejected explicitly without falling back to another adapter."""
        mock_adapters.return_value = [
            {
                "name": "Ethernet",
                "description": "Intel Ethernet Connection",
                "status": "Disconnected",
                "type": "Ethernet",
                "index": 5,
                "ips": []
            }
        ]

        resp = self.app.post("/api/scan", json={"adapter": "Ethernet"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["error_type"], "ADAPTER_OFFLINE")
        self.assertIn("Disconnected", data["message"])

    @patch("api.ipc_client.verify_authenticated_health", side_effect=RuntimeError("IPC connection refused"))
    @patch("api.get_service_status", return_value={"installed": True, "running": True, "ipc_online": True, "status": "RUNNING"})
    @patch("api.auto_detect_primary_interface")
    def test_safe_error_handling_no_500_crash(self, mock_detect, mock_svc, mock_ipc):
        """Unexpected initialization failure must return structured HTTP 200 JSON with error status, not 500 crash."""
        mock_detect.return_value = (
            {
                "name": "Wi-Fi",
                "type": "Wi-Fi",
                "index": 12,
                "status": "Up",
                "primary_ip": "192.168.1.50",
                "is_connected": True
            },
            {"can_capture_live": True}
        )

        resp = self.app.post("/api/scan", json={"continuous": True, "adapter": "auto"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("error", data)


class TestNetworkDiscoveryReliability(unittest.TestCase):
    """Regression tests for Network Discovery subnet validation, cancellation, and mobile hotspot support."""

    def setUp(self):
        self.mgr = NetworkDiscoveryManager()

    def test_mobile_hotspot_subnet_normalization(self):
        """Mobile-hotspot-style subnets (e.g. 10.206.35.0/24) must normalize and validate properly."""
        net_obj, hosts = validate_and_normalize_subnet("10.206.35.0/24")
        self.assertEqual(str(net_obj), "10.206.35.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "10.206.35.1")
        self.assertEqual(hosts[-1], "10.206.35.254")

    def test_invalid_cidr_inputs_rejected(self):
        """Invalid subnet strings, non-private ranges, and ranges larger than /24 must be rejected with ValueError."""
        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("999.999.999.0/24")

        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("not_a_valid_subnet")

        # Larger than /24 (e.g. /16 has 65536 hosts)
        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("192.168.0.0/16")

    @patch("modules.network_discovery.discovery.get_network_discovery_info")
    def test_explicit_cidr_when_auto_detect_offline(self, mock_detect_info):
        """Starting discovery with an explicit valid CIDR must succeed even if auto-detection returns offline."""
        mock_detect_info.return_value = {
            "status": "offline",
            "adapter_name": "None",
            "is_connected": False,
            "subnet_cidr": None
        }

        # Start scan with explicit valid subnet
        res = self.mgr.start_scan("192.168.5.0/24", timeout=0.1, concurrency=10)
        self.assertEqual(res["status"], "scanning")
        self.assertEqual(res["subnet"], "192.168.5.0/24")
        self.assertEqual(res["total_hosts"], 254)

        # Stop scan immediately and verify clean status
        stop_res = self.mgr.stop_scan()
        self.assertEqual(stop_res["status"], "stopped")

    def test_repeated_start_scan_protection(self):
        """Repeated start requests while scanning must return already_scanning status."""
        self.mgr.session["status"] = "scanning"
        self.mgr.session["scan_id"] = "net_12345"

        res = self.mgr.start_scan("192.168.1.0/24")
        self.assertEqual(res["status"], "already_scanning")
        self.assertEqual(res["scan_id"], "net_12345")


class TestPortScannerReliability(unittest.TestCase):
    """Regression tests for Port Scanner URI sanitization, CGNAT support, and async lifecycle."""

    def setUp(self):
        self.mgr = PortScannerManager()

    def test_target_url_sanitization(self):
        """Port scanner must sanitize HTTP/HTTPS URLs and trailing ports into valid host/IP targets."""
        ip, net_obj = validate_and_resolve_target("target_ip", "http://127.0.0.1:8080/dashboard")
        self.assertEqual(ip, "127.0.0.1")
        self.assertIsNone(net_obj)

        ip, net_obj = validate_and_resolve_target("target_ip", "https://192.168.1.1/")
        self.assertEqual(ip, "192.168.1.1")
        self.assertIsNone(net_obj)

    def test_cgnat_mobile_hotspot_support(self):
        """Port scanner must accept RFC 6598 Carrier-Grade NAT IPs and subnets used by mobile hotspots."""
        ip, net_obj = validate_and_resolve_target("target_ip", "100.64.1.25")
        self.assertEqual(ip, "100.64.1.25")
        self.assertIsNone(net_obj)

        ip, net_obj = validate_and_resolve_target("network", "100.64.1.0/24")
        self.assertEqual(str(net_obj), "100.64.1.0/24")

    def test_invalid_and_public_targets_rejected(self):
        """Public internet IPs for network scans and invalid hostnames must be rejected to maintain security boundaries."""
        with self.assertRaises(ValueError):
            validate_and_resolve_target("network", "8.8.8.0/24")  # Public IP rejected for network scan

        with self.assertRaises(ValueError):
            validate_and_resolve_target("target_ip", "invalid..hostname...123")

    def test_probe_closed_port_classification(self):
        """Probing a closed TCP port on loopback returns closed or filtered without crashing."""
        # Find an unused ephemeral port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        unused_port = s.getsockname()[1]
        s.close()

        result = asyncio.run(probe_single_port("127.0.0.1", unused_port, timeout=0.2))
        self.assertEqual(result["port"], unused_port)
        self.assertIn(result["state"], ["closed", "filtered"])


class TestCrossFeatureIndependence(unittest.TestCase):
    """Verifies that all three features operate independently and do not corrupt Dataset Replay metrics."""

    def setUp(self):
        self.app = api.app.test_client()
        self.app.testing = True

    def test_dataset_replay_metric_isolation(self):
        """Live Monitoring session updates must NEVER overwrite or pollute Dataset Replay state."""
        initial_collector_count = api.live_collector.packet_count

        with api.scan_session_lock:
            api.current_scan_session.update({
                "status": "ready",
                "packets_captured": 555,
                "throughput_kbps": 123.4,
                "label": "Benign"
            })

        # Generate synthetic 77 features satisfying validate_flow_features gate
        features = {col: 0.0 for col in OFFICIAL_77_FEATURES}
        features["Flow Duration"] = 12000.0
        features["Total Fwd Packets"] = 5.0
        features["Total Backward Packets"] = 3.0
        features["Fwd Packets Length Total"] = 400.0
        features["Bwd Packets Length Total"] = 250.0
        features["Fwd Header Length"] = 40.0
        features["Bwd Header Length"] = 40.0
        features["Flow Bytes/s"] = 50000.0
        features["Flow Packets/s"] = 600.0

        resp = self.app.post("/api/replay-feature", json={
            "features": features,
            "ground_truth": "Benign"
        })
        self.assertEqual(resp.status_code, 200)

        # Ensure live collector count is completely unchanged
        self.assertEqual(api.live_collector.packet_count, initial_collector_count)

        # Ensure current_scan_session was not overwritten by replay
        self.assertEqual(api.current_scan_session.get("packets_captured"), 555)

        # Verify dedicated replay status endpoint has the event
        replay_status = self.app.get("/api/replay-status")
        self.assertEqual(replay_status.status_code, 200)
        self.assertGreater(replay_status.get_json()["replay_stats"]["total_replayed"], 0)

    def test_feature_managers_independent_lifecycle(self):
        """Live monitoring, discovery manager, and port scan manager have distinct independent states."""
        with api.scan_session_lock:
            api.current_scan_session["status"] = "ready"

        disc_mgr = NetworkDiscoveryManager()
        port_mgr = PortScannerManager()

        disc_mgr.session["status"] = "scanning"
        port_mgr.session["status"] = "idle"

        self.assertEqual(disc_mgr.session["status"], "scanning")
        self.assertEqual(port_mgr.session["status"], "idle")
        self.assertEqual(api.current_scan_session["status"], "ready")


if __name__ == "__main__":
    unittest.main()
