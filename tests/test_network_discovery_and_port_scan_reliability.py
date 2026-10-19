#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for SocNet Network Discovery and Port Scanner Reliability & Rescan Features.
Distinguishes unit/mocked validation tests from real network probing tests.
"""

import sys
import time
import socket
import asyncio
import unittest
from unittest.mock import patch, MagicMock

import ipaddress
from modules.network_discovery.discovery import (
    validate_and_normalize_subnet,
    probe_host_tcp,
    NetworkDiscoveryManager,
    network_discovery_manager
)
from modules.port_scanner.scanner import (
    probe_single_port,
    probe_host_liveness,
    validate_and_resolve_target,
    parse_port_selection,
    PortScannerManager,
    port_scanner_manager
)
import api


class TestSubnetValidationReliability(unittest.TestCase):
    """Unit tests for subnet and IP target validation without network I/O."""

    def test_standard_cidr_validation(self):
        net, hosts = validate_and_normalize_subnet("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.254")

    def test_single_ip_auto_expansion(self):
        # When user types a single host IP like 192.168.1.15, auto-expand to enclosing /24
        net, hosts = validate_and_normalize_subnet("192.168.1.15")
        self.assertEqual(str(net), "192.168.1.0/24")
        self.assertEqual(len(hosts), 254)
        self.assertIn("192.168.1.15", hosts)

    def test_dash_range_notation(self):
        # Test full IP dash range
        net, hosts = validate_and_normalize_subnet("10.0.0.10-10.0.0.25")
        self.assertEqual(len(hosts), 16)
        self.assertEqual(hosts[0], "10.0.0.10")
        self.assertEqual(hosts[-1], "10.0.0.25")

        # Test short suffix dash range
        net, hosts = validate_and_normalize_subnet("192.168.5.1-10")
        self.assertEqual(len(hosts), 10)
        self.assertEqual(hosts[0], "192.168.5.1")
        self.assertEqual(hosts[-1], "192.168.5.10")

    def test_safety_boundary_enforcement(self):
        # Reject subnets larger than /22 (1024 hosts)
        with self.assertRaises(ValueError) as ctx:
            validate_and_normalize_subnet("10.0.0.0/16")
        self.assertIn("1,024", str(ctx.exception))

        # Reject malformed IPs
        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("999.999.999.999/24")

        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("invalid-subnet")


class TestPortStateClassification(unittest.TestCase):
    """Unit tests verifying that port states are classified into Open, Closed, Filtered, and Error."""

    def test_port_open_state(self):
        async def run_open_test():
            # Start a local TCP listener to verify actual open port check
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            try:
                res = await probe_single_port("127.0.0.1", port, timeout=0.5)
                self.assertEqual(res["state"], "open")
                self.assertEqual(res["port"], port)
                self.assertIsNotNone(res["latency_ms"])
            finally:
                srv.close()

        asyncio.run(run_open_test())

    def test_port_closed_state_on_rst(self):
        async def run_closed_test():
            # Mock asyncio.open_connection raising ConnectionRefusedError
            with patch("asyncio.open_connection", side_effect=ConnectionRefusedError("RST")):
                res = await probe_single_port("192.168.1.100", 80, timeout=0.2)
                self.assertEqual(res["state"], "closed")

            # Mock Windows WSAECONNREFUSED (winerror 10061)
            err = OSError()
            err.winerror = 10061
            with patch("asyncio.open_connection", side_effect=err):
                res = await probe_single_port("192.168.1.100", 80, timeout=0.2)
                self.assertEqual(res["state"], "closed")

        asyncio.run(run_closed_test())

    def test_port_filtered_state_on_timeout(self):
        async def run_timeout_test():
            # TimeoutError must be reported as filtered, never closed
            with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
                res = await probe_single_port("192.168.1.100", 80, timeout=0.1)
                self.assertEqual(res["state"], "filtered")

            # Windows WSAETIMEDOUT (winerror 10060)
            err = OSError()
            err.winerror = 10060
            with patch("asyncio.open_connection", side_effect=err):
                res = await probe_single_port("192.168.1.100", 80, timeout=0.1)
                self.assertEqual(res["state"], "filtered")

        asyncio.run(run_timeout_test())

    def test_port_error_state_on_unreachable(self):
        async def run_error_test():
            # Host/network unreachable error (e.g. WSAEHOSTUNREACH 10065 or 10051)
            err = OSError("Host unreachable")
            err.winerror = 10065
            with patch("asyncio.open_connection", side_effect=err):
                res = await probe_single_port("192.168.1.100", 80, timeout=0.1)
                self.assertEqual(res["state"], "error")
                self.assertIn("10065", res["banner"])

        asyncio.run(run_error_test())


class TestSubnetRescanAndHistoryComparison(unittest.TestCase):
    """Tests Subnet Rescan functionality and history tracking."""

    def setUp(self):
        self.mgr = NetworkDiscoveryManager()

    def test_history_comparison_computation(self):
        # Simulate Scan 1 completion
        self.mgr.session = {
            "status": "completed",
            "scan_id": "scan_1",
            "subnet": "192.168.1.0/24",
            "devices_count": 2,
            "online_count": 2,
            "duration_s": 1.2,
            "completed_at": "10:00:00",
            "devices": [
                {"ip": "192.168.1.1", "status": "Online", "verified": True},
                {"ip": "192.168.1.20", "status": "Online", "verified": True}
            ]
        }

        # Start Scan 2 (Rescan)
        res = self.mgr.start_scan("192.168.1.0/24", timeout=0.1, concurrency=10)
        self.assertEqual(res["status"], "scanning")
        self.assertTrue(res["has_previous_scan"])
        self.assertIsNotNone(self.mgr.last_completed_scan)
        self.assertEqual(self.mgr.last_completed_scan["scan_id"], "scan_1")

        # Stop scan
        self.mgr.stop_scan()
        self.assertEqual(self.mgr.get_status()["status"], "stopped")

    def test_duplicate_scan_prevention(self):
        # While scanning, starting another scan should be rejected
        self.mgr.session["status"] = "scanning"
        res = self.mgr.start_scan("192.168.1.0/24")
        self.assertEqual(res["status"], "already_scanning")


class TestPortRescanAndManagerReliability(unittest.TestCase):
    """Tests Port Rescan functionality, timestamping, and settings preservation."""

    def setUp(self):
        self.mgr = PortScannerManager()

    def test_port_rescan_preserves_target_and_mode(self):
        # Simulate Scan 1 completed
        self.mgr.session.update({
            "status": "completed",
            "scan_id": "pscan_1",
            "scan_type": "target_ip",
            "target": "127.0.0.1",
            "resolved_target": "127.0.0.1",
            "ports_mode": "top20",
            "completed_at": time.time(),
            "completed_at_str": "12:30:00",
            "open_ports_count": 1,
            "total_ports": 20,
            "results": [{"host": "127.0.0.1", "status": "online", "open_ports": []}]
        })

        # Start scan with empty target (triggering rescan of last configuration)
        res = self.mgr.start_scan(scan_type="target_ip", target="")
        self.assertEqual(res["status"], "started")
        self.assertEqual(res["target"], "127.0.0.1")
        self.assertIsNotNone(self.mgr.last_completed_scan)
        self.assertEqual(self.mgr.last_completed_scan["scan_id"], "pscan_1")

        # Cleanup
        self.mgr.stop_scan()

    def test_duplicate_port_scan_prevention(self):
        self.mgr._is_running = True
        res = self.mgr.start_scan(scan_type="localhost", target="127.0.0.1")
        self.assertEqual(res["status"], "already_scanning")
        self.mgr._is_running = False


class TestApiEndpointsPassThrough(unittest.TestCase):
    """Integration test verifying Flask API endpoints pass through rescan and status data."""

    def setUp(self):
        api.app.config["TESTING"] = True
        self.client = api.app.test_client()

    def test_port_scan_status_endpoint(self):
        res = self.client.get("/api/port-scan/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("status", data)
        self.assertIn("last_completed_scan", data)

    def test_network_discovery_status_endpoint(self):
        res = self.client.get("/api/network-discovery/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("status", data)
        self.assertIn("last_completed_scan", data)


if __name__ == "__main__":
    unittest.main()
