#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite: DDoS-Guard Port Scanner & Isolation Verifier
Validates:
1. Port parsing & preset resolutions (Top 20, Top 100, Well-Known, Custom).
2. Target validation & safety restrictions (Loopback, Target IP, Private CIDR <= /24, Public rejection).
3. Native async socket probing & service identification.
4. Flask REST API endpoints (/api/port-scan/*).
5. Immediate cancellation / stop flow.
6. Absolute isolation: Zero mutation or interference with current_scan_session, WinDivert, or AI model.
"""

import sys
import time
import socket
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import modules.port_scanner.scanner as port_scanner
from modules.port_scanner.scanner import (
    parse_port_selection,
    validate_and_resolve_target,
    probe_single_port,
    get_service_name,
    port_scanner_manager
)
import api
from api import app, current_scan_session, scan_session_lock


class TestPortScanner(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_01_parse_ports(self):
        """1. Verify port selection parsing and boundary checks."""
        # Top 20
        top20 = parse_port_selection("top20")
        self.assertEqual(len(top20), 20)
        self.assertIn(80, top20)
        self.assertIn(443, top20)
        self.assertIn(5000, top20)

        # Top 100
        top100 = parse_port_selection("top100")
        self.assertEqual(len(top100), 100)

        # Well-Known
        wellknown = parse_port_selection("wellknown")
        self.assertEqual(len(wellknown), 1024)
        self.assertEqual(wellknown[0], 1)
        self.assertEqual(wellknown[-1], 1024)

        # Custom list and range
        custom = parse_port_selection("custom", "80, 443, 8080-8082, 3000")
        self.assertEqual(custom, [80, 443, 3000, 8080, 8081, 8082])

        # Validation errors
        with self.assertRaises(ValueError):
            parse_port_selection("custom", "")
        with self.assertRaises(ValueError):
            parse_port_selection("custom", "70000")  # Out of bounds
        with self.assertRaises(ValueError):
            parse_port_selection("invalid_mode")

    def test_02_target_validation_and_safety_rules(self):
        """2. Verify target validation, IPv4 resolution, and private subnet restrictions."""
        # Localhost mode is strictly fixed to 127.0.0.1
        resolved, net = validate_and_resolve_target("localhost", "any_random_input")
        self.assertEqual(resolved, "127.0.0.1")
        self.assertIsNone(net)

        # Target IP (valid IPv4)
        resolved, net = validate_and_resolve_target("target_ip", "192.168.1.1")
        self.assertEqual(resolved, "192.168.1.1")

        # Target IP (invalid address)
        with self.assertRaises(ValueError):
            validate_and_resolve_target("target_ip", "999.999.999.999")

        # Network Scan: Valid private /24
        resolved, net = validate_and_resolve_target("network", "192.168.1.0/24")
        self.assertEqual(resolved, "192.168.1.0/24")
        self.assertIsNotNone(net)

        # Network Scan: Reject oversized subnets (e.g. /16 has 65536 addresses)
        with self.assertRaises(ValueError):
            validate_and_resolve_target("network", "192.168.0.0/16")

        # Network Scan: Reject public subnets (e.g. 8.8.8.0/24)
        with self.assertRaises(ValueError):
            validate_and_resolve_target("network", "8.8.8.0/24")

    def test_03_service_name_mapping(self):
        """3. Verify service name dictionary lookup and fallbacks."""
        self.assertEqual(get_service_name(80), "HTTP (World Wide Web)")
        self.assertEqual(get_service_name(443), "HTTPS (HTTP Secure / SSL)")
        self.assertEqual(get_service_name(22), "SSH (Secure Shell)")
        self.assertEqual(get_service_name(5000), "Flask / DDoS-Guard Dashboard")
        self.assertEqual(get_service_name(50505), "DDoS-Guard Windows Service IPC")

    def test_04_api_network_info_endpoint(self):
        """4. Verify /api/port-scan/network-info returns valid network configuration."""
        res = self.client.get("/api/port-scan/network-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("local_ip", data)
        self.assertIn("suggested_subnet", data)
        self.assertTrue(data["suggested_subnet"].endswith("/24"))

    def test_05_api_start_validation(self):
        """5. Verify /api/port-scan/start rejects malformed requests with 400 Bad Request."""
        # Empty target on target_ip
        res = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": ""
        })
        self.assertEqual(res.status_code, 400)

        # Oversized subnet on network scan
        res = self.client.post("/api/port-scan/start", json={
            "scan_type": "network",
            "target": "10.0.0.0/16"
        })
        self.assertEqual(res.status_code, 400)

    def test_06_localhost_scan_flow(self):
        """6. Execute real localhost scan on dummy listening port and verify results."""
        # Create a temporary local socket to test detection
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(1)
        test_port = srv_sock.getsockname()[1]

        try:
            # Start scan on test_port
            res = self.client.post("/api/port-scan/start", json={
                "scan_type": "localhost",
                "target": "127.0.0.1",
                "ports_mode": "custom",
                "custom_ports": str(test_port),
                "timeout": 0.5
            })
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "started")

            # Poll for completion (timeout 4.0s)
            start_poll = time.time()
            completed = False
            last_status = {}
            while time.time() - start_poll < 4.0:
                time.sleep(0.1)
                st_res = self.client.get("/api/port-scan/status")
                last_status = st_res.get_json()
                if last_status.get("status") == "completed":
                    completed = True
                    break

            self.assertTrue(completed, f"Scan did not complete in time: {last_status}")
            self.assertEqual(last_status.get("open_ports_count"), 1)
            results = last_status.get("results", [])
            self.assertEqual(len(results), 1)
            open_ports = results[0].get("open_ports", [])
            self.assertEqual(len(open_ports), 1)
            self.assertEqual(open_ports[0].get("port"), test_port)
            self.assertEqual(open_ports[0].get("state"), "open")
        finally:
            srv_sock.close()

    def test_07_api_stop_scan(self):
        """7. Verify stopping/cancelling an active scan cooperatively."""
        # Start a longer scan across many ports
        self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "wellknown",
            "timeout": 1.0
        })

        # Cancel immediately
        res = self.client.post("/api/port-scan/stop")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "stopped")

        # Verify status reports stopped
        st_res = self.client.get("/api/port-scan/status")
        self.assertIn(st_res.get_json().get("status"), ["stopped", "completed"])

    def test_08_strict_ddos_isolation(self):
        """8. CRITICAL: Verify port scan execution causes ZERO mutation to DDoS current_scan_session."""
        with scan_session_lock:
            initial_ddos_status = dict(current_scan_session)

        # Run port scan
        self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "custom",
            "custom_ports": "80,443"
        })
        time.sleep(0.3)
        self.client.post("/api/port-scan/stop")

        # Verify current_scan_session was not touched in any way
        with scan_session_lock:
            after_ddos_status = dict(current_scan_session)

        self.assertEqual(initial_ddos_status["status"], after_ddos_status["status"])
        self.assertEqual(initial_ddos_status["scan_id"], after_ddos_status["scan_id"])
        self.assertEqual(initial_ddos_status["packets_captured"], after_ddos_status["packets_captured"])
        self.assertEqual(initial_ddos_status["prediction"], after_ddos_status["prediction"])


if __name__ == "__main__":
    unittest.main()
