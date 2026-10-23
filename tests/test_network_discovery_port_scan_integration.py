#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite: Network Discovery → Port Scanning Integration
Verifies:
1. Scan Port action on discovered devices binds exact target IP.
2. Target fidelity across different devices (Device A vs Device B).
3. Graceful handling and rejection of missing, empty, or invalid target IPs.
4. Auto-trigger consumption and refresh (F5) stale state protection.
5. Preservation of normal manual port scanning (Localhost, Target IP, Subnet).
6. Duplicate scan prevention (already_scanning guard).
7. Cross-feature isolation (Live Monitoring and Network Discovery remain intact).
"""

import sys
import time
import json
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import api
from api import app, current_scan_session, scan_session_lock
import modules.port_scanner.scanner as port_scanner
from modules.port_scanner.scanner import port_scanner_manager, validate_and_resolve_target


class TestNetworkDiscoveryPortScanIntegration(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        # Ensure any running scan is cleanly stopped before each test
        try:
            port_scanner_manager.stop_scan()
        except Exception:
            pass

    def tearDown(self):
        try:
            port_scanner_manager.stop_scan()
        except Exception:
            pass

    def test_01_network_discovery_frontend_scan_port_contracts(self):
        """1. Verify network_discovery.html and network_discovery.js link templates and triggers."""
        res = self.client.get("/network-discovery")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # Modal link has nd-btn-scan-ports and tooltip title
        self.assertIn('id="modalPortScanLink"', html)
        self.assertIn('nd-btn-scan-ports', html)

        with open(PROJECT_ROOT / "static" / "network_discovery.js", "r", encoding="utf-8") as f:
            js = f.read()

        # URLs include target and trigger=discovery
        self.assertIn("/?view=port-scanner&target=", js)
        self.assertIn("&trigger=discovery", js)

        # One-time auto-trigger session token written on click
        self.assertIn("sessionStorage.setItem('port_scan_auto_trigger'", js)
        self.assertIn("isValidTargetIp", js)
        self.assertIn("triggerPortScanForDevice", js)

    def test_02_invalid_ip_rejection_logic_in_frontend(self):
        """2. Verify static/network_discovery.js and static/main.js contain strict IP validation."""
        with open(PROJECT_ROOT / "static" / "network_discovery.js", "r", encoding="utf-8") as f:
            nd_js = f.read()

        with open(PROJECT_ROOT / "static" / "main.js", "r", encoding="utf-8") as f:
            main_js = f.read()

        # Rejection of empty/unavailable/unknown
        self.assertIn("Unavailable", nd_js)
        self.assertIn("Not detected", nd_js)
        self.assertIn("Unavailable", main_js)
        self.assertIn("Not detected", main_js)

        # Helper in main.js handles incoming target and auto-scan
        self.assertIn("function isValidTargetAddress", main_js)
        self.assertIn("async function handleIncomingTarget", main_js)
        self.assertIn("function scanTarget", main_js)

    def test_03_refresh_stale_state_protection(self):
        """3. Verify auto-trigger session token is single-use and history.replaceState cleans URL."""
        with open(PROJECT_ROOT / "static" / "main.js", "r", encoding="utf-8") as f:
            main_js = f.read()

        # Token is immediately removed from sessionStorage upon arrival
        self.assertIn('sessionStorage.removeItem("port_scan_auto_trigger")', main_js)

        # URL is cleaned with history.replaceState to avoid repeated auto-scans on F5 refresh
        self.assertIn('window.history.replaceState({ view: "port-scanner" }', main_js)
        self.assertIn('cleanParams.delete("trigger")', main_js)

    def test_04_target_fidelity_device_a_and_device_b(self):
        """4. Verify backend accepts exact IP for Device A and distinct exact IP for Device B."""
        device_a_ip = "192.168.1.15"
        device_b_ip = "192.168.1.88"

        # Scan Device A
        res_a = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": device_a_ip,
            "ports_mode": "top20",
            "timeout": 0.2,
            "concurrency": 20
        })
        self.assertEqual(res_a.status_code, 200)
        data_a = res_a.get_json()
        self.assertEqual(data_a.get("status"), "started")
        self.assertEqual(data_a.get("target"), device_a_ip)
        self.assertEqual(data_a.get("resolved_target"), device_a_ip)

        # Check status reflects device A
        st_a = self.client.get("/api/port-scan/status").get_json()
        self.assertEqual(st_a.get("target"), device_a_ip)

        # Stop scan A cleanly
        self.client.post("/api/port-scan/stop")
        time.sleep(0.3)

        # Scan Device B
        res_b = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": device_b_ip,
            "ports_mode": "top20",
            "timeout": 0.2,
            "concurrency": 20
        })
        self.assertEqual(res_b.status_code, 200)
        data_b = res_b.get_json()
        self.assertEqual(data_b.get("status"), "started")
        self.assertEqual(data_b.get("target"), device_b_ip)
        self.assertEqual(data_b.get("resolved_target"), device_b_ip)

        # Check status reflects device B (strictly distinct from Device A)
        st_b = self.client.get("/api/port-scan/status").get_json()
        self.assertEqual(st_b.get("target"), device_b_ip)
        self.assertNotEqual(st_b.get("target"), device_a_ip)

        # Stop scan B
        self.client.post("/api/port-scan/stop")

    def test_05_invalid_target_ip_handling_on_backend(self):
        """5. Verify backend validation rejects malformed or unresolvable targets with 400 Bad Request."""
        # Malformed IP
        res_bad = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": "999.999.999.999",
            "ports_mode": "top20"
        })
        self.assertEqual(res_bad.status_code, 400)
        self.assertEqual(res_bad.get_json().get("status"), "error")

        # Empty target
        res_empty = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": "",
            "ports_mode": "top20"
        })
        self.assertEqual(res_empty.status_code, 400)

        # Python validator unit check
        with self.assertRaises(ValueError):
            validate_and_resolve_target("target_ip", "999.999.999.999")
        with self.assertRaises(ValueError):
            validate_and_resolve_target("target_ip", "")

    def test_06_manual_port_scanning_workflows_preserved(self):
        """6. Verify manual scanning for localhost and network subnet remains fully operational."""
        # Localhost scan
        res_lh = self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "target": "127.0.0.1",
            "ports_mode": "top20",
            "timeout": 0.2
        })
        self.assertEqual(res_lh.status_code, 200)
        self.assertEqual(res_lh.get_json().get("resolved_target"), "127.0.0.1")
        self.client.post("/api/port-scan/stop")
        time.sleep(0.2)

        # Network subnet scan validation
        resolved, net = validate_and_resolve_target("network", "192.168.1.0/24")
        self.assertEqual(resolved, "192.168.1.0/24")
        self.assertIsNotNone(net)

    def test_07_duplicate_scan_protection(self):
        """7. Verify duplicate scan attempt returns already_scanning without crashing."""
        res_first = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": "192.168.1.50",
            "ports_mode": "top20",
            "timeout": 1.0,
            "concurrency": 10
        })
        self.assertEqual(res_first.status_code, 200)

        # Second concurrent start
        res_second = self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": "192.168.1.99",
            "ports_mode": "top20"
        })
        self.assertEqual(res_second.status_code, 200)
        data2 = res_second.get_json()
        self.assertEqual(data2.get("status"), "already_scanning")

        # Stop
        self.client.post("/api/port-scan/stop")

    def test_08_strict_isolation_from_live_monitoring(self):
        """8. CRITICAL: Verify port scanning operations leave Live Monitoring session untouched."""
        with scan_session_lock:
            initial_mon = dict(current_scan_session)

        # Perform port scanning API calls
        self.client.post("/api/port-scan/start", json={
            "scan_type": "target_ip",
            "target": "127.0.0.1",
            "ports_mode": "top20",
            "timeout": 0.1
        })
        self.client.get("/api/port-scan/status")
        self.client.post("/api/port-scan/stop")

        with scan_session_lock:
            final_mon = dict(current_scan_session)

        self.assertEqual(initial_mon["status"], final_mon["status"])
        self.assertEqual(initial_mon.get("packets_captured"), final_mon.get("packets_captured"))


if __name__ == "__main__":
    unittest.main()
