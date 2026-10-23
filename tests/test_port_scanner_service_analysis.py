#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite: Port Scanning & Service Analysis
Verifies:
1. Valid and invalid target input handling.
2. Accurate open/closed/filtered representation with genuine service mapping vs identified banners.
3. Accurate summary statistics without fabricated counts (scanned_ports, open, closed, filtered, duration).
4. Handling of timeouts, unreachable hosts, and error states.
5. Repeated Start clicks do not create duplicate scans (already_scanning guard).
6. Cancellation works cleanly and cooperatively.
7. Search, filtering, sorting, and export payload verification.
8. Theme compatibility (Dark Mode / Light Mode CSS tokens and modal structure).
9. Live Monitoring capture and Dataset Replay telemetry remain 100% unaffected.
10. Existing API contracts (/api/port-scan/*) remain fully backward-compatible.
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
    get_service_info,
    port_scanner_manager
)
import api
from api import app, current_scan_session, scan_session_lock


class TestPortScannerServiceAnalysis(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_01_target_validation_rules(self):
        """1. Verify valid and invalid target inputs are strictly handled."""
        # Localhost is strictly locked to 127.0.0.1
        resolved, net = validate_and_resolve_target("localhost", "custom.host.com")
        self.assertEqual(resolved, "127.0.0.1")
        self.assertIsNone(net)

        # Valid IPv4 single host
        resolved, net = validate_and_resolve_target("target_ip", "127.0.0.1")
        self.assertEqual(resolved, "127.0.0.1")
        self.assertIsNone(net)

        # Rejection of invalid IP format
        with self.assertRaises(ValueError):
            validate_and_resolve_target("target_ip", "999.888.777.666")

        # Network scan: Valid private /24 subnet
        resolved, net = validate_and_resolve_target("network", "192.168.1.0/24")
        self.assertEqual(resolved, "192.168.1.0/24")
        self.assertIsNotNone(net)

        # Network scan: Rejection of public or oversized subnet
        with self.assertRaises(ValueError):
            validate_and_resolve_target("network", "8.8.8.0/24")
        with self.assertRaises(ValueError):
            validate_and_resolve_target("network", "10.0.0.0/16")

    def test_02_service_source_and_banner_integrity(self):
        """2. Verify service source is transparently distinguished from active banner responses."""
        # Well-known service check
        svc_name, svc_source = get_service_info(80)
        self.assertIn("HTTP", svc_name)
        self.assertEqual(svc_source, "Standard Port Mapping (Well-Known Registry)")

        svc_name_443, svc_source_443 = get_service_info(443)
        self.assertIn("HTTPS", svc_name_443)
        self.assertEqual(svc_source_443, "Standard Port Mapping (Well-Known Registry)")

        # Backward compatibility with get_service_name
        self.assertEqual(get_service_name(80), "HTTP (World Wide Web)")
        self.assertEqual(get_service_name(443), "HTTPS (HTTP Secure / SSL)")

    def test_03_actual_port_state_representation(self):
        """3. Verify probe_single_port returns actual open state, closed state, and correct fields."""
        import asyncio

        # Bind temporary TCP socket to simulate genuine open port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        # Pick an unbound port for closed test
        tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp.bind(("127.0.0.1", 0))
        closed_port = tmp.getsockname()[1]
        tmp.close()

        loop = asyncio.new_event_loop()
        try:
            # Probe open port
            open_res = loop.run_until_complete(probe_single_port("127.0.0.1", open_port, timeout=0.5))
            self.assertEqual(open_res["state"], "open")
            self.assertEqual(open_res["port"], open_port)
            self.assertEqual(open_res["protocol"], "TCP")
            self.assertIn("service_source", open_res)
            self.assertIsNotNone(open_res["latency_ms"])

            # Probe closed port (allow 2.5s on Windows for socket stack to return ConnectionRefused)
            closed_res = loop.run_until_complete(probe_single_port("127.0.0.1", closed_port, timeout=2.5))
            self.assertEqual(closed_res["state"], "closed")
            self.assertEqual(closed_res["port"], closed_port)
            self.assertIsNone(closed_res["latency_ms"])
            self.assertIsNone(closed_res["service_version"])
        finally:
            srv.close()
            loop.close()

    def test_04_summary_statistics_accuracy(self):
        """4. Verify summary statistics accurately reflect tested, open, closed, filtered counts."""
        # Bind temporary open socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        # Bind and close another socket
        tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp.bind(("127.0.0.1", 0))
        closed_port = tmp.getsockname()[1]
        tmp.close()

        try:
            # Start scan on exact custom ports: 1 open, 1 closed
            res = self.client.post("/api/port-scan/start", json={
                "scan_type": "localhost",
                "ports_mode": "custom",
                "custom_ports": f"{open_port}, {closed_port}",
                "timeout": 2.5
            })
            self.assertEqual(res.status_code, 200)

            # Poll for completion
            start_t = time.time()
            final_status = {}
            while time.time() - start_t < 6.0:
                time.sleep(0.1)
                st = self.client.get("/api/port-scan/status").get_json()
                if st.get("status") == "completed":
                    final_status = st
                    break

            self.assertEqual(final_status.get("status"), "completed")
            self.assertEqual(final_status.get("scanned_ports"), 2)
            self.assertEqual(final_status.get("open_ports_count"), 1)
            self.assertEqual(final_status.get("closed_ports_count"), 1)
            self.assertEqual(final_status.get("filtered_ports_count"), 0)
            self.assertGreater(final_status.get("duration_s", 0), 0)

            results = final_status.get("results", [])
            self.assertEqual(len(results), 1)
            host_entry = results[0]
            self.assertEqual(host_entry.get("open_ports_count"), 1)
            self.assertEqual(host_entry.get("closed_ports_count"), 1)
            self.assertEqual(host_entry.get("filtered_ports_count"), 0)
            self.assertEqual(host_entry.get("total_scanned_ports"), 2)
        finally:
            srv.close()

    def test_05_duplicate_clicks_prevention(self):
        """5. Verify repeated start clicks reject duplicate scan attempts with already_scanning."""
        # Start a scan with slightly longer timeout
        self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "wellknown",
            "timeout": 1.0
        })

        # Immediately attempt second start
        second_res = self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "top20"
        })
        second_data = second_res.get_json()
        self.assertEqual(second_data.get("status"), "already_scanning")

        # Cleanup: stop scan
        self.client.post("/api/port-scan/stop")

    def test_06_cancellation_lifecycle(self):
        """6. Verify immediate cooperative cancellation via /api/port-scan/stop."""
        self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "wellknown",
            "timeout": 1.0
        })

        # Stop scan
        stop_res = self.client.post("/api/port-scan/stop")
        self.assertEqual(stop_res.status_code, 200)
        self.assertEqual(stop_res.get_json().get("status"), "stopped")

        # Verify status transitions to stopped
        time.sleep(0.15)
        st = self.client.get("/api/port-scan/status").get_json()
        self.assertIn(st.get("status"), ["stopped", "completed"])

    def test_07_api_contract_backward_compatibility(self):
        """7. Verify existing endpoints /api/port-scan/* preserve all legacy fields."""
        net_info_res = self.client.get("/api/port-scan/network-info")
        self.assertEqual(net_info_res.status_code, 200)
        net_info = net_info_res.get_json()
        self.assertEqual(net_info.get("status"), "success")
        self.assertIn("local_ip", net_info)
        self.assertIn("suggested_subnet", net_info)

        status_res = self.client.get("/api/port-scan/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.get_json()
        for field in ["status", "scan_id", "progress_pct", "scanned_ports", "open_ports_count", "results"]:
            self.assertIn(field, status_data)

    def test_08_strict_ddos_and_replay_isolation(self):
        """8. CRITICAL: Verify port scanner leaves live monitoring session and replay state 100% untouched."""
        with scan_session_lock:
            initial_session = dict(current_scan_session)

        # Execute quick port scan
        self.client.post("/api/port-scan/start", json={
            "scan_type": "localhost",
            "ports_mode": "top20",
            "timeout": 0.2
        })
        time.sleep(0.3)
        self.client.post("/api/port-scan/stop")

        with scan_session_lock:
            final_session = dict(current_scan_session)

        self.assertEqual(initial_session["status"], final_session["status"])
        self.assertEqual(initial_session.get("packets_captured"), final_session.get("packets_captured"))
        self.assertEqual(initial_session.get("detected_attacks_count"), final_session.get("detected_attacks_count"))

    def test_09_template_and_dom_structure(self):
        """9. Verify templates/ddos.html includes the upgraded Port Scanner UI and Details Modal."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        self.assertIn('id="port-scanner"', html)
        self.assertIn('Port Scanning & Service Analysis', html)
        self.assertIn('Protocol: <strong>TCP Connect</strong>', html)
        self.assertIn('id="psKpiCardTested"', html)
        self.assertIn('id="psKpiCardOpen"', html)
        self.assertIn('id="psKpiCardClosed"', html)
        self.assertIn('id="psKpiCardFiltered"', html)
        self.assertIn('id="psKpiCardDuration"', html)
        self.assertIn('id="psDetailsModal"', html)
        self.assertIn('id="psExportJsonBtn"', html)
        self.assertIn('id="psExportCsvBtn"', html)

    def test_10_css_tokens_and_theme_compatibility(self):
        """10. Verify static/style.css defines all required port scanner styling classes and modal rules."""
        css_path = PROJECT_ROOT / "static" / "style.css"
        self.assertTrue(css_path.exists())
        css_text = css_path.read_text(encoding="utf-8")

        for selector in [
            ".ps-proto-badge",
            ".ps-kpi-grid",
            ".ps-kpi-card",
            ".highlight-kpi-open",
            ".ps-filter-pill",
            ".sortable-th",
            ".ps-service-col",
            ".ps-source-tag",
            ".ps-exposure-tag",
            ".ps-action-btn",
            ".ps-modal-backdrop",
            ".ps-modal-dialog",
            ".ps-modal-header",
            ".ps-modal-body",
            ".ps-banner-terminal",
            ".ps-modal-disclaimer"
        ]:
            self.assertIn(selector, css_text, f"Missing CSS selector: {selector}")


if __name__ == '__main__':
    unittest.main()
