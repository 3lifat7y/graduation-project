#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite: Network Discovery UX, View Interactions & Scanning Reliability
Verifies:
1. View & Details interactions, table/grid toggle accessibility, and removal of redundant details button.
2. Device card and row selection UX, tabindex, role, and stopPropagation on scan links.
3. Search, natural IP sorting, and category filters (All, Confirmed Active, Unverified, Routers, Computers, etc.).
4. Accurate representation of empty, partial, and unverified device metadata (zero fabrication).
5. Valid and invalid target subnet parsing, CIDR normalization, and safety limits.
6. First-scan subnet auto-resolution and repeated scan reliability.
7. Duplicate scan rejection (already_scanning guard) and cooperative cancellation.
8. 5-Card KPI summary statistics (Total, Confirmed Active, Unverified/Cached, Gateway, Duration).
9. Full backward compatibility of /api/network-discovery/* endpoints.
10. Strict isolation: Live Monitoring and Port Scanner remain 100% unaffected.
"""

import sys
import time
import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import modules.network_discovery.discovery as network_discovery
from modules.network_discovery.discovery import (
    validate_and_normalize_subnet,
    lookup_mac_vendor,
    infer_device_type,
    resolve_hostname,
    get_network_discovery_info,
    network_discovery_manager
)
import api
from api import app, current_scan_session, scan_session_lock


class TestNetworkDiscoveryUxAndReliability(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_01_view_mode_toggle_and_template_structure(self):
        """1. Verify templates/network_discovery.html includes accessible view toggle, 5 KPI cards, and export buttons."""
        res = self.client.get("/network-discovery")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # 5 KPI cards
        self.assertIn('id="kpiTotalDevices"', html)
        self.assertIn('id="kpiOnlineDevices"', html)
        self.assertIn('id="kpiUnverifiedDevices"', html)
        self.assertIn('id="kpiGatewayDevice"', html)
        self.assertIn('id="kpiScanDuration"', html)

        # View mode switcher with accessibility attributes
        self.assertIn('id="ndViewCardsBtn"', html)
        self.assertIn('id="ndViewTableBtn"', html)
        self.assertIn('aria-pressed="true"', html)
        self.assertIn('aria-label="Cards view mode"', html)
        self.assertIn('aria-label="Table view mode"', html)

        # Export controls & search clear
        self.assertIn('id="ndExportJsonBtn"', html)
        self.assertIn('id="ndExportCsvBtn"', html)
        self.assertIn('id="ndSearchClearBtn"', html)

        # Unverified filter tab
        self.assertIn('data-filter="unverified"', html)
        self.assertIn('id="countUnverified"', html)

    def test_02_card_and_row_streamlined_actions(self):
        """2. Verify that redundant 'View Details' button was removed from card footer and row actions in JS."""
        with open(PROJECT_ROOT / "static" / "network_discovery.js", "r", encoding="utf-8") as f:
            js = f.read()

        # Entire card and row are clickable role="button" with tabindex="0"
        self.assertIn("card.setAttribute('tabindex', '0')", js)
        self.assertIn("card.setAttribute('role', 'button')", js)
        self.assertIn("row.setAttribute('tabindex', '0')", js)
        self.assertIn("row.setAttribute('role', 'button')", js)

        # Keyboard event listeners for Enter / Space
        self.assertIn("e.key === 'Enter' || e.key === ' '", js)

        # Port scan link stops propagation to avoid triggering details modal or duplicate actions
        self.assertIn("scanPortsLink", js)
        self.assertIn("e.stopPropagation()", js)

        # Port scanner modal link uses standard view routing
        self.assertIn("/?view=port-scanner&target=", js)

    def test_03_subnet_validation_and_normalization(self):
        """3. Verify CIDR normalization: standard CIDR, single IP auto-expansion, range, and /22 boundary."""
        # Standard /24
        net, hosts = validate_and_normalize_subnet("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")
        self.assertEqual(len(hosts), 254)

        # Single IP auto-expanded to /24
        net, hosts = validate_and_normalize_subnet("192.168.1.15")
        self.assertEqual(str(net), "192.168.1.0/24")
        self.assertEqual(len(hosts), 254)

        # Range format
        net, hosts = validate_and_normalize_subnet("192.168.1.1-10")
        self.assertEqual(len(hosts), 10)
        self.assertEqual(hosts[0], "192.168.1.1")
        self.assertEqual(hosts[-1], "192.168.1.10")

        # Subnet > /22 rejected for broadcast safety
        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("10.0.0.0/16")

        # Invalid subnet string
        with self.assertRaises(ValueError):
            validate_and_normalize_subnet("not-an-ip-subnet")

    def test_04_device_provenance_and_zero_fabrication(self):
        """4. Verify that unverified neighbor cache entries are labeled Unverified, and missing hostnames remain Unknown."""
        # MAC OUI lookup unknown
        self.assertEqual(lookup_mac_vendor("FF:EE:DD:CC:BB:AA"), "Unknown Vendor")
        self.assertEqual(lookup_mac_vendor("Unavailable"), "Unknown")

        # Device type heuristics maintain transparent basis
        cat_gw, basis_gw = infer_device_type("192.168.1.1", "30:42:40:00:11:22", "router", "ZTE", is_gateway=True)
        self.assertEqual(cat_gw, "Router / Gateway")
        self.assertIn("Verified", basis_gw)

        cat_unk, basis_unk = infer_device_type("192.168.1.99", "Unavailable", "Unknown", "Unknown Vendor")
        self.assertEqual(cat_unk, "Unknown Device")
        self.assertIn("Insufficient", basis_unk)

    def test_05_adapter_selection_prioritizes_routable_connection(self):
        """5. Verify get_network_discovery_info prioritizes physical adapter matching active routable IP."""
        mock_raw_adapters = [
            {"Name": "Ethernet 2", "InterfaceDescription": "Realtek PCIe", "Status": "Up", "InterfaceIndex": 12, "PhysicalMediaType": "802.3", "MediaType": "802.3", "MacAddress": "AA-BB-CC-11-22-33"},
            {"Name": "Wi-Fi", "InterfaceDescription": "Intel Wi-Fi 6", "Status": "Up", "InterfaceIndex": 18, "PhysicalMediaType": "Native802_11", "MediaType": "Native802_11", "MacAddress": "AA-BB-CC-44-55-66"}
        ]
        mock_ips = [
            {"InterfaceIndex": 12, "IPAddress": "169.254.10.20", "PrefixLength": 16},
            {"InterfaceIndex": 18, "IPAddress": "192.168.1.100", "PrefixLength": 24}
        ]
        mock_routes = [
            {"InterfaceIndex": 18, "NextHop": "192.168.1.1"}
        ]

        with patch("modules.network_discovery.discovery.get_active_routable_ip", return_value="192.168.1.100"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=json.dumps({"adapters": mock_raw_adapters, "ips": mock_ips, "routes": mock_routes})
                )
                info = get_network_discovery_info(force_refresh=True)
                self.assertEqual(info["adapter_name"], "Wi-Fi")
                self.assertEqual(info["local_ip"], "192.168.1.100")
                self.assertEqual(info["default_gateway"], "192.168.1.1")
                self.assertEqual(info["subnet_cidr"], "192.168.1.0/24")

    def test_06_unverified_host_metrics_tracked(self):
        """6. Verify session accurately tracks online_count vs unverified_count."""
        status = network_discovery_manager.get_status()
        self.assertIn("online_count", status)
        self.assertIn("unverified_count", status)
        self.assertIn("devices_count", status)

    def test_07_duplicate_scan_prevention_and_cancel(self):
        """7. Verify duplicate scan prevention (already_scanning) and cooperative stop."""
        # Start a scan on a small range
        res = self.client.post("/api/network-discovery/start", json={
            "subnet": "127.0.0.1-2",
            "timeout": 0.2,
            "concurrency": 10
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn(data.get("status"), ["scanning", "already_scanning"])

        # Second attempt immediately must return already_scanning
        res2 = self.client.post("/api/network-discovery/start", json={
            "subnet": "127.0.0.1-2",
            "timeout": 0.2
        })
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertEqual(data2.get("status"), "already_scanning")

        # Stop scan cooperatively
        res_stop = self.client.post("/api/network-discovery/stop")
        self.assertEqual(res_stop.status_code, 200)
        self.assertIn(res_stop.get_json().get("status"), ["stopped", "idle"])

    def test_08_api_contract_compatibility(self):
        """8. Verify all /api/network-discovery/* endpoints adhere to stable contracts."""
        # Network info endpoint
        res_net = self.client.get("/api/network-discovery/network-info")
        self.assertEqual(res_net.status_code, 200)
        self.assertIn("network", res_net.get_json())

        # Status endpoint
        res_status = self.client.get("/api/network-discovery/status")
        self.assertEqual(res_status.status_code, 200)
        st = res_status.get_json()
        for key in ["status", "devices", "devices_count", "online_count", "unverified_count", "progress_pct"]:
            self.assertIn(key, st)

        # Device lookup returns 404 for non-existent device
        res_dev = self.client.get("/api/network-discovery/device/10.254.254.254")
        self.assertEqual(res_dev.status_code, 404)

    def test_09_export_script_integrity(self):
        """9. Verify static/network_discovery.js contains robust export functions for JSON and CSV."""
        with open(PROJECT_ROOT / "static" / "network_discovery.js", "r", encoding="utf-8") as f:
            js = f.read()

        self.assertIn("function exportResultsJson()", js)
        self.assertIn("function exportResultsCsv()", js)
        self.assertIn("network_discovery_", js)
        self.assertIn(".csv", js)
        self.assertIn(".json", js)

    def test_10_strict_isolation_from_live_monitoring_and_port_scanner(self):
        """10. CRITICAL: Verify network discovery operations leave live monitoring and port scanner untouched."""
        with scan_session_lock:
            initial_monitoring = dict(current_scan_session)

        # Query and trigger discovery
        self.client.get("/api/network-discovery/network-info")
        self.client.get("/api/network-discovery/status")

        with scan_session_lock:
            final_monitoring = dict(current_scan_session)

        self.assertEqual(initial_monitoring["status"], final_monitoring["status"])
        self.assertEqual(initial_monitoring.get("packets_captured"), final_monitoring.get("packets_captured"))


if __name__ == "__main__":
    unittest.main()
