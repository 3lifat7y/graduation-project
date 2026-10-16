"""
Comprehensive Automated Test Suite for DDoS-Guard Network Discovery Feature
Tests subnet detection, OUI vendor database, hostname resolution, device type inference,
concurrent async scan lifecycle, cooperative cancellation, duplicate scan rejection,
CIDR input boundaries, and Flask REST API endpoints.
"""

import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import unittest
from unittest.mock import patch, MagicMock
import ipaddress
import json
import time

# Feature Backend Module Under Test
import modules.network_discovery.discovery as network_discovery
from modules.network_discovery.discovery import (
    lookup_mac_vendor,
    infer_device_type,
    resolve_hostname,
    get_network_discovery_info,
    read_windows_arp_cache,
    NetworkDiscoveryManager,
    MAC_OUI_DATABASE
)

# Flask Application & Endpoints Under Test
import api


class TestNetworkDiscoveryUnits(unittest.TestCase):
    """Unit tests for network reconnaissance utilities and parsing engines."""

    def test_mac_oui_lookup(self):
        """Verify IEEE MAC OUI lookup for known, unknown, and edge cases."""
        # Known vendor prefixes
        self.assertEqual(lookup_mac_vendor("30:42:40:E2:D2:54"), "ZTE")
        self.assertEqual(lookup_mac_vendor("B8:27:EB:12:34:56"), "Raspberry Pi Foundation")
        self.assertEqual(lookup_mac_vendor("00-02-B3-AA-BB-CC"), "Intel")
        self.assertEqual(lookup_mac_vendor("001478aabbcc"), "TP-Link")
        self.assertEqual(lookup_mac_vendor("00:00:0C:11:22:33"), "Cisco")
        self.assertEqual(lookup_mac_vendor("00:00:85:12:34:56"), "Canon")
        self.assertEqual(lookup_mac_vendor("18:FE:34:AA:BB:CC"), "Espressif (ESP8266/ESP32)")

        # Unknown / Edge cases (Never fabricate)
        self.assertEqual(lookup_mac_vendor("99:99:99:99:99:99"), "Unknown Vendor")
        self.assertEqual(lookup_mac_vendor(""), "Unknown")
        self.assertEqual(lookup_mac_vendor(None), "Unknown")
        self.assertEqual(lookup_mac_vendor("Unavailable"), "Unknown")
        self.assertEqual(lookup_mac_vendor("Unknown"), "Unknown")

    def test_device_type_inference(self):
        """Verify device category heuristics and verified vs inferred distinctions."""
        # 1. Gateway is always verified
        cat, basis = infer_device_type("192.168.1.1", "30:42:40:11:22:33", "router.local", "ZTE", is_gateway=True)
        self.assertEqual(cat, "Router / Gateway")
        self.assertIn("Verified", basis)

        # 2. Local machine interface is verified
        cat, basis = infer_device_type("192.168.1.9", "AA:BB:CC:DD:EE:FF", "DESKTOP-DEV", "Intel", is_gateway=False, is_local_host=True)
        self.assertEqual(cat, "Computer / Workstation")
        self.assertIn("Verified", basis)

        # 3. Network infrastructure vendor inference
        cat, basis = infer_device_type("192.168.1.50", "00:14:78:11:22:33", "Unknown", "TP-Link")
        self.assertEqual(cat, "Router / Access Point")
        self.assertIn("Inferred", basis)

        # 4. Printer vendor inference
        cat, basis = infer_device_type("192.168.1.80", "00:00:85:11:22:33", "hp-printer", "Canon")
        self.assertEqual(cat, "Printer")
        self.assertIn("Inferred", basis)

        # 5. IoT / Microcontroller inference
        cat, basis = infer_device_type("192.168.1.95", "18:FE:34:11:22:33", "Unknown", "Espressif (ESP8266/ESP32)")
        self.assertEqual(cat, "IoT / Embedded")
        self.assertIn("Inferred", basis)

        # 6. Mobile device inference
        cat, basis = infer_device_type("192.168.1.110", "18:59:36:11:22:33", "redmi-note", "Xiaomi")
        self.assertEqual(cat, "Mobile Device")
        self.assertIn("Inferred", basis)

        # 7. Insufficient data fallback
        cat, basis = infer_device_type("192.168.1.200", "Unavailable", "Unknown", "Unknown Vendor")
        self.assertEqual(cat, "Unknown Device")
        self.assertIn("Insufficient", basis)

    def test_hostname_resolution_no_fabrication(self):
        """Ensure unresolved hosts return 'Unknown' rather than inventing hostnames."""
        with patch('socket.gethostbyaddr', side_effect=Exception("Host not found")):
            with patch('network_discovery.probe_netbios_name', return_value=None):
                name = resolve_hostname("192.168.1.240")
                self.assertEqual(name, "Unknown")

    def test_hostname_resolution_success(self):
        """Verify successful reverse DNS resolution."""
        with patch('socket.gethostbyaddr', return_value=("gateway.home", [], ["192.168.1.1"])):
            name = resolve_hostname("192.168.1.1")
            self.assertEqual(name, "gateway.home")

    def test_windows_arp_cache_parser(self):
        """Verify parsing of Windows `arp -a` output and filtering of broadcast/multicast."""
        sample_arp_output = """
Interface: 192.168.1.9 --- 0xc
  Internet Address      Physical Address      Type
  192.168.1.1           30-42-40-e2-d2-54     dynamic
  192.168.1.5           50-c7-bf-12-34-56     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=sample_arp_output)
            entries = read_windows_arp_cache()
            self.assertIn("192.168.1.1", entries)
            self.assertEqual(entries["192.168.1.1"], "30:42:40:E2:D2:54")
            self.assertIn("192.168.1.5", entries)
            self.assertEqual(entries["192.168.1.5"], "50:C7:BF:12:34:56")
            # Multicast / broadcast filtered
            self.assertNotIn("224.0.0.22", entries)
            self.assertNotIn("239.255.255.250", entries)
            self.assertNotIn("255.255.255.255", entries)

    def test_network_info_structure(self):
        """Check the schema and structure of auto-detected network parameters."""
        info = get_network_discovery_info()
        self.assertIn("local_ip", info)
        self.assertIn("subnet_mask", info)
        self.assertIn("subnet_cidr", info)
        self.assertIn("adapter_name", info)
        self.assertIn("total_hosts", info)
        self.assertIn("is_connected", info)
        # Ensure total_hosts is a reasonable integer
        self.assertIsInstance(info["total_hosts"], int)


class TestNetworkDiscoveryManager(unittest.TestCase):
    """Lifecycle and concurrency tests for NetworkDiscoveryManager."""

    def setUp(self):
        self.manager = NetworkDiscoveryManager()

    def tearDown(self):
        self.manager.stop_scan()

    def test_initial_state(self):
        """Initial state should be idle with empty devices."""
        status = self.manager.get_status()
        self.assertEqual(status["status"], "idle")
        self.assertEqual(len(status["devices"]), 0)

    def test_subnet_validation_invalid_cidr(self):
        """Rejects malformed CIDR strings."""
        with self.assertRaises(ValueError):
            self.manager.start_scan("not-an-ip/24")

    def test_subnet_validation_too_large(self):
        """Rejects networks with > 1024 hosts (e.g. /16 or /8) to avoid network loops."""
        with self.assertRaises(ValueError) as ctx:
            self.manager.start_scan("10.0.0.0/16")
        self.assertIn("1,024 hosts", str(ctx.exception))

    def test_duplicate_scan_prevention(self):
        """Prevents launching multiple concurrent discovery scans."""
        with patch.object(self.manager, '_discovery_worker', return_value=None):
            res1 = self.manager.start_scan("192.168.1.0/29", timeout=0.1, concurrency=5)
            self.assertEqual(res1["status"], "scanning")

            res2 = self.manager.start_scan("192.168.1.0/29", timeout=0.1, concurrency=5)
            self.assertEqual(res2["status"], "already_scanning")

    def test_cooperative_cancellation(self):
        """Verifies stop_scan cleanly marks status as stopped and flags stop event."""
        with patch.object(self.manager, '_discovery_worker', return_value=None):
            self.manager.start_scan("192.168.1.0/29", timeout=0.1, concurrency=5)
            self.assertEqual(self.manager.session["status"], "scanning")

            stop_res = self.manager.stop_scan()
            self.assertEqual(stop_res["status"], "stopped")
            self.assertTrue(self.manager._stop_event.is_set())
            self.assertEqual(self.manager.session["status"], "stopped")


class TestNetworkDiscoveryApi(unittest.TestCase):
    """Integration tests for Flask API network discovery endpoints."""

    def setUp(self):
        self.app = api.app.test_client()
        self.app.testing = True

    def test_page_route(self):
        """GET /network-discovery returns 200 and loads HTML structure."""
        resp = self.app.get('/network-discovery')
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Local Network Discovery", html)
        self.assertIn("ndStartBtn", html)
        self.assertIn("ndDeviceTable", html)
        self.assertIn("network_discovery.js", html)

    def test_api_network_info(self):
        """GET /api/network-discovery/network-info returns adapter and subnet metrics."""
        resp = self.app.get('/api/network-discovery/network-info')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.get_data(as_text=True))
        self.assertEqual(data["status"], "success")
        self.assertIn("network", data)
        self.assertIn("local_ip", data["network"])
        self.assertIn("subnet_cidr", data["network"])

    def test_api_status_idle(self):
        """GET /api/network-discovery/status returns current manager session status."""
        resp = self.app.get('/api/network-discovery/status')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.get_data(as_text=True))
        self.assertIn("status", data)
        self.assertIn("devices", data)

    def test_api_start_bad_cidr(self):
        """POST /api/network-discovery/start with invalid subnet returns 400 error."""
        resp = self.app.post(
            '/api/network-discovery/start',
            data=json.dumps({"subnet": "999.999.999.999/24"}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.get_data(as_text=True))
        self.assertEqual(data["status"], "error")
        self.assertIn("Invalid IPv4 subnet", data["message"])

    def test_api_stop_when_idle(self):
        """POST /api/network-discovery/stop when idle succeeds gracefully."""
        resp = self.app.post('/api/network-discovery/stop')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.get_data(as_text=True))
        self.assertIn("status", data)

    def test_api_device_not_found(self):
        """GET /api/network-discovery/device/<ip> returns 404 for nonexistent host."""
        resp = self.app.get('/api/network-discovery/device/10.254.254.254')
        self.assertEqual(resp.status_code, 404)
        data = json.loads(resp.get_data(as_text=True))
        self.assertEqual(data["status"], "not_found")


if __name__ == '__main__':
    unittest.main()
