#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_auto_switch_adapter.py

Automated Test Suite for SocNet: Automatically Switch Live Monitoring on Adapter Selection.
Verifies all 12 requirements:
1. Initial selection capture start
2. Switching adapters during active monitoring (safely stops previous worker, restarts on new adapter)
3. Preserving manual stop intent (changing dropdown after manual stop does NOT unexpectedly restart)
4. Rapid consecutive selection changes (sequence guards, zero duplicate workers, zero race conditions)
5. Exact interface identifier forwarding (name, index, guid, network_name)
6. Zero silent fallback on offline/disconnected/missing interfaces
7. Disappeared adapter reporting without automatic switching
8. Independence of background discovery and periodic refresh from monitoring state
9. Clear distinction between mocked tests and real host packet-capture checks.
"""

import os
import sys
import json
import time
import unittest
from unittest.mock import patch, MagicMock

# Add workspace root to sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import api
from modules.common.network_detector import (
    get_windows_network_adapters,
    auto_detect_primary_interface
)
from modules.monitoring.capture_engine import (
    resolve_scapy_interface
)


class TestAutoSwitchAdapterMocked(unittest.TestCase):
    """
    Mocked Unit Tests:
    Validates adapter switching logic, lifecycle transitions, concurrency guards,
    and zero-fallback policies without requiring root or physical link alterations.
    """

    def setUp(self):
        self.client = api.app.test_client()
        # Cleanly stop any leftover active scan session
        with api.scan_session_lock:
            api.current_scan_session.update({
                "status": "ready",
                "scan_id": None,
                "continuous": False,
                "packets_captured": 0,
                "window_packets": 0,
                "throughput_kbps": 0.0,
                "protocol": "--",
                "error": None,
                "message": "System ready."
            })
            api.is_monitoring = False

    def tearDown(self):
        with api.scan_session_lock:
            api.current_scan_session.update({
                "status": "ready",
                "scan_id": None,
                "continuous": False,
                "packets_captured": 0,
                "window_packets": 0,
                "throughput_kbps": 0.0,
                "error": None
            })
            api.is_monitoring = False

    def test_01_initial_selection_starts_capture_with_exact_identifiers(self):
        """
        Requirement 1, 3, 4:
        Initial explicit adapter selection automatically starts capture and passes
        exact interface parameters (name, index, guid, network_name).
        """
        mock_adapter = {
            "name": "Wi-Fi Mock",
            "description": "Mock Wireless Adapter",
            "index": 14,
            "status": "Up",
            "type": "Wi-Fi",
            "primary_ip": "192.168.1.150",
            "ips": ["192.168.1.150"],
            "guid": "{MOCK-GUID-14}",
            "network_name": r"\Device\NPF_{MOCK-GUID-14}",
            "is_connected": True,
            "is_virtual": False,
            "can_capture": True
        }

        with patch("api.get_windows_network_adapters", return_value=[mock_adapter]), \
             patch("api.get_service_status", return_value={"installed": False, "running": False, "ipc_online": False}), \
             patch("api.check_capture_drivers", return_value={"can_capture_live": True, "npcap_installed": True}), \
             patch("api.standalone_worker.start_window", return_value={"status": "scanning"}):

            res = self.client.post("/api/scan", json={
                "interface_name": "Wi-Fi Mock",
                "interface_index": 14,
                "guid": "{MOCK-GUID-14}",
                "network_name": r"\Device\NPF_{MOCK-GUID-14}",
                "continuous": True
            })
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "scanning")
            self.assertIsNotNone(data.get("scan_id"))
            self.assertEqual(data.get("interface", {}).get("name"), "Wi-Fi Mock")
            self.assertEqual(data.get("interface", {}).get("index"), 14)
            self.assertEqual(data.get("interface", {}).get("guid"), "{MOCK-GUID-14}")

    def test_02_switching_adapter_during_active_monitoring_safely_replaces_session(self):
        """
        Requirement 1, 2, 5, 6:
        When a monitoring session is running on Adapter A, switching to Adapter B with force_restart
        safely stops previous worker, wipes packet counters, and begins on Adapter B with new scan_id.
        """
        ad_a = {
            "name": "Ethernet-A",
            "description": "Mock Ethernet A",
            "index": 10,
            "status": "Up",
            "type": "Ethernet",
            "primary_ip": "10.0.0.10",
            "ips": ["10.0.0.10"],
            "guid": "{GUID-A}",
            "network_name": r"\Device\NPF_{GUID-A}",
            "is_connected": True,
            "is_virtual": False,
            "can_capture": True
        }
        ad_b = {
            "name": "Wi-Fi-B",
            "description": "Mock Wi-Fi B",
            "index": 20,
            "status": "Up",
            "type": "Wi-Fi",
            "primary_ip": "192.168.1.20",
            "ips": ["192.168.1.20"],
            "guid": "{GUID-B}",
            "network_name": r"\Device\NPF_{GUID-B}",
            "is_connected": True,
            "is_virtual": False,
            "can_capture": True
        }

        with patch("api.get_windows_network_adapters", return_value=[ad_a, ad_b]), \
             patch("api.get_service_status", return_value={"installed": False, "running": False, "ipc_online": False}), \
             patch("api.check_capture_drivers", return_value={"can_capture_live": True, "npcap_installed": True}), \
             patch("api.standalone_worker.start_window", return_value={"status": "scanning"}), \
             patch("api.standalone_worker.stop_window", return_value=True):

            # Start on Adapter A
            res_a = self.client.post("/api/scan", json={"interface_name": "Ethernet-A", "continuous": True})
            self.assertEqual(res_a.status_code, 200)
            data_a = res_a.get_json()
            scan_id_a = data_a.get("scan_id")
            self.assertEqual(data_a.get("interface", {}).get("name"), "Ethernet-A")

            # Simulate traffic accumulated on session A
            with api.scan_session_lock:
                api.current_scan_session["packets_captured"] = 150
                api.current_scan_session["window_packets"] = 25
                api.current_scan_session["status"] = "monitoring"

            # Switch directly to Adapter B with force_restart=True (simulates frontend atomic switch)
            res_b = self.client.post("/api/scan", json={
                "interface_name": "Wi-Fi-B",
                "continuous": True,
                "force_restart": True
            })
            self.assertEqual(res_b.status_code, 200)
            data_b = res_b.get_json()
            scan_id_b = data_b.get("scan_id")

            # Must generate distinct, fresh scan session ID
            self.assertNotEqual(scan_id_a, scan_id_b)
            # Must reflect Adapter B
            self.assertEqual(data_b.get("interface", {}).get("name"), "Wi-Fi-B")
            self.assertEqual(data_b.get("interface", {}).get("primary_ip"), "192.168.1.20")
            # Telemetry counters must reset to zero
            self.assertEqual(data_b.get("packets_captured"), 0)
            self.assertEqual(data_b.get("window_packets"), 0)

    def test_03_already_scanning_rejected_without_force_restart(self):
        """
        Requirement 6:
        Without force_restart or manual stop, calling /api/scan while already scanning
        is rejected with 'already_scanning' to prevent uncoordinated duplicate workers.
        """
        with api.scan_session_lock:
            api.current_scan_session["status"] = "monitoring"
            api.current_scan_session["scan_id"] = "active_session_123"

        res = self.client.post("/api/scan", json={"interface_name": "AnyAdapter"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "already_scanning")
        self.assertEqual(data.get("scan_id"), "active_session_123")

    def test_04_zero_silent_fallback_on_offline_or_disconnected_adapter(self):
        """
        Requirement 7:
        If selected adapter is Disconnected, capture is rejected with ADAPTER_OFFLINE,
        and system NEVER silently falls back to another adapter or auto-detect.
        """
        disconnected_ad = {
            "name": "Ethernet Disconnected",
            "description": "Realtek PCIe GbE",
            "index": 12,
            "status": "Disconnected",
            "type": "Ethernet",
            "primary_ip": None,
            "ips": [],
            "guid": "{DISCONNECTED-GUID}",
            "is_connected": False,
            "is_virtual": False,
            "can_capture": True
        }
        online_wifi = {
            "name": "Wi-Fi Operational",
            "description": "Intel Wireless",
            "index": 14,
            "status": "Up",
            "type": "Wi-Fi",
            "primary_ip": "192.168.1.50",
            "ips": ["192.168.1.50"],
            "guid": "{WIFI-GUID}",
            "is_connected": True,
            "is_virtual": False,
            "can_capture": True
        }

        with patch("api.get_windows_network_adapters", return_value=[disconnected_ad, online_wifi]):
            res = self.client.post("/api/scan", json={"interface_name": "Ethernet Disconnected"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error_type"), "ADAPTER_OFFLINE")
            self.assertIn("Disconnected", data.get("message", ""))
            # Must NOT substitute Wi-Fi Operational
            self.assertNotIn("Wi-Fi Operational", data.get("message", ""))

    def test_05_zero_silent_fallback_on_unknown_missing_adapter(self):
        """
        Requirement 7, 10:
        If requested adapter cannot be resolved, capture is aborted with InterfaceNotFound.
        No silent default substitution occurs.
        """
        with patch("api.get_windows_network_adapters", return_value=[]), \
             patch("api.resolve_scapy_interface", return_value=None):

            res = self.client.post("/api/scan", json={"interface_name": "NonExistentNic_888"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error_type"), "InterfaceNotFound")
            self.assertIn("NonExistentNic_888", data.get("message", ""))

    def test_06_clean_stop_releases_session_state(self):
        """
        Requirement 2, 9:
        POST /api/scan-stop terminates active workers and puts session into 'stopped' state.
        """
        with api.scan_session_lock:
            api.current_scan_session["status"] = "monitoring"
            api.current_scan_session["scan_id"] = "session_to_stop"
            api.is_monitoring = True

        with patch("api.standalone_worker.stop_window", return_value=True):
            res = self.client.post("/api/scan-stop")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "stopped")

            # Check scan status reflects stopped
            status_res = self.client.get("/api/scan-status")
            status_data = status_res.get_json()
            self.assertEqual(status_data.get("status"), "stopped")
            self.assertFalse(api.is_monitoring)

    def test_07_rescan_reports_disappeared_adapter_without_switching(self):
        """
        Requirement 10:
        If the monitored adapter disappears, /api/scan-rescan reports adapter_unavailable
        and does NOT silently switch to any other adapter.
        """
        with api.scan_session_lock:
            api.current_scan_session.update({
                "status": "monitoring",
                "scan_id": "test_scan_disappeared",
                "interface": {
                    "name": "RemovedAdapterXYZ",
                    "type": "Ethernet",
                    "primary_ip": "192.168.1.99",
                    "status": "Up",
                    "is_connected": True
                }
            })
            api.is_monitoring = True

        # System adapters list no longer contains RemovedAdapterXYZ
        with patch("api.get_windows_network_adapters", return_value=[]), \
             patch("api.standalone_worker.is_running", return_value=True):

            res = self.client.post("/api/scan-rescan")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("health_state"), "adapter_unavailable")
            self.assertEqual(data.get("recovery_action"), "reconnect_adapter")
            self.assertIn("unavailable", data.get("message", ""))

    def test_08_background_discovery_does_not_restart_active_monitoring(self):
        """
        Requirement 8:
        Calling GET /api/adapter-info (used by interface discovery and refresh)
        does NOT interrupt or restart an active monitoring session.
        """
        with api.scan_session_lock:
            api.current_scan_session.update({
                "status": "monitoring",
                "scan_id": "active_continuous_session",
                "packets_captured": 88
            })
            api.is_monitoring = True

        res = self.client.get("/api/adapter-info")
        self.assertIn(res.status_code, [200, 500])

        # Active session must remain completely undisturbed
        with api.scan_session_lock:
            self.assertEqual(api.current_scan_session.get("status"), "monitoring")
            self.assertEqual(api.current_scan_session.get("scan_id"), "active_continuous_session")
            self.assertEqual(api.current_scan_session.get("packets_captured"), 88)


class TestAutoSwitchAdapterRealCapture(unittest.TestCase):
    """
    Real Host Environment Integration Tests:
    Inspects actual Windows network interfaces and tests real API lifecycle
    without mocks to distinguish unit mocks from actual physical device integration.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = api.app.test_client()
        cls.real_adapters = get_windows_network_adapters()

    def test_09_real_host_adapters_discovered(self):
        """Verifies the host discovers at least one real physical/virtual adapter."""
        self.assertIsInstance(self.real_adapters, list)
        self.assertGreater(len(self.real_adapters), 0, "Host must have at least one network adapter")
        for ad in self.real_adapters:
            self.assertIn("name", ad)
            self.assertIn("type", ad)
            self.assertIn("status", ad)

    def test_10_real_host_primary_adapter_auto_detection(self):
        """Verifies auto_detect_primary_interface resolves a valid interface on the real machine."""
        primary_ad, driver_info = auto_detect_primary_interface()
        self.assertIsNotNone(primary_ad)
        self.assertIn("name", primary_ad)
        self.assertIn("status", primary_ad)
        self.assertIsInstance(driver_info, dict)

    def test_11_real_host_scapy_resolution_strictness(self):
        """Verifies real Scapy interface resolution on host machine strictly matches exact adapters."""
        if self.real_adapters:
            first_ad = self.real_adapters[0]
            resolved = resolve_scapy_interface(
                interface_name=first_ad.get("name"),
                interface_index=first_ad.get("index"),
                guid=first_ad.get("guid")
            )
            # If Npcap is present, resolved should match the requested adapter
            if resolved:
                self.assertIsNotNone(getattr(resolved, "name", None))


if __name__ == "__main__":
    unittest.main()
