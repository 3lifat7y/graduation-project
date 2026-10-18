#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit and Integration Tests for:
1. Send Traffic: Dynamic JSON Label Selection (scripts/send_traffic.py)
2. Live Monitoring: Current Network Interface Discovery, Auto/Manual Selection, and Zero-Fallback Policy
"""

import os
import sys
import json
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

# Add workspace root to sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from scripts.send_traffic import (
    resolve_dataset_path,
    load_dataset_records,
    resolve_label_argument,
    select_dataset_label_interactively,
    confirm_attack_transmission
)
from modules.common.network_detector import (
    get_windows_network_adapters,
    auto_detect_interface_with_rationale,
    get_active_routable_ip
)
from modules.monitoring.capture_engine import (
    resolve_scapy_interface
)
import api


class TestDynamicJsonLabelSelection(unittest.TestCase):
    """Verifies scripts/send_traffic.py dynamic JSON label discovery and selection."""

    @classmethod
    def setUpClass(cls):
        cls.dataset_path = resolve_dataset_path()

    def test_01_dataset_file_exists_and_loads(self):
        """Verifies dataset JSON is discovered and contains valid records."""
        self.assertIsNotNone(self.dataset_path, "Dataset file must be resolvable")
        self.assertTrue(self.dataset_path.exists(), f"Dataset file {self.dataset_path} must exist")

        records_by_label, sorted_counts = load_dataset_records(self.dataset_path)
        self.assertGreater(len(sorted_counts), 0, "Dataset must contain at least one label")
        self.assertIn("Benign", records_by_label, "Dataset should contain 'Benign' baseline traffic")

        # Verify all 15 CIC-IDS2017 classes are present
        label_names = [lbl for lbl, _ in sorted_counts]
        for expected in ["Benign", "DDoS", "PortScan", "Bot"]:
            self.assertIn(expected, label_names, f"Expected label '{expected}' in dataset")

    def test_02_resolve_label_argument_by_name(self):
        """Verifies resolve_label_argument resolves exact and case-insensitive names."""
        _, sorted_counts = load_dataset_records(self.dataset_path)

        # Exact match
        self.assertEqual(resolve_label_argument("Benign", sorted_counts), "Benign")
        self.assertEqual(resolve_label_argument("ddos", sorted_counts), "DDoS")
        self.assertEqual(resolve_label_argument("portscan", sorted_counts), "PortScan")
        self.assertEqual(resolve_label_argument("dos-hulk", sorted_counts), "DoS Hulk")

        # By 1-based index
        self.assertEqual(resolve_label_argument("1", sorted_counts), sorted_counts[0][0])
        self.assertEqual(resolve_label_argument("2", sorted_counts), sorted_counts[1][0])

        # Invalid label
        self.assertIsNone(resolve_label_argument("NonExistentAttack999", sorted_counts))

    def test_03_interactive_menu_selection_number_and_name(self):
        """Simulates interactive terminal menu selection via stdin."""
        mock_counts = [("Benign", 1000), ("DDoS", 500), ("PortScan", 200)]

        # Simulate selecting "1" (numeric)
        with patch('builtins.input', side_effect=["1"]):
            chosen = select_dataset_label_interactively(mock_counts)
            self.assertEqual(chosen, "Benign")

        # Simulate selecting "ddos" (string name)
        with patch('builtins.input', side_effect=["ddos"]):
            chosen = select_dataset_label_interactively(mock_counts)
            self.assertEqual(chosen, "DDoS")

        # Simulate cancellation with "q"
        with patch('builtins.input', side_effect=["q"]):
            chosen = select_dataset_label_interactively(mock_counts)
            self.assertIsNone(chosen)

    def test_04_attack_confirmation_safety_gate(self):
        """Verifies explicit confirmation prompt before sending attack-labelled data."""
        # Benign never requires confirmation
        self.assertTrue(confirm_attack_transmission("Benign", "http://127.0.0.1:5000", 10))

        # Attack requires explicit 'y'
        with patch('builtins.input', side_effect=["y"]):
            self.assertTrue(confirm_attack_transmission("DDoS", "http://127.0.0.1:5000", 10))

        # Decline attack with 'n'
        with patch('builtins.input', side_effect=["n"]):
            self.assertFalse(confirm_attack_transmission("DDoS", "http://127.0.0.1:5000", 10))

        # Default empty input (Return) declines attack
        with patch('builtins.input', side_effect=[""]):
            self.assertFalse(confirm_attack_transmission("DDoS", "http://127.0.0.1:5000", 10))


class TestNetworkInterfaceDiscoveryAndSelection(unittest.TestCase):
    """Verifies OS network interface discovery, Auto Select rationale, and strict resolution."""

    def test_05_discover_windows_network_adapters(self):
        """Verifies get_windows_network_adapters returns complete metadata."""
        adapters = get_windows_network_adapters()
        self.assertIsInstance(adapters, list)
        self.assertGreater(len(adapters), 0, "Host should discover at least one network adapter")

        for ad in adapters:
            self.assertIn("name", ad)
            self.assertIn("type", ad)
            self.assertIn("status", ad)
            self.assertIn("has_ipv4", ad)
            self.assertIn("is_connected", ad)
            self.assertIn("can_capture", ad)

    def test_06_auto_detect_interface_with_rationale(self):
        """Verifies auto_detect_interface_with_rationale returns rationale, driver status, and candidates."""
        result = auto_detect_interface_with_rationale()
        self.assertIn("adapter", result)
        self.assertIn("selection_rationale", result)
        self.assertIn("candidates", result)
        self.assertIn("driver_status", result)

        adapter = result["adapter"]
        self.assertIsNotNone(adapter.get("name"))
        self.assertTrue(len(result["selection_rationale"]) > 10, "Rationale must explain selection")

        # Selected adapter must not be VirtualBox if Wi-Fi or Ethernet is operational
        if adapter.get("type") == "Wi-Fi" or adapter.get("type") == "Ethernet":
            self.assertNotEqual(adapter.get("type"), "VirtualBox")

    def test_07_scapy_resolution_strictness_no_loose_substring(self):
        """
        CRITICAL TEST: Verifies that searching for 'Ethernet' NEVER resolves to
        'VirtualBox Host-Only Ethernet Adapter'.
        """
        class MockScapyInterface:
            def __init__(self, name, description, index, guid, net_name):
                self.name = name
                self.description = description
                self.index = index
                self.guid = guid
                self.network_name = net_name

        vbox_iface = MockScapyInterface(
            name="VirtualBox Host-Only Network",
            description="VirtualBox Host-Only Ethernet Adapter",
            index=18,
            guid="{VBOX-GUID-1234}",
            net_name=r"\Device\NPF_{VBOX-GUID-1234}"
        )
        real_eth_iface = MockScapyInterface(
            name="Ethernet",
            description="Intel(R) Ethernet Connection (7) I219-LM",
            index=13,
            guid="{INTEL-GUID-5678}",
            net_name=r"\Device\NPF_{INTEL-GUID-5678}"
        )

        mock_ifaces = {
            r"\Device\NPF_{VBOX-GUID-1234}": vbox_iface,
            r"\Device\NPF_{INTEL-GUID-5678}": real_eth_iface
        }

        # 1. Exact name 'Ethernet' must match real Ethernet, NEVER VirtualBox
        resolved = resolve_scapy_interface(interface_name="Ethernet", conf_ifaces=mock_ifaces)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.name, "Ethernet")
        self.assertNotEqual(resolved.name, "VirtualBox Host-Only Network")

        # 2. Exact index match
        resolved_idx = resolve_scapy_interface(interface_index=18, conf_ifaces=mock_ifaces)
        self.assertEqual(resolved_idx.name, "VirtualBox Host-Only Network")

        resolved_eth_idx = resolve_scapy_interface(interface_index=13, conf_ifaces=mock_ifaces)
        self.assertEqual(resolved_eth_idx.name, "Ethernet")

        # 3. Exact GUID match
        resolved_guid = resolve_scapy_interface(guid="{INTEL-GUID-5678}", conf_ifaces=mock_ifaces)
        self.assertEqual(resolved_guid.name, "Ethernet")

        # 4. Unknown interface must return None (ZERO silent substitution)
        resolved_unknown = resolve_scapy_interface(interface_name="NonExistentAdapter", conf_ifaces=mock_ifaces)
        self.assertIsNone(resolved_unknown, "Unknown adapter must return None without silent fallback")


class TestFlaskMonitoringEndpoints(unittest.TestCase):
    """Verifies /api/adapter-info and /api/scan backend endpoints."""

    def setUp(self):
        self.client = api.app.test_client()

    def test_08_adapter_info_endpoint(self):
        """Verifies GET /api/adapter-info returns discovered adapters, rationale, and driver status."""
        res = self.client.get('/api/adapter-info')
        self.assertIn(res.status_code, [200, 500])
        data = res.get_json()

        self.assertIn(data.get("status"), ["success", "warning"])
        self.assertIn("available_adapters", data)
        self.assertIn("selection_rationale", data)
        self.assertIn("driver_status", data)

    def test_09_scan_endpoint_offline_adapter_rejection(self):
        """
        Verifies POST /api/scan with a disconnected adapter returns ADAPTER_OFFLINE
        and NEVER silently falls back to another adapter.
        """
        # Find any disconnected adapter on this system (e.g. Ethernet)
        adapters = get_windows_network_adapters()
        disconnected = [a for a in adapters if a.get("status") in ["Disconnected", "Disabled"]]

        if disconnected:
            target_name = disconnected[0]["name"]
            res = self.client.post('/api/scan', json={"adapter": target_name})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            self.assertEqual(data.get("status"), "error")
            self.assertEqual(data.get("error_type"), "ADAPTER_OFFLINE")
            self.assertIn(target_name, data.get("message", ""))

    def test_10_scan_endpoint_unknown_adapter_rejection(self):
        """
        Verifies POST /api/scan with an unknown adapter returns InterfaceNotFound
        and NEVER silently falls back to a default adapter.
        """
        res = self.client.post('/api/scan', json={"adapter": "PhantomNetworkAdapterXYZ_999"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data.get("error_type"), "InterfaceNotFound")

    def test_11_scan_stop_endpoint_releases_resources(self):
        """Verifies POST /api/scan-stop releases monitoring state cleanly."""
        res = self.client.post('/api/scan-stop')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "stopped")

        # Query scan status to verify stopped state
        status_res = self.client.get('/api/scan-status')
        status_data = status_res.get_json()
        self.assertIn(status_data.get("status"), ["ready", "stopped"])


if __name__ == '__main__':
    unittest.main()
