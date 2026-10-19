#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for SocNet Ethernet Network Discovery, Adapter Type Classification,
Gateway-less Subnet Resolution, and Routing Behavior.

Distinguishes:
1. Mocked Unit Tests: Simulates gateway-connected Ethernet, isolated Ethernet (no default gateway),
   disabled Wi-Fi, and fully disconnected states.
2. Actual System Tests: Exercises the live system network stack without mocking to verify real OS behavior.
"""

import os
import json
import socket
import asyncio
import unittest
from unittest.mock import patch, MagicMock

import ipaddress
from modules.network_discovery.discovery import (
    get_network_discovery_info,
    validate_and_normalize_subnet,
    classify_adapter_media_type,
    NetworkDiscoveryManager
)
from modules.port_scanner.scanner import (
    probe_single_port,
    validate_and_resolve_target
)
import api


class TestMockedEthernetDiscoveryAndRouting(unittest.TestCase):
    """
    Mocked unit tests for validating interface detection, adapter type classification,
    and subnet calculation under various network configurations.
    """

    def setUp(self):
        self.app = api.app.test_client()
        self.app.testing = True

    def test_adapter_classification_logic(self):
        """Verifies accurate classification of Ethernet, Wi-Fi, Virtual, and Loopback interfaces."""
        # Ethernet variants
        self.assertEqual(classify_adapter_media_type("Ethernet", "Intel(R) Ethernet Connection I219-V"), "Ethernet")
        self.assertEqual(classify_adapter_media_type("Local Area Connection", "Realtek PCIe GbE Family Controller"), "Ethernet")
        self.assertEqual(classify_adapter_media_type("Ethernet 2", "Killer E2500 Gigabit Ethernet Controller"), "Ethernet")
        self.assertEqual(classify_adapter_media_type("vSwitch_Eth", "USB Ethernet Adapter"), "Ethernet")

        # Wi-Fi variants
        self.assertEqual(classify_adapter_media_type("Wi-Fi", "Intel(R) Wi-Fi 6 AX200 160MHz"), "Wi-Fi")
        self.assertEqual(classify_adapter_media_type("Wireless Network Connection", "Qualcomm Atheros Wireless"), "Wi-Fi")
        self.assertEqual(classify_adapter_media_type("WLAN", "Realtek 8821CE Wireless LAN 802.11ac"), "Wi-Fi")

        # Virtual / Loopback
        self.assertEqual(classify_adapter_media_type("Loopback", "Npcap Loopback Adapter"), "Virtual")
        self.assertEqual(classify_adapter_media_type("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet"), "Virtual")
        self.assertEqual(classify_adapter_media_type("VirtualBox Host-Only Network", "VirtualBox Adapter"), "Virtual")

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value="192.168.1.150")
    @patch("subprocess.run")
    def test_gateway_connected_ethernet_detection(self, mock_subproc, mock_ip):
        """When Ethernet is Up with an active default gateway, it is detected with adapter_type='Ethernet'."""
        ps_payload = {
            "adapters": [
                {
                    "Name": "Ethernet",
                    "InterfaceDescription": "Intel(R) Ethernet Connection I219-V",
                    "Status": "Up",
                    "InterfaceIndex": 12,
                    "MacAddress": "00:11:22:33:44:55",
                    "PhysicalMediaType": "802.3",
                    "MediaType": "802.3"
                }
            ],
            "ips": [
                {
                    "InterfaceIndex": 12,
                    "IPAddress": "192.168.1.150",
                    "PrefixLength": 24
                }
            ],
            "routes": [
                {
                    "InterfaceIndex": 12,
                    "NextHop": "192.168.1.1"
                }
            ]
        }
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(ps_payload))

        info = get_network_discovery_info()
        self.assertTrue(info["is_connected"])
        self.assertEqual(info["status"], "online")
        self.assertEqual(info["adapter_name"], "Ethernet")
        self.assertEqual(info["adapter_type"], "Ethernet")
        self.assertNotEqual(info["adapter_type"], "Wi-Fi")
        self.assertEqual(info["local_ip"], "192.168.1.150")
        self.assertEqual(info["subnet_cidr"], "192.168.1.0/24")
        self.assertEqual(info["default_gateway"], "192.168.1.1")
        self.assertEqual(info["local_mac"], "00:11:22:33:44:55")

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value=None)
    @patch("subprocess.run")
    def test_isolated_ethernet_no_gateway_detection(self, mock_subproc, mock_ip):
        """
        When Ethernet is connected in an isolated LAN (no internet / no default gateway),
        get_active_routable_ip() fails (returns None), but the adapter is still correctly discovered.
        """
        ps_payload = {
            "adapters": [
                {
                    "Name": "Ethernet Direct",
                    "InterfaceDescription": "Realtek PCIe GbE Family Controller",
                    "Status": "Up",
                    "InterfaceIndex": 18,
                    "MacAddress": "AA:BB:CC:DD:EE:FF",
                    "PhysicalMediaType": "802.3",
                    "MediaType": "802.3"
                }
            ],
            "ips": [
                {
                    "InterfaceIndex": 18,
                    "IPAddress": "192.168.10.50",
                    "PrefixLength": 24
                }
            ],
            "routes": []  # No default route (0.0.0.0/0) exists on isolated network
        }
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(ps_payload))

        info = get_network_discovery_info()
        self.assertTrue(info["is_connected"])
        self.assertEqual(info["status"], "online")
        self.assertEqual(info["adapter_name"], "Ethernet Direct")
        self.assertEqual(info["adapter_type"], "Ethernet")
        self.assertEqual(info["local_ip"], "192.168.10.50")
        self.assertEqual(info["subnet_cidr"], "192.168.10.0/24")
        self.assertEqual(info["total_hosts"], 254)

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value=None)
    @patch("subprocess.run")
    def test_wifi_disabled_ethernet_active(self, mock_subproc, mock_ip):
        """When Wi-Fi is disabled/disconnected and Ethernet is active, Ethernet is auto-selected."""
        ps_payload = {
            "adapters": [
                {
                    "Name": "Wi-Fi",
                    "InterfaceDescription": "Intel(R) Wireless-AC 9560",
                    "Status": "Disabled",
                    "InterfaceIndex": 5,
                    "MacAddress": "11:22:33:44:55:66",
                    "PhysicalMediaType": "Native802_11",
                    "MediaType": "802.11"
                },
                {
                    "Name": "Ethernet",
                    "InterfaceDescription": "Intel(R) Ethernet Connection I219-LM",
                    "Status": "Up",
                    "InterfaceIndex": 8,
                    "MacAddress": "22:33:44:55:66:77",
                    "PhysicalMediaType": "802.3",
                    "MediaType": "802.3"
                }
            ],
            "ips": [
                {
                    "InterfaceIndex": 8,
                    "IPAddress": "10.0.5.25",
                    "PrefixLength": 24
                }
            ],
            "routes": [
                {"InterfaceIndex": 8, "NextHop": "10.0.5.1"}
            ]
        }
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(ps_payload))

        info = get_network_discovery_info()
        self.assertEqual(info["adapter_name"], "Ethernet")
        self.assertEqual(info["adapter_type"], "Ethernet")
        self.assertEqual(info["local_ip"], "10.0.5.25")
        self.assertEqual(info["subnet_cidr"], "10.0.5.0/24")

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value=None)
    @patch("subprocess.run")
    def test_all_interfaces_disconnected_behavior(self, mock_subproc, mock_ip):
        """When all interfaces are disconnected, no silent fallback to 192.168.1.0/24 occurs."""
        ps_payload = {
            "adapters": [],
            "ips": [],
            "routes": []
        }
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(ps_payload))

        info = get_network_discovery_info()
        self.assertFalse(info["is_connected"])
        self.assertEqual(info["status"], "offline")
        self.assertIsNone(info["subnet_cidr"])
        self.assertEqual(info["local_ip"], "127.0.0.1")

        # validate_and_normalize_subnet should reject blank input with clear error
        with self.assertRaises(ValueError) as ctx:
            validate_and_normalize_subnet("", default_cidr=info["subnet_cidr"])
        self.assertIn("No active local subnet detected", str(ctx.exception))

        # Manager scan with no subnet should fail gracefully
        mgr = NetworkDiscoveryManager()
        with self.assertRaises(ValueError) as ctx2:
            mgr.start_scan(None)
        self.assertIn("No active local subnet detected", str(ctx2.exception))

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value=None)
    @patch("subprocess.run")
    def test_manual_subnet_allowed_when_offline(self, mock_subproc, mock_ip):
        """When offline, the user can manually specify a subnet to scan."""
        ps_payload = {"adapters": [], "ips": [], "routes": []}
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(ps_payload))

        net_obj, targets = validate_and_normalize_subnet("172.16.50.0/24")
        self.assertEqual(str(net_obj), "172.16.50.0/24")
        self.assertEqual(len(targets), 254)

    @patch("modules.network_discovery.discovery.get_active_routable_ip", return_value=None)
    @patch("subprocess.run")
    def test_port_scan_network_info_endpoint_offline_vs_isolated(self, mock_subproc, mock_ip):
        """Port Scanner endpoint returns null subnet when offline, and isolated subnet when Ethernet is up."""
        # 1. Completely offline
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps({"adapters": [], "ips": [], "routes": []}))
        res = self.app.get('/api/port-scan/network-info')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["is_connected"])
        self.assertIsNone(data["suggested_subnet"])
        self.assertEqual(data["local_ip"], "127.0.0.1")

        # 2. Isolated Ethernet up (no default route)
        isolated_payload = {
            "adapters": [
                {
                    "Name": "Ethernet",
                    "InterfaceDescription": "Intel Gigabit",
                    "Status": "Up",
                    "InterfaceIndex": 10,
                    "MacAddress": "00:AA:BB:CC:DD:EE",
                    "PhysicalMediaType": "802.3",
                    "MediaType": "802.3"
                }
            ],
            "ips": [{"InterfaceIndex": 10, "IPAddress": "192.168.4.100", "PrefixLength": 24}],
            "routes": []
        }
        mock_subproc.return_value = MagicMock(returncode=0, stdout=json.dumps(isolated_payload))
        res2 = self.app.get('/api/port-scan/network-info')
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2["is_connected"])
        self.assertEqual(data2["adapter_name"], "Ethernet")
        self.assertEqual(data2["adapter_type"], "Ethernet")
        self.assertEqual(data2["local_ip"], "192.168.4.100")
        self.assertEqual(data2["suggested_subnet"], "192.168.4.0/24")


class TestActualNetworkAndRoutingEnvironment(unittest.TestCase):
    """
    Live tests verifying actual OS networking stack behavior on the local machine
    without any mocks. Validates schema, return types, and real TCP socket routing.
    """

    def test_actual_live_network_discovery_info_schema(self):
        """Queries the actual Windows OS configuration and verifies returned data schema."""
        info = get_network_discovery_info()
        self.assertIsInstance(info, dict)
        self.assertIn("status", info)
        self.assertIn("adapter_name", info)
        self.assertIn("adapter_type", info)
        self.assertIn("local_ip", info)
        self.assertIn("subnet_cidr", info)
        self.assertIn("is_connected", info)
        self.assertIn("total_hosts", info)

        valid_types = {"Ethernet", "Wi-Fi", "Virtual", "Loopback", "Other", "None"}
        self.assertIn(info["adapter_type"], valid_types)

        if info["is_connected"]:
            self.assertIn(info["status"], ["online"])
            self.assertIsNotNone(info["subnet_cidr"])
            self.assertNotEqual(info["local_ip"], "127.0.0.1")
            # Verify subnet CIDR is a valid parseable network
            net = ipaddress.ip_network(info["subnet_cidr"], strict=False)
            self.assertEqual(net.version, 4)
        else:
            self.assertEqual(info["status"], "offline")
            self.assertIsNone(info["subnet_cidr"])

    def test_actual_live_port_scanner_loopback_routing(self):
        """Verifies real TCP socket connection on loopback 127.0.0.1 using OS routing."""
        target, net_obj = validate_and_resolve_target("localhost", "127.0.0.1")
        self.assertEqual(target, "127.0.0.1")
        self.assertIsNone(net_obj)

        # Probe port 5000 where api.py is running
        res = asyncio.run(probe_single_port("127.0.0.1", 5000, timeout=1.0))
        self.assertIsInstance(res, dict)
        self.assertEqual(res["port"], 5000)
        self.assertEqual(res["protocol"], "TCP")
        self.assertEqual(res["state"], "open")
        self.assertGreater(res["latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
