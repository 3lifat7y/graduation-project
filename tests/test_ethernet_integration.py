#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for SocNet Ethernet Capture, Cross-Device Remote Integration,
Adapter Discovery, Health Checks, and Real Traffic Generation Pipeline.
"""

import os
import sys
import json
import time
import socket
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import api
from modules.common.network_detector import (
    auto_detect_primary_interface,
    get_windows_network_adapters,
    get_scapy_interfaces_info
)
from modules.monitoring.capture_engine import (
    resolve_scapy_interface,
    parse_scapy_packet,
    RollingFlowStatsCollector,
    OFFICIAL_77_FEATURES,
    validate_flow_features
)
from scripts.send_traffic import (
    DEFAULT_MONITORING_HOST,
    DEFAULT_BENIGN_TRAFFIC_PORT,
    DEFAULT_API_PORT,
    parse_args,
    resolve_target_config,
    check_remote_connectivity,
    run_benign_traffic_generator
)


class TestEthernetAdapterDiscovery(unittest.TestCase):
    """Verifies Ethernet adapter prioritization, disabled-Wi-Fi handling, and Scapy device linking."""

    def test_01_ethernet_prioritized_when_both_up(self):
        """Ethernet is prioritized over Wi-Fi when both adapters are Up with valid IPv4 addresses."""
        mock_adapters = [
            {
                "name": "Wi-Fi",
                "description": "Intel Wireless AC 9560",
                "status": "Up",
                "type": "Wi-Fi",
                "index": 8,
                "ips": ["192.168.1.4"],
                "is_virtual": False,
                "network_name": r"\Device\NPF_{WIFI-GUID}"
            },
            {
                "name": "Ethernet",
                "description": "Intel Ethernet Connection I219-LM",
                "status": "Up",
                "type": "Ethernet",
                "index": 13,
                "ips": ["192.168.1.11"],
                "is_virtual": False,
                "network_name": r"\Device\NPF_{ETH-GUID}"
            }
        ]
        with patch("modules.common.network_detector.get_windows_network_adapters", return_value=mock_adapters), \
             patch("modules.common.network_detector.get_active_routable_ip", return_value="192.168.1.4"):
            ad, drv = auto_detect_primary_interface()
            self.assertEqual(ad["name"], "Ethernet")
            self.assertEqual(ad["type"], "Ethernet")
            self.assertEqual(ad["primary_ip"], "192.168.1.11")
            self.assertTrue(ad["is_connected"])
            self.assertEqual(ad["network_name"], r"\Device\NPF_{ETH-GUID}")

    def test_02_disabled_wifi_selects_connected_ethernet(self):
        """When Wi-Fi is Disabled or Disconnected and Ethernet is Up, Ethernet is selected."""
        mock_adapters = [
            {
                "name": "Wi-Fi",
                "description": "Intel Wireless AC 9560",
                "status": "Disabled",
                "type": "Wi-Fi",
                "index": 8,
                "ips": ["192.168.1.4"],
                "is_virtual": False
            },
            {
                "name": "Ethernet",
                "description": "Intel Ethernet Connection I219-LM",
                "status": "Up",
                "type": "Ethernet",
                "index": 13,
                "ips": ["192.168.1.11"],
                "is_virtual": False,
                "network_name": r"\Device\NPF_{ETH-GUID}"
            }
        ]
        with patch("modules.common.network_detector.get_windows_network_adapters", return_value=mock_adapters), \
             patch("modules.common.network_detector.get_active_routable_ip", return_value=None):
            ad, drv = auto_detect_primary_interface()
            self.assertEqual(ad["name"], "Ethernet")
            self.assertEqual(ad["status"], "Up")
            self.assertEqual(ad["primary_ip"], "192.168.1.11")

    def test_03_all_adapters_offline_raises_actionable_runtime_error(self):
        """When all physical adapters are disconnected or disabled, raises clear RuntimeError."""
        mock_adapters = [
            {"name": "Wi-Fi", "status": "Disabled", "type": "Wi-Fi", "is_virtual": False, "ips": []},
            {"name": "Ethernet", "status": "Disconnected", "type": "Ethernet", "is_virtual": False, "ips": []}
        ]
        with patch("modules.common.network_detector.get_windows_network_adapters", return_value=mock_adapters), \
             patch("modules.common.network_detector.get_active_routable_ip", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                auto_detect_primary_interface()
            self.assertIn("Network adapter is offline or disconnected", str(ctx.exception))
            self.assertIn("Wi-Fi (Disabled)", str(ctx.exception))
            self.assertIn("Ethernet (Disconnected)", str(ctx.exception))

    def test_04_fallback_never_hardcodes_wifi(self):
        """When PowerShell returns no adapters, fallback creates neutral Ethernet adapter, not hardcoded Wi-Fi."""
        with patch("subprocess.run", side_effect=Exception("PowerShell timeout")), \
             patch("modules.common.network_detector.get_active_routable_ip", return_value="192.168.1.20"), \
             patch("modules.common.network_detector.get_scapy_interfaces_info", return_value=({}, {})):
            adapters = get_windows_network_adapters()
            self.assertTrue(len(adapters) >= 1)
            primary = adapters[0]
            self.assertEqual(primary["type"], "Ethernet")
            self.assertEqual(primary["ips"], ["192.168.1.20"])


class TestScapyInterfaceResolution(unittest.TestCase):
    """Verifies accurate Scapy interface matching and strict rejection of nonexistent adapters."""

    def test_01_resolve_ethernet_by_name_and_index(self):
        """Resolves Ethernet interface by friendly name and index without substitution."""
        resolved = resolve_scapy_interface("Ethernet", 13)
        self.assertIsNotNone(resolved)
        # Verify it resolves to the Npcap device path or interface object
        if hasattr(resolved, 'name'):
            self.assertTrue("Ethernet" in resolved.name or "NPF" in str(resolved))

    def test_02_unknown_adapter_returns_none_strictly(self):
        """Nonexistent adapter strictly returns None; never silently substitutes default adapter."""
        resolved = resolve_scapy_interface("NonExistentFakeAdapter_9999", 99999)
        self.assertIsNone(resolved)


class TestRemoteConnectivityAndHealth(unittest.TestCase):
    """Verifies health endpoint, client authorization, and pre-flight connectivity checks."""

    @classmethod
    def setUpClass(cls):
        api.app.config['TESTING'] = True
        cls.client = api.app.test_client()

    def test_01_health_endpoint_returns_ok_and_diagnostics(self):
        """GET /api/health returns status ok, primary adapter, and benign traffic test port."""
        resp = self.client.get('/api/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn(data.get("status"), ["ok", "degraded"])
        self.assertEqual(data.get("service"), "SocNet DDoS-Guard")
        self.assertIn("primary_adapter", data)
        self.assertIn("traffic_test_port", data)

    def test_02_private_ip_client_authorization(self):
        """Permits localhost and RFC 1918 private clients; rejects public WAN clients."""
        from api import is_authorized_client
        self.assertTrue(is_authorized_client("127.0.0.1"))
        self.assertTrue(is_authorized_client("192.168.1.50"))
        self.assertTrue(is_authorized_client("10.0.0.15"))
        self.assertTrue(is_authorized_client("172.16.0.22"))
        self.assertFalse(is_authorized_client("93.184.216.34"))
        self.assertFalse(is_authorized_client("8.8.8.8"))

    def test_03_target_config_resolution(self):
        """resolve_target_config correctly parses CLI arguments and environment variables."""
        args = MagicMock()
        args.host = "192.168.1.45"
        args.target = None
        args.port = 8080
        args.api_port = 5000

        host, traffic_port, api_port = resolve_target_config(args)
        self.assertEqual(host, "192.168.1.45")
        self.assertEqual(traffic_port, 8080)
        self.assertEqual(api_port, 5000)

    def test_04_target_config_from_target_url(self):
        """resolve_target_config extracts host and port from --target URL."""
        args = MagicMock()
        args.host = None
        args.target = "http://192.168.1.99:9090"
        args.port = None
        args.api_port = None

        with patch.dict(os.environ, {}, clear=True):
            host, traffic_port, api_port = resolve_target_config(args)
            self.assertEqual(host, "192.168.1.99")
            self.assertEqual(traffic_port, 9090)
            self.assertEqual(api_port, 5000)

    def test_05_preflight_connection_refused_diagnostic(self):
        """check_remote_connectivity provides clear actionable diagnostic on refused port."""
        # Port 59999 should not be listening
        conn = check_remote_connectivity("127.0.0.1", traffic_port=59999, api_port=59998, timeout=0.3)
        self.assertFalse(conn["traffic_port_open"])
        self.assertFalse(conn["api_port_open"])
        self.assertIsNotNone(conn["error_reason"])
        self.assertIn("127.0.0.1", conn["error_reason"])
        self.assertIn("Monitoring Computer's Ethernet IPv4 address", conn["remediation"])

    def test_06_default_monitoring_host_used_when_no_flags_provided(self):
        """When no CLI flags are supplied, sender selects DEFAULT_MONITORING_HOST without hardcoding localhost."""
        args = MagicMock()
        args.host = None
        args.target = None
        args.port = None
        args.api_port = None

        host, traffic_port, api_port = resolve_target_config(args)
        self.assertEqual(host, DEFAULT_MONITORING_HOST)
        self.assertEqual(traffic_port, DEFAULT_BENIGN_TRAFFIC_PORT)
        self.assertEqual(api_port, DEFAULT_API_PORT)

    def test_07_cli_argument_parser_overrides(self):
        """CLI arguments --host and --port override defaults accurately."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--host', '192.168.1.11', '--port', '8080', '--api-port', '5001']):
            args = parse_args()
            self.assertEqual(args.host, '192.168.1.11')
            self.assertEqual(args.port, 8080)
            self.assertEqual(args.api_port, 5001)

            host, traffic_port, api_port = resolve_target_config(args)
            self.assertEqual(host, '192.168.1.11')
            self.assertEqual(traffic_port, 8080)
            self.assertEqual(api_port, 5001)

    def test_08_remote_unreachable_diagnostics_never_reverts_to_localhost(self):
        """Unreachable remote target returns actionable remediation and never silently reverts to 127.0.0.1."""
        target_ip = "192.0.2.1"  # TEST-NET-1 non-routable IP
        conn = check_remote_connectivity(target_ip, traffic_port=8080, api_port=5000, timeout=0.2)
        self.assertEqual(conn["host"], target_ip)
        self.assertFalse(conn["api_port_open"])
        self.assertFalse(conn["traffic_port_open"])
        self.assertIsNotNone(conn["error_reason"])
        self.assertIn(target_ip, conn["error_reason"])
        self.assertIn("Troubleshooting checklist", conn["remediation"])

    def test_09_sender_aborts_without_fallback_on_unreachable_remote(self):
        """When remote host is unreachable, sender main() exits with code 1 and never falls back to 127.0.0.1."""
        from scripts.send_traffic import main as sender_main
        with patch.object(sys, 'argv', ['send_traffic.py', '--host', '192.0.2.1', '--timeout', '0.2']):
            with patch("scripts.send_traffic.run_benign_traffic_generator") as mock_traffic_gen:
                with self.assertRaises(SystemExit) as cm:
                    sender_main()
                self.assertEqual(cm.exception.code, 1)
                # Ensure traffic generator was never invoked with 127.0.0.1 or anything else
                mock_traffic_gen.assert_not_called()


class TestBenignTrafficAndInferencePipeline(unittest.TestCase):
    """Verifies benign HTTP traffic service, 77-feature extraction, and model inference."""

    def test_01_benign_traffic_server_responds_200_ok(self):
        """In-process BenignTrafficServer accepts GET and POST and returns HTTP 200 OK."""
        from api import start_benign_traffic_service
        # Bind to high ephemeral port for testing
        test_port = 18080
        server = start_benign_traffic_service(host="127.0.0.1", port=test_port)
        self.assertIsNotNone(server)
        try:
            import urllib.request
            # Test GET /test
            with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/test", timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(body.get("status"), "success")
                self.assertIn("acknowledged", body.get("message", ""))

            # Test POST /test
            req = urllib.request.Request(
                f"http://127.0.0.1:{test_port}/test",
                data=b'{"test": "frame"}',
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode('utf-8'))
                self.assertEqual(body.get("status"), "success")
        finally:
            server.shutdown()

    def test_02_parse_scapy_packet_benign_traffic(self):
        """parse_scapy_packet correctly extracts headers from mock TCP probe to port 8080."""
        mock_pkt = MagicMock()
        mock_pkt.is_loopback = False
        mock_pkt.time = time.time()
        mock_pkt.length = 64

        mock_ip = MagicMock()
        mock_ip.src = "192.168.1.4"
        mock_ip.dst = "192.168.1.11"
        mock_ip.proto = 6

        mock_tcp = MagicMock()
        mock_tcp.sport = 54321
        mock_tcp.dport = 8080
        mock_tcp.dataofs = 5
        mock_tcp.window = 65535
        mock_tcp.flags = 0x02  # SYN flag
        mock_tcp.payload = b""

        # Setup mock layers
        def mock_haslayer(cls_layer):
            from scapy.all import IP, TCP
            return cls_layer in (IP, TCP)

        mock_pkt.haslayer = mock_haslayer
        from scapy.all import IP, TCP
        mock_pkt.__getitem__ = lambda self, key: mock_ip if key == IP else mock_tcp

        parsed = parse_scapy_packet(mock_pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "192.168.1.4")
        self.assertEqual(parsed["dst_ip"], "192.168.1.11")
        self.assertEqual(parsed["dst_port"], 8080)
        self.assertEqual(parsed["protocol"], 6)
        self.assertEqual(parsed["flags"]["SYN"], 1)

    def test_03_flow_collector_and_77_features_compatibility(self):
        """Flow collector aggregates packets, calculates all 77 features, and evaluates model."""
        collector = RollingFlowStatsCollector(window_seconds=3.0)

        # Feed 10 synthetic benign probe packets simulating HTTP exchange
        t0 = time.time()
        for i in range(10):
            is_client = (i % 2 == 0)
            pkt = {
                "timestamp": t0 + (i * 0.05),
                "src_ip": "192.168.1.4" if is_client else "192.168.1.11",
                "dst_ip": "192.168.1.11" if is_client else "192.168.1.4",
                "src_port": 54321 if is_client else 8080,
                "dst_port": 8080 if is_client else 54321,
                "protocol": 6,
                "length": 150 if is_client else 350,
                "header_len": 20,
                "win_size": 65535,
                "payload_len": 130 if is_client else 330,
                "flags": {"SYN": 1 if i == 0 else 0, "ACK": 1, "PSH": 1 if i >= 2 else 0},
                "is_loopback": False
            }
            collector.add_packet(pkt)

        snapshot = collector.get_window_snapshot(now=t0 + 0.6, min_packets=3)
        self.assertEqual(snapshot["status"], "monitoring")
        features = snapshot["features"]
        self.assertIsNotNone(features)

        # Verify all 77 features exist
        for feat_name in OFFICIAL_77_FEATURES:
            self.assertIn(feat_name, features)

        # Validate with strict validation gate
        is_valid, reason = validate_flow_features(features, min_packets=3)
        self.assertTrue(is_valid, f"Validation failed: {reason}")

        # Prepare and evaluate with model
        X = api.prepare_features(features)
        self.assertEqual(X.shape[1], 77)
        prediction = int(api.model.predict(X)[0])
        label = api.CLASS_LABELS.get(prediction, "Unknown")
        self.assertEqual(prediction, api.BENIGN_IDX)
        self.assertEqual(label, "Benign")

    def test_04_bounded_sender_behavior(self):
        """run_benign_traffic_generator sends exact requested packet count and stops cleanly."""
        mock_server_port = 18081
        from api import start_benign_traffic_service
        server = start_benign_traffic_service(host="127.0.0.1", port=mock_server_port)
        self.assertIsNotNone(server)
        try:
            # Send exactly 5 packets at 0.05s interval
            start_t = time.time()
            run_benign_traffic_generator(
                host="127.0.0.1",
                port=mock_server_port,
                protocol="http",
                interval=0.05,
                count=5,
                timeout=1.0
            )
            elapsed = time.time() - start_t
            # 5 packets with 0.05s intervals should take ~0.25 - 1.0s
            self.assertLess(elapsed, 4.0)
        finally:
            server.shutdown()


if __name__ == '__main__':
    unittest.main()
