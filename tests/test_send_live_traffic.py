#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Unit Test Suite for scripts/send_live_traffic.py:
1. Rejection of 127.0.0.1/loopback without --allow-loopback to prevent local-only testing.
2. Acceptance of loopback when --allow-loopback is explicitly specified.
3. Host validation and DNS gaierror handling.
4. Unreachable target aborts preflight check with exit code 1 and zero traffic sent.
5. Reachable target passes preflight check and begins transmission.
6. HTTP frame generation transmits genuine HTTP POST frames to destination service.
7. UDP datagram transmission clearly reports unconfirmed connectionless delivery.
8. TCP SYN/probe generation transmits Layer-4 frames.
9. Rate limiting via --rate overrides --interval.
10. Continuous mode terminates cleanly on user interruption (KeyboardInterrupt).
11. Bounded packet count stops exactly at specified count.
12. Duration limit terminates transmission when duration is exceeded.
13. Interactive confirmation rejection ('n') sends zero traffic and exits cleanly.
14. Auto-confirm (-y/--yes) bypasses confirmation prompt.
15. Root compatibility shim 'send_live_traffic.py' aliases 'scripts.send_live_traffic'.
"""

import sys
import os
import unittest
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import StringIO
from unittest.mock import patch, MagicMock

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import scripts.send_live_traffic as slt
import send_live_traffic as slt_root


class DummyTrafficHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_len) if content_len > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"success","service":"MockSink"}')


class TestSendLiveTraffic(unittest.TestCase):

    def test_01_loopback_rejected_by_default(self):
        """1. Targeting 127.0.0.1 without --allow-loopback aborts with code 1."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '127.0.0.1']):
            captured_out = StringIO()
            with patch('sys.stdout', captured_out):
                with self.assertRaises(SystemExit) as cm:
                    slt.main()
            self.assertEqual(cm.exception.code, 1)
            out = captured_out.getvalue()
            self.assertIn("DESTINATION HOST CONFIGURATION ERROR", out)
            self.assertIn("resolves to loopback", out)
            self.assertIn("--allow-loopback", out)

    def test_02_loopback_allowed_with_flag(self):
        """2. Targeting 127.0.0.1 with --allow-loopback passes host validation."""
        valid, resolved, err = slt.validate_destination_host("127.0.0.1", allow_loopback=True)
        self.assertTrue(valid)
        self.assertEqual(resolved, "127.0.0.1")
        self.assertIsNone(err)

    def test_03_invalid_hostname_resolution_failure(self):
        """3. Unresolvable hostname returns error message."""
        valid, resolved, err = slt.validate_destination_host("invalid.domain.that.does.not.exist.example", allow_loopback=False)
        self.assertFalse(valid)
        self.assertIn("Unable to resolve host", err)

    def test_04_unreachable_target_aborts_without_sending(self):
        """4. Unreachable target aborts preflight check with exit code 1."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '192.168.1.99', '--allow-loopback', '-y']):
            with patch('scripts.send_live_traffic.check_destination_service', return_value=(False, "Connection refused")):
                with patch('scripts.send_live_traffic.run_live_traffic_generator') as mock_gen:
                    captured_out = StringIO()
                    with patch('sys.stdout', captured_out):
                        with self.assertRaises(SystemExit) as cm:
                            slt.main()
                    self.assertEqual(cm.exception.code, 1)
                    mock_gen.assert_not_called()
                    out = captured_out.getvalue()
                    self.assertIn("TARGET DESTINATION SERVICE UNREACHABLE", out)
                    self.assertIn("Zero network traffic was transmitted", out)

    def test_05_reachable_target_begins_transmission(self):
        """5. Reachable target passes preflight and begins transmission."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '192.168.1.15', '--count', '10', '-y']):
            with patch('scripts.send_live_traffic.check_destination_service', return_value=(True, None)):
                with patch('scripts.send_live_traffic.run_live_traffic_generator') as mock_gen:
                    captured_out = StringIO()
                    with patch('sys.stdout', captured_out):
                        slt.main()
                    mock_gen.assert_called_once()
                    self.assertEqual(mock_gen.call_args[1]["host"], "192.168.1.15")
                    self.assertEqual(mock_gen.call_args[1]["count"], 10)

    def test_06_http_frame_transmission(self):
        """6. Real HTTP POST frame generation against HTTP server verifies frame count and latency tracking."""
        server = HTTPServer(('127.0.0.1', 0), DummyTrafficHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            captured_out = StringIO()
            with patch('sys.stdout', captured_out):
                stats = slt.run_live_traffic_generator(
                    host='127.0.0.1',
                    port=port,
                    protocol='http',
                    interval=0.01,
                    count=5,
                    timeout=2.0,
                    payload_size=64
                )
            self.assertEqual(stats["sent"], 5)
            self.assertEqual(stats["successful"], 5)
            self.assertEqual(stats["failed"], 0)
            out = captured_out.getvalue()
            self.assertIn("LIVE TRAFFIC GENERATION SUMMARY", out)
            self.assertIn("5/5", out)
            self.assertIn("HTTP 200 OK", out)
        finally:
            server.shutdown()
            server.server_close()

    def test_07_udp_transmission_reporting(self):
        """7. UDP transmissions clearly report unconfirmed connectionless dispatch."""
        captured_out = StringIO()
        with patch('sys.stdout', captured_out):
            stats = slt.run_live_traffic_generator(
                host='127.0.0.1',
                port=8080,
                protocol='udp',
                interval=0.01,
                count=3,
                timeout=1.0,
                payload_size=64
            )
        self.assertEqual(stats["sent"], 3)
        self.assertEqual(stats["successful"], 3)
        out = captured_out.getvalue()
        self.assertIn("Result=transmitted (unconfirmed delivery)", out)
        self.assertIn("UDP is a connectionless transport protocol", out)
        self.assertIn("Remote arrival cannot be confirmed without an application-layer reply", out)

    def test_08_tcp_probe_transmission(self):
        """8. TCP SYN handshake and probe payload transmission verified."""
        server = HTTPServer(('127.0.0.1', 0), DummyTrafficHandler)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            captured_out = StringIO()
            with patch('sys.stdout', captured_out):
                stats = slt.run_live_traffic_generator(
                    host='127.0.0.1',
                    port=port,
                    protocol='tcp',
                    interval=0.01,
                    count=3,
                    timeout=2.0,
                    payload_size=64
                )
            self.assertEqual(stats["sent"], 3)
            self.assertEqual(stats["successful"], 3)
            out = captured_out.getvalue()
            self.assertIn("TCP Handshake OK", out)
        finally:
            server.shutdown()
            server.server_close()

    def test_09_rate_argument_calculates_interval(self):
        """9. Passing --rate 10 sets effective interval to 0.1s."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '192.168.1.15', '--rate', '10', '-y']):
            with patch('scripts.send_live_traffic.check_destination_service', return_value=(True, None)):
                with patch('scripts.send_live_traffic.run_live_traffic_generator') as mock_gen:
                    captured_out = StringIO()
                    with patch('sys.stdout', captured_out):
                        slt.main()
                    mock_gen.assert_called_once()
                    self.assertEqual(mock_gen.call_args[1]["interval"], 0.1)

    def test_10_clean_shutdown_on_keyboard_interrupt(self):
        """10. Continuous mode handles KeyboardInterrupt cleanly and displays summary."""
        def mock_sleep_interrupt(secs):
            raise KeyboardInterrupt()

        captured_out = StringIO()
        with patch('time.sleep', side_effect=mock_sleep_interrupt):
            with patch('urllib.request.urlopen'):
                with patch('sys.stdout', captured_out):
                    stats = slt.run_live_traffic_generator(
                        host='127.0.0.1',
                        port=8080,
                        protocol='http',
                        interval=0.01,
                        count=None,
                        timeout=1.0
                    )
        out = captured_out.getvalue()
        self.assertIn("Traffic generation stopped cleanly by user (Ctrl+C)", out)
        self.assertIn("LIVE TRAFFIC GENERATION SUMMARY", out)

    def test_11_bounded_packet_count_stops_at_limit(self):
        """11. Explicit --count limits transmission to exactly the specified number."""
        captured_out = StringIO()
        with patch('urllib.request.urlopen') as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_url.return_value.__enter__.return_value = mock_resp

            with patch('sys.stdout', captured_out):
                stats = slt.run_live_traffic_generator(
                    host='127.0.0.1',
                    port=8080,
                    protocol='http',
                    interval=0.001,
                    count=4,
                    timeout=1.0
                )
            self.assertEqual(stats["sent"], 4)

    def test_12_duration_limit_stops_transmission(self):
        """12. Reaching max_duration terminates transmission gracefully."""
        captured_out = StringIO()
        with patch('urllib.request.urlopen') as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_url.return_value.__enter__.return_value = mock_resp

            with patch('sys.stdout', captured_out):
                stats = slt.run_live_traffic_generator(
                    host='127.0.0.1',
                    port=8080,
                    protocol='http',
                    interval=0.001,
                    count=None,
                    max_duration=0.05
                )
        out = captured_out.getvalue()
        self.assertIn("Maximum test duration limit", out)

    def test_13_user_declining_confirmation_sends_nothing(self):
        """13. Responding 'n' to interactive confirmation prompt cancels execution."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '192.168.1.15', '--allow-loopback']):
            with patch('builtins.input', return_value='n'):
                with patch('scripts.send_live_traffic.check_destination_service') as mock_check:
                    with patch('scripts.send_live_traffic.run_live_traffic_generator') as mock_gen:
                        captured_out = StringIO()
                        with patch('sys.stdout', captured_out):
                            with self.assertRaises(SystemExit) as cm:
                                slt.main()
                        self.assertEqual(cm.exception.code, 0)
                        mock_check.assert_not_called()
                        mock_gen.assert_not_called()
                        out = captured_out.getvalue()
                        self.assertIn("[CANCELLED] Operation aborted by user", out)

    def test_14_auto_confirm_bypasses_prompt(self):
        """14. Passing -y/--yes bypasses interactive prompt."""
        with patch.object(sys, 'argv', ['send_live_traffic.py', '--host', '192.168.1.15', '-y']):
            with patch('builtins.input') as mock_input:
                with patch('scripts.send_live_traffic.check_destination_service', return_value=(True, None)):
                    with patch('scripts.send_live_traffic.run_live_traffic_generator'):
                        captured_out = StringIO()
                        with patch('sys.stdout', captured_out):
                            slt.main()
                        mock_input.assert_not_called()

    def test_15_root_shim_aliases_scripts_module(self):
        """15. Root send_live_traffic.py exports the exact same interface as scripts.send_live_traffic."""
        self.assertEqual(slt_root.run_live_traffic_generator, slt.run_live_traffic_generator)
        self.assertEqual(slt_root.validate_destination_host, slt.validate_destination_host)
        self.assertEqual(slt_root.check_destination_service, slt.check_destination_service)


if __name__ == '__main__':
    unittest.main()
