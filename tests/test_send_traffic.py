#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated unit tests for scripts/send_traffic.py:
1. An unreachable target: no transmission occurs.
2. A reachable target with an available service: transmission starts.
3. A reachable host with a closed required port: transmission does not start.
4. Dataset mode checks the API port rather than incorrectly requiring the traffic-sink port.
5. Configuration changes affect actual behavior and terminal output.
6. CLI arguments override file-level defaults.
7. Connectivity loss during continuous mode stops transmission.
8. UDP results are not falsely reported as confirmed remote delivery.
"""

import sys
import os
import json
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import scripts.send_traffic as st


class TestSendTrafficConnectivityAndConfiguration(unittest.TestCase):
    """Verifies real connectivity validation, centralized configuration, and safety rules."""

    def test_01_unreachable_target_aborts_immediately_without_transmission(self):
        """1. An unreachable target aborts preflight with exit code 1; zero traffic is transmitted."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--wire-traffic', '--host', '192.0.2.1', '--timeout', '0.1']):
            with patch("scripts.send_traffic.check_destination_service", return_value=(False, "Connection timed out")):
                with patch("scripts.send_traffic.run_benign_traffic_generator") as mock_traffic_gen:
                    with patch("scripts.send_traffic.run_dataset_feature_stream") as mock_dataset_stream:
                        captured_out = StringIO()
                        with patch("sys.stdout", captured_out):
                            with self.assertRaises(SystemExit) as cm:
                                st.main()
                        self.assertEqual(cm.exception.code, 1)
                        # Verify NO transmission occurred
                        mock_traffic_gen.assert_not_called()
                        mock_dataset_stream.assert_not_called()
                        out_text = captured_out.getvalue()
                        self.assertIn("[CHECK] Checking target 192.0.2.1", out_text)
                        self.assertIn("[STOP] Preflight check failed", out_text)
                        self.assertIn("no network traffic will be transmitted", out_text)

    def test_02_reachable_target_starts_transmission(self):
        """2. A reachable target with an available service passes preflight and begins transmission."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--wire-traffic', '--host', '192.168.1.11', '--port', '8080', '--count', '5']):
            with patch("scripts.send_traffic.check_destination_service", return_value=(True, None)):
                with patch("scripts.send_traffic.run_benign_traffic_generator") as mock_traffic_gen:
                    captured_out = StringIO()
                    with patch("sys.stdout", captured_out):
                        st.main()

                    mock_traffic_gen.assert_called_once()
                    call_kwargs = mock_traffic_gen.call_args[1]
                    self.assertEqual(call_kwargs["host"], "192.168.1.11")
                    self.assertEqual(call_kwargs["port"], 8080)
                    self.assertEqual(call_kwargs["count"], 5)
                    out_text = captured_out.getvalue()
                    self.assertIn("[OK] Target service is reachable.", out_text)
                    self.assertIn("SOCNET SENDER: TARGET & CONNECTIVITY INITIALIZATION", out_text)

    def test_03_reachable_host_with_closed_required_port_aborts(self):
        """3. A reachable host with a closed required traffic port aborts before sending."""
        def mock_check(host, port, **kwargs):
            # Simulate host having port 5000 open, but port 8080 closed
            if port == 8080:
                return False, "Connection refused on port 8080"
            return True, None

        with patch.object(sys, 'argv', ['send_traffic.py', '--host', '192.168.1.11', '--port', '8080', '--probe']):
            with patch("scripts.send_traffic.check_destination_service", side_effect=mock_check):
                with patch("scripts.send_traffic.run_benign_traffic_generator") as mock_traffic_gen:
                    captured_out = StringIO()
                    with patch("sys.stdout", captured_out):
                        with self.assertRaises(SystemExit) as cm:
                            st.main()
                    self.assertEqual(cm.exception.code, 1)
                    mock_traffic_gen.assert_not_called()
                    out_text = captured_out.getvalue()
                    self.assertIn("TARGET SERVICE UNREACHABLE", out_text)
                    self.assertIn("Connection refused on port 8080", out_text)
                    self.assertIn("[STOP] Preflight check failed", out_text)

    def test_04_dataset_mode_checks_api_port_only_not_port_8080(self):
        """4. Dataset mode checks API port 5000 and does NOT require traffic sink port 8080 to be open."""
        checked_ports = []

        def mock_check(host, port, **kwargs):
            checked_ports.append(port)
            if port == 5000:
                return True, None
            return False, "Port 8080 is intentionally closed"

        with patch.object(sys, 'argv', ['send_traffic.py', '--host', '192.168.1.11', '--api-port', '5000', '--label', 'BENIGN', '--count', '2', '--yes']):
            with patch("scripts.send_traffic.check_destination_service", side_effect=mock_check):
                with patch("scripts.send_traffic.confirm_replay_transmission", return_value=True):
                    with patch("scripts.send_traffic.run_dataset_feature_stream") as mock_stream:
                        captured_out = StringIO()
                        with patch("sys.stdout", captured_out):
                            st.main()

                        # Port 5000 was checked and passed
                        self.assertIn(5000, checked_ports)
                        # Port 8080 was NEVER required or probed
                        self.assertNotIn(8080, checked_ports)
                        mock_stream.assert_called_once()
                        out_text = captured_out.getvalue()
                        self.assertIn("[CHECK] Checking target 192.168.1.11:5000 (Replay API Endpoint)...", out_text)
                        self.assertIn("[OK] Target Replay API is reachable.", out_text)

    def test_05_configuration_changes_affect_defaults_and_terminal_output(self):
        """5. Modifying file-level configuration variables directly changes defaults and terminal output."""
        with patch.object(st, 'TARGET_HOST', '10.50.60.70'), \
             patch.object(st, 'TARGET_PORT', 9876), \
             patch.object(st, 'TRAFFIC_PROTOCOL', 'tcp'), \
             patch.object(st, 'TRAFFIC_COUNT', 77), \
             patch.object(st, 'TRAFFIC_PAYLOAD_SIZE_BYTES', 512):

            with patch.object(sys, 'argv', ['send_traffic.py', '--wire-traffic']):
                args = st.parse_args()
                cfg = st.resolve_effective_config(args)
                self.assertEqual(cfg["host"], "10.50.60.70")
                self.assertEqual(cfg["traffic_port"], 9876)
                self.assertEqual(cfg["protocol"], "tcp")
                self.assertEqual(cfg["count"], 77)
                self.assertEqual(cfg["payload_size"], 512)

                # Verify terminal output shows new file defaults
                with patch("scripts.send_traffic.check_destination_service", return_value=(True, None)):
                    with patch("scripts.send_traffic.run_benign_traffic_generator") as mock_gen:
                        captured_out = StringIO()
                        with patch("sys.stdout", captured_out):
                            st.main()
                        out_text = captured_out.getvalue()
                        self.assertIn("10.50.60.70", out_text)
                        self.assertIn("9876", out_text)
                        self.assertIn("TCP", out_text)
                        self.assertIn("77", out_text)
                        self.assertIn("512 bytes", out_text)

    def test_06_cli_arguments_override_file_level_defaults(self):
        """6. Explicit CLI arguments strictly override file-level configuration values."""
        with patch.object(st, 'TARGET_HOST', '192.168.1.11'), \
             patch.object(st, 'TARGET_PORT', 8080), \
             patch.object(st, 'TRAFFIC_PROTOCOL', 'http'), \
             patch.object(st, 'TRAFFIC_COUNT', 20):

            cli_cmd = [
                'send_traffic.py',
                '--host', '172.16.0.5',
                '--port', '9000',
                '--protocol', 'udp',
                '--count', '12',
                '--interval', '0.2',
                '--payload-size', '1024',
                '--timeout', '4.5'
            ]
            with patch.object(sys, 'argv', cli_cmd):
                args = st.parse_args()
                cfg = st.resolve_effective_config(args)
                self.assertEqual(cfg["host"], "172.16.0.5")
                self.assertEqual(cfg["traffic_port"], 9000)
                self.assertEqual(cfg["protocol"], "udp")
                self.assertEqual(cfg["count"], 12)
                self.assertEqual(cfg["interval"], 0.2)
                self.assertEqual(cfg["payload_size"], 1024)
                self.assertEqual(cfg["timeout"], 4.5)

    def test_07_connectivity_loss_during_continuous_mode_stops_transmission(self):
        """7. Periodic reachability check during continuous mode halts transmission if target is lost."""
        checks = [True, False]  # First check passes, second check fails

        def mock_check_service(host, port, **kwargs):
            if checks:
                return checks.pop(0), None if checks else "Host dropped from local network"
            return False, "Target disconnected"

        captured_out = StringIO()
        with patch("scripts.send_traffic.check_destination_service", side_effect=mock_check_service):
            with patch("urllib.request.urlopen") as mock_url:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_url.return_value.__enter__.return_value = mock_resp

                with patch("sys.stdout", captured_out):
                    # Run with continuous mode (count=None) and very low check_interval
                    st.run_benign_traffic_generator(
                        host="127.0.0.1",
                        port=8080,
                        protocol="http",
                        interval=0.01,
                        count=None,
                        timeout=0.5,
                        payload_size=64,
                        check_interval=0.01
                    )

        out_text = captured_out.getvalue()
        self.assertIn("[STOP] Target is no longer reachable", out_text)
        self.assertIn("Transmission stopped.", out_text)

    def test_08_udp_results_clearly_distinguished_and_not_reported_as_confirmed_receipt(self):
        """8. UDP transmissions report 'transmitted (unconfirmed delivery)' without claiming remote receipt."""
        captured_out = StringIO()
        with patch("socket.socket") as mock_sock_cls:
            mock_s = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_s

            with patch("sys.stdout", captured_out):
                st.run_benign_traffic_generator(
                    host="127.0.0.1",
                    port=8080,
                    protocol="udp",
                    interval=0.01,
                    count=2,
                    timeout=1.0,
                    payload_size=128
                )

        out_text = captured_out.getvalue()
        self.assertIn("Result=transmitted (unconfirmed delivery)", out_text)
        self.assertNotIn("confirmed delivery", out_text.lower().replace("(unconfirmed delivery)", ""))
        self.assertIn("UDP is a connectionless transport protocol", out_text)
        self.assertIn("Remote arrival cannot be confirmed without an application-layer reply", out_text)

    def test_09_no_argument_displays_label_menu_and_sends_nothing_if_cancelled(self):
        """9. No-argument execution defaults to Dataset Replay, displays menu, and sends nothing if cancelled."""
        with patch.object(sys, 'argv', ['send_traffic.py']):
            # Simulate user entering 'q' at interactive prompt
            with patch('builtins.input', side_effect=['q']):
                with patch('scripts.send_traffic.check_destination_service') as mock_check:
                    with patch('scripts.send_traffic.run_benign_traffic_generator') as mock_gen:
                        with patch('scripts.send_traffic.run_dataset_feature_stream') as mock_stream:
                            captured_out = StringIO()
                            with patch('sys.stdout', captured_out):
                                with self.assertRaises(SystemExit) as cm:
                                    st.main()
                            self.assertEqual(cm.exception.code, 0)
                            # Verify zero network checks or transmissions occurred
                            mock_check.assert_not_called()
                            mock_gen.assert_not_called()
                            mock_stream.assert_not_called()
                            out_text = captured_out.getvalue()
                            self.assertIn("DYNAMIC DATASET LABELS DISCOVERED", out_text)
                            self.assertIn("[CANCELLED] Operation cancelled by user.", out_text)

    def test_10_default_workflow_never_invokes_benign_traffic_generator(self):
        """10. Default workflow is Dataset Replay and never invokes run_benign_traffic_generator."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--label', 'Benign', '--count', '3', '--yes']):
            with patch('scripts.send_traffic.check_destination_service', return_value=(True, None)):
                with patch('scripts.send_traffic.run_benign_traffic_generator') as mock_traffic_gen:
                    with patch('scripts.send_traffic.run_dataset_feature_stream') as mock_dataset_stream:
                        captured_out = StringIO()
                        with patch('sys.stdout', captured_out):
                            st.main()
                        mock_traffic_gen.assert_not_called()
                        mock_dataset_stream.assert_called_once()
                        call_kwargs = mock_dataset_stream.call_args[1]
                        self.assertEqual(call_kwargs["label"], "Benign")
                        self.assertEqual(call_kwargs["count"], 3)

    def test_11_selected_label_remains_fixed_throughout_replay(self):
        """11. The selected label remains strictly fixed throughout the entire replay stream."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--label', 'DDoS', '--count', '5', '--yes']):
            with patch('scripts.send_traffic.check_destination_service', return_value=(True, None)):
                with patch('scripts.send_traffic.run_dataset_feature_stream') as mock_stream:
                    captured_out = StringIO()
                    with patch('sys.stdout', captured_out):
                        st.main()
                    mock_stream.assert_called_once()
                    call_kwargs = mock_stream.call_args[1]
                    self.assertEqual(call_kwargs["label"], "DDoS")
                    # Ensure records passed all have Label == DDoS
                    for rec in call_kwargs["records"]:
                        self.assertEqual(rec.get("Label"), "DDoS")

    def test_12_no_fixed_count_imposed_when_count_omitted(self):
        """12. Omitting --count runs continuous replay indefinitely without imposing a fixed count of 200 or 20."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--label', 'Benign']):
            args = st.parse_args()
            cfg = st.resolve_effective_config(args)
            self.assertEqual(cfg["mode"], "dataset")
            self.assertTrue(cfg["continuous"])
            self.assertIsNone(cfg["count"])

    def test_13_explicit_count_runs_bounded_test(self):
        """13. Explicitly supplying --count switches continuous mode off and limits transmission to count."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--label', 'Benign', '--count', '7']):
            args = st.parse_args()
            cfg = st.resolve_effective_config(args)
            self.assertEqual(cfg["mode"], "dataset")
            self.assertFalse(cfg["continuous"])
            self.assertEqual(cfg["count"], 7)

    def test_14_correct_receiver_api_endpoint_used(self):
        """14. Replay targets /api/replay-feature on configured API port and never targets port 8080."""
        checked_ports = []
        def mock_check(host, port, **kwargs):
            checked_ports.append(port)
            return True, None

        with patch.object(sys, 'argv', ['send_traffic.py', '--host', '10.0.0.50', '--api-port', '5000', '--label', 'Benign', '--count', '2', '--yes']):
            with patch('scripts.send_traffic.check_destination_service', side_effect=mock_check):
                with patch('scripts.send_traffic.run_dataset_feature_stream') as mock_stream:
                    captured_out = StringIO()
                    with patch('sys.stdout', captured_out):
                        st.main()
                    self.assertIn(5000, checked_ports)
                    self.assertNotIn(8080, checked_ports)
                    mock_stream.assert_called_once()
                    self.assertEqual(mock_stream.call_args[1]["target_api_url"], "http://10.0.0.50:5000")

    def test_15_non_confirmed_prompt_sends_nothing(self):
        """15. Declining confirmation ('n') cancels replay and transmits zero records."""
        with patch.object(sys, 'argv', ['send_traffic.py', '--label', 'Benign']):
            # Simulate answering 'n' to confirmation prompt
            with patch('builtins.input', side_effect=['n']):
                with patch('scripts.send_traffic.check_destination_service') as mock_check:
                    with patch('scripts.send_traffic.run_dataset_feature_stream') as mock_stream:
                        captured_out = StringIO()
                        with patch('sys.stdout', captured_out):
                            with self.assertRaises(SystemExit) as cm:
                                st.main()
                        self.assertEqual(cm.exception.code, 0)
                        mock_check.assert_not_called()
                        mock_stream.assert_not_called()
                        out_text = captured_out.getvalue()
                        self.assertIn("[CANCELLED]", out_text)

    def test_16_interactive_mode_1_continuous(self):
        """16. Interactive Mode 1 selects Continuous Real-Time mode."""
        with patch('builtins.input', side_effect=['1']):
            is_cont, cnt = st.select_sending_mode_interactively(unit_name="records")
            self.assertTrue(is_cont)
            self.assertIsNone(cnt)

    def test_17_interactive_mode_2_fixed_count(self):
        """17. Interactive Mode 2 prompts for record count and validates positive integers."""
        # Test invalid input ('bad', '-5', '0') followed by valid count '25'
        with patch('builtins.input', side_effect=['2', 'bad', '-5', '0', '25']):
            captured_out = StringIO()
            with patch('sys.stdout', captured_out):
                is_cont, cnt = st.select_sending_mode_interactively(unit_name="records")
            self.assertFalse(is_cont)
            self.assertEqual(cnt, 25)
            out = captured_out.getvalue()
            self.assertIn("not a valid integer", out)
            self.assertIn("positive integer greater than zero", out)

    def test_18_interactive_mode_exit(self):
        """18. Interactive Mode option 0 exits cleanly."""
        with patch('builtins.input', side_effect=['0']):
            with self.assertRaises(SystemExit) as cm:
                st.select_sending_mode_interactively(unit_name="records")
            self.assertEqual(cm.exception.code, 0)

    def test_19_dataset_record_cycling_when_count_exceeds_available(self):
        """19. When requested count exceeds available records, replay cycles sequentially."""
        records = [{"Feature_1": 1.0, "Label": "Benign"}, {"Feature_1": 2.0, "Label": "Benign"}]
        replayed_payloads = []

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "status": "success",
            "predicted_label": "Benign",
            "prediction": 0,
            "ground_truth": "Benign",
            "match": True,
            "confidence": 99.0
        }).encode('utf-8')
        mock_resp.__enter__.return_value = mock_resp

        def fake_urlopen(req, **kwargs):
            body = json.loads(req.data.decode('utf-8'))
            replayed_payloads.append(body["features"]["Feature_1"])
            return mock_resp

        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            captured_out = StringIO()
            with patch('sys.stdout', captured_out):
                stats = st.run_dataset_feature_stream(
                    records=records,
                    label="Benign",
                    target_api_url="http://127.0.0.1:5000",
                    interval=0.001,
                    count=5
                )

        self.assertEqual(stats["sent"], 5)
        self.assertEqual(stats["successful_inferences"], 5)
        # Should cycle: rec0, rec1, rec0, rec1, rec0
        self.assertEqual(replayed_payloads, [1.0, 2.0, 1.0, 2.0, 1.0])


if __name__ == '__main__':
    unittest.main()

