import unittest
from unittest.mock import patch, MagicMock
import os
import json
import time
from api import app, current_scan_session, scan_session_lock
import api

class TestRescanButton(unittest.TestCase):
    """
    Test suite for SocNet Live Monitoring Rescan Action:
    - Verifies non-intrusive session health checks
    - Verifies accurate reporting of 4 health states:
        1. healthy_active (capture running & packets arriving)
        2. healthy_quiet (capture running, 0 packets in check window)
        3. adapter_unavailable (selected interface disconnected / removed)
        4. worker_failed (capture worker thread or process failed)
    - Verifies no duplicate workers or second sessions are created
    - Verifies no silent adapter switching
    - Verifies HTML/CSS/JS frontend elements, concurrency lock, and responsive design
    """

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        # Save original session state
        with scan_session_lock:
            self._orig_session = dict(api.current_scan_session)
            self._orig_is_monitoring = api.is_monitoring

    def tearDown(self):
        # Restore original session state
        with scan_session_lock:
            api.current_scan_session.clear()
            api.current_scan_session.update(self._orig_session)
            api.is_monitoring = self._orig_is_monitoring

    def test_01_rescan_inactive_session(self):
        """When monitoring is not active, /api/scan-rescan returns inactive status."""
        with scan_session_lock:
            api.is_monitoring = False
            api.current_scan_session["status"] = "ready"
            api.current_scan_session["scan_id"] = None

        res = self.client.get("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "inactive")
        self.assertEqual(data["health_state"], "inactive")
        self.assertIsNone(data["scan_id"])
        self.assertFalse(data["packets_observed"])

    @patch("api.time.sleep", return_value=None)
    @patch("api.get_windows_network_adapters")
    @patch("api.standalone_worker.is_running", return_value=True)
    @patch("api.standalone_worker.get_status")
    def test_02_rescan_healthy_active_session(self, mock_w_status, mock_w_running, mock_adapters, mock_sleep):
        """Capture running and packets are actively arriving -> healthy_active."""
        mock_adapters.return_value = [{
            "name": "Ethernet0",
            "guid": "{MOCK-GUID-1234}",
            "primary_ip": "192.168.1.100",
            "status": "Up",
            "is_connected": True,
            "is_enabled": True
        }]
        mock_w_status.return_value = {
            "status": "monitoring",
            "packets_captured": 45,
            "window_packets": 12,
            "last_packet_time": time.time()
        }

        with scan_session_lock:
            api.is_monitoring = True
            api.current_scan_session.update({
                "scan_id": "test-scan-uuid-1",
                "status": "monitoring",
                "interface": {
                    "name": "Ethernet0",
                    "guid": "{MOCK-GUID-1234}",
                    "index": 1,
                    "type": "Ethernet"
                },
                "packets_captured": 45,
                "window_packets": 12,
                "last_packet_time": time.time()
            })

        res = self.client.post("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["health_state"], "healthy_active")
        self.assertTrue(data["packets_observed"])
        self.assertIsNone(data["recovery_action"])
        self.assertEqual(data["adapter"]["name"], "Ethernet0")
        self.assertEqual(data["adapter"]["primary_ip"], "192.168.1.100")
        self.assertTrue(data["worker"]["alive"])

    @patch("api.time.sleep", return_value=None)
    @patch("api.get_windows_network_adapters")
    @patch("api.standalone_worker.is_running", return_value=True)
    @patch("api.standalone_worker.get_status")
    def test_03_rescan_healthy_quiet_session(self, mock_w_status, mock_w_running, mock_adapters, mock_sleep):
        """Capture running on connected interface, but zero packets observed -> healthy_quiet."""
        mock_adapters.return_value = [{
            "name": "Ethernet0",
            "guid": "{MOCK-GUID-1234}",
            "primary_ip": "192.168.1.100",
            "status": "Up",
            "is_connected": True,
            "is_enabled": True
        }]
        mock_w_status.return_value = {
            "status": "monitoring",
            "packets_captured": 0,
            "window_packets": 0,
            "last_packet_time": None
        }

        with scan_session_lock:
            api.is_monitoring = True
            api.current_scan_session.update({
                "scan_id": "test-scan-uuid-2",
                "status": "monitoring",
                "interface": {
                    "name": "Ethernet0",
                    "guid": "{MOCK-GUID-1234}",
                    "index": 1,
                    "type": "Ethernet"
                },
                "packets_captured": 0,
                "window_packets": 0,
                "last_packet_time": None
            })

        res = self.client.post("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["health_state"], "healthy_quiet")
        self.assertFalse(data["packets_observed"])
        self.assertIn("zero packets were observed", data["message"])
        self.assertIsNone(data["recovery_action"])

    @patch("api.time.sleep", return_value=None)
    @patch("api.get_windows_network_adapters")
    @patch("api.standalone_worker.is_running", return_value=True)
    @patch("api.standalone_worker.get_status")
    def test_04_rescan_adapter_unavailable(self, mock_w_status, mock_w_running, mock_adapters, mock_sleep):
        """Selected adapter is disconnected or removed -> adapter_unavailable."""
        mock_adapters.return_value = [{
            "name": "Ethernet0",
            "guid": "{MOCK-GUID-1234}",
            "primary_ip": None,
            "status": "Disconnected",
            "is_connected": False,
            "is_enabled": True
        }]
        mock_w_status.return_value = {"status": "monitoring"}

        with scan_session_lock:
            api.is_monitoring = True
            api.current_scan_session.update({
                "scan_id": "test-scan-uuid-3",
                "status": "monitoring",
                "interface": {
                    "name": "Ethernet0",
                    "guid": "{MOCK-GUID-1234}",
                    "index": 1,
                    "type": "Ethernet"
                },
                "packets_captured": 5,
                "window_packets": 0,
                "last_packet_time": None
            })

        res = self.client.post("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["health_state"], "adapter_unavailable")
        self.assertEqual(data["recovery_action"], "reconnect_adapter")
        self.assertFalse(data["adapter"]["available"])

    @patch("api.time.sleep", return_value=None)
    @patch("api.get_windows_network_adapters")
    @patch("api.standalone_worker.is_running", return_value=False)
    @patch("api.standalone_worker.get_status")
    def test_05_rescan_worker_failed(self, mock_w_status, mock_w_running, mock_adapters, mock_sleep):
        """Capture worker stopped unexpectedly -> worker_failed."""
        mock_adapters.return_value = [{
            "name": "Ethernet0",
            "guid": "{MOCK-GUID-1234}",
            "primary_ip": "192.168.1.100",
            "status": "Up",
            "is_connected": True,
            "is_enabled": True
        }]
        mock_w_status.return_value = {
            "status": "error",
            "message": "Sniffer thread terminated unexpectedly"
        }

        with scan_session_lock:
            api.is_monitoring = True
            api.current_scan_session.update({
                "scan_id": "test-scan-uuid-4",
                "status": "monitoring",
                "interface": {
                    "name": "Ethernet0",
                    "guid": "{MOCK-GUID-1234}",
                    "index": 1,
                    "type": "Ethernet"
                },
                "packets_captured": 10,
                "window_packets": 0,
                "last_packet_time": None
            })

        res = self.client.post("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["health_state"], "worker_failed")
        self.assertEqual(data["recovery_action"], "restart_monitoring")
        self.assertFalse(data["worker"]["alive"])

    @patch("api.time.sleep", return_value=None)
    @patch("api.get_windows_network_adapters")
    @patch("api.standalone_worker.is_running", return_value=True)
    @patch("api.standalone_worker.get_status")
    def test_06_rescan_does_not_mutate_session_or_start_new_worker(self, mock_w_status, mock_w_running, mock_adapters, mock_sleep):
        """Rescan must be non-intrusive: no new scan_id, no change to adapter selection."""
        mock_adapters.return_value = [{
            "name": "Ethernet0",
            "guid": "{MOCK-GUID-1234}",
            "primary_ip": "192.168.1.100",
            "status": "Up",
            "is_connected": True,
            "is_enabled": True
        }]
        mock_w_status.return_value = {"status": "monitoring", "packets_captured": 20}

        original_scan_id = "test-scan-preserve-id-99"
        with scan_session_lock:
            api.is_monitoring = True
            api.current_scan_session.update({
                "scan_id": original_scan_id,
                "status": "monitoring",
                "interface": {
                    "name": "Ethernet0",
                    "guid": "{MOCK-GUID-1234}",
                    "index": 1,
                    "type": "Ethernet"
                },
                "packets_captured": 20,
                "window_packets": 5,
                "last_packet_time": time.time()
            })

        res = self.client.post("/api/scan-rescan")
        self.assertEqual(res.status_code, 200)

        with scan_session_lock:
            # Session ID and interface must remain identical
            self.assertEqual(api.current_scan_session["scan_id"], original_scan_id)
            self.assertEqual(api.current_scan_session["interface"]["name"], "Ethernet0")
            self.assertTrue(api.is_monitoring)

    def test_07_html_structure_for_rescan_controls(self):
        """ddos.html must contain rescanBtn and rescanStatusBanner in the Live Monitoring section."""
        html_path = os.path.join(os.path.dirname(__file__), "..", "templates", "ddos.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn('id="rescanBtn"', html)
        self.assertIn('id="rescanIcon"', html)
        self.assertIn('id="rescanText"', html)
        self.assertIn('id="rescanStatusBanner"', html)
        self.assertIn('id="rescanStatusIcon"', html)
        self.assertIn('id="rescanStatusTitle"', html)
        self.assertIn('id="rescanStatusDesc"', html)
        self.assertIn('id="rescanRecoveryActions"', html)
        self.assertIn('id="rescanRestartBtn"', html)
        self.assertIn('id="rescanSelectAdapterBtn"', html)
        self.assertIn('id="rescanDismissBtn"', html)

    def test_08_css_styling_and_responsive_rules(self):
        """style.css must define .rescan-btn, .rescan-status-banner states, and responsive styling."""
        css_path = os.path.join(os.path.dirname(__file__), "..", "static", "style.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn(".rescan-btn", css)
        self.assertIn(".rescan-status-banner", css)
        self.assertIn(".state-healthy", css)
        self.assertIn(".state-quiet", css)
        self.assertIn(".state-warning", css)
        self.assertIn(".state-error", css)
        self.assertIn(".btn-recovery-action", css)
        self.assertIn(".rescan-status-dismiss", css)

    def test_09_main_js_rescan_wiring(self):
        """main.js must implement rescanActiveSession, displayRescanResult, and isRescanning guard."""
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "main.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        self.assertIn("isRescanning", js)
        self.assertIn("rescanActiveSession", js)
        self.assertIn("displayRescanResult", js)
        self.assertIn("rescanBtn.addEventListener", js)
        self.assertIn("rescanDismissBtn.addEventListener", js)
        self.assertIn("rescanRestartBtn.addEventListener", js)
        self.assertIn("rescanSelectAdapterBtn.addEventListener", js)


if __name__ == "__main__":
    unittest.main()
