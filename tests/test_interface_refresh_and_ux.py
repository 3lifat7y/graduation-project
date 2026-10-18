import unittest
from unittest.mock import patch, MagicMock
import re
import os
import json
from api import app
from modules.common.network_detector import (
    get_windows_network_adapters,
    auto_detect_interface_with_rationale
)

class TestInterfaceRefreshAndUX(unittest.TestCase):
    """
    Test suite for SocNet Network Interface Refresh and UX enhancements:
    - Single logical refresh execution without duplicate queries
    - Response schema contains all 4-card metadata (device, IP, status, driver)
    - Lightweight /api/service-status without adapter polling
    - HTML and CSS structural completeness for responsive UI
    - Frontend JavaScript concurrency locking, sequence checks, and disappeared adapter guards
    - Backend zero-fallback protection against missing/disappeared interfaces
    """

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_01_adapter_info_endpoint_response_structure(self):
        """Verify /api/adapter-info returns all required metadata for 4-card responsive UI."""
        res = self.client.get("/api/adapter-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("status", data)
        self.assertIn("available_adapters", data)
        self.assertIn("selection_rationale", data)
        self.assertIn("candidates", data)
        self.assertIn("driver_status", data)

        adapters = data["available_adapters"]
        self.assertIsInstance(adapters, list)
        if len(adapters) > 0:
            ad = adapters[0]
            # Verify fields needed for the 4-card UI
            self.assertIn("name", ad)
            self.assertIn("type", ad)
            self.assertIn("status", ad)
            self.assertIn("can_capture", ad)
            self.assertIn("guid", ad)
            self.assertIn("primary_ip", ad)
            self.assertIn("gateway", ad)
            self.assertIn("link_speed", ad)

    def test_02_adapter_info_reuses_discovered_adapters(self):
        """Verify /api/adapter-info does not re-query PowerShell twice."""
        mock_adapters = [
            {
                "name": "Ethernet",
                "type": "Ethernet",
                "status": "Up",
                "is_enabled": True,
                "is_connected": True,
                "is_virtual": False,
                "primary_ip": "192.168.1.50",
                "ips": ["192.168.1.50"],
                "gateway": "192.168.1.1",
                "can_capture": True,
                "guid": "{1111-2222-3333}",
                "network_name": "\\Device\\NPF_{1111-2222-3333}",
                "link_speed": "1 Gbps",
                "mac": "AA-BB-CC-DD-EE-FF"
            }
        ]

        with patch("api.get_windows_network_adapters", return_value=mock_adapters) as mock_get_adapters:
            with patch("api.auto_detect_interface_with_rationale", wraps=auto_detect_interface_with_rationale) as mock_auto_detect:
                res = self.client.get("/api/adapter-info")
                self.assertEqual(res.status_code, 200)
                data = res.get_json()

                # get_windows_network_adapters should be called exactly once
                self.assertEqual(mock_get_adapters.call_count, 1)

                # auto_detect_interface_with_rationale should have received the adapters keyword
                self.assertEqual(mock_auto_detect.call_count, 1)
                call_kwargs = mock_auto_detect.call_args[1]
                self.assertIn("adapters", call_kwargs)
                self.assertEqual(call_kwargs["adapters"], mock_adapters)

                # Data should match
                self.assertEqual(len(data["available_adapters"]), 1)
                self.assertEqual(data["available_adapters"][0]["name"], "Ethernet")

    def test_03_service_status_endpoint_is_lightweight(self):
        """Verify /api/service-status does NOT invoke adapter discovery or PowerShell."""
        with patch("api.get_windows_network_adapters") as mock_get_adapters:
            res = self.client.get("/api/service-status")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "success")
            self.assertIn("service", data)
            # get_windows_network_adapters must NOT be called
            mock_get_adapters.assert_not_called()

    def test_04_html_contains_redesigned_adapter_hub_elements(self):
        """Verify templates/ddos.html contains all responsive hub elements and cards."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # Core Hub
        self.assertIn('class="adapter-selection-hub"', html)
        self.assertIn('id="adapterSelectionHub"', html)
        self.assertIn('id="refreshAdaptersBtn"', html)
        self.assertIn('id="refreshAdaptersIcon"', html)
        self.assertIn('id="refreshAdaptersText"', html)
        self.assertIn('id="autoSelectAdapterBtn"', html)
        self.assertIn('id="adapterModeBadge"', html)

        # Selector & Count
        self.assertIn('id="monitoringAdapterSelect"', html)
        self.assertIn('id="adapterCountPill"', html)

        # 4 Responsive Cards
        self.assertIn('id="adapterDetailsGrid"', html)
        self.assertIn('id="cardDevice"', html)
        self.assertIn('id="cardIp"', html)
        self.assertIn('id="cardStatus"', html)
        self.assertIn('id="cardDriver"', html)

        # Card metadata fields
        self.assertIn('id="adapterName"', html)
        self.assertIn('id="adapterTypeMeta"', html)
        self.assertIn('id="adapterIp"', html)
        self.assertIn('id="adapterGatewayMeta"', html)
        self.assertIn('id="adapterStatusText"', html)
        self.assertIn('id="adapterStatusDot"', html)
        self.assertIn('id="adapterLinkSpeedMeta"', html)
        self.assertIn('id="driverStatusBadge"', html)
        self.assertIn('id="adapterDriverMeta"', html)

        # State Alerts
        self.assertIn('id="adapterEmptyCard"', html)
        self.assertIn('id="adapterDisappearedAlert"', html)
        self.assertIn('id="monitoringAdapterError"', html)

    def test_05_css_contains_responsive_grid_and_mobile_styles(self):
        """Verify static/style.css defines responsive grid and loading states."""
        css_path = os.path.join(os.path.dirname(__file__), "..", "static", "style.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()

        self.assertIn(".adapter-selection-hub", css)
        self.assertIn(".adapter-details-grid", css)
        self.assertIn("grid-template-columns: repeat(4, 1fr)", css)
        self.assertIn(".adapter-card", css)
        self.assertIn(".hub-refreshing", css)
        self.assertIn(".adapter-alert-card", css)
        self.assertIn(".adapter-empty-card", css)

        # Media queries for tablet & mobile
        self.assertTrue(
            ("@media (max-width: 1024px)" in css) or ("@media (max-width: 992px)" in css),
            "Responsive tablet breakpoint missing in style.css"
        )
        self.assertIn("@media (max-width: 640px)", css)

    def test_06_main_js_concurrency_lock_and_sequence_guard(self):
        """Verify static/main.js has concurrency locking, sequence checks, and no polling loop."""
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "main.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        # Concurrency & Sequence
        self.assertIn("let isAdapterRefreshing = false;", js)
        self.assertIn("let adapterRefreshSequence = 0;", js)
        self.assertIn("if (isAdapterRefreshing)", js)
        self.assertIn("reqSeq !== adapterRefreshSequence", js)

        # Abort timeout
        self.assertIn("AbortController", js)
        self.assertIn("8000", js)

        # Disappeared alert & strict zero fallback
        self.assertIn("selectedAdapterDisappeared", js)
        self.assertIn("adapterDisappearedAlert", js)

        # Verify syncServiceStatus does NOT call discoverInterfaces
        # Match function syncServiceStatus body
        sync_match = re.search(r"async function syncServiceStatus\(\)\s*\{(.*?)\}", js, re.DOTALL)
        self.assertIsNotNone(sync_match)
        sync_body = sync_match.group(1)
        self.assertNotIn("discoverInterfaces", sync_body, "syncServiceStatus must NOT trigger discoverInterfaces!")

    def test_07_disappeared_adapter_blocks_scan_without_silent_fallback(self):
        """Verify backend rejects scans for missing/disappeared adapters without silent switch."""
        payload = {
            "continuous": True,
            "adapter": "NonExistentDisappearedAdapter_777",
            "interface_name": "NonExistentDisappearedAdapter_777"
        }
        res = self.client.post("/api/scan", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("could not be resolved", data["message"])
        # Must not silently fallback or succeed
        self.assertFalse(data.get("scan_active", False))

if __name__ == "__main__":
    unittest.main()
