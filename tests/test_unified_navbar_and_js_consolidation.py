"""
Unit and Integration Tests for SCOUT — Unified Application Architecture,
Navbar Consistency & JavaScript Consolidation.
"""
import os
import re
import unittest
from pathlib import Path
from api import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class TestUnifiedNavbarAndJsConsolidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.app.testing = True
        cls.client = cls.app.test_client()

        cls.ddos_html_path = PROJECT_ROOT / "templates" / "ddos.html"
        cls.nd_html_path = PROJECT_ROOT / "templates" / "network_discovery.html"
        cls.main_js_path = PROJECT_ROOT / "static" / "main.js"
        cls.nd_js_path = PROJECT_ROOT / "static" / "network_discovery.js"

        cls.ddos_html = cls.ddos_html_path.read_text(encoding="utf-8")
        cls.nd_html = cls.nd_html_path.read_text(encoding="utf-8")
        cls.main_js = cls.main_js_path.read_text(encoding="utf-8")
        cls.nd_js = cls.nd_js_path.read_text(encoding="utf-8")

    def test_01_both_templates_share_unified_navbar_structure(self):
        """1. Verify ddos.html and network_discovery.html share identical core global navbar structure."""
        required_navbar_elements = [
            'id="globalTopNavbar"',
            'id="topNavBrandLink"',
            'id="navbarSidebarToggleBtn"',
            'id="themeToggleBtn"',
            'id="userProfileMenu"',
            'id="userProfileDropdownBtn"',
            'id="userDropdownCard"'
        ]
        for elem in required_navbar_elements:
            self.assertIn(elem, self.ddos_html, f"Missing {elem} in ddos.html navbar")
            self.assertIn(elem, self.nd_html, f"Missing {elem} in network_discovery.html navbar")

    def test_02_navbar_engine_status_removed_from_global_navbar(self):
        """2. Verify engine core status is absent from global navbar in both templates."""
        # Top nav health pill should not exist in either top navbar
        self.assertNotIn('id="topNavHealthPill"', self.nd_html)
        self.assertNotIn('id="topNavHealthPill"', self.ddos_html)

    def test_03_go_to_dashboard_cta_in_network_discovery(self):
        """3. Verify redundant Go to Dashboard navbar button is absent from network_discovery.html top navbar."""
        self.assertNotIn('id="publicDashboardCta"', self.nd_html)
        self.assertNotIn('id="publicDashboardCtaWrap"', self.nd_html)
        # Dedicated toolbar breadcrumbs
        self.assertIn('id="dedicatedToolBar"', self.nd_html)
        self.assertIn('id="breadcrumbHomeLink"', self.nd_html)
        self.assertIn('id="breadcrumbDashboardLink"', self.nd_html)

    def test_04_templates_load_main_js(self):
        """4. Verify network_discovery.html loads main.js as the primary unified application script."""
        self.assertIn('<script src="/static/main.js"></script>', self.nd_html)
        self.assertIn('<script src="/static/main.js"></script>', self.ddos_html)

    def test_05_main_js_contains_network_discovery_engine(self):
        """5. Verify static/main.js consolidates Network Discovery logic."""
        self.assertIn("const NetworkDiscoveryUI", self.main_js)
        self.assertIn("window.NetworkDiscoveryUI = NetworkDiscoveryUI;", self.main_js)
        self.assertIn("window.initNetworkDiscovery = NetworkDiscoveryUI.init;", self.main_js)
        self.assertIn("NetworkDiscoveryUI.init();", self.main_js)

    def test_06_main_js_has_page_specific_guards(self):
        """6. Verify static/main.js guards Live Monitoring, Port Scanner, and Network Discovery."""
        # Live Monitoring guard
        self.assertIn("hasMonitoringElements", self.main_js)
        # Port Scanner guard
        self.assertIn('if (!document.getElementById("portScannerSection") && !startBtn)', self.main_js)
        # Network Discovery guard
        self.assertIn("window.__scoutNetworkDiscoveryInitialized", self.main_js)

    def test_07_main_js_view_routing_and_navigation(self):
        """7. Verify getQueryView, updateNavbarContext, and switchView handle network-discovery."""
        # View query detection
        self.assertIn('window.location.pathname.startsWith("/network-discovery")', self.main_js)
        self.assertIn('return "network-discovery";', self.main_js)

        # Context updates
        self.assertIn('else if (document.body.classList.contains("network-discovery-page") || window.location.pathname.startsWith("/network-discovery")) currentView = "network-discovery";', self.main_js)

        # Cross-page navigation in switchView
        self.assertIn('if (targetView === "network-discovery")', self.main_js)
        self.assertIn('window.location.href = "/network-discovery";', self.main_js)

        # Sidebar active normalization
        self.assertIn('else if (normalized === "network-discovery" || normalized === "discovery")', self.main_js)

    def test_08_network_discovery_js_idempotent_bridge(self):
        """8. Verify static/network_discovery.js contains idempotent guards to prevent duplicate runs."""
        self.assertIn("window.__scoutNetworkDiscoveryInitialized", self.nd_js)
        # Preserves core functions for backward compatibility
        self.assertIn("function startDiscoveryScan", self.nd_js)
        self.assertIn("function stopDiscoveryScan", self.nd_js)
        self.assertIn("renderDeviceTable", self.nd_js)
        self.assertIn("function autoCloseSidebarAfterNav", self.nd_js)

    def test_09_flask_route_network_discovery_live_response(self):
        """9. Verify GET /network-discovery returns 200 with complete navbar and scripts."""
        from modules.auth.security import create_session_token, COOKIE_NAME
        from modules.auth.db import get_db_session
        from modules.auth.models import User

        with get_db_session() as s:
            u = s.query(User).filter_by(role='Admin', is_active=True).first()
            token = create_session_token(u.id, u.role, u.session_version)

        self.client.set_cookie(key=COOKIE_NAME, value=token)
        res = self.client.get('/network-discovery', headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        self.assertIn('id="globalTopNavbar"', html)
        self.assertNotIn('id="publicDashboardCtaWrap"', html)
        self.assertNotIn('id="publicDashboardCta"', html)
        self.assertIn('/static/main.js', html)

if __name__ == '__main__':
    unittest.main()
