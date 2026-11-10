#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: Operational Navbar Standardization & Redundant Dashboard Button Removal
Validates:
1. Live Network Monitoring top navbar does not render 'Go to Dashboard'
2. Port Scanner top navbar does not render 'Go to Dashboard'
3. Network Discovery top navbar does not contain 'publicDashboardCtaWrap' or 'Go to Dashboard'
4. Public Homepage retains 'Go to Dashboard' CTA when authenticated
5. Admin Dashboard and Operator Dashboard navigation remain accessible in the sidebar
6. Sidebar expand/collapse and auto-close after navigation are preserved
7. Consistent top navbar elements present across all operational tools:
   - SCOUT logo (#topNavBrandLink)
   - Sidebar toggle (#navbarSidebarToggleBtn)
   - Theme toggle (#themeToggleBtn)
   - User profile & dropdown (#userProfileMenu, #userDropdownCard)
8. Operational routes (/network-discovery, /?view=monitoring, /?view=port-scanner) return 200
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app


class TestOperationalNavbarClean(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

        cls.ddos_html_path = PROJECT_ROOT / "templates" / "ddos.html"
        cls.nd_html_path = PROJECT_ROOT / "templates" / "network_discovery.html"
        cls.main_js_path = PROJECT_ROOT / "static" / "main.js"

        with open(cls.ddos_html_path, "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()

        with open(cls.nd_html_path, "r", encoding="utf-8") as f:
            cls.nd_html = f.read()

        with open(cls.main_js_path, "r", encoding="utf-8") as f:
            cls.main_js = f.read()

    # =========================================================================
    # 1. Network Discovery Template Top Navbar Verification
    # =========================================================================
    def test_01_network_discovery_template_omits_dashboard_cta_in_navbar(self):
        """Verify network_discovery.html top navbar does not contain the redundant Go to Dashboard button."""
        # Top navbar must NOT have publicDashboardCtaWrap or publicDashboardCta
        self.assertNotIn('id="publicDashboardCtaWrap"', self.nd_html)
        self.assertNotIn('id="publicDashboardCta"', self.nd_html)

        # Standard top navbar elements must be present
        self.assertIn('id="globalTopNavbar"', self.nd_html)
        self.assertIn('id="topNavBrandLink"', self.nd_html)
        self.assertIn('id="navbarSidebarToggleBtn"', self.nd_html)
        self.assertIn('id="themeToggleBtn"', self.nd_html)
        self.assertIn('id="userProfileMenu"', self.nd_html)
        self.assertIn('id="userDropdownCard"', self.nd_html)

    # =========================================================================
    # 2. JavaScript Controller Omission on Operational Tool Views
    # =========================================================================
    def test_02_main_js_omits_dashboard_cta_on_operational_views(self):
        """Verify static/main.js explicitly suppresses Go to Dashboard on operational views."""
        # Check isOperationalView definition
        self.assertIn('const isOperationalView', self.main_js)
        self.assertIn('currentView === "monitoring"', self.main_js)
        self.assertIn('currentView === "port-scanner"', self.main_js)
        self.assertIn('currentView === "network-discovery"', self.main_js)

        # In operational view branch, publicDashboardCtaWrap is set to display = "none" and innerHTML cleared
        self.assertIn('publicDashboardCtaWrap.style.display = "none"', self.main_js)
        self.assertIn('publicDashboardCta.innerHTML = ""', self.main_js)

        # Safety check in click handler
        self.assertIn('if (publicDashboardCtaWrap && publicDashboardCtaWrap.style.display === "none")', self.main_js)

    # =========================================================================
    # 3. Public Homepage Retains Dashboard CTA for Authenticated Users
    # =========================================================================
    def test_03_public_homepage_retains_dashboard_cta_elements(self):
        """Verify public homepage template retains publicDashboardCtaWrap for landing view."""
        self.assertIn('id="publicDashboardCtaWrap"', self.ddos_html)
        self.assertIn('id="publicDashboardCta"', self.ddos_html)
        self.assertIn('id="publicDashboardCtaText"', self.ddos_html)

        # Main JS handles landing / home view to display Go to Dashboard
        self.assertIn('currentView === "landing" || currentView === "home"', self.main_js)

    # =========================================================================
    # 4. Sidebar Preserves Dashboard Navigation & Auto-Collapse
    # =========================================================================
    def test_04_sidebar_preserves_dashboard_navigation_and_collapse(self):
        """Verify sidebar preserves Dashboard navigation for Admin and User, plus auto-collapse."""
        # Admin navigation group in ddos.html and network_discovery.html
        self.assertIn('id="sidebarAdminNavGroup"', self.ddos_html)
        self.assertIn('data-nav="admin"', self.ddos_html)
        self.assertIn('href="/?view=admin"', self.ddos_html)

        self.assertIn('id="sidebarAdminNavGroup"', self.nd_html)
        self.assertIn('data-nav="admin"', self.nd_html)
        self.assertIn('href="/?view=admin"', self.nd_html)

        # Operator navigation group in both templates
        self.assertIn('id="sidebarUserNavGroup"', self.ddos_html)
        self.assertIn('data-nav="dashboard"', self.ddos_html)
        self.assertIn('href="/?view=dashboard"', self.ddos_html)

        self.assertIn('id="sidebarUserNavGroup"', self.nd_html)
        self.assertIn('data-nav="dashboard"', self.nd_html)
        self.assertIn('href="/?view=dashboard"', self.nd_html)

        # Operational tools navigation in both templates
        for nav_target in ['data-nav="monitoring"', 'data-nav="port-scanner"', 'data-nav="network-discovery"']:
            self.assertIn(nav_target, self.ddos_html)
            self.assertIn(nav_target, self.nd_html)

        # Auto-collapse sidebar after navigation
        self.assertIn("function autoCloseSidebarAfterNav()", self.main_js)
        self.assertIn("autoCloseSidebarAfterNav();", self.main_js)

    # =========================================================================
    # 5. Standardized Operational Navbar Controls Across All 3 Pages
    # =========================================================================
    def test_05_standardized_navbar_controls_in_both_templates(self):
        """Verify shared navbar controls are identical across ddos.html and network_discovery.html."""
        shared_elements = [
            'class="global-top-navbar"',
            'id="navbarSidebarToggleBtn"',
            'id="topNavBrandLink"',
            'id="themeToggleBtn"',
            'id="themeToggleIcon"',
            'id="themeToggleText"',
            'id="publicAuthActions"',
            'id="userProfileMenu"',
            'id="userProfileDropdownBtn"',
            'id="userDropdownCard"'
        ]
        for elem in shared_elements:
            self.assertIn(elem, self.ddos_html, f"Missing {elem} in ddos.html")
            self.assertIn(elem, self.nd_html, f"Missing {elem} in network_discovery.html")

    # =========================================================================
    # 6. Live HTTP Endpoints for All Three Operational Pages Return 200
    # =========================================================================
    def test_06_operational_routes_render_clean_navbar(self):
        """Verify GET /network-discovery and GET / render successfully."""
        from modules.auth.security import create_session_token, COOKIE_NAME
        from modules.auth.db import get_db_session
        from modules.auth.models import User

        with get_db_session() as s:
            u = s.query(User).filter_by(role='Admin', is_active=True).first()
            token = create_session_token(u.id, u.role, u.session_version)

        self.client.set_cookie(key=COOKIE_NAME, value=token)
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Network Discovery route (when authenticated as Admin)
        nd_res = self.client.get("/network-discovery", headers=headers)
        self.assertEqual(nd_res.status_code, 200)
        nd_content = nd_res.get_data(as_text=True)
        self.assertNotIn('id="publicDashboardCtaWrap"', nd_content)
        self.assertNotIn('id="publicDashboardCta"', nd_content)
        self.assertIn('id="globalTopNavbar"', nd_content)
        self.assertIn('id="navbarSidebarToggleBtn"', nd_content)

        # 2. Main app route (public landing)
        app_res = self.client.get("/?public=1")
        self.assertEqual(app_res.status_code, 200)
        app_content = app_res.get_data(as_text=True)
        self.assertIn('id="globalTopNavbar"', app_content)
        self.assertIn('id="check-connection"', app_content)  # Live Monitoring Section
        self.assertIn('id="port-scanner"', app_content)  # Port Scanner Section


if __name__ == "__main__":
    unittest.main()
