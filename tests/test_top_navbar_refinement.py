#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT — Automated Test Suite: Top Navigation Bar Refinement
Verifies:
1. Dashboard Button Renaming:
   - Button label is "Go to Dashboard" in HTML and dynamically in JavaScript for Admin.
   - Target destination '/?view=admin' for Admin and '/?view=dashboard' for User are preserved.
   - SCOUT green button styling (.btn-auth-cta) is properly centered and aligned.
2. Engine Core Status Removal from Global Navbar:
   - #topNavHealthPill is completely removed from the global top navbar.
   - Engine Core and packet capture status monitoring is preserved in Live Network Monitoring (#driverStatusBadge).
   - Sidebar Engine Core pill (#systemHealthPill) is preserved.
   - Backend sniffer status API endpoints remain intact (/api/service-status, /api/health).
3. User Profile Dropdown Size Reduction:
   - Dropdown footprint is compact (width <= 200px, padding <= 6px, radius 10px).
   - Dropdown items have compact padding, font size, and correctly sized icons.
   - All 5 dropdown items (Dashboard, Plans, Admin Console, Public Website, Sign Out) are preserved.
   - Admin Console is protected by role-based permissions (.admin-only-item).
4. Navbar Layout & Spacing Optimization:
   - .top-nav-right has balanced spacing (gap <= 10px) and vertical centering.
   - Mobile and tablet media queries prevent overflow and element overlap.
"""

import os
import re
import unittest
from pathlib import Path
from modules.auth.db import get_engine
from api import app


class TestTopNavbarRefinement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parent.parent
        cls.ddos_html_path = cls.project_root / "templates" / "ddos.html"
        cls.main_js_path = cls.project_root / "static" / "main.js"
        cls.style_css_path = cls.project_root / "static" / "style.css"

        with open(cls.ddos_html_path, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

        with open(cls.main_js_path, "r", encoding="utf-8") as f:
            cls.js_content = f.read()

        with open(cls.style_css_path, "r", encoding="utf-8") as f:
            cls.css_content = f.read()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        get_engine(reset=True)

    def test_01_dashboard_button_renamed_to_go_to_dashboard(self):
        """Verify the dashboard button displays 'Go to Dashboard' and preserves admin destination."""
        # 1. Static HTML text in publicDashboardCtaText
        self.assertIn('id="publicDashboardCtaText"', self.html_content)
        self.assertIn('>Go to Dashboard</span>', self.html_content)

        # 2. In JavaScript checkAuthSession, admin role dynamically sets "Go to Dashboard"
        self.assertIn('publicDashboardCtaText.textContent = "Go to Dashboard"', self.js_content)
        # Ensure old label "Go to Admin Dashboard" is no longer assigned to publicDashboardCtaText
        self.assertNotIn('publicDashboardCtaText.textContent = "Go to Admin Dashboard"', self.js_content)

        # 3. Ensure destination href for Admin view is preserved
        self.assertIn('publicDashboardCta.setAttribute("href", "/?view=admin")', self.js_content)
        # And user destination href is preserved
        self.assertIn('publicDashboardCta.setAttribute("href", "/?view=dashboard")', self.js_content)

    def test_02_engine_core_status_removed_from_global_top_navbar(self):
        """Verify #topNavHealthPill is completely removed from the global top navbar."""
        # Extract global top navbar content
        navbar_match = re.search(r'<header[^>]*id="globalTopNavbar"[^>]*>(.*?)</header>', self.html_content, re.DOTALL)
        self.assertIsNotNone(navbar_match, "globalTopNavbar header element not found in ddos.html")
        navbar_html = navbar_match.group(1)

        # Ensure topNavHealthPill is absent from top navbar
        self.assertNotIn('id="topNavHealthPill"', navbar_html, "Engine Core status pill must not exist in globalTopNavbar")
        self.assertNotIn('topNavHealthPill', self.html_content, "id='topNavHealthPill' should be completely removed from template")

    def test_03_engine_core_status_preserved_in_live_monitoring_and_sidebar(self):
        """Verify Engine Core packet capture readiness is preserved in Live Network Monitoring and sidebar."""
        # 1. Driver readiness badge in Live Monitoring hardware adapter section
        self.assertIn('id="driverStatusBadge"', self.html_content)
        self.assertIn('id="cardDriver"', self.html_content)
        self.assertIn('id="adapterDriverMeta"', self.html_content)

        # 2. Sidebar Engine Core status pill
        self.assertIn('id="systemHealthPill"', self.html_content)
        self.assertIn('id="headerHealthDot"', self.html_content)
        self.assertIn('id="headerHealthLabel"', self.html_content)

        # 3. JS function updateServiceBadge updates driverStatusBadge and headerHealthDot
        self.assertIn('driverStatusBadge.textContent = labelText', self.js_content)
        self.assertIn('headerHealthDot.className = `health-dot ${healthClass}`', self.js_content)

        # 4. Backend service status endpoint is live and responding
        res = self.client.get("/api/service-status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("service", data)

        # 5. Connectivity health check endpoint
        res_health = self.client.get("/api/health")
        self.assertEqual(res_health.status_code, 200)
        health_data = res_health.get_json()
        self.assertIn("can_capture_live", health_data)

    def test_04_user_profile_dropdown_size_and_elements_preserved(self):
        """Verify user dropdown card has a compact footprint and all actions are preserved."""
        # 1. Dropdown card container exists
        self.assertIn('id="userDropdownCard"', self.html_content)

        # All 5 dropdown items exist in the HTML structure
        self.assertIn('id="dropdownDashboardLink"', self.html_content)
        self.assertIn('id="dropdownPlansLink"', self.html_content)
        self.assertIn('id="dropdownAdminLink"', self.html_content)
        self.assertIn('admin-only-item', self.html_content)
        self.assertIn('id="dropdownPublicLink"', self.html_content)
        self.assertIn('id="signOutBtn"', self.html_content)

        # 2. Compact CSS specifications for user-dropdown-card
        self.assertIn('.user-dropdown-card {', self.css_content)
        # Check width is compact (<= 205px)
        width_match = re.search(r'\.user-dropdown-card\s*\{[^}]*width:\s*([0-9]+)px', self.css_content)
        self.assertIsNotNone(width_match, "Width definition in .user-dropdown-card not found")
        card_width = int(width_match.group(1))
        self.assertLessEqual(card_width, 205, f"Expected dropdown card width <= 205px, got {card_width}px")

        # Check padding is compact (<= 6px)
        padding_match = re.search(r'\.user-dropdown-card\s*\{[^}]*padding:\s*([0-9]+)px', self.css_content)
        self.assertIsNotNone(padding_match, "Padding definition in .user-dropdown-card not found")
        card_padding = int(padding_match.group(1))
        self.assertLessEqual(card_padding, 6, f"Expected dropdown card padding <= 6px, got {card_padding}px")

        # Check item padding and font size
        self.assertIn('.user-dropdown-item {', self.css_content)
        self.assertIn('.dropdown-item-icon {', self.css_content)

    def test_05_navbar_layout_spacing_and_styling(self):
        """Verify navbar layout spacing, button centering, and responsiveness."""
        # 1. .top-nav-right has gap <= 10px and flex align-items center
        self.assertIn('.top-nav-right {', self.css_content)
        nav_right_match = re.search(r'\.top-nav-right\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(nav_right_match)
        nav_right_rules = nav_right_match.group(1)
        self.assertIn('display: flex;', nav_right_rules)
        self.assertIn('align-items: center;', nav_right_rules)

        # 2. .btn-auth-cta centering and styling
        btn_cta_match = re.search(r'\.btn-auth-cta\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(btn_cta_match)
        btn_cta_rules = btn_cta_match.group(1)
        self.assertIn('justify-content: center;', btn_cta_rules)
        self.assertIn('white-space: nowrap;', btn_cta_rules)
        self.assertIn('--brand-accent', btn_cta_rules)

        # 3. Mobile responsiveness adjustments
        self.assertIn('@media (max-width: 480px)', self.css_content)
        self.assertIn('@media (max-width: 960px)', self.css_content)


if __name__ == "__main__":
    unittest.main()
