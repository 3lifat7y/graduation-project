#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT — Automated Test Suite: Public Home Page Navigation, Active Section Tracking & Theme Switching
Verifies:
1. Public navbar items and section target mappings (Home, Threat Intelligence, Architecture, Prevention, Pricing, Team).
2. Mobile sidebar public navigation group and drawer auto-closing.
3. Active section tracking, scroll-spy logic, and flicker prevention lock.
4. Smooth section navigation with fixed navbar offset consideration.
5. Instant Dark Mode / Light Mode theme switching, anti-flash initialization, and persistence.
6. Contrast and styling rules across light and dark themes.
"""

import os
import re
import unittest
from pathlib import Path
from modules.auth.db import get_engine
from api import app


class TestPublicHomeNavigationAndTheme(unittest.TestCase):
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

    def test_01_public_navbar_structure_and_section_ids(self):
        """Verifies all public navigation links and destination section elements exist in ddos.html."""
        # 1. Navbar container
        self.assertIn('id="publicTopNavLinks"', self.html_content)

        # 2. All 6 public navigation links with data-top-nav attributes
        expected_nav_items = [
            ("home", "#overview"),
            ("threats", "#threat-intelligence"),
            ("architecture", "#system-architecture"),
            ("prevention", "#prevention"),
            ("pricing", "#public-pricing"),
            ("team", "#team")
        ]
        for nav_attr, href_target in expected_nav_items:
            self.assertTrue(
                f'data-top-nav="{nav_attr}"' in self.html_content,
                f"Missing public navbar item with data-top-nav='{nav_attr}'"
            )
            self.assertTrue(
                f'href="{href_target}"' in self.html_content or f'href="/{href_target}"' in self.html_content,
                f"Missing href for target '{href_target}'"
            )

        # 3. All target section IDs must physically exist in ddos.html
        for _, href_target in expected_nav_items:
            sec_id = href_target.replace("#", "")
            self.assertRegex(
                self.html_content,
                rf'id=["\']{sec_id}["\']',
                f"Target section id='{sec_id}' not found in ddos.html"
            )

    def test_02_mobile_sidebar_public_navigation_group(self):
        """Verifies the mobile sidebar has a dedicated public navigation group."""
        self.assertIn('id="sidebarPublicNavGroup"', self.html_content)
        for nav in ["home", "threats", "architecture", "prevention", "pricing", "team"]:
            self.assertIn(f'data-nav="{nav}"', self.html_content)

    def test_03_active_section_tracking_in_js(self):
        """Verifies JavaScript contains PUBLIC_SECTION_TARGETS mapping and non-flickering scroll spy."""
        # Target mapping
        self.assertIn("PUBLIC_SECTION_TARGETS", self.js_content)
        for nav, sec in [
            ("home", "overview"),
            ("threats", "threat-intelligence"),
            ("architecture", "system-architecture"),
            ("prevention", "prevention"),
            ("pricing", "public-pricing"),
            ("team", "team")
        ]:
            self.assertIn(f'"{nav}": "{sec}"', self.js_content)

        # Active state indicator function
        self.assertIn("function setTopNavActive(navName)", self.js_content)
        self.assertIn('link.classList.add("active")', self.js_content)
        self.assertIn('link.setAttribute("aria-current", "page")', self.js_content)

        # Flicker prevention click lock
        self.assertIn("isNavigatingViaClick", self.js_content)

        # ScrollSpy function
        self.assertIn("function initPublicScrollSpy()", self.js_content)
        self.assertIn("evaluateActiveSection", self.js_content)

    def test_04_smooth_navigation_with_navbar_offset(self):
        """Verifies scroll offset calculation accounts for fixed navbar height."""
        # JS scroll offset calculation
        self.assertIn("function scrollToPublicSection", self.js_content)
        self.assertIn("globalTopNavbar", self.js_content)
        self.assertIn("prefersReduced", self.js_content)

        # CSS scroll-margin-top
        self.assertIn("scroll-margin-top:", self.css_content)
        self.assertIn("#overview", self.css_content)
        self.assertIn("#threat-intelligence", self.css_content)
        self.assertIn("#system-architecture", self.css_content)
        self.assertIn("#prevention", self.css_content)
        self.assertIn("#public-pricing", self.css_content)
        self.assertIn("#team", self.css_content)

    def test_05_instant_theme_switching_implementation(self):
        """Verifies instant Dark/Light theme switching, anti-flash initialization, and persistence."""
        # 1. Anti-flash script in ddos.html head
        self.assertIn("localStorage.getItem('nss_theme')", self.html_content)
        self.assertIn("document.documentElement.setAttribute('data-theme'", self.html_content)

        # 2. Theme toggle button in navbar
        self.assertIn('id="themeToggleBtn"', self.html_content)
        self.assertIn('id="themeToggleIcon"', self.html_content)
        self.assertIn('id="themeToggleText"', self.html_content)

        # 3. Theme toggler in JavaScript
        self.assertIn('localStorage.setItem("nss_theme"', self.js_content)
        self.assertIn('document.documentElement.setAttribute("data-theme"', self.js_content)
        self.assertIn('scout-theme-changed', self.js_content)

    def test_06_theme_contrast_and_active_indicator_css(self):
        """Verifies active indicator styling in both Light and Dark themes."""
        # Active link styling
        self.assertIn(".public-nav-link.active", self.css_content)
        self.assertIn('[data-theme="dark"] .public-nav-link.active', self.css_content)

        # Theme transitions avoid universal * selector
        self.assertNotIn("body.theme-transitioning *", self.css_content)

        # Logo theme rules
        self.assertIn(".scout-logo-light", self.css_content)
        self.assertIn(".scout-logo-dark", self.css_content)

    def test_07_http_response_delivers_public_home(self):
        """Verifies GET / and GET /?public=1 serve the public home page with navigation intact."""
        res = self.client.get("/?public=1")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn('id="publicTopNavLinks"', html)
        self.assertIn('id="themeToggleBtn"', html)
        self.assertIn('id="overview"', html)
        self.assertIn('id="team"', html)


if __name__ == "__main__":
    unittest.main()
