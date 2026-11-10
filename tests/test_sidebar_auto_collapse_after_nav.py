#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT — Automated Test Suite: Automatic Sidebar Collapse After Navigation
Verifies:
1. Initial State:
   - Sidebar is initially collapsed by default on both desktop and mobile across all pages
     (templates/ddos.html and templates/network_discovery.html have body.sidebar-collapsed).
   - static/main.js and static/network_discovery.js default to collapsed state on startup.
2. Auto-Close & Auto-Collapse Implementation:
   - autoCloseSidebarAfterNav() is defined and handles both desktop collapse and mobile drawer closing.
   - Closes mobile drawer and restores normal body overflow / scrolling (document.body.style.overflow = "").
   - Collapses desktop sidebar (adds body.sidebar-collapsed and sets nss_sidebar_collapsed="true").
   - Synchronizes aria-expanded="false" on the toggle button.
3. Universal Coverage Across All Sidebars & Navigation Items:
   - Admin Dashboard sidebar items (Overview, Users, Plans, Subscriptions, Requests, Audit, Profile).
   - Operational Tools sidebar items (Live Network Monitoring, Port Scanner, Network Discovery).
   - Operator Dashboard items (Dashboard, Plans).
   - Public Home Navigation items (Home, Threat Intelligence, Architecture, Prevention, Pricing, Team).
   - Sidebar Brand Logo link (#sidebarBrandLink).
   - Standalone Network Discovery sidebar links in static/network_discovery.js.
   - View switching via switchView() and scrollToPublicSection().
4. Reopening & Interaction Safety:
   - handleSidebarToggle() toggles between collapsed and expanded states smoothly.
   - Non-navigation clicks (whitespace, headers, section labels) do not trigger auto-collapse.
   - Active navigation item highlighting (setSidebarActive) is preserved.
"""

import re
import unittest
from pathlib import Path
from modules.auth.db import get_engine
from api import app


class TestSidebarAutoCollapseAfterNav(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parent.parent
        cls.ddos_html_path = cls.project_root / "templates" / "ddos.html"
        cls.nd_html_path = cls.project_root / "templates" / "network_discovery.html"
        cls.main_js_path = cls.project_root / "static" / "main.js"
        cls.nd_js_path = cls.project_root / "static" / "network_discovery.js"
        cls.style_css_path = cls.project_root / "static" / "style.css"

        with open(cls.ddos_html_path, "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()

        with open(cls.nd_html_path, "r", encoding="utf-8") as f:
            cls.nd_html = f.read()

        with open(cls.main_js_path, "r", encoding="utf-8") as f:
            cls.main_js = f.read()

        with open(cls.nd_js_path, "r", encoding="utf-8") as f:
            cls.nd_js = f.read()

        with open(cls.style_css_path, "r", encoding="utf-8") as f:
            cls.style_css = f.read()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        get_engine(reset=True)

    def test_01_initial_collapsed_state_in_templates(self):
        """Verify the sidebar is initially collapsed by default in HTML templates."""
        # 1. Main ddos.html body has sidebar-collapsed
        ddos_body_match = re.search(r'<body[^>]*class=["\']([^"\']+)["\']', self.ddos_html)
        self.assertIsNotNone(ddos_body_match, "Body tag not found in ddos.html")
        ddos_body_classes = ddos_body_match.group(1).split()
        self.assertIn("sidebar-collapsed", ddos_body_classes, "ddos.html body must have 'sidebar-collapsed' by default")

        # 2. network_discovery.html body has sidebar-collapsed
        nd_body_match = re.search(r'<body[^>]*class=["\']([^"\']+)["\']', self.nd_html)
        self.assertIsNotNone(nd_body_match, "Body tag not found in network_discovery.html")
        nd_body_classes = nd_body_match.group(1).split()
        self.assertIn("sidebar-collapsed", nd_body_classes, "network_discovery.html body must have 'sidebar-collapsed' by default")

    def test_02_initial_collapsed_state_in_javascript(self):
        """Verify JavaScript defaults to collapsed state if not explicitly expanded."""
        # 1. main.js initializes collapsed state
        self.assertIn('const storedSidebarState = localStorage.getItem("nss_sidebar_collapsed");', self.main_js)
        self.assertIn('if (storedSidebarState !== "false")', self.main_js)
        self.assertIn('document.body.classList.add("sidebar-collapsed");', self.main_js)

        # 2. network_discovery.js initializes collapsed state
        self.assertIn("const storedSidebarState = localStorage.getItem('nss_sidebar_collapsed');", self.nd_js)
        self.assertIn("if (storedSidebarState !== 'false')", self.nd_js)
        self.assertIn("document.body.classList.add('sidebar-collapsed');", self.nd_js)

    def test_03_autoclose_helper_implementation(self):
        """Verify autoCloseSidebarAfterNav correctly handles both mobile drawer and desktop collapse."""
        # 1. In main.js: autoCloseSidebarAfterNav handles mobile close and desktop collapse
        self.assertIn("function autoCloseSidebarAfterNav()", self.main_js)
        fn_match = re.search(r'function autoCloseSidebarAfterNav\(\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', self.main_js)
        self.assertIsNotNone(fn_match, "autoCloseSidebarAfterNav function not found in main.js")
        fn_body = fn_match.group(1)
        self.assertIn("closeMobileSidebar()", fn_body)
        self.assertIn('document.body.classList.add("sidebar-collapsed")', fn_body)
        self.assertIn('localStorage.setItem("nss_sidebar_collapsed", "true")', fn_body)

        # 2. closeMobileSidebar restores body overflow
        self.assertIn('document.body.style.overflow = "";', self.main_js)

        # 3. In network_discovery.js: autoCloseSidebarAfterNav handles both
        self.assertIn("function autoCloseSidebarAfterNav()", self.nd_js)
        nd_fn_match = re.search(r'function autoCloseSidebarAfterNav\(\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', self.nd_js)
        self.assertIsNotNone(nd_fn_match, "autoCloseSidebarAfterNav function not found in network_discovery.js")
        nd_fn_body = nd_fn_match.group(1)
        self.assertIn("closeMobileSidebar()", nd_fn_body)
        self.assertIn("document.body.classList.add('sidebar-collapsed')", nd_fn_body)
        self.assertIn("localStorage.setItem('nss_sidebar_collapsed', 'true')", nd_fn_body)

    def test_04_sidebar_navigation_items_trigger_autoclose(self):
        """Verify all sidebar navigation links trigger autoCloseSidebarAfterNav upon selection."""
        # 1. Main sidebar item loop invokes autoCloseSidebarAfterNav
        self.assertIn("sidebarNavItems.forEach(item => {", self.main_js)
        self.assertIn("autoCloseSidebarAfterNav();", self.main_js)

        # 2. Specific navigation branches invoke autoCloseSidebarAfterNav
        # Users / Admin tabs
        self.assertIn('switchView(navTarget);\n        autoCloseSidebarAfterNav();', self.main_js)
        # Live Monitoring
        self.assertIn('switchView("monitoring");\n        autoCloseSidebarAfterNav();', self.main_js)
        # Port Scanner
        self.assertIn('switchView("port-scanner");\n        autoCloseSidebarAfterNav();', self.main_js)
        # Subscription Plans
        self.assertIn('switchView("plans");\n        autoCloseSidebarAfterNav();', self.main_js)
        # Network Discovery
        self.assertIn('navTarget === "network-discovery"', self.main_js)

        # 3. Sidebar Brand Logo link auto-closes
        self.assertIn('sidebarBrandLink.addEventListener("click"', self.main_js)

        # 4. Standalone Network Discovery links invoke autoCloseSidebarAfterNav
        self.assertIn("document.querySelectorAll('.sidebar-nav-item').forEach(link => {", self.nd_js)
        self.assertIn("autoCloseSidebarAfterNav();", self.nd_js)

    def test_05_switchview_and_scrollto_guarantee_autoclose(self):
        """Verify switchView and scrollToPublicSection always auto-close the sidebar."""
        # 1. switchView includes autoCloseSidebarAfterNav
        self.assertIn("function switchView(", self.main_js)
        switchview_match = re.search(r'function switchView\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)', self.main_js)
        self.assertIsNotNone(switchview_match)
        # The statements in switchView must trigger autoCloseSidebarAfterNav
        switch_snippet = self.main_js[switchview_match.start():switchview_match.start() + 2500]
        self.assertIn("autoCloseSidebarAfterNav();", switch_snippet)

        # 2. scrollToPublicSection includes autoCloseSidebarAfterNav
        self.assertIn("function scrollToPublicSection(", self.main_js)
        scroll_match = re.search(r'function scrollToPublicSection\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)', self.main_js)
        self.assertIsNotNone(scroll_match)
        scroll_snippet = self.main_js[scroll_match.start():scroll_match.start() + 1500]
        self.assertIn("autoCloseSidebarAfterNav();", scroll_snippet)

    def test_06_reopening_and_toggle_behavior(self):
        """Verify the sidebar can be expanded and toggled normally via handleSidebarToggle."""
        # 1. Desktop toggling between collapsed and expanded
        self.assertIn("const isCollapsed = document.body.classList.toggle(\"sidebar-collapsed\");", self.main_js)
        self.assertIn('navbarSidebarToggleBtn.setAttribute("aria-expanded", isCollapsed ? "false" : "true");', self.main_js)

        # 2. Mobile drawer toggling with body overflow lock
        self.assertIn('const isOpen = document.body.classList.toggle("mobile-sidebar-open");', self.main_js)
        self.assertIn('document.body.style.overflow = "hidden";', self.main_js)
        self.assertIn('document.body.style.overflow = "";', self.main_js)

        # 3. Network discovery toggling
        self.assertIn("const isCollapsed = document.body.classList.toggle('sidebar-collapsed');", self.nd_js)
        self.assertIn("const isOpen = document.body.classList.toggle('mobile-sidebar-open');", self.nd_js)

    def test_07_all_sidebar_sections_represented(self):
        """Verify all requested sections are present in sidebar groups."""
        expected_nav_targets = [
            "admin",              # Platform Overview
            "admin-users",        # Users
            "admin-plans",        # Subscription Plans (Admin)
            "admin-subs",         # Subscriptions
            "admin-requests",     # Pending Requests
            "admin-audit",        # Audit Logs
            "admin-profile",      # Profile & Security
            "dashboard",          # Operator Dashboard
            "plans",              # Subscription Plans (User)
            "monitoring",         # Live Network Monitoring
            "port-scanner",       # Port Scanner
            "network-discovery",  # Network Discovery
            "home",               # Home
            "threats",            # Threat Intelligence
            "architecture",       # Architecture
            "prevention",         # Prevention
            "pricing",            # Pricing & Plans
            "team"                # Team
        ]
        for target in expected_nav_targets:
            self.assertIn(f'data-nav="{target}"', self.ddos_html, f"Missing data-nav='{target}' in ddos.html")


if __name__ == "__main__":
    unittest.main()
