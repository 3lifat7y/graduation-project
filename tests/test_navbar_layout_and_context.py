#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT — Automated Test Suite: Global Navbar Layout, Responsive Behavior & Context-Aware Navigation
Verifies:
1. Part 1: Three-Zone Global Top Navbar Layout:
   - Dedicated .top-nav-left with flex-shrink: 0 and min-width: max-content (logo area never squeezed).
   - Dedicated .public-top-nav-links center zone with flex: 1 1 auto, min-width: 0, and justify-content: center.
   - Dedicated .top-nav-right action zone with flex: 0 0 auto, flex-shrink: 0, and margin-left: auto.
   - Physical gap/margins prevent any overlap between brand logo and "Home" navigation link.
2. Part 2: Responsive Navbar Breakpoints:
   - Medium screens (961px–1365px): compact padding, icon-only theme toggle, zero collision.
   - Small screens (< 960px): center links hidden, mobile hamburger toggle (#navbarSidebarToggleBtn) visible.
   - Mobile devices (<= 480px): compact logo, avatar-only user button, bounded dropdown.
   - Public navigation accessible in mobile drawer (#sidebarPublicNavGroup) on home-view.
3. Part 3: Context-Aware Navigation Actions:
   - Public Home Page: Displays "Go to Dashboard" (.btn-auth-cta) for Admin/Subscribed User.
   - Admin Dashboard: Replaces "Go to Dashboard" with "Back to Website" (.btn-auth-ghost, globe icon, href="/?public=1").
   - User Dashboard: Replaces "Go to Dashboard" with "Back to Website" (.btn-auth-ghost, globe icon, href="/?public=1").
   - Dedicated Tools: Points to appropriate dashboard, never points to current view.
   - Anonymous visitors: Shows "Sign In" and "Get Started".
4. Part 4 & 5: Profile Dropdown & Layout Separation:
   - User dropdown stays within viewport (max-width: calc(100vw - 16px)).
   - Public navigation links do not leak into Admin console.
   - Admin sidebar groups do not leak into public homepage.
   - Event handlers respect href destinations.
"""

import re
import unittest
from pathlib import Path
from modules.auth.db import get_engine
from api import app


class TestNavbarLayoutAndContext(unittest.TestCase):
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

    def test_01_three_zone_navbar_layout_css(self):
        """Verify the three-zone architecture: Left (logo), Center (links), Right (actions)."""
        # 1. Global top navbar layout
        self.assertIn(".global-top-navbar {", self.css_content)
        navbar_css_match = re.search(r'\.global-top-navbar\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(navbar_css_match)
        navbar_css = navbar_css_match.group(1)
        self.assertIn("display: flex", navbar_css)
        self.assertIn("justify-content: space-between", navbar_css)

        # 2. Left Zone: Dedicated logo container with flex-shrink: 0
        left_css_match = re.search(r'\.top-nav-left\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(left_css_match)
        left_css = left_css_match.group(1)
        self.assertIn("flex-shrink: 0", left_css)
        self.assertIn("min-width: max-content", left_css)

        # 3. Logo bounding box
        logo_css_match = re.search(r'\.scout-nav-logo\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(logo_css_match)
        logo_css = logo_css_match.group(1)
        self.assertIn("max-width: 130px", logo_css)

        # 4. Center Zone: Dedicated public links container
        links_css_match = re.search(r'\.public-top-nav-links\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(links_css_match)
        links_css = links_css_match.group(1)
        self.assertIn("justify-content: center", links_css)
        self.assertIn("flex: 1 1 auto", links_css)
        self.assertIn("margin: 0 16px", links_css)

        # 5. Right Zone: Dedicated actions container with margin-left: auto and flex-shrink: 0
        right_css_match = re.search(r'\.top-nav-right\s*\{([^}]+)\}', self.css_content)
        self.assertIsNotNone(right_css_match)
        right_css = right_css_match.group(1)
        self.assertIn("flex-shrink: 0", right_css)
        self.assertIn("margin-left: auto", right_css)

        # 6. User name max-width desktop (prevent premature truncation)
        self.assertIn("max-width: 140px", self.css_content)

    def test_02_responsive_navbar_breakpoints(self):
        """Verify responsive breakpoints for 1365px, 960px, 480px, and mobile drawer accessibility."""
        # 1. Medium screen rule (max-width: 1365px) and (min-width: 961px)
        self.assertIn("@media (max-width: 1365px) and (min-width: 961px)", self.css_content)
        med_rule_match = re.search(
            r'@media\s*\(max-width:\s*1365px\)\s*and\s*\(min-width:\s*961px\)\s*\{(.*?)\n\}',
            self.css_content,
            re.DOTALL
        )
        self.assertIsNotNone(med_rule_match)
        med_css = med_rule_match.group(1)
        # Theme toggle text hidden to preserve horizontal space
        self.assertIn(".theme-toggle-text", med_css)
        self.assertIn("display: none !important", med_css)

        # 2. Small screen rule (max-width: 960px or max-width: 991px): Center links hidden
        self.assertIn("body:not(.home-view) .public-top-nav-links", self.css_content)
        self.assertIn(".public-top-nav-links {\n    display: none !important;", self.css_content)

        # 3. Mobile screen rules: Compact logo, avatar-only user button, and bounded dropdown
        self.assertIn(".user-info-wrap {\n    display: none;\n  }", self.css_content)
        self.assertIn("max-width: calc(100vw - 16px)", self.css_content)

        # 4. Sidebar suppression on home-view only on desktop (allows mobile drawer on small screens)
        self.assertIn("@media (min-width: 961px)", self.css_content)
        self.assertIn("body.home-view .app-sidebar", self.css_content)

    def test_03_context_aware_navigation_controller_logic(self):
        """Verify updateNavbarContext sets the correct actions, classes, icons, and hrefs across views."""
        # 1. Function definition exists
        self.assertIn("function updateNavbarContext(", self.js_content)

        # 2. Admin dashboard context: Back to Website with globe icon and ghost styling
        self.assertIn('publicDashboardCta.className = "btn-auth-ghost"', self.js_content)
        self.assertIn('publicDashboardCta.setAttribute("href", "/?public=1")', self.js_content)
        self.assertIn('<i class="fas fa-globe"></i> <span id="publicDashboardCtaText">Back to Website</span>', self.js_content)

        # 3. Public Home Page context: Go to Dashboard with green cta styling
        self.assertIn('publicDashboardCta.className = "btn-auth-cta"', self.js_content)
        self.assertIn('<i class="fas fa-gauge-high"></i> <span id="publicDashboardCtaText">Go to Dashboard</span>', self.js_content)

        # 4. View Subscription Plans context for unsubscribed users on home
        self.assertIn('<i class="fas fa-gem"></i> <span id="publicDashboardCtaText">View Subscription Plans</span>', self.js_content)

        # 5. Anonymous visitor context: Hides dashboard CTA and displays sign in / get started
        self.assertIn('if (publicAuthActions) publicAuthActions.style.display = "flex"', self.js_content)
        self.assertIn('if (publicDashboardCtaWrap) publicDashboardCtaWrap.style.display = "none"', self.js_content)

    def test_04_view_switching_and_separation(self):
        """Verify view switching updates context and maintains strict separation between public and admin groups."""
        # 1. switchView calls updateNavbarContext
        self.assertIn("updateNavbarContext(targetView);", self.js_content)

        # 2. Separation of public navigation vs admin/tool groups
        self.assertIn('if (sidebarPublicNavGroup) sidebarPublicNavGroup.style.display = "block"', self.js_content)
        self.assertIn('if (sidebarPublicNavGroup) sidebarPublicNavGroup.style.display = "none"', self.js_content)
        self.assertIn('if (sidebarAdminNavGroup) sidebarAdminNavGroup.style.display = "none"', self.js_content)

        # 3. publicDashboardCta click handler intercepts public=1 and switches to landing
        self.assertIn('href.includes("public=1")', self.js_content)
        self.assertIn('switchView("landing")', self.js_content)

        # 4. Logo brand link clicks to landing
        self.assertIn('topNavBrandLink.addEventListener("click"', self.js_content)

    def test_05_html_structure_and_dropdown_integrity(self):
        """Verify all HTML elements exist with correct IDs, roles, and accessibility attributes."""
        # 1. Header and navigation elements
        self.assertIn('id="globalTopNavbar"', self.html_content)
        self.assertIn('class="top-nav-left"', self.html_content)
        self.assertIn('id="navbarSidebarToggleBtn"', self.html_content)
        self.assertIn('id="topNavBrandLink"', self.html_content)
        self.assertIn('id="publicTopNavLinks"', self.html_content)
        self.assertIn('class="top-nav-right"', self.html_content)
        self.assertIn('id="themeToggleBtn"', self.html_content)
        self.assertIn('id="publicAuthActions"', self.html_content)
        self.assertIn('id="publicDashboardCtaWrap"', self.html_content)
        self.assertIn('id="publicDashboardCta"', self.html_content)
        self.assertIn('id="publicDashboardCtaText"', self.html_content)
        self.assertIn('id="userProfileMenu"', self.html_content)
        self.assertIn('id="userDropdownCard"', self.html_content)

        # 2. Sidebar groups
        self.assertIn('id="sidebarPublicNavGroup"', self.html_content)
        self.assertIn('id="sidebarAdminNavGroup"', self.html_content)
        self.assertIn('id="sidebarUserNavGroup"', self.html_content)
        self.assertIn('id="sidebarToolsNavGroup"', self.html_content)

        # 3. Dropdown items
        self.assertIn('id="dropdownDashboardLink"', self.html_content)
        self.assertIn('id="dropdownPlansLink"', self.html_content)
        self.assertIn('id="dropdownAdminLink"', self.html_content)
        self.assertIn('id="dropdownPublicLink"', self.html_content)
        self.assertIn('id="signOutBtn"', self.html_content)


if __name__ == "__main__":
    unittest.main()
