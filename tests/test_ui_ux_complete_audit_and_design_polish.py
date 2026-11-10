"""
==============================================================================
SCOUT — UI/UX Complete Platform Audit & Design Polish Verification Test Suite
==============================================================================
Verifies design tokens, keyboard accessibility (:focus-visible), button
standardization, WCAG AA contrast compliance in Light and Dark modes,
responsive layout wrapping, and visual hierarchy across all platform pages.
"""

import os
import re
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api import app
from modules.auth.models import User
from modules.subscriptions.models import SubscriptionPlan, UserSubscription


class TestUIUXAuditAndDesignPolish(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

        cls.template_ddos = os.path.join(PROJECT_ROOT, "templates", "ddos.html")
        cls.template_login = os.path.join(PROJECT_ROOT, "templates", "login.html")
        cls.template_register = os.path.join(PROJECT_ROOT, "templates", "register.html")
        cls.template_nd = os.path.join(PROJECT_ROOT, "templates", "network_discovery.html")
        cls.css_path = os.path.join(PROJECT_ROOT, "static", "style.css")
        cls.js_main = os.path.join(PROJECT_ROOT, "static", "main.js")
        cls.js_nd = os.path.join(PROJECT_ROOT, "static", "network_discovery.js")

        with open(cls.css_path, "r", encoding="utf-8") as f:
            cls.css_content = f.read()
        with open(cls.js_main, "r", encoding="utf-8") as f:
            cls.js_content = f.read()
        with open(cls.template_ddos, "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()

    def test_01_global_accessibility_focus_visible_ring(self):
        """Verify global keyboard focus rings are defined for WCAG 2.1 AA compliance."""
        self.assertIn("button:focus-visible", self.css_content)
        self.assertIn("outline: 2px solid var(--accent, #A3E635) !important", self.css_content)
        self.assertIn('[data-theme="light"] button:focus-visible', self.css_content)
        self.assertIn("outline: 2px solid #18181B !important", self.css_content)

    def test_02_button_standardization_and_details_class(self):
        """Verify .btn-admin-action has standardized .details class and disabled-locked class."""
        self.assertIn(".btn-admin-action.details", self.css_content)
        self.assertIn(".btn-admin-action.disabled-locked", self.css_content)
        # Check that light mode overrides exist for all admin action types
        self.assertIn('[data-theme="light"] .btn-admin-action.activate', self.css_content)
        self.assertIn('[data-theme="light"] .btn-admin-action.reject', self.css_content)
        self.assertIn('[data-theme="light"] .btn-admin-action.cancel', self.css_content)
        self.assertIn('[data-theme="light"] .btn-admin-action.dates', self.css_content)
        self.assertIn('[data-theme="light"] .btn-admin-action.details', self.css_content)

    def test_03_elimination_of_inline_hardcoded_button_styles(self):
        """Verify main.js card renderers use semantic CSS classes rather than inline lime/cyan styles."""
        # Check that inline lime buttons in main.js were removed
        self.assertNotIn(
            'data-sub-details-id="${r.id}" style="background: rgba(163, 230, 53, 0.15)',
            self.js_content,
        )
        self.assertNotIn(
            'data-sub-details-id="${s.id}" style="background: rgba(163, 230, 53, 0.15)',
            self.js_content,
        )
        self.assertNotIn(
            'data-plan-details-id="${p.id}" style="background: rgba(163, 230, 53, 0.15)',
            self.js_content,
        )
        self.assertNotIn(
            'data-edit-user="${u.id}" style="background: rgba(56, 189, 248, 0.15)',
            self.js_content,
        )

        # Check semantic classes are present in main.js
        self.assertIn('class="btn-admin-action details"', self.js_content)
        self.assertIn('class="btn-card-action btn-card-edit"', self.js_content)

    def test_04_status_badges_light_mode_contrast_overrides(self):
        """Verify .sub-badge elements have high-contrast styling in Light Mode."""
        self.assertIn('[data-theme="light"] .sub-badge.active', self.css_content)
        self.assertIn('#15803D', self.css_content)  # WCAG AA green
        self.assertIn('[data-theme="light"] .sub-badge.pending', self.css_content)
        self.assertIn('#B45309', self.css_content)  # WCAG AA amber
        self.assertIn('[data-theme="light"] .sub-badge.expired', self.css_content)
        self.assertIn('#B91C1C', self.css_content)  # WCAG AA red
        self.assertIn('[data-theme="light"] .sub-badge.canceled', self.css_content)
        self.assertIn('#334155', self.css_content)  # WCAG AA slate

    def test_05_port_scanner_active_tab_dark_mode_contrast(self):
        """Verify Port Scanner active tab in dark mode avoids white-on-lime low contrast."""
        self.assertIn('[data-theme="dark"] .ps-mode-tab.active', self.css_content)
        self.assertIn('[data-theme="dark"] .ps-mode-tab.active .ps-mode-pill', self.css_content)

    def test_06_live_monitoring_check_btn_dark_mode_contrast(self):
        """Verify Start Monitoring button in dark mode uses dark text/icon on lime."""
        self.assertIn('[data-theme="dark"] .check-btn', self.css_content)
        self.assertIn('[data-theme="dark"] .check-btn i', self.css_content)

    def test_07_user_dashboard_light_mode_surfaces(self):
        """Verify Operator Dashboard cards adapt cleanly to Light Mode."""
        self.assertIn('[data-theme="light"] .user-dash-header-card', self.css_content)
        self.assertIn('[data-theme="light"] .user-dash-profile-card', self.css_content)
        self.assertIn('[data-theme="light"] .dash-tool-card', self.css_content)
        self.assertIn('[data-theme="light"] .dash-input', self.css_content)
        self.assertIn('[data-theme="light"] .btn-dash-action', self.css_content)

    def test_08_confirmation_modal_clean_classes(self):
        """Verify admin confirm modal uses clean CSS classes without hardcoded dark inline styles."""
        self.assertIn('class="confirm-target-box"', self.ddos_html)
        self.assertIn('class="confirm-consequences-box"', self.ddos_html)
        self.assertIn(".confirm-target-box", self.css_content)
        self.assertIn(".confirm-consequences-box", self.css_content)
        self.assertIn('[data-theme="light"] .confirm-target-box', self.css_content)
        self.assertIn('[data-theme="light"] .confirm-consequences-box', self.css_content)

    def test_09_responsive_toolbar_wrapping(self):
        """Verify .panel-actions-group supports flex wrapping and responsive stacking."""
        self.assertIn("flex-wrap: wrap", self.css_content)
        self.assertIn(".panel-actions-group", self.css_content)
        self.assertIn("@media (max-width: 768px)", self.css_content)

    def test_10_all_pages_route_render_and_auth_integrity(self):
        """Verify all core pages render with status 200 and maintain theme bootstrap."""
        pages = [
            ("/", "Autonomous Real-Time Traffic Inspection"),
            ("/login", "Sign In to SCOUT"),
            ("/register", "Create SCOUT Account"),
            ("/network-discovery", "Local Network Discovery"),
        ]
        for url, title_snip in pages:
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 200, f"Failed for {url}")
            html = resp.get_data(as_text=True)
            self.assertIn(title_snip, html, f"Missing title snippet in {url}")
            # Anti-flash theme initializer present on all pages
            self.assertIn("data-theme", html, f"Missing theme initializer in {url}")


if __name__ == "__main__":
    unittest.main()
