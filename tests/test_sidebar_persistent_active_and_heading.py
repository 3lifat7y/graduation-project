#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Acceptance Test Suite:
SCOUT Admin — Persistent Active Sidebar State and Platform Overview Heading

Covers:
1. Persistent active sidebar highlight across navigation and scroll events.
2. High-contrast active styling and visible indicators in Light and Dark modes.
3. Hover/focus distinction and mouse-leave state preservation.
4. Heading placement: 'SCOUT Administrative Console' isolated exclusively to Platform Overview.
5. Independent header titles and descriptions for all other admin sections.
6. Route query parameter parsing and alias normalization.
"""

import os
import re
import tempfile
from pathlib import Path
import unittest

from api import app
from modules.auth.db import get_engine, get_session_factory, init_db
from modules.auth.models import User
from modules.subscriptions.models import SubscriptionPlan


class TestSidebarPersistentActiveAndHeading(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key-sidebar-active-fix"

        # Read template and static asset contents
        root_dir = Path(__file__).resolve().parent.parent
        cls.html_content = (root_dir / "templates" / "ddos.html").read_text(encoding="utf-8")
        cls.js_content = (root_dir / "static" / "main.js").read_text(encoding="utf-8")
        cls.css_content = (root_dir / "static" / "style.css").read_text(encoding="utf-8")

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_sidebar_active.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with self.SessionFactory() as session:
            admin = User(
                username="admin_tester",
                email="admin_tester@scout.local",
                role="Admin",
                is_active=True
            )
            admin.set_password("AdminSecurePass!123")
            session.add(admin)
            session.commit()

    def tearDown(self):
        if hasattr(self, "engine") and self.engine is not None:
            self.engine.dispose()
        if self.old_db_path is not None:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_sidebar_html_admin_nav_items_and_data_nav(self):
        """Ensure all 7 admin sidebar navigation items exist with exact data-nav keys."""
        expected_nav_items = [
            ("admin", "Platform Overview"),
            ("admin-users", "Users"),
            ("admin-plans", "Subscription Plans"),
            ("admin-subs", "Subscriptions"),
            ("admin-requests", "Pending Requests"),
            ("admin-audit", "Audit Logs"),
            ("admin-profile", "Profile & Security")
        ]
        for data_nav, label in expected_nav_items:
            pattern = f'data-nav="{data_nav}"'
            self.assertIn(pattern, self.html_content, f"Missing sidebar item with data-nav='{data_nav}'")
            self.assertIn(label, self.html_content, f"Missing label '{label}' for data-nav='{data_nav}'")

    def test_platform_overview_heading_isolation(self):
        """Ensure 'SCOUT Administrative Console' heading is isolated exclusively to Platform Overview."""
        # 1. Heading appears in adminPanelOverview
        self.assertIn('id="adminPanelOverview"', self.html_content)
        overview_match = re.search(r'<div[^>]*id="adminPanelOverview"[^>]*>(.*?)</div>\s*<!-- Panel 1:', self.html_content, re.DOTALL)
        self.assertTrue(overview_match, "Could not extract adminPanelOverview panel from templates/ddos.html")
        overview_html = overview_match.group(1)

        self.assertIn("SCOUT Administrative Console", overview_html)
        self.assertIn("Platform Governance & Access Telemetry", overview_html)
        self.assertIn("Root Clearance", overview_html)

        # 2. adminPanelOverview has style="display:none;" by default so it never renders on subtabs
        panel_tag = re.search(r'<div[^>]*id="adminPanelOverview"[^>]*>', self.html_content).group(0)
        self.assertIn('style="display:none;"', panel_tag, "adminPanelOverview must have style='display:none;' by default")

        # 3. Check each other panel does NOT contain the overview heading
        other_panels = [
            ("adminPanelRequests", "Pending Subscription Requests"),
            ("adminPanelSubscriptions", "Global Subscription Registry"),
            ("adminPanelUsers", "Operator Accounts"),
            ("adminPanelPlans", "Subscription Plans Catalog"),
            ("adminPanelAudit", "Subscription Security Audit Log"),
            ("adminPanelProfile", "Admin Profile & Account Security")
        ]
        for panel_id, expected_title in other_panels:
            self.assertIn(f'id="{panel_id}"', self.html_content)
            panel_pattern = rf'<div[^>]*id="{panel_id}"[^>]*>(.*?)</div>\s*<!-- Panel'
            match = re.search(panel_pattern, self.html_content, re.DOTALL)
            if not match:
                panel_pattern = rf'<div[^>]*id="{panel_id}"[^>]*>(.*?)</section>'
                match = re.search(panel_pattern, self.html_content, re.DOTALL)
            self.assertTrue(match, f"Could not extract panel {panel_id}")
            panel_inner = match.group(1)
            self.assertNotIn("SCOUT Administrative Console", panel_inner, f"{panel_id} must not contain 'SCOUT Administrative Console'")
            self.assertIn(expected_title, panel_inner, f"{panel_id} must contain its own title '{expected_title}'")

    def test_scroll_immunity_in_javascript(self):
        """Ensure scroll event handler never removes active class when in admin view."""
        self.assertIn("function highlightNavOnScroll()", self.js_content)
        scroll_fn_match = re.search(r'function highlightNavOnScroll\(\)\s*\{([^}]+)\}', self.js_content)
        self.assertTrue(scroll_fn_match, "highlightNavOnScroll function not found")
        scroll_fn_body = scroll_fn_match.group(1)
        self.assertIn('document.body.classList.contains("home-view")', scroll_fn_body)
        self.assertIn('return;', scroll_fn_body)

    def test_alias_normalization_and_aria_current_in_javascript(self):
        """Ensure setSidebarActive normalizes aliases and sets aria-current."""
        self.assertIn("function setSidebarActive(navName)", self.js_content)
        set_active_match = re.search(r'function setSidebarActive\(navName\)\s*\{(.*?)\n  \}', self.js_content, re.DOTALL)
        self.assertTrue(set_active_match, "setSidebarActive function not found")
        body = set_active_match.group(1)
        self.assertIn('normalized === "admin-overview"', body)
        self.assertIn('normalized === "admin-operators"', body)
        self.assertIn('normalized === "admin-subscriptions"', body)
        self.assertIn('aria-current', body)

    def test_admin_tab_switch_synchronization(self):
        """Ensure activateAdminTab always keeps the sidebar active state synchronized."""
        self.assertIn("function activateAdminTab(tabKey", self.js_content)
        activate_match = re.search(r'function activateAdminTab\(tabKey.*?\)\s*\{(.*?)\n  \}', self.js_content, re.DOTALL)
        self.assertTrue(activate_match, "activateAdminTab function not found")
        body = activate_match.group(1)
        self.assertIn("setSidebarActive(viewKey)", body)
        self.assertIn("document.title = titleMap[tabKey]", body)
        self.assertIn("history.pushState", body)

    def test_dedicated_toolbar_hidden_on_admin(self):
        """Ensure dedicatedToolBar breadcrumb bar is hidden on admin views."""
        switch_view_match = re.search(r'else if \(targetView === "admin".*?\)\s*\{(.*?)\n    \} else \{', self.js_content, re.DOTALL)
        self.assertTrue(switch_view_match, "switchView admin branch not found")
        admin_branch = switch_view_match.group(1)
        self.assertIn('dedicatedToolBar.style.display = "none"', admin_branch)

    def test_css_active_styling_contrast_and_indicators(self):
        """Verify CSS tokens for Light and Dark modes provide high contrast, lime accent, and indicators."""
        # Light mode active styling
        self.assertIn(".sidebar-nav-item.active {", self.css_content)
        self.assertIn("background: #18181B;", self.css_content)
        self.assertIn("color: #FFFFFF;", self.css_content)
        self.assertIn("color: #A3E635;", self.css_content)
        self.assertIn("box-shadow: inset 3.5px 0 0 #84CC16", self.css_content)

        # Dark mode active styling
        self.assertIn('[data-theme="dark"] .sidebar-nav-item.active {', self.css_content)
        self.assertIn("background: #A3E635;", self.css_content)
        self.assertIn("color: #09090B;", self.css_content)
        self.assertIn("box-shadow: inset 3.5px 0 0 #09090B", self.css_content)

        # Focus visible
        self.assertIn(".sidebar-nav-item:focus-visible", self.css_content)
        self.assertIn('[data-theme="dark"] .sidebar-nav-item:focus-visible', self.css_content)

        # Hover state preserves active
        self.assertIn(".sidebar-nav-item.active:hover", self.css_content)
        self.assertIn('[data-theme="dark"] .sidebar-nav-item.active:hover', self.css_content)

    def test_admin_authentication_and_api_functionality(self):
        """Verify Admin login and access to admin management API endpoints."""
        login_res = self.client.post("/api/auth/login", json={
            "username": "admin_tester",
            "password": "AdminSecurePass!123"
        })
        self.assertEqual(login_res.status_code, 200)

        # Metrics API
        metrics_res = self.client.get("/api/admin/metrics")
        self.assertEqual(metrics_res.status_code, 200)
        metrics_json = metrics_res.get_json()
        self.assertIn("metrics", metrics_json)
        self.assertIn("total_users", metrics_json["metrics"])

        # Users API
        users_res = self.client.get("/api/admin/users")
        self.assertEqual(users_res.status_code, 200)

        # Subscriptions API
        subs_res = self.client.get("/api/admin/subscriptions")
        self.assertEqual(subs_res.status_code, 200)

        # Audit Logs API
        audit_res = self.client.get("/api/admin/audit-logs")
        self.assertEqual(audit_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
