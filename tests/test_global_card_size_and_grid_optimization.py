"""
SCOUT — Global Card Size Reduction & Responsive Grid Optimization Test Suite
Validates:
1. Unified Sidebar-Aware Grid System across Admin cards (Users, Plans, Subscriptions, Requests, Devices).
2. Desktop column requirements:
   - 4 cards per row when sidebar is collapsed on desktop.
   - 3 cards per row when sidebar is expanded on desktop.
   - 2-3 cards on medium desktop/laptop.
   - 2 cards on tablet.
   - 1 card on mobile.
3. Card Dimension & Padding reductions across:
   - Admin user cards (.admin-user-card)
   - Subscription plan cards (.admin-plan-card)
   - Subscription cards (.admin-sub-card)
   - Request cards (.admin-request-card)
   - Metric overview cards (.admin-metric-card)
   - User dashboard tools (.dash-tool-card)
   - Plans catalog cards (.plan-card, .public-plan-card)
   - Threat intelligence cards (.card)
   - Defensive tips (.tip-card)
   - Management dossier cards (.management-card, .management-dossier-grid)
   - Network discovery device cards (.nd-device-card)
"""

import os
import re
import unittest

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STYLE_CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")
DDOS_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")


class TestGlobalCardSizeAndGridOptimization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(STYLE_CSS_PATH, "r", encoding="utf-8") as f:
            cls.css_content = f.read()
        with open(DDOS_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

    def test_css_brace_balance(self):
        """Ensure CSS has no mismatched or unbalanced curly braces."""
        open_braces = self.css_content.count("{")
        close_braces = self.css_content.count("}")
        self.assertEqual(
            open_braces,
            close_braces,
            f"Unbalanced braces in style.css: {open_braces} open vs {close_braces} close",
        )

    def test_admin_card_containers_have_container_type(self):
        """Card containers should declare container-type: inline-size for container-aware queries."""
        containers = [
            ".admin-users-card-container",
            ".admin-plans-card-container",
            ".admin-subs-card-container",
            ".admin-requests-card-container",
        ]
        for c in containers:
            pattern = re.compile(re.escape(c) + r"\s*\{[^}]*container-type:\s*inline-size", re.DOTALL)
            self.assertTrue(
                pattern.search(self.css_content),
                f"Container {c} should declare container-type: inline-size",
            )

    def test_sidebar_collapsed_four_column_grid_definitions(self):
        """When sidebar is collapsed, grids must target 4 columns on desktop."""
        grids = [
            ".admin-users-cards-grid",
            ".admin-plans-cards-grid",
            ".admin-subs-cards-grid",
        ]
        # Look for body.sidebar-collapsed rules targeting repeat(4, ...)
        for g in grids:
            pattern = re.compile(
                r"body\.sidebar-collapsed[^{}]*" + re.escape(g) + r"[^{}]*\{[^}]*grid-template-columns:\s*repeat\(4,",
                re.DOTALL,
            )
            self.assertTrue(
                pattern.search(self.css_content),
                f"Grid {g} should have 4 columns under body.sidebar-collapsed on desktop",
            )

    def test_sidebar_expanded_three_column_grid_definitions(self):
        """When sidebar is expanded, grids must target 3 columns on desktop."""
        grids = [
            ".admin-users-cards-grid",
            ".admin-plans-cards-grid",
            ".admin-subs-cards-grid",
        ]
        # Look for body:not(.sidebar-collapsed) rules targeting repeat(3, ...)
        for g in grids:
            pattern = re.compile(
                r"body:not\(\.sidebar-collapsed\)[^{}]*" + re.escape(g) + r"[^{}]*\{[^}]*grid-template-columns:\s*repeat\(3,",
                re.DOTALL,
            )
            self.assertTrue(
                pattern.search(self.css_content),
                f"Grid {g} should have 3 columns when sidebar is expanded on desktop",
            )

    def test_admin_requests_cards_grid_desktop_multiple_columns(self):
        """Pending requests cards are wider and display multiple cards per row on desktop (2-3 columns)."""
        pattern_collapsed = re.compile(
            r"body\.sidebar-collapsed[^{}]*\.admin-requests-cards-grid[^{}]*\{[^}]*grid-template-columns:\s*repeat\([23],",
            re.DOTALL,
        )
        self.assertTrue(
            pattern_collapsed.search(self.css_content),
            "Requests grid should have 2-3 columns under body.sidebar-collapsed on desktop",
        )
        pattern_expanded = re.compile(
            r"body:not\(\.sidebar-collapsed\)[^{}]*\.admin-requests-cards-grid[^{}]*\{[^}]*grid-template-columns:\s*repeat\([23],",
            re.DOTALL,
        )
        self.assertTrue(
            pattern_expanded.search(self.css_content),
            "Requests grid should have 2-3 columns when sidebar is expanded on desktop",
        )

    def test_container_query_four_columns(self):
        """Grids should support container queries @container (min-width: 1100px) for 4 columns."""
        pattern = re.compile(
            r"@container\s*\(min-width:\s*1100px\)\s*\{[^}]*repeat\(4,\s*minmax\(0,\s*1fr\)\)",
            re.DOTALL,
        )
        self.assertTrue(
            pattern.search(self.css_content),
            "Container query @container (min-width: 1100px) must exist with repeat(4, minmax(0, 1fr))",
        )

    def test_admin_user_card_compact_dimensions(self):
        """User cards should have standardized padding and compact avatar (36px)."""
        card_pattern = re.compile(r"\.admin-user-card\s*\{([^}]+)\}", re.DOTALL)
        match = card_pattern.search(self.css_content)
        self.assertIsNotNone(match, ".admin-user-card rule must exist")
        block = match.group(1)
        self.assertTrue("padding: 20px" in block or "padding: 14px" in block)

        avatar_pattern = re.compile(r"\.user-card-avatar\s*\{([^}]+)\}", re.DOTALL)
        match_avatar = avatar_pattern.search(self.css_content)
        self.assertIsNotNone(match_avatar, ".user-card-avatar rule must exist")
        avatar_block = match_avatar.group(1)
        self.assertIn("width: 36px", avatar_block)
        self.assertIn("height: 36px", avatar_block)

    def test_admin_plan_card_compact_dimensions(self):
        """Admin plan cards should have standardized padding and compact typography."""
        card_pattern = re.compile(r"\.admin-plan-card\s*\{([^}]+)\}", re.DOTALL)
        match = card_pattern.search(self.css_content)
        self.assertIsNotNone(match, ".admin-plan-card rule must exist")
        block = match.group(1)
        self.assertTrue("padding: 20px" in block or "padding: 14px" in block)

    def test_admin_sub_card_compact_dimensions(self):
        """Subscription cards should have standardized padding."""
        card_pattern = re.compile(r"\.admin-sub-card\s*\{([^}]+)\}", re.DOTALL)
        match = card_pattern.search(self.css_content)
        self.assertIsNotNone(match, ".admin-sub-card rule must exist")
        block = match.group(1)
        self.assertTrue("padding: 20px" in block or "padding: 14px" in block)

    def test_admin_request_card_compact_dimensions(self):
        """Request cards should have standardized padding."""
        card_pattern = re.compile(r"\.admin-request-card\s*\{([^}]+)\}", re.DOTALL)
        match = card_pattern.search(self.css_content)
        self.assertIsNotNone(match, ".admin-request-card rule must exist")
        block = match.group(1)
        self.assertTrue("padding: 20px" in block or "padding: 14px" in block)

    def test_admin_metric_overview_card_dimensions(self):
        """Metric overview cards (.admin-metric-card) should have min-height <= 100px and compact padding."""
        pattern = re.compile(r"\.admin-metric-card\s*\{([^}]+)\}", re.DOTALL)
        match = pattern.search(self.css_content)
        self.assertIsNotNone(match, ".admin-metric-card rule must exist")
        block = match.group(1)
        self.assertIn("min-height: 96px", block)
        self.assertIn("padding: 12px 14px", block)

    def test_user_dashboard_tools_card_dimensions(self):
        """User dashboard tool cards should have reduced padding (16px) and compact icon."""
        pattern = re.compile(r"\.dash-tool-card\s*\{([^}]+)\}", re.DOTALL)
        match = pattern.search(self.css_content)
        self.assertIsNotNone(match, ".dash-tool-card rule must exist")
        block = match.group(1)
        self.assertIn("padding: 16px 16px", block)

    def test_plans_catalog_dimensions(self):
        """Plans catalog cards (.plan-card and .public-plan-card) should have reduced padding."""
        # Authenticated plan card
        pattern1 = re.compile(r"\.plan-card\s*\{([^}]+)\}", re.DOTALL)
        match1 = pattern1.search(self.css_content)
        self.assertIsNotNone(match1, ".plan-card rule must exist")
        self.assertIn("padding: 18px 20px", match1.group(1))

        # Public plan card
        pattern2 = re.compile(r"\.public-plan-card\s*\{([^}]+)\}", re.DOTALL)
        match2 = pattern2.search(self.css_content)
        self.assertIsNotNone(match2, ".public-plan-card rule must exist")
        self.assertIn("padding: 20px 22px", match2.group(1))
        self.assertIn("max-width: 380px", match2.group(1))

    def test_threat_intel_slider_card_dimensions(self):
        """Threat intelligence cards (.card) should be compacted to 260px width and 230px min-height."""
        pattern = re.compile(r"\.card\s*\{([^}]+)\}", re.DOTALL)
        match = pattern.search(self.css_content)
        self.assertIsNotNone(match, ".card rule must exist")
        block = match.group(1)
        self.assertIn("width: 260px", block)
        self.assertIn("min-height: 230px", block)
        self.assertIn("padding: 14px 14px", block)

    def test_defensive_tips_card_dimensions(self):
        """Defensive tip cards (.tip-card) should have min-height 140px and compact padding."""
        pattern = re.compile(r"\n\.tip-card\s*\{([^}]+)\}", re.DOTALL)
        match = pattern.search(self.css_content)
        self.assertIsNotNone(match, "Base .tip-card rule must exist")
        block = match.group(1)
        self.assertIn("min-height: 140px", block)
        self.assertIn("padding: 14px 16px", block)

    def test_management_dossier_card_dimensions(self):
        """Management dossier cards (.management-card) should have reduced padding and tighter grid minmax."""
        card_pattern = re.compile(r"\.management-card\s*\{([^}]+)\}", re.DOTALL)
        match_card = card_pattern.search(self.css_content)
        self.assertIsNotNone(match_card, ".management-card rule must exist")
        self.assertTrue("padding: 26px" in match_card.group(1) or "padding: 16px" in match_card.group(1))

        grid_pattern = re.compile(r"\.management-dossier-grid\s*\{([^}]+)\}", re.DOTALL)
        match_grid = grid_pattern.search(self.css_content)
        self.assertIsNotNone(match_grid, ".management-dossier-grid rule must exist")
        self.assertTrue("minmax(210px, 1fr)" in match_grid.group(1) or "minmax(190px, 1fr)" in match_grid.group(1))

    def test_network_discovery_cards_grid_dimensions(self):
        """Network discovery device cards (.nd-device-card) should have reduced padding and minmax."""
        grid_pattern = re.compile(r"\.nd-device-cards-grid\s*\{([^}]+)\}", re.DOTALL)
        match_grid = grid_pattern.search(self.css_content)
        self.assertIsNotNone(match_grid, ".nd-device-cards-grid rule must exist")
        self.assertIn("minmax(260px, 1fr)", match_grid.group(1))

        card_pattern = re.compile(r"\.nd-device-card\s*\{([^}]+)\}", re.DOTALL)
        match_card = card_pattern.search(self.css_content)
        self.assertIsNotNone(match_card, ".nd-device-card rule must exist")
        self.assertIn("padding: 12px 14px", match_card.group(1))

    def test_html_contains_card_grids(self):
        """Ensure ddos.html contains the expected grid containers."""
        self.assertIn("admin-users-cards-grid", self.html_content)
        self.assertIn("admin-plans-cards-grid", self.html_content)
        self.assertIn("admin-subs-cards-grid", self.html_content)
        self.assertIn("admin-requests-cards-grid", self.html_content)
        self.assertIn("public-plans-grid", self.html_content)
        self.assertIn("tips-container", self.html_content)
        self.assertIn("card-container", self.html_content)


if __name__ == "__main__":
    unittest.main()
