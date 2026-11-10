"""
Tests for SCOUT Full-Page Management Experience, Navigation, Hidden Scrollbars, and Profile Dropdown Refinement
Verifies:
1. All 10 full-page management sections exist in templates/ddos.html.
2. Legacy complex modals are disabled/hidden, while lightweight confirmation modal remains functional.
3. static/main.js full-page view mapping, loaders, deep linking, sidebar active normalization, and init.
4. static/style.css universal scrollbar hiding and profile dropdown hover state refinement in light and dark modes.
"""

import os
import re
import unittest

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DDOS_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")
MAIN_JS_PATH = os.path.join(WORKSPACE_DIR, "static", "main.js")
STYLE_CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")


class TestFullPageManagementAndScrollbars(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DDOS_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html_content = f.read()
        with open(MAIN_JS_PATH, "r", encoding="utf-8") as f:
            cls.js_content = f.read()
        with open(STYLE_CSS_PATH, "r", encoding="utf-8") as f:
            cls.css_content = f.read()

    # --------------------------------------------------------------------------
    # Part 1, 2, 3: Full-Page Management Views in DOM
    # --------------------------------------------------------------------------
    def test_full_page_management_views_exist_in_html(self):
        """All 10 full-page management sections must exist inside templates/ddos.html within admin panels container."""
        expected_views = [
            "adminPageUserCreate",
            "adminPageUserDetails",
            "adminPageUserEdit",
            "adminPagePlanCreate",
            "adminPagePlanDetails",
            "adminPagePlanEdit",
            "adminPageSubDetails",
            "adminPageSubEdit",
            "adminPageSubExtend",
            "adminPageRequestDetails",
        ]
        for view_id in expected_views:
            with self.subTest(view_id=view_id):
                self.assertIn(
                    f'id="{view_id}"',
                    self.html_content,
                    f"Full-page management view '{view_id}' must exist in templates/ddos.html",
                )

    def test_full_page_management_elements_have_proper_structure(self):
        """Management views must have breadcrumb bar, header with actions, and proper form/dossier containers."""
        required_classes = [
            "full-page-management-view",
            "management-breadcrumb-bar",
            "management-header",
            "management-header-left",
            "management-badge",
            "management-title",
            "management-subtitle",
            "management-actions",
            "management-card",
        ]
        for cls_name in required_classes:
            with self.subTest(cls_name=cls_name):
                self.assertIn(
                    cls_name,
                    self.html_content,
                    f"Class '{cls_name}' must be used in templates/ddos.html for full-page management views",
                )

    # --------------------------------------------------------------------------
    # Part 7: Legacy Modals vs Fast Confirmation Modal
    # --------------------------------------------------------------------------
    def test_legacy_complex_modals_are_suppressed(self):
        """Legacy complex modals should have display:none !important to prevent popup collisions."""
        suppressed_modals = [
            "adminCreateUserModal",
            "adminUserDetailsModal",
            "adminPlanModal",
            "adminDateModal",
            "adminRenewSubModal",
            "adminExtendSubModal",
            "adminPlanDetailsModal",
            "adminSubDetailsModal",
        ]
        for modal_id in suppressed_modals:
            with self.subTest(modal_id=modal_id):
                pattern = rf'id="{modal_id}"[^>]*style="[^"]*display:\s*none\s*!important'
                self.assertRegex(
                    self.html_content,
                    pattern,
                    f"Modal '{modal_id}' should be suppressed with display:none !important in templates/ddos.html",
                )

    def test_lightweight_confirmation_modal_preserved(self):
        """The lightweight admin action confirmation modal must remain functional without display:none !important."""
        self.assertIn('id="adminConfirmActionModal"', self.html_content)
        pattern = r'id="adminConfirmActionModal"[^>]*style="[^"]*display:\s*none\s*!important'
        self.assertNotRegex(
            self.html_content,
            pattern,
            "adminConfirmActionModal must NOT be suppressed with !important because it is the fast confirmation dialog.",
        )

    # --------------------------------------------------------------------------
    # JavaScript Routing, Loaders, Deep Linking, and Handlers
    # --------------------------------------------------------------------------
    def test_full_page_views_registered_in_js(self):
        """FULL_PAGE_MANAGEMENT_VIEWS mapping in static/main.js must map views to DOM IDs."""
        self.assertIn("const FULL_PAGE_MANAGEMENT_VIEWS = {", self.js_content)
        expected_mappings = [
            '"admin-users-create": "adminPageUserCreate"',
            '"admin-user-details": "adminPageUserDetails"',
            '"admin-user-edit": "adminPageUserEdit"',
            '"admin-plans-create": "adminPagePlanCreate"',
            '"admin-plan-details": "adminPagePlanDetails"',
            '"admin-plan-edit": "adminPagePlanEdit"',
            '"admin-sub-details": "adminPageSubDetails"',
            '"admin-sub-edit": "adminPageSubEdit"',
            '"admin-sub-extend": "adminPageSubExtend"',
            '"admin-request-details": "adminPageRequestDetails"',
        ]
        for mapping in expected_mappings:
            with self.subTest(mapping=mapping):
                self.assertIn(
                    mapping,
                    self.js_content,
                    f"Mapping '{mapping}' must exist in FULL_PAGE_MANAGEMENT_VIEWS in static/main.js",
                )

    def test_sidebar_active_normalization_for_subroutes(self):
        """setSidebarActive in static/main.js must normalize management subroutes to keep parent categories active."""
        self.assertIn('normalized = "admin-users";', self.js_content)
        self.assertIn('normalized = "admin-plans";', self.js_content)
        self.assertIn('normalized = "admin-subs";', self.js_content)
        self.assertIn('normalized = "admin-requests";', self.js_content)
        self.assertIn('normalized = "admin-profile";', self.js_content)

    def test_full_page_management_handlers_initialized(self):
        """initFullPageManagementHandlers() must be defined and called during DOMContentLoaded initialization."""
        self.assertIn("function initFullPageManagementHandlers()", self.js_content)
        self.assertIn("initFullPageManagementHandlers();", self.js_content)

    def test_legacy_modal_functions_delegate_to_switch_view(self):
        """Legacy modal open functions should redirect to switchView to ensure 100% full-page experience."""
        delegations = [
            ("openPlanDetailsModal", 'switchView("admin-plan-details"'),
            ("openSubDetailsModal", 'switchView("admin-sub-details"'),
            ("openAdminUserDetails", 'switchView("admin-user-details"'),
            ("openCreateUserModal", 'switchView("admin-users-create"'),
            ("openCreatePlanModal", 'switchView("admin-plans-create"'),
            ("openEditPlanModal", 'switchView("admin-plan-edit"'),
            ("openAdminDateModal", 'switchView("admin-sub-edit"'),
            ("openAdminRenewModal", 'switchView("admin-sub-extend"'),
            ("openAdminExtendModal", 'switchView("admin-sub-extend"'),
        ]
        for func_name, expected_call in delegations:
            with self.subTest(func_name=func_name):
                pattern = rf'function {func_name}\([^)]*\)\s*\{{[^}}]*{re.escape(expected_call)}'
                self.assertRegex(
                    self.js_content,
                    pattern,
                    f"Function '{func_name}' must delegate to '{expected_call}'",
                )

    def test_deep_linking_and_browser_history_handling(self):
        """switchView and popstate must support deep linking with entity ID query params and back/forward navigation."""
        self.assertIn('urlParams.get("id")', self.js_content)
        self.assertIn('history.pushState({ view: targetView, id: finalId }', self.js_content)
        self.assertIn('switchView(qView, false, qId)', self.js_content)

    # --------------------------------------------------------------------------
    # Part 4: Universal Scrollbar Hiding
    # --------------------------------------------------------------------------
    def test_universal_scrollbar_hiding_rules(self):
        """Universal scrollbar hiding must apply scrollbar-width: none and display: none for WebKit while preserving scroll."""
        self.assertIn("scrollbar-width: none;", self.css_content)
        self.assertIn("-ms-overflow-style: none;", self.css_content)
        self.assertIn("*::-webkit-scrollbar", self.css_content)
        self.assertIn("display: none;", self.css_content)

    # --------------------------------------------------------------------------
    # Part 5: User Profile Dropdown Hover Refinement
    # --------------------------------------------------------------------------
    def test_user_profile_dropdown_hover_styles(self):
        """User profile dropdown hover must be refined in both light and dark modes without black hover glitch."""
        # Dark mode hover
        self.assertIn(".user-dropdown-item:hover", self.css_content)
        self.assertIn("color: var(--scout-lime, #A3E635);", self.css_content)

        # Light mode hover: must not use dark/black backgrounds
        self.assertIn('[data-theme="light"] .user-dropdown-item:hover', self.css_content)
        self.assertIn("background: #F1F5F9;", self.css_content)
        self.assertIn("color: #0F172A;", self.css_content)

    # --------------------------------------------------------------------------
    # Full-Page Management CSS Rules
    # --------------------------------------------------------------------------
    def test_full_page_management_css_rules_exist(self):
        """Dedicated management styling rules must exist in static/style.css."""
        css_selectors = [
            ".full-page-management-view",
            ".management-breadcrumb-bar",
            ".management-header",
            ".management-card",
            ".management-actions-footer",
            ".btn-management-primary",
            ".btn-management-secondary",
            ".btn-management-danger",
            ".management-alert",
        ]
        for sel in css_selectors:
            with self.subTest(sel=sel):
                self.assertIn(
                    sel,
                    self.css_content,
                    f"Selector '{sel}' must exist in static/style.css",
                )


if __name__ == "__main__":
    unittest.main()
