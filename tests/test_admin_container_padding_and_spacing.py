"""
Unit & Integration Test Suite: Comprehensive Container Padding & Spacing (Users & Subscriptions)
Verifies:
1. Main container padding across all target admin panels and full-page management views.
2. Card padding across Users, Plans, Subscriptions, and Requests listings.
3. Form spacing, row gaps, label margins, and no double margins.
4. Details dossier grids, dossier items, and table containers.
5. Confirmation surfaces: confirm-target-box, confirm-consequences-box, and modal dialogs.
6. Responsive breakpoints (Desktop, Tablet <=1024px, Mobile <=768px, Small Mobile <=480px).
7. Theme fidelity (Dark Mode and Light Mode overrides).
8. Template DOM elements and structure across all targeted pages and dialogs.
"""

import os
import re
import unittest

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")
HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")
JS_PATH = os.path.join(WORKSPACE_DIR, "static", "main.js")


class TestAdminContainerPaddingAndSpacing(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            cls.css = f.read()
        with open(HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()
        with open(JS_PATH, "r", encoding="utf-8") as f:
            cls.js = f.read()

    # =========================================================================
    # 1. Main Container Padding (.admin-panel and .full-page-management-view)
    # =========================================================================
    def test_01_main_container_padding_desktop(self):
        """Verify .admin-panel and .full-page-management-view have consistent desktop padding."""
        # .admin-panel desktop padding
        panel_match = re.search(r'\n\.admin-panel\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(panel_match, ".admin-panel CSS rule must exist")
        panel_body = panel_match.group(1)
        self.assertIn("padding: 28px 32px;", panel_body, ".admin-panel must have 28px 32px desktop padding")

        # .full-page-management-view desktop padding
        fp_match = re.search(r'\n\.full-page-management-view\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(fp_match, ".full-page-management-view CSS rule must exist")
        fp_body = fp_match.group(1)
        self.assertIn("padding: 28px 32px 40px 32px;", fp_body, ".full-page-management-view must have 28px 32px 40px 32px padding")

    def test_02_main_container_padding_responsive(self):
        """Verify .admin-panel and .full-page-management-view scale responsively at 1024px and 768px."""
        # Find all 1024px media query blocks and verify the one with management views
        blocks_1024 = re.findall(r'@media\s*\(\s*max-width:\s*1024px\s*\)\s*\{([\s\S]*?)\n\}', self.css)
        matched_1024 = False
        for b in blocks_1024:
            if ".full-page-management-view" in b and ".admin-panel" in b:
                matched_1024 = True
                self.assertIn("padding: 24px 24px;", b)
                self.assertIn("padding: 24px 24px 36px 24px;", b)
        self.assertTrue(matched_1024, "Responsive 1024px block for management views must exist")

        # Find all 768px media query blocks and verify the one with management views
        blocks_768 = re.findall(r'@media\s*\(\s*max-width:\s*768px\s*\)\s*\{([\s\S]*?)\n\}', self.css)
        matched_768 = False
        for b in blocks_768:
            if ".full-page-management-view" in b and ".admin-panel" in b:
                matched_768 = True
                self.assertIn("padding: 18px 16px;", b)
                self.assertIn("padding: 18px 16px 32px 16px;", b)
        self.assertTrue(matched_768, "Responsive 768px block for management views must exist")

    # =========================================================================
    # 2. Listing Cards & Grids (.admin-*-card)
    # =========================================================================
    def test_03_card_padding_standards(self):
        """Verify .admin-user-card, .admin-plan-card, .admin-sub-card, .admin-request-card have 20px padding."""
        card_classes = ["admin-user-card", "admin-plan-card", "admin-sub-card", "admin-request-card"]
        for cls_name in card_classes:
            m = re.search(rf'\n\.{cls_name}\s*\{{([^}}]+)\}}', self.css)
            self.assertIsNotNone(m, f".{cls_name} rule must exist")
            rule_body = m.group(1)
            self.assertIn("padding: 20px 20px;", rule_body, f".{cls_name} must have padding: 20px 20px")
            self.assertIn("border-radius: 12px;", rule_body, f".{cls_name} must have border-radius: 12px")

    def test_04_card_internal_spacing(self):
        """Verify card header margins, user subscription box padding, and action area margins."""
        # Header bottom margin
        for hdr in ["user-card-header", "plan-card-header", "request-card-header", "sub-card-header"]:
            m = re.search(rf'\n\.{hdr}\s*\{{([^}}]+)\}}', self.css)
            self.assertIsNotNone(m, f".{hdr} rule must exist")
            self.assertIn("margin-bottom: 12px;", m.group(1), f".{hdr} must have margin-bottom: 12px")

        # User card subscription box
        sub_box_m = re.search(r'\n\.user-card-sub-box\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(sub_box_m, ".user-card-sub-box must exist")
        self.assertIn("padding: 10px 12px;", sub_box_m.group(1), "Sub box must have 10px 12px padding")

        # User card actions
        actions_m = re.search(r'\n\.user-card-actions\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(actions_m, ".user-card-actions must exist")
        self.assertIn("margin-top: 12px;", actions_m.group(1))
        self.assertIn("padding-top: 12px;", actions_m.group(1))

        # Button action padding
        btn_action_m = re.search(r'\n\.btn-card-action\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(btn_action_m, ".btn-card-action must exist")
        self.assertIn("padding: 6px 10px;", btn_action_m.group(1))

    def test_05_card_grid_gaps_and_loading_states(self):
        """Verify card grids have 18px desktop gap and .admin-cards-loading state is styled."""
        for grid in ["admin-users-cards-grid", "admin-plans-cards-grid", "admin-subs-cards-grid", "admin-requests-cards-grid"]:
            m = re.search(rf'\n\.{grid}\s*\{{([^}}]+)\}}', self.css)
            self.assertIsNotNone(m, f".{grid} rule must exist")
            self.assertIn("gap: 18px;", m.group(1), f".{grid} must have gap: 18px")

        # Loading state
        loading_m = re.search(r'\n\.admin-cards-loading\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(loading_m, ".admin-cards-loading must exist")
        self.assertIn("padding: 40px 20px;", loading_m.group(1))
        self.assertIn("border-radius: 12px;", loading_m.group(1))

    # =========================================================================
    # 3. Form Spacing & Elimination of Double Margins
    # =========================================================================
    def test_06_form_spacing_and_no_double_margin(self):
        """Verify .management-form-row, .management-form-group, and no double margins."""
        # Check .management-form-row
        row_m = re.search(r'\n\.management-form-row\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(row_m, ".management-form-row must exist")
        self.assertIn("gap: 20px;", row_m.group(1), ".management-form-row must have gap: 20px")
        self.assertIn("margin-bottom: 18px;", row_m.group(1), ".management-form-row must have margin-bottom: 18px")

        # Check .management-form-row .management-form-group
        child_m = re.search(r'\.management-form-row\s+\.management-form-group\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(child_m, ".management-form-row .management-form-group must exist to avoid double margins")
        self.assertIn("margin-bottom: 0;", child_m.group(1))

        # Check standalone .management-form-group
        group_m = re.search(r'\n\.management-form-group\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(group_m, ".management-form-group must exist")
        self.assertIn("margin-bottom: 18px;", group_m.group(1))

        # Check inputs and textareas
        input_m = re.search(r'\.management-input,\s*\.management-select\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(input_m, ".management-input, .management-select must exist")
        self.assertIn("padding: 11px 14px;", input_m.group(1))

        textarea_m = re.search(r'\n\.management-textarea\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(textarea_m, ".management-textarea must exist")
        self.assertIn("padding: 12px 14px;", textarea_m.group(1))
        self.assertIn("min-height: 95px;", textarea_m.group(1))

    # =========================================================================
    # 4. Details Pages, Dossier Telemetry & Table Containers
    # =========================================================================
    def test_07_dossier_telemetry_and_table_containers(self):
        """Verify .management-dossier-grid, .management-dossier-item, and .admin-table-container."""
        # Dossier grid
        dossier_grid_m = re.search(r'\n\.management-dossier-grid\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(dossier_grid_m, ".management-dossier-grid must exist")
        self.assertIn("gap: 14px;", dossier_grid_m.group(1))
        self.assertIn("margin-bottom: 20px;", dossier_grid_m.group(1))

        # Dossier item
        dossier_item_m = re.search(r'\n\.management-dossier-item\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(dossier_item_m, ".management-dossier-item must exist")
        self.assertIn("padding: 14px 16px;", dossier_item_m.group(1))
        self.assertIn("border-radius: 10px;", dossier_item_m.group(1))

        # Table container
        table_container_m = re.search(r'\n\.admin-table-container\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(table_container_m, ".admin-table-container must exist")
        self.assertIn("overflow-x: auto;", table_container_m.group(1))
        self.assertIn("border-radius: 10px;", table_container_m.group(1))
        self.assertIn("margin-top: 16px;", table_container_m.group(1))

        # Table cell padding
        table_th_m = re.search(r'\.admin-table\s+th\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(table_th_m)
        self.assertIn("padding: 13px 16px;", table_th_m.group(1))

        table_td_m = re.search(r'\.admin-table\s+td\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(table_td_m)
        self.assertIn("padding: 13px 16px;", table_td_m.group(1))

    # =========================================================================
    # 5. Confirmation Surfaces & Dialog Modals
    # =========================================================================
    def test_08_confirmation_boxes_and_modal_dialogs(self):
        """Verify .confirm-target-box, .confirm-consequences-box, and modal dialog padding."""
        target_m = re.search(r'\n\.confirm-target-box\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(target_m, ".confirm-target-box must exist")
        self.assertIn("padding: 16px 18px;", target_m.group(1))
        self.assertIn("margin-bottom: 16px;", target_m.group(1))

        conseq_m = re.search(r'\n\.confirm-consequences-box\s*\{([^}]+)\}', self.css)
        self.assertIsNotNone(conseq_m, ".confirm-consequences-box must exist")
        self.assertIn("padding: 16px 18px;", conseq_m.group(1))
        self.assertIn("margin-bottom: 18px;", conseq_m.group(1))

        # Check responsive modal rules at 768px and 480px
        blocks_768 = re.findall(r'@media\s*\(\s*max-width:\s*768px\s*\)\s*\{([\s\S]*?)\n\}', self.css)
        matched_modal_768 = any(".auth-modal-dialog" in b and "padding: 20px;" in b for b in blocks_768)
        self.assertTrue(matched_modal_768, "768px media query must include .auth-modal-dialog padding: 20px")

        blocks_480 = re.findall(r'@media\s*\(\s*max-width:\s*480px\s*\)\s*\{([\s\S]*?)\n\}', self.css)
        matched_modal_480 = any(".auth-modal-dialog" in b and "padding: 16px;" in b for b in blocks_480)
        self.assertTrue(matched_modal_480, "480px media query must include .auth-modal-dialog padding: 16px")

    # =========================================================================
    # 6. Light Mode Fidelity
    # =========================================================================
    def test_09_light_mode_theme_overrides(self):
        """Verify light mode styling for cards, dossier items, loading states, and table containers."""
        self.assertIn('[data-theme="light"] .admin-panel', self.css)
        self.assertIn('[data-theme="light"] .management-card', self.css)
        self.assertIn('[data-theme="light"] .admin-table-container', self.css)
        self.assertIn('[data-theme="light"] .admin-cards-loading', self.css)
        self.assertIn('[data-theme="light"] .confirm-target-box', self.css)
        self.assertIn('[data-theme="light"] .confirm-consequences-box', self.css)
        self.assertIn('[data-theme="light"] .management-dossier-item', self.css)

    # =========================================================================
    # 7. Complete HTML DOM Target Inspection
    # =========================================================================
    def test_10_html_template_all_target_containers_exist(self):
        """Verify that all target pages, full-page management views, and modals exist in ddos.html."""
        target_ids = [
            # Listing panels
            "adminPanelUsers",
            "adminPanelPlans",
            "adminPanelSubscriptions",
            "adminPanelRequests",
            # Full page views
            "adminPageUserDetails",
            "adminPageUserCreate",
            "adminPageUserEdit",
            "adminPagePlanCreate",
            "adminPagePlanDetails",
            "adminPagePlanEdit",
            "adminPageSubDetails",
            "adminPageSubEdit",
            "adminPageSubExtend",
            "adminPageRequestDetails",
            # Modals & Dialogs
            "adminConfirmActionModal",
            "adminConfirmTargetBox",
            "adminConfirmConsequencesBox",
            "adminCreateUserModal",
            "adminUserDetailsModal",
            "adminPlanModal",
            "adminPlanDetailsModal",
            "adminSubDetailsModal",
            "adminDateModal",
            "adminRenewSubModal",
            "adminExtendSubModal"
        ]
        for tid in target_ids:
            self.assertTrue(
                f'id="{tid}"' in self.html or f"id='{tid}'" in self.html,
                f"Container #{tid} must exist in templates/ddos.html"
            )


if __name__ == "__main__":
    unittest.main()
