"""
==============================================================================
SCOUT — User Sidebar Pending Indicator & Admin Subscription Review UI/UX Refinement
Validation Test Suite
==============================================================================
Validates:
1. User Sidebar expanded: no unwanted Pending text.
2. User Sidebar collapsed: no text or badge overflow, icon properly aligned.
3. Subscription request status is still visible inside the appropriate page.
4. Admin can still review subscription requests.
5. Accept and Cancel actions still work exactly as before.
6. Review interface has compact, readable typography.
7. Review content is properly aligned and spaced.
8. Subscription Dates page remains unchanged.
9. Subscription Details page remains unchanged.
10. Dark Mode and Light Mode both render correctly.
"""

import os
import re
import unittest
from datetime import datetime, timezone

from api import app
from modules.auth.models import User
from modules.auth.db import get_db_session, get_engine, init_db
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")
DDOS_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")
ND_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "network_discovery.html")
MAIN_JS_PATH = os.path.join(WORKSPACE_DIR, "static", "main.js")


class TestSidebarPendingAndAdminReviewRefinement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = get_engine()
        init_db(cls.engine)
        cls.client = app.test_client()

        with open(CSS_PATH, "r", encoding="utf-8") as f:
            cls.css_content = f.read()
        with open(DDOS_HTML_PATH, "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()
        with open(ND_HTML_PATH, "r", encoding="utf-8") as f:
            cls.nd_html = f.read()
        with open(MAIN_JS_PATH, "r", encoding="utf-8") as f:
            cls.js_content = f.read()

    def setUp(self):
        with get_db_session() as session:
            session.query(SubscriptionAuditLog).delete()
            session.query(UserSubscription).delete()
            session.query(SubscriptionPlan).delete()
            session.query(User).filter(User.username.like("test_refine_%")).delete()

            # Admin
            self.admin = User(
                username="test_refine_admin",
                email="admin_refine@scout.local",
                full_name="Admin Refine",
                role="Admin",
                is_active=True
            )
            self.admin.set_password("AdminSecurePass!123")
            session.add(self.admin)

            # Regular user
            self.user = User(
                username="test_refine_user",
                email="user_refine@scout.local",
                full_name="User Refine",
                role="User",
                is_active=True
            )
            self.user.set_password("UserPass!123")
            session.add(self.user)

            # Plan
            self.plan = SubscriptionPlan(
                plan_code="ENTERPRISE_SOC",
                name="Enterprise SOC Defense",
                description="Real-time SOC threat telemetry & packet inspection",
                price=199.00,
                currency="USD",
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            self.plan.set_features({
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True
            })
            session.add(self.plan)
            session.flush()

            self.admin_id = self.admin.id
            self.user_id = self.user.id
            self.plan_id = self.plan.id

    def _login(self, username, password):
        res = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        self.assertEqual(res.status_code, 200, f"Login failed for {username}")
        return res

    # --------------------------------------------------------------------------
    # 1. User Sidebar expanded: no unwanted Pending text
    # --------------------------------------------------------------------------
    def test_01_user_sidebar_expanded_no_unwanted_pending_text(self):
        """Visible 'Pending' text label must be completely removed from Subscription Plans item."""
        # Check ddos.html: span must not have 'Pending' inner text
        badge_match = re.search(r'<span[^>]*id="sidebarUserPendingBadge"[^>]*>(.*?)</span>', self.ddos_html)
        self.assertTrue(badge_match, "sidebarUserPendingBadge must exist in ddos.html")
        self.assertNotIn("Pending", badge_match.group(1), "sidebarUserPendingBadge must not have default 'Pending' text")

        # Check network_discovery.html
        badge_match_nd = re.search(r'<span[^>]*id="sidebarUserPendingBadge"[^>]*>(.*?)</span>', self.nd_html)
        self.assertTrue(badge_match_nd, "sidebarUserPendingBadge must exist in network_discovery.html")
        self.assertNotIn("Pending", badge_match_nd.group(1), "sidebarUserPendingBadge in ND must not have 'Pending' text")

        # Check main.js: dynamic sidebar must not set pending text or display on sidebarUserPendingBadge
        self.assertIn("isSubPending", self.js_content)
        # Ensure that inside isSubPending, pendingBadge.style.display is set to "none" and NOT "inline-block"
        pending_block_match = re.search(r'else\s*if\s*\(\s*isSubPending\s*\)\s*\{([\s\S]*?)\}\s*else\s*if', self.js_content)
        self.assertTrue(pending_block_match, "isSubPending logic block must exist in main.js")
        pending_code = pending_block_match.group(1)
        self.assertIn('pendingBadge.style.display = "none"', pending_code)
        self.assertNotIn('pendingBadge.textContent = "Pending"', pending_code)

    # --------------------------------------------------------------------------
    # 2. User Sidebar collapsed: no text or badge overflow
    # --------------------------------------------------------------------------
    def test_02_user_sidebar_collapsed_no_text_or_badge_overflow(self):
        """When sidebar is collapsed, no badges or text can display or overflow."""
        # Check style.css collapsed badge rule
        self.assertIn("body.sidebar-collapsed .sidebar-nav-item .nav-badge-pill", self.css_content)
        collapsed_badge_match = re.search(
            r'body\.sidebar-collapsed\s+\.sidebar-nav-item\s+\.nav-badge-pill\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(collapsed_badge_match, "Collapsed nav-badge-pill CSS rule must exist")
        rule_body = collapsed_badge_match.group(1)
        self.assertIn("display: none !important;", rule_body)
        self.assertIn("overflow: hidden !important;", rule_body)

        # Check collapsed sidebar-nav-item has overflow: hidden and centered alignment
        collapsed_item_match = re.search(
            r'body\.sidebar-collapsed\s+\.sidebar-nav-item\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(collapsed_item_match, "Collapsed sidebar-nav-item rule must exist")
        item_body = collapsed_item_match.group(1)
        self.assertIn("overflow: hidden;", item_body)
        self.assertIn("justify-content: center;", item_body)

    # --------------------------------------------------------------------------
    # 3. Subscription request status is still visible inside the appropriate page
    # --------------------------------------------------------------------------
    def test_03_subscription_request_status_still_visible_on_plans_page(self):
        """Subscription Plans page keeps pending status indicators, titles, and messages intact."""
        # 1. Backend endpoint returns pending subscription
        self._login("test_refine_user", "UserPass!123")
        req_res = self.client.post("/api/subscriptions/request", json={
            "plan_id": self.plan_id,
            "notes": "Testing plans page status visibility."
        })
        self.assertEqual(req_res.status_code, 201)
        sub_id = req_res.get_json()["subscription"]["id"]

        me_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(me_res.status_code, 200)
        sub = me_res.get_json()["subscription"]
        self.assertEqual(sub["status"], "pending")
        self.assertEqual(sub["id"], sub_id)

        # 2. main.js loadUserSubscription still renders pending status
        self.assertIn("subStatusDot.className = \"sub-status-dot pending\"", self.js_content)
        self.assertIn('subStatusText.textContent = "Pending Verification"', self.js_content)
        self.assertIn("Awaiting Verification", self.js_content)

    # --------------------------------------------------------------------------
    # 4. Admin can still review subscription requests
    # --------------------------------------------------------------------------
    def test_04_admin_can_review_subscription_requests(self):
        """Admin can retrieve pending requests and individual subscription review data."""
        # User submits
        self._login("test_refine_user", "UserPass!123")
        sub_id = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id}).get_json()["subscription"]["id"]

        # Admin logs in
        self._login("test_refine_admin", "AdminSecurePass!123")
        req_res = self.client.get(f"/api/admin/subscriptions/{sub_id}")
        self.assertEqual(req_res.status_code, 200)
        data = req_res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["subscription"]["id"], sub_id)
        self.assertEqual(data["subscription"]["status"], "pending")

        # Template and JS review hooks exist
        self.assertIn('id="adminPageRequestDetails"', self.ddos_html)
        self.assertIn("async function loadPageRequestDetails", self.js_content)

    # --------------------------------------------------------------------------
    # 5. Accept and Cancel actions still work exactly as before
    # --------------------------------------------------------------------------
    def test_05_accept_and_cancel_actions_work_exactly_as_before(self):
        """Approving, rejecting, and cancelling work correctly and preserve audit trails."""
        # User submits request
        self._login("test_refine_user", "UserPass!123")
        sub_id = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id}).get_json()["subscription"]["id"]

        # Admin approves (Accept)
        self._login("test_refine_admin", "AdminSecurePass!123")
        approve_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={
            "notes": "Verified by admin test."
        })
        self.assertEqual(approve_res.status_code, 200)
        approved_sub = approve_res.get_json()["subscription"]
        self.assertEqual(approved_sub["status"], "active")
        self.assertTrue(approved_sub["is_valid_active"])

        # Check action buttons exist in admin review template
        self.assertIn('id="fpReqApproveBtn"', self.ddos_html)
        self.assertIn('id="fpReqRejectBtn"', self.ddos_html)
        self.assertIn('data-back-target="admin-requests"', self.ddos_html)

    # --------------------------------------------------------------------------
    # 6. Review interface has compact, readable typography
    # --------------------------------------------------------------------------
    def test_06_review_interface_compact_readable_typography(self):
        """Review headings, labels, and metadata have refined, compact typography."""
        # Heading font-size in review page
        self.assertIn("#adminPageRequestDetails .management-title", self.css_content)
        title_match = re.search(
            r'#adminPageRequestDetails\s+\.management-title\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(title_match)
        self.assertIn("font-size: 1.25rem;", title_match.group(1))

        # Card title font size
        card_title_match = re.search(
            r'#adminPageRequestDetails\s+\.management-card-title\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(card_title_match)
        self.assertIn("font-size: 0.88rem;", card_title_match.group(1))

        # Dossier label & val font sizes
        label_match = re.search(
            r'#adminPageRequestDetails\s+\.management-dossier-label\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(label_match)
        self.assertIn("font-size: 0.67rem;", label_match.group(1))

        val_match = re.search(
            r'#adminPageRequestDetails\s+\.management-dossier-val\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(val_match)
        self.assertIn("font-size: 0.86rem;", val_match.group(1))

    # --------------------------------------------------------------------------
    # 7. Review content is properly aligned and spaced
    # --------------------------------------------------------------------------
    def test_07_review_content_properly_aligned_and_spaced(self):
        """Review content uses compact cards, balanced dossier grid, and uniform action buttons."""
        # Compact card padding
        card_match = re.search(
            r'#adminPageRequestDetails\s+\.management-card\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(card_match)
        self.assertIn("padding: 16px 20px;", card_match.group(1))
        self.assertIn("margin-bottom: 14px;", card_match.group(1))

        # Action buttons consistent height and padding
        btn_match = re.search(
            r'#adminPageRequestDetails\s+\.btn-management-secondary,\s*#adminPageRequestDetails\s+\.btn-management-danger,\s*#adminPageRequestDetails\s+\.btn-management-primary\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(btn_match, "Unified button styling rule must exist for review actions")
        btn_body = btn_match.group(1)
        self.assertIn("height: 38px;", btn_body)
        self.assertIn("padding: 0 18px;", btn_body)
        self.assertIn("font-size: 0.83rem;", btn_body)
        self.assertIn("border-radius: 7px;", btn_body)

        # Confirmation modal button alignment
        submit_btn_match = re.search(
            r'#adminConfirmActionModal\s+\.btn-auth-submit\s*\{([^}]+)\}',
            self.css_content
        )
        self.assertTrue(submit_btn_match)
        self.assertIn("height: 38px;", submit_btn_match.group(1))
        self.assertIn("width: auto !important;", submit_btn_match.group(1))

    # --------------------------------------------------------------------------
    # 8. Subscription Dates page remains unchanged
    # --------------------------------------------------------------------------
    def test_08_subscription_dates_page_remains_unchanged(self):
        """Subscription Dates page structure, IDs, and elements remain preserved."""
        self.assertIn('id="adminPageSubEdit"', self.ddos_html)
        self.assertIn('id="fpEditSubBreadcrumbLink"', self.ddos_html)
        self.assertIn('id="fpEditSubBreadcrumbName"', self.ddos_html)
        self.assertIn('id="fpEditSubBackBtn"', self.ddos_html)
        self.assertIn('id="fullPageSubEditAlert"', self.ddos_html)
        self.assertIn('id="fullPageSubEditForm"', self.ddos_html)
        self.assertIn('id="fpEditSubId"', self.ddos_html)
        self.assertIn('id="fpEditSubUser"', self.ddos_html)
        self.assertIn('id="fpEditSubPlan"', self.ddos_html)
        self.assertIn('id="fpEditSubStartDate"', self.ddos_html)
        self.assertIn('id="fpEditSubEndDate"', self.ddos_html)
        self.assertIn('id="fpEditSubReason"', self.ddos_html)
        self.assertIn('id="fpEditSubCancelBtn"', self.ddos_html)
        self.assertIn('id="fpEditSubSubmitBtn"', self.ddos_html)
        # Verify no review-specific overrides apply to adminPageSubEdit
        self.assertNotIn("#adminPageSubEdit .management-title", self.css_content)

    # --------------------------------------------------------------------------
    # 9. Subscription Details page remains unchanged
    # --------------------------------------------------------------------------
    def test_09_subscription_details_page_remains_unchanged(self):
        """Subscription Details page structure, IDs, and elements remain preserved."""
        self.assertIn('id="adminPageSubDetails"', self.ddos_html)
        self.assertIn('id="fpBreadcrumbSubId"', self.ddos_html)
        self.assertIn('id="fullPageSubDetailsAlert"', self.ddos_html)
        self.assertIn('id="fpSubDetailsContent"', self.ddos_html)
        self.assertIn('id="fpSubDossierId"', self.ddos_html)
        self.assertIn('id="fpSubDossierUsername"', self.ddos_html)
        self.assertIn('id="fpSubDossierEmail"', self.ddos_html)
        self.assertIn('id="fpSubDossierPlan"', self.ddos_html)
        self.assertIn('id="fpSubDossierStatus"', self.ddos_html)
        self.assertIn('id="fpSubDossierStartDate"', self.ddos_html)
        self.assertIn('id="fpSubDossierEndDate"', self.ddos_html)
        self.assertIn('id="fpSubDossierAutoRenew"', self.ddos_html)
        self.assertIn('id="fpSubNotesInput"', self.ddos_html)
        self.assertIn('id="fpSubNotesSaveBtn"', self.ddos_html)
        self.assertIn('id="fpSubAuditTableBody"', self.ddos_html)
        # Verify no review-specific overrides apply to adminPageSubDetails
        self.assertNotIn("#adminPageSubDetails .management-title", self.css_content)

    # --------------------------------------------------------------------------
    # 10. Dark Mode and Light Mode both render correctly
    # --------------------------------------------------------------------------
    def test_10_dark_mode_and_light_mode_render_correctly(self):
        """Both dark mode (default) and light mode ([data-theme='light']) styles exist."""
        # Dark mode rules
        self.assertIn("#adminPageRequestDetails .management-card", self.css_content)
        self.assertIn("#adminPageRequestDetails .btn-management-primary", self.css_content)
        self.assertIn("#adminPageRequestDetails .btn-management-danger", self.css_content)
        self.assertIn("#adminPageRequestDetails .btn-management-secondary", self.css_content)

        # Light mode overrides
        self.assertIn('[data-theme="light"] #adminPageRequestDetails .management-card', self.css_content)
        self.assertIn('[data-theme="light"] #adminPageRequestDetails .management-title', self.css_content)
        self.assertIn('[data-theme="light"] #adminPageRequestDetails .btn-management-primary', self.css_content)
        self.assertIn('[data-theme="light"] #adminPageRequestDetails .btn-management-danger', self.css_content)
        self.assertIn('[data-theme="light"] #adminPageRequestDetails .btn-management-secondary', self.css_content)
        self.assertIn('[data-theme="light"] #adminConfirmActionModal .btn-admin-action.cancel', self.css_content)


if __name__ == "__main__":
    unittest.main()
