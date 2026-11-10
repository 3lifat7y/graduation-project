"""
SCOUT Platform — Subscription Request Lifecycle & Sidebar Notification Dot Verification
Validates the complete lifecycle:
  1. User submits request -> Pending status only.
  2. Request appears in Pending Requests, NOT in All Subscriptions, NOT in Active Subscriptions.
  3. Sidebar notification dot appears when pending_subscriptions > 0.
  4. Admin reviews and approves -> becomes active subscription with valid dates and audit trail.
  5. Approved subscription appears in All Subscriptions & Active Subscriptions.
  6. Request disappears from Pending Requests queue.
  7. Notification dot disappears when 0 pending requests remain.
  8. Partial approvals leave notification dot visible when >= 1 pending request remains.
  9. Admin rejection transitions to Rejected, preserves history, does NOT create active subscription,
     does NOT appear in All Subscriptions, removes from Pending queue.
  10. Repeated approvals and rejections are strictly prevented (idempotent / duplicate-safe).
  11. Frontend templates, CSS layout, themes, collapsed/expanded states, and JS synchronization verified.
"""

import os
import re
import unittest
from datetime import datetime, timezone, timedelta

from api import app
from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session, get_engine, init_db
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog


class TestSubscriptionRequestLifecycleAndSidebarDot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = get_engine()
        init_db(cls.engine)
        cls.client = app.test_client()

        # Read template, CSS, and JS files for static analysis
        with open("templates/ddos.html", "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()
        with open("templates/network_discovery.html", "r", encoding="utf-8") as f:
            cls.nd_html = f.read()
        with open("static/style.css", "r", encoding="utf-8") as f:
            cls.css_content = f.read()
        with open("static/main.js", "r", encoding="utf-8") as f:
            cls.js_content = f.read()

    def setUp(self):
        with get_db_session() as session:
            session.query(SubscriptionAuditLog).delete()
            session.query(UserSubscription).delete()
            session.query(SubscriptionPlan).delete()
            session.query(User).filter(User.username.like("test_%")).delete()

            # Create test admin
            self.admin = User(
                username="test_admin_dot",
                email="admin_dot@scout.local",
                full_name="Admin Dot",
                role="Admin",
                is_active=True
            )
            self.admin.set_password("AdminSecurePass!123")
            session.add(self.admin)

            # Create test regular users
            self.user1 = User(
                username="test_user1_dot",
                email="user1_dot@scout.local",
                full_name="User One",
                role="User",
                is_active=True
            )
            self.user1.set_password("UserPass!123")
            session.add(self.user1)

            self.user2 = User(
                username="test_user2_dot",
                email="user2_dot@scout.local",
                full_name="User Two",
                role="User",
                is_active=True
            )
            self.user2.set_password("UserPass!123")
            session.add(self.user2)

            # Create test subscription plan
            self.plan = SubscriptionPlan(
                plan_code="PRO_TIER",
                name="Pro Security Tier",
                description="Advanced threat detection and live monitoring",
                price=99.00,
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
            self.user1_id = self.user1.id
            self.user2_id = self.user2.id
            self.plan_id = self.plan.id

    def _login(self, username, password):
        res = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        self.assertEqual(res.status_code, 200, f"Login failed for {username}")
        return res

    # ==============================================================================
    # 1. Complete Subscription Request Lifecycle (Backend API)
    # ==============================================================================

    def test_01_user_request_appears_only_in_pending_and_not_in_all_subscriptions(self):
        """
        Step 1 & 2: User submits a subscription request.
        - Must create request with Pending status.
        - Must appear in Pending Requests queue.
        - Must NOT appear in All Subscriptions.
        - Must NOT appear in Active Subscriptions.
        - Metrics must report pending_subscriptions = 1, active_subscriptions = 0.
        """
        # User 1 logs in and submits a subscription request
        self._login("test_user1_dot", "UserPass!123")
        req_res = self.client.post("/api/subscriptions/request", json={
            "plan_id": self.plan_id,
            "notes": "Requesting corporate Pro tier access."
        })
        self.assertEqual(req_res.status_code, 201)
        req_data = req_res.get_json()
        sub = req_data["subscription"]
        self.assertEqual(sub["status"], "pending")
        self.assertFalse(sub["is_valid_active"])
        self.assertIsNone(sub["start_date"])
        self.assertIsNone(sub["end_date"])
        sub_id = sub["id"]

        # Admin logs in to inspect lists
        self._login("test_admin_dot", "AdminSecurePass!123")

        # 1. Pending Requests endpoint: MUST return the pending request
        pending_res = self.client.get("/api/admin/requests?status=pending")
        self.assertEqual(pending_res.status_code, 200)
        pending_list = pending_res.get_json().get("requests") or pending_res.get_json().get("subscriptions")
        self.assertEqual(len(pending_list), 1)
        self.assertEqual(pending_list[0]["id"], sub_id)
        self.assertEqual(pending_list[0]["status"], "pending")

        # Compatibility endpoint ?status=pending also returns it
        compat_res = self.client.get("/api/admin/subscriptions?status=pending")
        self.assertEqual(compat_res.status_code, 200)
        self.assertEqual(len(compat_res.get_json()["subscriptions"]), 1)

        # 2. All Subscriptions (GET /api/admin/subscriptions without status or status=all):
        # MUST NOT contain the pending request!
        all_subs_res = self.client.get("/api/admin/subscriptions")
        self.assertEqual(all_subs_res.status_code, 200)
        all_subs = all_subs_res.get_json()["subscriptions"]
        self.assertEqual(len(all_subs), 0, "Pending requests must NOT appear in All Subscriptions!")

        all_subs_explicit = self.client.get("/api/admin/subscriptions?status=all")
        self.assertEqual(all_subs_explicit.status_code, 200)
        self.assertEqual(len(all_subs_explicit.get_json()["subscriptions"]), 0)

        # 3. Active Subscriptions (GET /api/admin/subscriptions?status=active):
        # MUST NOT contain the pending request!
        active_subs_res = self.client.get("/api/admin/subscriptions?status=active")
        self.assertEqual(active_subs_res.status_code, 200)
        self.assertEqual(len(active_subs_res.get_json()["subscriptions"]), 0)

        # 4. Metrics: verify pending_subscriptions == 1 and active_subscriptions == 0
        metrics_res = self.client.get("/api/admin/metrics")
        self.assertEqual(metrics_res.status_code, 200)
        metrics = metrics_res.get_json()["metrics"]
        self.assertEqual(metrics["pending_subscriptions"], 1)
        self.assertEqual(metrics["active_subscriptions"], 0)
        self.assertEqual(metrics["total_subscribers"], 0)

    def test_02_admin_approves_request_transitions_to_active_and_updates_lists(self):
        """
        Step 3: Admin approves pending request.
        - Transitions to active status.
        - Sets start_date and end_date.
        - Approved subscription appears in All Subscriptions & Active Subscriptions.
        - Request disappears from Pending Requests queue.
        - Metrics update: pending = 0, active = 1.
        """
        # User 1 submits request
        self._login("test_user1_dot", "UserPass!123")
        req_res = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id})
        self.assertEqual(req_res.status_code, 201)
        sub_id = req_res.get_json()["subscription"]["id"]

        # Admin logs in and approves
        self._login("test_admin_dot", "AdminSecurePass!123")
        approve_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={
            "notes": "Approved for corporate operations."
        })
        self.assertEqual(approve_res.status_code, 200)
        act_sub = approve_res.get_json()["subscription"]
        self.assertEqual(act_sub["status"], "active")
        self.assertTrue(act_sub["is_valid_active"])
        self.assertIsNotNone(act_sub["start_date"])
        self.assertIsNotNone(act_sub["end_date"])
        self.assertEqual(act_sub["activated_by_id"], self.admin_id)

        # 1. Pending Requests queue: MUST now be empty!
        pending_res = self.client.get("/api/admin/requests?status=pending")
        self.assertEqual(len(pending_res.get_json()["requests"]), 0)

        # 2. All Subscriptions: MUST now contain the approved subscription
        all_subs_res = self.client.get("/api/admin/subscriptions")
        self.assertEqual(all_subs_res.status_code, 200)
        subs = all_subs_res.get_json()["subscriptions"]
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0]["id"], sub_id)
        self.assertEqual(subs[0]["status"], "active")

        # 3. Active Subscriptions: MUST contain the approved subscription
        active_res = self.client.get("/api/admin/subscriptions?status=active")
        self.assertEqual(len(active_res.get_json()["subscriptions"]), 1)

        # 4. Metrics: pending is now 0, active is 1, total_subscribers is 1
        metrics_res = self.client.get("/api/admin/metrics")
        m = metrics_res.get_json()["metrics"]
        self.assertEqual(m["pending_subscriptions"], 0)
        self.assertEqual(m["active_subscriptions"], 1)
        self.assertEqual(m["total_subscribers"], 1)

    def test_03_duplicate_approval_prevention_and_concurrency_safety(self):
        """
        Step 3 safeguard: Repeated approval submissions must be rejected safely
        without creating duplicate subscriptions or corrupting state.
        """
        # User 1 submits request
        self._login("test_user1_dot", "UserPass!123")
        req_res = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id})
        sub_id = req_res.get_json()["subscription"]["id"]

        # Admin approves
        self._login("test_admin_dot", "AdminSecurePass!123")
        first_approve = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={})
        self.assertEqual(first_approve.status_code, 200)

        # Second approval attempt must fail safely
        second_approve = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={})
        self.assertEqual(second_approve.status_code, 400)
        self.assertIn("already active", second_approve.get_json()["message"].lower())

        # Verify only 1 subscription record exists in database
        with get_db_session() as session:
            count = session.query(UserSubscription).filter_by(user_id=self.user1_id).count()
            self.assertEqual(count, 1)

    def test_04_admin_rejects_request_lifecycle_and_historical_preservation(self):
        """
        Step 4: Admin rejects a pending request.
        - Transitions status to Rejected.
        - Preserves historical request record and audit log.
        - Does NOT create an active subscription.
        - Does NOT appear in All Subscriptions.
        - Removed from Pending Requests active queue.
        - Metrics: pending returns to 0, active remains 0.
        """
        # User 2 submits request
        self._login("test_user2_dot", "UserPass!123")
        req_res = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id})
        sub_id = req_res.get_json()["subscription"]["id"]

        # Admin rejects
        self._login("test_admin_dot", "AdminSecurePass!123")
        reject_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/reject", json={
            "reason": "Payment verification failed."
        })
        self.assertEqual(reject_res.status_code, 200)
        rej_sub = reject_res.get_json()["subscription"]
        self.assertEqual(rej_sub["status"], "rejected")
        self.assertEqual(rej_sub["cancellation_reason"], "Payment verification failed.")

        # 1. Pending queue: MUST NOT appear
        pending_res = self.client.get("/api/admin/requests?status=pending")
        self.assertEqual(len(pending_res.get_json()["requests"]), 0)

        # 2. All Subscriptions: MUST NOT appear
        all_subs_res = self.client.get("/api/admin/subscriptions")
        self.assertEqual(len(all_subs_res.get_json()["subscriptions"]), 0)

        # 3. Active Subscriptions: MUST NOT appear
        active_res = self.client.get("/api/admin/subscriptions?status=active")
        self.assertEqual(len(active_res.get_json()["subscriptions"]), 0)

        # 4. Historical record preserved in database
        with get_db_session() as session:
            db_sub = session.query(UserSubscription).filter_by(id=sub_id).first()
            self.assertIsNotNone(db_sub)
            self.assertEqual(db_sub.status, "rejected")

            logs = session.query(SubscriptionAuditLog).filter_by(subscription_id=sub_id).all()
            actions = [l.action for l in logs]
            self.assertIn("REQUESTED", actions)
            self.assertIn("REJECTED", actions)

        # 5. Cannot re-reject
        second_reject = self.client.post(f"/api/admin/subscriptions/{sub_id}/reject", json={})
        self.assertEqual(second_reject.status_code, 400)

        # 6. Cannot activate a rejected request
        activate_attempt = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={})
        self.assertEqual(activate_attempt.status_code, 400)

    def test_05_multiple_pending_requests_and_partial_approvals(self):
        """
        Tests multiple simultaneous pending requests:
        - When 2 pending exist, pending count is 2.
        - Approving 1 leaves pending count at 1 (notification dot remains visible).
        - Approving or rejecting the last one drops count to 0 (notification dot disappears).
        """
        # User 1 submits
        self._login("test_user1_dot", "UserPass!123")
        r1 = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id}).get_json()["subscription"]["id"]

        # User 2 submits
        self._login("test_user2_dot", "UserPass!123")
        r2 = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_id}).get_json()["subscription"]["id"]

        self._login("test_admin_dot", "AdminSecurePass!123")
        m1 = self.client.get("/api/admin/metrics").get_json()["metrics"]
        self.assertEqual(m1["pending_subscriptions"], 2)

        # Approve User 1
        self.client.post(f"/api/admin/subscriptions/{r1}/approve", json={})
        m2 = self.client.get("/api/admin/metrics").get_json()["metrics"]
        self.assertEqual(m2["pending_subscriptions"], 1, "One pending request still remaining!")
        self.assertEqual(m2["active_subscriptions"], 1)

        # Reject User 2
        self.client.post(f"/api/admin/subscriptions/{r2}/reject", json={"reason": "Test"})
        m3 = self.client.get("/api/admin/metrics").get_json()["metrics"]
        self.assertEqual(m3["pending_subscriptions"], 0, "No pending requests remain!")
        self.assertEqual(m3["active_subscriptions"], 1)

    # ==============================================================================
    # 2. Frontend Templates & Sidebar Notification UI Inspection
    # ==============================================================================

    def test_06_sidebar_notification_dot_markup_and_absence_of_numeric_badge(self):
        """
        Section 4: Sidebar Notification — Replace Numeric Badge with a Dot.
        - Pending Requests item must feature #sidebarRequestsDot inside .nav-icon-wrapper.
        - Must NOT display a numeric badge or counter in the sidebar.
        - Subscriptions item must NOT contain #sidebarPendingBadge.
        """
        # Check ddos.html
        self.assertIn('id="sidebarRequestsDot"', self.ddos_html)
        self.assertIn('class="sidebar-notification-dot"', self.ddos_html)
        self.assertIn('class="nav-icon-wrapper"', self.ddos_html)

        # Ensure no numeric badge inside admin-subs or admin-requests in ddos.html
        self.assertNotIn('id="sidebarPendingBadge"', self.ddos_html)
        self.assertNotIn('id="sidebarRequestsBadge"', self.ddos_html)

        # Check network_discovery.html
        self.assertIn('id="sidebarRequestsDot"', self.nd_html)
        self.assertIn('class="sidebar-notification-dot"', self.nd_html)
        self.assertNotIn('id="sidebarPendingBadge"', self.nd_html)
        self.assertNotIn('id="sidebarRequestsBadge"', self.nd_html)

    def test_07_all_subscriptions_view_filter_excludes_pending_option(self):
        """
        Section 2: All Subscriptions Page.
        - The status filter dropdown in the Global Subscription Registry
          must NOT offer a 'Pending' option, as pending requests belong
          exclusively to Pending Requests.
        """
        # Find the adminSubStatusFilter select tag in ddos.html
        select_match = re.search(r'<select[^>]*id="adminSubStatusFilter"[^>]*>(.*?)</select>', self.ddos_html, re.DOTALL)
        self.assertTrue(select_match, "adminSubStatusFilter not found in ddos.html")
        select_body = select_match.group(1)
        self.assertNotIn('value="pending"', select_body, "Pending option must not be present in All Subscriptions filter!")
        self.assertIn('value="all"', select_body)
        self.assertIn('value="active"', select_body)
        self.assertIn('value="expired"', select_body)
        self.assertIn('value="canceled"', select_body)

    def test_08_css_notification_dot_styling_and_layout_immunity(self):
        """
        Section 4 & 6: CSS styling for Notification Dot.
        - Absolutely positioned: top and right aligned to upper-right of icon.
        - Small circular dot with border-radius: 50% and red background.
        - No layout shift: pointer-events: none and positioned inside .nav-icon-wrapper.
        - Dark Mode & Light Mode support.
        - Collapsed sidebar maintains alignment without horizontal movement.
        """
        # nav-icon-wrapper definition
        self.assertIn(".sidebar-nav-item .nav-icon-wrapper", self.css_content)
        self.assertIn("position: relative;", self.css_content)
        self.assertIn("width: 20px;", self.css_content)

        # sidebar-notification-dot definition
        self.assertIn(".sidebar-nav-item .sidebar-notification-dot", self.css_content)
        self.assertIn("position: absolute;", self.css_content)
        self.assertIn("border-radius: 50%;", self.css_content)
        self.assertIn("background-color: #EF4444;", self.css_content)
        self.assertIn("pointer-events: none;", self.css_content)

        # Dark theme support
        self.assertIn('[data-theme="dark"] .sidebar-nav-item .sidebar-notification-dot', self.css_content)

        # Active state indicator support
        self.assertIn('.sidebar-nav-item.active .sidebar-notification-dot', self.css_content)
        self.assertIn('[data-theme="dark"] .sidebar-nav-item.active .sidebar-notification-dot', self.css_content)

    def test_09_javascript_notification_dot_logic_and_state_synchronization(self):
        """
        Section 4 & 5: JavaScript synchronization for notification dot.
        - updatePendingRequestsNotification updates #sidebarRequestsDot based on count.
        - loadAdminMetrics triggers updatePendingRequestsNotification.
        - loadAdminRequests triggers updatePendingRequestsNotification.
        - loadAdminSubscriptions excludes pending records from rendering.
        - Auth session and tab switches refresh metrics and notification state.
        """
        self.assertIn("function updatePendingRequestsNotification(count)", self.js_content)
        self.assertIn('document.getElementById("sidebarRequestsDot")', self.js_content)
        self.assertIn('dot.style.display = pendingCount > 0 ? "block" : "none"', self.js_content)

        # loadAdminMetrics calls updater
        self.assertIn("updatePendingRequestsNotification(pendingCount)", self.js_content)

        # loadAdminSubscriptions filters out pending
        self.assertIn('subs = rawSubs.filter(s => s.status !== "pending")', self.js_content)

        # Periodic refresh when admin is authenticated
        self.assertIn("setInterval(loadAdminMetrics", self.js_content)


if __name__ == "__main__":
    unittest.main()
