"""
SCOUT Cybersecurity Platform — Free Subscription Plan Test Suite
Validates:
1. Admin Create & Edit Subscription Plan:
   - Free Plan checkbox (is_free).
   - Price automatically set / forced to $0.00.
   - Duration and feature permissions remain fully configurable.
   - Displayed as Free in subscription catalogs.
2. User Free Plan Activation:
   - Available Free Plans displayed in user Subscription Plans page.
   - Immediate activation upon selection without payment, receipt, or admin approval.
   - Features and dashboard access granted immediately.
3. One-Time Eligibility & Anti-Abuse:
   - Each user can activate a Free Plan only once in their lifetime.
   - Strict tracking across registered account (user_id), email, and phone number.
   - Anti-abuse: Users cannot register with different email and same phone, or different phone and same email to claim again.
   - Free Plan is hidden from the user's available plans catalog after activation.
4. Concurrency & Integrity:
   - Duplicate activation and concurrent request safeguards.
   - Paid subscription workflows preserved intact.
   - Comprehensive audit logs (FREE_ACTIVATION) and claim records (FreePlanClaim).
"""

import os
import re
import unittest
import threading
from datetime import datetime, timezone, timedelta

from api import app
from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session, get_engine, init_db
from modules.subscriptions.models import (
    SubscriptionPlan, UserSubscription, SubscriptionAuditLog,
    FreePlanClaim
)
from modules.subscriptions.services import (
    check_free_plan_eligibility,
    activate_free_subscription,
    normalize_claim_email,
    extract_phone_digits
)


class TestFreeSubscriptionPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = get_engine()
        init_db(cls.engine)
        cls.client = app.test_client()

        with open("templates/ddos.html", "r", encoding="utf-8") as f:
            cls.ddos_html = f.read()
        with open("static/main.js", "r", encoding="utf-8") as f:
            cls.js_content = f.read()
        with open("static/style.css", "r", encoding="utf-8") as f:
            cls.css_content = f.read()

    def setUp(self):
        with get_db_session() as session:
            session.query(FreePlanClaim).delete()
            session.query(SubscriptionAuditLog).delete()
            session.query(UserSubscription).delete()
            session.query(SubscriptionPlan).delete()
            session.query(User).filter(User.username.like("test_free_%")).delete()

            # Create test Admin
            self.admin = User(
                username="test_free_admin",
                email="free_admin@scout.local",
                phone_number="+15550000001",
                role="Admin",
                full_name="Admin Free Test",
                is_active=True
            )
            self.admin.set_password("AdminSecurePass!123")
            session.add(self.admin)

            # Create test Users
            self.user1 = User(
                username="test_free_user1",
                email="alice@scout.local",
                phone_number="+12025550101",
                role="User",
                full_name="Alice Sentinel",
                is_active=True
            )
            self.user1.set_password("AliceSecurePass!123")
            session.add(self.user1)

            self.user2 = User(
                username="test_free_user2",
                email="bob@scout.local",
                phone_number="+12025550102",
                role="User",
                full_name="Bob Defender",
                is_active=True
            )
            self.user2.set_password("BobSecurePass!123")
            session.add(self.user2)

            # Create a standard Paid Plan
            self.paid_plan = SubscriptionPlan(
                plan_code="SCOUT-PAID-PRO",
                name="SCOUT Enterprise Paid",
                description="Standard paid tier requiring manual payment checkout",
                price=99.00,
                currency="USD",
                duration_value=30,
                duration_unit="days",
                is_active=True,
                is_free=False
            )
            self.paid_plan.set_features({
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True
            })
            session.add(self.paid_plan)

            session.flush()
            self.admin_id = self.admin.id
            self.user1_id = self.user1.id
            self.user2_id = self.user2.id
            self.paid_plan_id = self.paid_plan.id

    def _login(self, username, password):
        res = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        self.assertEqual(res.status_code, 200, f"Login failed for {username}")
        return res

    # ==============================================================================
    # 1. Admin — Create & Edit Subscription Plan (is_free and Price Enforcement)
    # ==============================================================================

    def test_01_admin_create_free_plan_forces_zero_price_and_preserves_features(self):
        """Admin creates a plan with is_free=True; price is automatically forced to $0.00."""
        self._login("test_free_admin", "AdminSecurePass!123")
        res = self.client.post("/api/admin/plans", json={
            "plan_code": "SCOUT-COMMUNITY-FREE",
            "name": "Community Defense Free Tier",
            "description": "Complimentary cybersecurity monitoring for small teams",
            "is_free": True,
            "price": 49.99,  # Even if nonzero price sent, must be forced to 0.00
            "duration_value": 45,
            "duration_unit": "days",
            "is_active": True,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": False
            }
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        plan = data["plan"]
        self.assertTrue(plan["is_free"])
        self.assertEqual(plan["price"], 0.0)
        self.assertEqual(plan["duration_value"], 45)
        self.assertTrue(plan["features"]["can_live_monitoring"])
        self.assertTrue(plan["features"]["can_port_scan"])
        self.assertFalse(plan["features"]["can_network_discovery"])

        # Check DB directly
        with get_db_session() as session:
            db_plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-COMMUNITY-FREE").first()
            self.assertIsNotNone(db_plan)
            self.assertTrue(db_plan.is_free)
            self.assertEqual(db_plan.price, 0.0)

    def test_02_admin_update_plan_to_free_forces_zero_price(self):
        """Admin updates an existing paid plan to is_free=True; price becomes $0.00."""
        self._login("test_free_admin", "AdminSecurePass!123")
        res = self.client.put(f"/api/admin/plans/{self.paid_plan_id}", json={
            "is_free": True,
            "price": 79.00  # Attempting nonzero price with is_free=True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        plan = data["plan"]
        self.assertTrue(plan["is_free"])
        self.assertEqual(plan["price"], 0.0)

        # Check DB
        with get_db_session() as session:
            p = session.query(SubscriptionPlan).filter_by(id=self.paid_plan_id).first()
            self.assertTrue(p.is_free)
            self.assertEqual(p.price, 0.0)

    def test_03_admin_plans_list_reports_is_free(self):
        """Admin plans catalog lists plans with is_free boolean indicator."""
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-PILOT",
                name="Pilot Free",
                price=0.0,
                duration_value=14,
                is_active=True,
                is_free=True
            )
            session.add(free_p)

        self._login("test_free_admin", "AdminSecurePass!123")
        res = self.client.get("/api/admin/plans")
        self.assertEqual(res.status_code, 200)
        plans = res.get_json()["plans"]
        free_found = [p for p in plans if p["plan_code"] == "FREE-PILOT"]
        self.assertEqual(len(free_found), 1)
        self.assertTrue(free_found[0]["is_free"])
        self.assertEqual(free_found[0]["price"], 0.0)

    # ==============================================================================
    # 2. User Free Plan Activation (Immediate, No Payment, No Approval)
    # ==============================================================================

    def test_04_user_free_plan_activation_immediate_access_and_audit(self):
        """
        User activates a Free Plan:
        - Status is immediately 'active' (not 'pending').
        - Valid start_date and end_date set according to duration.
        - No payment or admin approval required.
        - SubscriptionAuditLog created with FREE_ACTIVATION.
        - FreePlanClaim record created.
        """
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="SCOUT-START-FREE",
                name="SCOUT Starter Free",
                description="Full free access for 30 days",
                price=0.0,
                duration_value=30,
                duration_unit="days",
                is_active=True,
                is_free=True
            )
            free_p.set_features({
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True
            })
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        self._login("test_free_user1", "AliceSecurePass!123")

        # Activate via dedicated endpoint
        res = self.client.post("/api/subscriptions/free/activate", json={
            "plan_id": free_plan_id
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        sub = data["subscription"]
        self.assertEqual(sub["status"], "active")
        self.assertEqual(sub["plan_id"], free_plan_id)
        self.assertEqual(sub["plan_price_snapshot"], 0.0)
        self.assertIsNotNone(sub["start_date"])
        self.assertIsNotNone(sub["end_date"])

        # Check DB subscription record
        with get_db_session() as session:
            db_sub = session.query(UserSubscription).filter_by(user_id=self.user1_id).first()
            self.assertIsNotNone(db_sub)
            self.assertEqual(db_sub.status, "active")
            self.assertTrue(db_sub.is_valid_active())

            # Check audit log
            audit = session.query(SubscriptionAuditLog).filter_by(subscription_id=db_sub.id).first()
            self.assertIsNotNone(audit)
            self.assertEqual(audit.action, "FREE_ACTIVATION")
            self.assertEqual(audit.new_status, "active")
            self.assertEqual(audit.actor_id, self.user1_id)

            # Check claim tracking record
            claim = session.query(FreePlanClaim).filter_by(user_id=self.user1_id).first()
            self.assertIsNotNone(claim)
            self.assertEqual(claim.email, "alice@scout.local")
            self.assertEqual(claim.phone_number, "+12025550101")
            self.assertEqual(claim.plan_id, free_plan_id)

    def test_05_user_free_plan_activation_via_request_endpoint_auto_activates(self):
        """POST /api/subscriptions/request automatically activates immediately when plan is free."""
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-AUTO-TIER",
                name="Auto Free Tier",
                price=0.0,
                duration_value=15,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        self._login("test_free_user2", "BobSecurePass!123")
        res = self.client.post("/api/subscriptions/request", json={
            "plan_id": free_plan_id
        })
        self.assertEqual(res.status_code, 201)
        sub = res.get_json()["subscription"]
        self.assertEqual(sub["status"], "active")

        # Verify user has active subscription
        status_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.get_json()
        self.assertTrue(status_data["has_subscription"])
        self.assertEqual(status_data["subscription"]["status"], "active")

    # ==============================================================================
    # 3. One-Time Eligibility & Anti-Abuse Protection
    # ==============================================================================

    def test_06_one_time_eligibility_same_account_prevented(self):
        """A user cannot activate a free plan twice on the same account."""
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-ONCE",
                name="Free Once Plan",
                price=0.0,
                duration_value=30,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        self._login("test_free_user1", "AliceSecurePass!123")

        # First activation -> Success
        res1 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res1.status_code, 201)

        # Second activation attempt -> Rejected
        res2 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("already claimed", res2.get_json()["message"].lower())

    def test_07_anti_abuse_different_email_same_phone_prevented(self):
        """
        Anti-Abuse: User claims free plan on Account 1.
        User registers Account 2 with a DIFFERENT email, but the SAME phone number.
        Account 2 is strictly blocked from claiming the free plan offer.
        """
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-PHONE-CHECK",
                name="Free Phone Protected",
                price=0.0,
                duration_value=30,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        # Alice claims free plan with phone +12025550101
        self._login("test_free_user1", "AliceSecurePass!123")
        res1 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res1.status_code, 201)

        # Create new account with DIFFERENT email but SAME phone (format variant without '+')
        with get_db_session() as session:
            alt_user = User(
                username="test_free_alice_alt",
                email="alice_new_alt@scout.local",
                phone_number="2025550101",  # Same phone number, format variant!
                role="User",
                full_name="Alice Duplicate",
                is_active=True
            )
            alt_user.set_password("AltSecurePass!123")
            session.add(alt_user)

        self._login("test_free_alice_alt", "AltSecurePass!123")
        res2 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("phone number", res2.get_json()["message"].lower())

    def test_08_anti_abuse_different_phone_same_email_prevented(self):
        """
        Anti-Abuse: User claims free plan on Account 1.
        User registers Account 3 with a DIFFERENT phone number, but the SAME/aliased email.
        Account 3 is strictly blocked from claiming the free plan offer.
        """
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-EMAIL-CHECK",
                name="Free Email Protected",
                price=0.0,
                duration_value=30,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        # Alice claims free plan with email alice@scout.local
        self._login("test_free_user1", "AliceSecurePass!123")
        res1 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res1.status_code, 201)

        # Create new account with DIFFERENT phone number but uppercase / same email
        with get_db_session() as session:
            email_dup_user = User(
                username="test_free_alice_email_dup",
                email="ALICE@scout.local",  # Same email uppercase
                phone_number="+19995550999",  # Different phone
                role="User",
                full_name="Alice Email Dup",
                is_active=True
            )
            email_dup_user.set_password("DupSecurePass!123")
            session.add(email_dup_user)

        self._login("test_free_alice_email_dup", "DupSecurePass!123")
        res2 = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("email address", res2.get_json()["message"].lower())

    def test_09_free_plan_hidden_from_catalog_after_activation(self):
        """
        Once a user activates a Free Plan, that Free Plan is completely hidden
        from the user's available plans catalog (/api/plans).
        """
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-HIDE-TEST",
                name="Hide After Activation Plan",
                price=0.0,
                duration_value=30,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        self._login("test_free_user1", "AliceSecurePass!123")

        # Before activation: user sees the free plan
        cat_before = self.client.get("/api/plans").get_json()
        plan_codes_before = [p["plan_code"] for p in cat_before["plans"]]
        self.assertIn("FREE-HIDE-TEST", plan_codes_before)

        # Activate free plan
        act_res = self.client.post("/api/subscriptions/free/activate", json={"plan_id": free_plan_id})
        self.assertEqual(act_res.status_code, 201)

        # After activation: free plan is HIDDEN from user's catalog
        cat_after = self.client.get("/api/plans").get_json()
        plan_codes_after = [p["plan_code"] for p in cat_after["plans"]]
        self.assertNotIn("FREE-HIDE-TEST", plan_codes_after)
        # Paid plan remains visible
        self.assertIn("SCOUT-PAID-PRO", plan_codes_after)

    def test_10_paid_plan_flow_preserved_requires_checkout(self):
        """Paid plans are not auto-activated and follow the standard checkout/approval flow."""
        self._login("test_free_user1", "AliceSecurePass!123")
        res = self.client.post("/api/subscriptions/request", json={
            "plan_id": self.paid_plan_id,
            "notes": "Paid plan checkout"
        })
        self.assertEqual(res.status_code, 201)
        sub = res.get_json()["subscription"]
        # Must be pending, NOT active
        self.assertEqual(sub["status"], "pending")

    def test_11_concurrent_activation_requests_strictly_single_success(self):
        """Concurrency test: Multiple parallel activation calls result in exactly 1 active subscription."""
        with get_db_session() as session:
            free_p = SubscriptionPlan(
                plan_code="FREE-CONCURRENT-TEST",
                name="Concurrent Free Tier",
                price=0.0,
                duration_value=30,
                is_active=True,
                is_free=True
            )
            session.add(free_p)
            session.flush()
            free_plan_id = free_p.id

        results = []

        def worker():
            success, msg, data = activate_free_subscription(self.user1_id, free_plan_id)
            results.append((success, msg))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        # Exactly 1 activation must succeed
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 4)

        with get_db_session() as session:
            subs = session.query(UserSubscription).filter_by(user_id=self.user1_id, status="active").all()
            claims = session.query(FreePlanClaim).filter_by(user_id=self.user1_id).all()
            self.assertEqual(len(subs), 1)
            self.assertEqual(len(claims), 1)

    # ==============================================================================
    # 4. Frontend Static Verification (HTML, CSS, JS)
    # ==============================================================================

    def test_12_frontend_admin_forms_contain_free_plan_checkbox(self):
        """Verify templates/ddos.html includes Free Plan checkboxes across modal and full-page forms."""
        self.assertIn('id="planFormIsFree"', self.ddos_html)
        self.assertIn('id="fpCreatePlanIsFree"', self.ddos_html)
        self.assertIn('id="fpEditPlanIsFree"', self.ddos_html)

    def test_13_frontend_js_and_css_free_plan_elements(self):
        """Verify static/main.js and static/style.css have free plan activation and styling handlers."""
        self.assertIn("activateFreePlan", self.js_content)
        self.assertIn("/api/subscriptions/free/activate", self.js_content)
        self.assertIn("btn-plan-free", self.js_content)
        self.assertIn(".btn-plan-free", self.css_content)


if __name__ == "__main__":
    unittest.main()
