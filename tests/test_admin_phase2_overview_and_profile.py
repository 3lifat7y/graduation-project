#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite for Admin Dashboard Phase 2: Overview & Profile & Security
Validates:
1. 8 Verified Database Metrics:
   - total_users
   - active_users
   - inactive_users
   - total_active_subscriptions
   - pending_subscriptions
   - expired_subscriptions
   - canceled_subscriptions
   - available_plans
2. Zero Mock / Hardcoded Data: Display counts strictly match database records.
3. Admin Profile Data Retrieval: GET /api/auth/me returns valid admin data.
4. Admin Profile Update: PUT /api/auth/profile updates display name and email.
5. Admin Password Change: POST /api/auth/change-password requires current password and updates hash.
6. HTML Template Elements: 8 metric cards, quick shortcuts toolbar, profile tab, and forms.
"""

import os
import sys
import json
import unittest
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.security import hash_password
from modules.auth.db import get_engine, init_db, get_session_factory, get_db_session
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription
from scripts.seed_plans import seed_default_subscription_plans


class TestAdminPhase2OverviewAndProfile(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_admin_p2.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed plans
        seed_default_subscription_plans()

        with get_db_session() as session:
            # Create Admins
            self.admin = User(
                username="superadmin",
                email="superadmin@scout.local",
                password_hash=hash_password("MasterAdmin123!"),
                full_name="Chief SecOps",
                role="Admin",
                is_active=True
            )
            # Create Users with diverse statuses
            self.active_user = User(
                username="user_active",
                email="user_active@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Active Analyst",
                role="User",
                is_active=True
            )
            self.inactive_user = User(
                username="user_suspended",
                email="user_suspended@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Suspended Operator",
                role="User",
                is_active=False
            )
            session.add_all([self.admin, self.active_user, self.inactive_user])
            session.flush()

            self.admin_id = self.admin.id
            self.active_user_id = self.active_user.id
            self.inactive_user_id = self.inactive_user.id

            # Create Subscriptions with diverse statuses
            plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-PRO").first()
            self.plan_id = plan.id

            sub_active = UserSubscription(
                user_id=self.active_user_id,
                plan_id=self.plan_id,
                status="active",
                start_date=datetime.now(timezone.utc) - timedelta(days=5),
                end_date=datetime.now(timezone.utc) + timedelta(days=25)
            )
            sub_pending = UserSubscription(
                user_id=self.active_user_id,
                plan_id=self.plan_id,
                status="pending"
            )
            sub_expired = UserSubscription(
                user_id=self.active_user_id,
                plan_id=self.plan_id,
                status="expired",
                start_date=datetime.now(timezone.utc) - timedelta(days=60),
                end_date=datetime.now(timezone.utc) - timedelta(days=30)
            )
            sub_canceled = UserSubscription(
                user_id=self.inactive_user_id,
                plan_id=self.plan_id,
                status="canceled"
            )
            session.add_all([sub_active, sub_pending, sub_expired, sub_canceled])
            session.flush()

    def tearDown(self):
        if hasattr(self, "engine"):
            self.engine.dispose()
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _login_admin(self):
        resp = self.client.post("/api/auth/login", json={
            "username": "superadmin",
            "password": "MasterAdmin123!"
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json().get("token")

    # =========================================================================
    # 1. 8 Verified Database Metrics
    # =========================================================================
    def test_admin_metrics_contains_all_8_database_metrics(self):
        token = self._login_admin()
        resp = self.client.get("/api/admin/metrics", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        m = data["metrics"]

        # Validate all 8 required metrics:
        # 1. Total users = 3 (admin + active_user + inactive_user)
        self.assertEqual(m["total_users"], 3)
        # 2. Active users = 2 (admin + active_user)
        self.assertEqual(m["active_users"], 2)
        # 3. Inactive users = 1 (inactive_user)
        self.assertEqual(m["inactive_users"], 1)
        # 4. Active subscriptions = 1
        self.assertEqual(m["active_subscriptions"], 1)
        # 5. Pending subscriptions = 1
        self.assertEqual(m["pending_subscriptions"], 1)
        # 6. Expired subscriptions = 1
        self.assertEqual(m["expired_subscriptions"], 1)
        # 7. Canceled subscriptions = 1
        self.assertEqual(m["canceled_subscriptions"], 1)
        # 8. Available plans = 3 (seeded default plans)
        self.assertGreaterEqual(m["available_plans"], 3)
        self.assertEqual(m["active_plans"], m["available_plans"])
        self.assertIn("inactive_plans", m)
        # 9. Distinct Subscribers (distinct user_ids: active_user and inactive_user; avoids double-counting)
        self.assertEqual(m["total_subscribers"], 2)
        self.assertEqual(m["active_subscribers"], 1)

    # =========================================================================
    # 2. Admin Profile Endpoint (GET /api/auth/me)
    # =========================================================================
    def test_admin_profile_me_endpoint(self):
        token = self._login_admin()
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["authenticated"])
        u = data["user"]
        self.assertEqual(u["username"], "superadmin")
        self.assertEqual(u["email"], "superadmin@scout.local")
        self.assertEqual(u["full_name"], "Chief SecOps")
        self.assertEqual(u["role"], "Admin")
        self.assertTrue(u["is_active"])

    # =========================================================================
    # 3. Admin Profile Update (PUT /api/auth/profile)
    # =========================================================================
    def test_admin_profile_update(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.put("/api/auth/profile", headers=headers, json={
            "full_name": "Chief Security Architect",
            "email": "architect@scout.local"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["user"]["full_name"], "Chief Security Architect")
        self.assertEqual(data["user"]["email"], "architect@scout.local")

        # Confirm persisted in DB
        with get_db_session() as session:
            db_admin = session.query(User).filter_by(id=self.admin_id).first()
            self.assertEqual(db_admin.full_name, "Chief Security Architect")
            self.assertEqual(db_admin.email, "architect@scout.local")

    # =========================================================================
    # 4. Admin Password Change (POST /api/auth/change-password)
    # =========================================================================
    def test_admin_password_change(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Wrong current password fails
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "WrongPassword123!",
            "new_password": "BrandNewAdminPass123!",
            "confirm_new_password": "BrandNewAdminPass123!"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Incorrect current password", resp.get_json()["message"])

        # Weak new password fails
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "MasterAdmin123!",
            "new_password": "short",
            "confirm_new_password": "short"
        })
        self.assertEqual(resp.status_code, 400)

        # Successful password change
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "MasterAdmin123!",
            "new_password": "BrandNewAdminPass123!",
            "confirm_new_password": "BrandNewAdminPass123!"
        })
        self.assertEqual(resp.status_code, 200)

        # Old password no longer works
        login_fail = self.client.post("/api/auth/login", json={
            "username": "superadmin",
            "password": "MasterAdmin123!"
        })
        self.assertEqual(login_fail.status_code, 401)

        # New password works
        login_ok = self.client.post("/api/auth/login", json={
            "username": "superadmin",
            "password": "BrandNewAdminPass123!"
        })
        self.assertEqual(login_ok.status_code, 200)

    # =========================================================================
    # 5. HTML Elements Verification
    # =========================================================================
    def test_html_contains_phase2_admin_elements(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # 8 Metric elements
        self.assertIn('id="adminMetricTotalUsers"', html)
        self.assertIn('id="adminMetricActiveUsers"', html)
        self.assertIn('id="adminMetricInactiveUsers"', html)
        self.assertIn('id="adminMetricPendingSubs"', html)
        self.assertIn('id="adminMetricActiveSubs"', html)
        self.assertIn('id="adminMetricExpiredSubs"', html)
        self.assertIn('id="adminMetricCanceledSubs"', html)
        self.assertIn('id="adminMetricPlans"', html)

        # Quick actions toolbar
        self.assertIn('id="adminShortcutsToolbar"', html)
        self.assertIn('data-jump-tab="users"', html)
        self.assertIn('data-jump-tab="plans"', html)
        self.assertIn('data-jump-tab="subscriptions"', html)
        self.assertIn('data-jump-tab="requests"', html)
        self.assertIn('data-jump-tab="profile"', html)

        # Profile tab and panel
        self.assertIn('data-admin-tab="profile"', html)
        self.assertIn('id="adminPanelProfile"', html)
        self.assertIn('id="adminProfileForm"', html)
        self.assertIn('id="adminPasswordForm"', html)
        self.assertIn('id="adminPanelLogoutBtn"', html)


if __name__ == "__main__":
    unittest.main()
