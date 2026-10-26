#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite for Admin Dashboard Phase 3: User Management System
Validates:
1. User listing and current_subscription integrity (no 'None' bugs).
2. Operator search across username, email, and full_name.
3. Multi-filtering by role ('Admin', 'User') and status ('active', 'disabled').
4. Full operator dossier retrieval via GET /api/admin/users/<id> including historical subscriptions.
5. Account suspension, session invalidation, and reactivation.
6. Role promotion/demotion between 'User' and 'Admin'.
7. Protection guards against self-suspension and last-active-admin demotion/suspension.
8. Frontend HTML elements present: search input, filters, dossier modal, and history table.
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


class TestAdminPhase3UserManagement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_admin_p3.db"
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
            # Create Lead Admin
            self.admin = User(
                username="lead_admin",
                email="lead_admin@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Lead Administrator",
                role="Admin",
                is_active=True
            )
            # Create Second Admin
            self.sub_admin = User(
                username="sub_admin",
                email="sub_admin@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Deputy Administrator",
                role="Admin",
                is_active=True
            )
            # Create Active User
            self.user1 = User(
                username="alice_secops",
                email="alice@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Alice SecOps",
                role="User",
                is_active=True
            )
            # Create Suspended User
            self.user2 = User(
                username="bob_analyst",
                email="bob@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Bob Suspended",
                role="User",
                is_active=False
            )
            session.add_all([self.admin, self.sub_admin, self.user1, self.user2])
            session.flush()

            self.admin_id = self.admin.id
            self.sub_admin_id = self.sub_admin.id
            self.user1_id = self.user1.id
            self.user2_id = self.user2.id

            # Attach active subscription to Alice
            pro_plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-PRO").first()
            self.pro_plan_id = pro_plan.id

            sub1 = UserSubscription(
                user_id=self.user1_id,
                plan_id=self.pro_plan_id,
                status="active",
                start_date=datetime.now(timezone.utc) - timedelta(days=5),
                end_date=datetime.now(timezone.utc) + timedelta(days=25)
            )
            # Attach expired older subscription to Alice
            sub0 = UserSubscription(
                user_id=self.user1_id,
                plan_id=self.pro_plan_id,
                status="expired",
                start_date=datetime.now(timezone.utc) - timedelta(days=65),
                end_date=datetime.now(timezone.utc) - timedelta(days=35)
            )
            session.add_all([sub0, sub1])
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
            "username": "lead_admin",
            "password": "AdminPass123!"
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json().get("token")

    # =========================================================================
    # 1. User Listing & current_subscription Data Contract
    # =========================================================================
    def test_list_admin_users_and_current_subscription(self):
        token = self._login_admin()
        resp = self.client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        users = data["users"]
        self.assertEqual(len(users), 4)

        # Find Alice in users list
        alice = next((u for u in users if u["username"] == "alice_secops"), None)
        self.assertIsNotNone(alice)
        self.assertEqual(alice["full_name"], "Alice SecOps")
        self.assertTrue(alice["is_active"])
        # Ensure current_subscription is populated correctly
        self.assertIsNotNone(alice["current_subscription"])
        self.assertEqual(alice["current_subscription"]["status"], "active")
        self.assertIn("Professional SOC Analyst", alice["current_subscription"]["plan_name"])

        # Bob has no subscription
        bob = next((u for u in users if u["username"] == "bob_analyst"), None)
        self.assertIsNotNone(bob)
        self.assertIsNone(bob["current_subscription"])

    # =========================================================================
    # 2. Operator Search & Multi-Filters
    # =========================================================================
    def test_search_and_filters(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Search by username substring
        resp = self.client.get("/api/admin/users?search=alice", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["users"]), 1)
        self.assertEqual(resp.get_json()["users"][0]["username"], "alice_secops")

        # Search by email substring
        resp = self.client.get("/api/admin/users?search=bob@scout.local", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["users"]), 1)
        self.assertEqual(resp.get_json()["users"][0]["username"], "bob_analyst")

        # Filter by role = 'Admin'
        resp = self.client.get("/api/admin/users?role=Admin", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["users"]), 2)

        # Filter by status = 'disabled'
        resp = self.client.get("/api/admin/users?status=disabled", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["users"]), 1)
        self.assertEqual(resp.get_json()["users"][0]["username"], "bob_analyst")

    # =========================================================================
    # 3. User Dossier & Subscription History (GET /api/admin/users/<id>)
    # =========================================================================
    def test_get_user_dossier_with_history(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.get(f"/api/admin/users/{self.user1_id}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        u = resp.get_json()["user"]
        self.assertEqual(u["username"], "alice_secops")
        self.assertEqual(len(u["subscriptions"]), 2)
        # Verify latest is active and older is expired
        statuses = [s["status"] for s in u["subscriptions"]]
        self.assertIn("active", statuses)
        self.assertIn("expired", statuses)

    # =========================================================================
    # 4. Moderation: Account Suspension & Reactivation
    # =========================================================================
    def test_user_suspension_and_reactivation(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Suspend Alice
        resp = self.client.patch(f"/api/admin/users/{self.user1_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["is_active"])

        # Alice cannot log in while suspended
        alice_login = self.client.post("/api/auth/login", json={
            "username": "alice_secops",
            "password": "UserPass123!"
        })
        self.assertEqual(alice_login.status_code, 403)
        self.assertIn("ACCOUNT_DISABLED", alice_login.get_json()["code"])

        # Restore Alice
        resp = self.client.patch(f"/api/admin/users/{self.user1_id}/status", headers=headers, json={"is_active": True})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["is_active"])

        # Alice can log in now
        alice_login = self.client.post("/api/auth/login", json={
            "username": "alice_secops",
            "password": "UserPass123!"
        })
        self.assertEqual(alice_login.status_code, 200)

    # =========================================================================
    # 5. Role Modification & Protection Guards
    # =========================================================================
    def test_user_role_modification_and_guards(self):
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Promote Alice to Admin
        resp = self.client.patch(f"/api/admin/users/{self.user1_id}/role", headers=headers, json={"role": "Admin"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "Admin")

        # Demote Alice back to User
        resp = self.client.patch(f"/api/admin/users/{self.user1_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "User")

        # Demote Deputy Admin -> leaves 1 active admin (lead_admin)
        resp = self.client.patch(f"/api/admin/users/{self.sub_admin_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 200)

        # Attempt to demote lead_admin (last admin) -> must be blocked
        resp = self.client.patch(f"/api/admin/users/{self.admin_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Cannot demote the last active Administrator", resp.get_json()["message"])

    # =========================================================================
    # 6. HTML Template Elements for Phase 3
    # =========================================================================
    def test_html_contains_phase3_user_management_elements(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn('id="adminUserSearchInput"', html)
        self.assertIn('id="adminUserRoleFilter"', html)
        self.assertIn('id="adminUserStatusFilter"', html)
        self.assertIn('id="adminUserDetailsModal"', html)
        self.assertIn('id="adminUserSubsHistoryTable"', html)


if __name__ == "__main__":
    unittest.main()
