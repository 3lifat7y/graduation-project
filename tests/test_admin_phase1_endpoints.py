#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite for Admin Dashboard Phase 1: Backend Foundation & API Hardening
Validates:
1. PUT /api/auth/profile - Profile updates, input validation, unique email, role tamper prevention.
2. GET /api/admin/users/<id> - Admin retrieval of full user profile, current sub, and history.
3. PATCH /api/admin/users/<id>/role - Role promotion/demotion and last active admin demotion protection.
4. PATCH /api/admin/users/<id>/status - Account suspension/reactivation, session revocation, last admin protection.
5. DELETE /api/admin/plans/<id> - Safe archiving when subscribers exist vs. hard deletion when 0 subscribers.
6. POST /api/admin/subscriptions/<id>/renew - Subscription renewal and audit logging.
7. POST /api/admin/subscriptions/<id>/extend - Subscription extension from expiry/now and audit logging.
8. GET /api/admin/subscriptions?search=... - Subscription search by username, email, or ID.
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
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog
from scripts.seed_plans import seed_default_subscription_plans


class TestAdminPhase1Endpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_admin_p1.db"
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
            # Create Super Admin
            self.admin = User(
                username="leadadmin",
                email="leadadmin@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Lead Administrator",
                role="Admin",
                is_active=True
            )
            # Create Second Admin
            self.admin2 = User(
                username="subadmin",
                email="subadmin@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Sub Administrator",
                role="Admin",
                is_active=True
            )
            # Create Regular User
            self.user = User(
                username="analyst1",
                email="analyst1@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="SOC Analyst 1",
                role="User",
                is_active=True
            )
            # Create Second User
            self.user2 = User(
                username="analyst2",
                email="analyst2@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="SOC Analyst 2",
                role="User",
                is_active=True
            )
            session.add_all([self.admin, self.admin2, self.user, self.user2])
            session.flush()

            self.admin_id = self.admin.id
            self.admin2_id = self.admin2.id
            self.user_id = self.user.id
            self.user2_id = self.user2.id

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

    def _login(self, username, password):
        resp = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        self.assertEqual(resp.status_code, 200, f"Login failed for {username}: {resp.data}")
        data = resp.get_json()
        return data.get("token")

    # =========================================================================
    # 1. Profile Update Endpoint (PUT /api/auth/profile)
    # =========================================================================
    def test_profile_update_success_and_validation(self):
        # 1. Anonymous access rejected
        resp = self.client.put("/api/auth/profile", json={"full_name": "Ghost User"})
        self.assertEqual(resp.status_code, 401)

        token = self._login("analyst1", "UserPass123!")
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Successful update of full_name and email
        resp = self.client.put("/api/auth/profile", headers=headers, json={
            "full_name": "Updated Analyst One",
            "email": "updated.analyst@scout.local"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["user"]["full_name"], "Updated Analyst One")
        self.assertEqual(data["user"]["email"], "updated.analyst@scout.local")

        # 3. Invalid email format rejected
        resp = self.client.put("/api/auth/profile", headers=headers, json={
            "email": "not-an-email"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid email", resp.get_json()["message"])

        # 4. Duplicate email rejected
        resp = self.client.put("/api/auth/profile", headers=headers, json={
            "email": "analyst2@scout.local"
        })
        self.assertEqual(resp.status_code, 409)
        self.assertIn("already exists", resp.get_json()["message"])

        # 5. Role tampering ignored / prevented
        resp = self.client.put("/api/auth/profile", headers=headers, json={
            "full_name": "Tamper Attempt",
            "role": "Admin",
            "is_active": False
        })
        self.assertEqual(resp.status_code, 200)
        # Verify in DB that role was NOT escalated
        with get_db_session() as session:
            u = session.query(User).filter_by(id=self.user_id).first()
            self.assertEqual(u.role, "User")
            self.assertTrue(u.is_active)

    # =========================================================================
    # 2. User Details Endpoint (GET /api/admin/users/<id>)
    # =========================================================================
    def test_get_admin_user_details(self):
        user_token = self._login("analyst1", "UserPass123!")
        admin_token = self._login("leadadmin", "AdminPass123!")

        # 1. Non-admin forbidden
        resp = self.client.get(f"/api/admin/users/{self.user_id}", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(resp.status_code, 403)

        # 2. Admin retrieves user details with subscription history
        resp = self.client.get(f"/api/admin/users/{self.user_id}", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("user", data)
        self.assertEqual(data["user"]["username"], "analyst1")
        self.assertIsNone(data["user"]["current_subscription"])
        self.assertEqual(len(data["user"]["subscriptions"]), 0)

        # 3. Non-existent user returns 404
        resp = self.client.get("/api/admin/users/9999", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(resp.status_code, 404)

    # =========================================================================
    # 3. Role Update & Last Admin Guard (PATCH /api/admin/users/<id>/role)
    # =========================================================================
    def test_user_role_update_and_last_admin_protection(self):
        admin_token = self._login("leadadmin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Invalid role rejected
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/role", headers=headers, json={"role": "Superuser"})
        self.assertEqual(resp.status_code, 400)

        # 2. Promote regular user to Admin
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/role", headers=headers, json={"role": "Admin"})
        self.assertEqual(resp.status_code, 200)
        with get_db_session() as session:
            u = session.query(User).filter_by(id=self.user_id).first()
            self.assertEqual(u.role, "Admin")

        # 3. Demote promoted user back to User (now 2 other admins remain)
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 200)

        # 4. Demote subadmin (admin2) -> 1 admin remains (leadadmin)
        resp = self.client.patch(f"/api/admin/users/{self.admin2_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 200)

        # 5. Attempt to demote leadadmin (the last active admin) -> MUST BE BLOCKED
        resp = self.client.patch(f"/api/admin/users/{self.admin_id}/role", headers=headers, json={"role": "User"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Cannot demote the last active Administrator", resp.get_json()["message"])

        # DB confirms leadadmin is still Admin
        with get_db_session() as session:
            lead = session.query(User).filter_by(id=self.admin_id).first()
            self.assertEqual(lead.role, "Admin")

    # =========================================================================
    # 4. User Status & Last Admin Guard (PATCH /api/admin/users/<id>/status)
    # =========================================================================
    def test_user_status_update_and_last_admin_suspension_guard(self):
        admin_token = self._login("leadadmin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Admin cannot deactivate self
        resp = self.client.patch(f"/api/admin/users/{self.admin_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("cannot deactivate their own account", resp.get_json()["message"])

        # 2. Deactivate regular user -> succeeds and revokes session
        with get_db_session() as session:
            u_before = session.query(User).filter_by(id=self.user_id).first()
            ver_before = u_before.session_version

        resp = self.client.patch(f"/api/admin/users/{self.user_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 200)

        with get_db_session() as session:
            u_after = session.query(User).filter_by(id=self.user_id).first()
            self.assertFalse(u_after.is_active)
            self.assertGreater(u_after.session_version, ver_before)

        # 3. Reactivate user
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/status", headers=headers, json={"is_active": True})
        self.assertEqual(resp.status_code, 200)
        with get_db_session() as session:
            u_react = session.query(User).filter_by(id=self.user_id).first()
            self.assertTrue(u_react.is_active)

        # 4. Deactivate admin2 (succeeds because leadadmin is also an active admin)
        resp = self.client.patch(f"/api/admin/users/{self.admin2_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 200)
        with get_db_session() as session:
            a2 = session.query(User).filter_by(id=self.admin2_id).first()
            self.assertFalse(a2.is_active)

    # =========================================================================
    # 5. Plan Safe Deletion / Archival (DELETE /api/admin/plans/<id>)
    # =========================================================================
    def test_plan_safe_deletion_or_archival(self):
        admin_token = self._login("leadadmin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Get existing plans
        with get_db_session() as session:
            pro_plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-PRO").first()
            pro_plan_id = pro_plan.id

            # Create an unused dummy plan
            dummy_plan = SubscriptionPlan(
                plan_code="unused_test_plan",
                name="Unused Plan",
                description="Test description",
                price=19.99,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            session.add(dummy_plan)
            session.flush()
            dummy_plan_id = dummy_plan.id

            # Attach a subscription to pro_plan
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=pro_plan_id,
                status="active",
                start_date=datetime.now(timezone.utc),
                end_date=datetime.now(timezone.utc) + timedelta(days=30)
            )
            session.add(sub)
            session.flush()

        # 1. DELETE dummy_plan with 0 subscribers -> Should be hard DELETED
        resp = self.client.delete(f"/api/admin/plans/{dummy_plan_id}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "deleted")
        with get_db_session() as session:
            p = session.query(SubscriptionPlan).filter_by(id=dummy_plan_id).first()
            self.assertIsNone(p)

        # 2. DELETE pro_plan with subscribers > 0 -> Should be safely ARCHIVED (is_active = False)
        resp = self.client.delete(f"/api/admin/plans/{pro_plan_id}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "archived")
        with get_db_session() as session:
            p = session.query(SubscriptionPlan).filter_by(id=pro_plan_id).first()
            self.assertIsNotNone(p)
            self.assertFalse(p.is_active)

    # =========================================================================
    # 6. Subscription Renewal & Extension Endpoints
    # =========================================================================
    def test_subscription_renewal_and_extension(self):
        admin_token = self._login("leadadmin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create expired subscription
        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-PRO").first()
            expired_sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="expired",
                start_date=datetime.now(timezone.utc) - timedelta(days=60),
                end_date=datetime.now(timezone.utc) - timedelta(days=30)
            )
            session.add(expired_sub)
            session.flush()
            sub_id = expired_sub.id

        # 1. RENEW subscription
        resp = self.client.post(f"/api/admin/subscriptions/{sub_id}/renew", headers=headers, json={
            "duration_days": 45,
            "notes": "Admin courtesy renewal."
        })
        self.assertEqual(resp.status_code, 200)
        sub_data = resp.get_json()["subscription"]
        self.assertEqual(sub_data["status"], "active")
        self.assertTrue(sub_data["is_valid_active"])

        # Check audit log in DB
        with get_db_session() as session:
            logs = session.query(SubscriptionAuditLog).filter_by(subscription_id=sub_id, action="RENEWED").all()
            self.assertEqual(len(logs), 1)
            self.assertIn("courtesy renewal", logs[0].details)

        # 2. EXTEND active subscription by 15 days
        resp = self.client.post(f"/api/admin/subscriptions/{sub_id}/extend", headers=headers, json={
            "extension_days": 15,
            "notes": "Bonus extension."
        })
        self.assertEqual(resp.status_code, 200)
        ext_data = resp.get_json()["subscription"]
        self.assertEqual(ext_data["status"], "active")

        # Check audit log in DB
        with get_db_session() as session:
            logs = session.query(SubscriptionAuditLog).filter_by(subscription_id=sub_id, action="EXTENDED").all()
            self.assertEqual(len(logs), 1)
            self.assertIn("extended subscription by 15 days", logs[0].details)

        # 3. Invalid extension days validation
        resp = self.client.post(f"/api/admin/subscriptions/{sub_id}/extend", headers=headers, json={
            "extension_days": -5
        })
        self.assertEqual(resp.status_code, 400)

    # =========================================================================
    # 7. Subscription Search Filter (GET /api/admin/subscriptions?search=...)
    # =========================================================================
    def test_subscription_search_filter(self):
        admin_token = self._login("leadadmin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {admin_token}"}

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).first()
            s1 = UserSubscription(user_id=self.user_id, plan_id=plan.id, status="active")
            s2 = UserSubscription(user_id=self.user2_id, plan_id=plan.id, status="pending")
            session.add_all([s1, s2])
            session.flush()
            s1_id = s1.id

        # Search by username
        resp = self.client.get("/api/admin/subscriptions?search=analyst1", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["subscriptions"]), 1)
        self.assertEqual(data["subscriptions"][0]["username"], "analyst1")

        # Search by subscription ID
        resp = self.client.get(f"/api/admin/subscriptions?search={s1_id}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["subscriptions"]), 1)
        self.assertEqual(data["subscriptions"][0]["id"], s1_id)


if __name__ == "__main__":
    unittest.main()
