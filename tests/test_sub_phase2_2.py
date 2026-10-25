#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 2.2: Admin Subscription & User Management Backend
Validates:
1. Admin plan catalog creation, listing, updating, and soft deactivation.
2. Duplicate plan code prevention.
3. User search, moderation, and account status toggle.
4. Non-admin access denial (403 Forbidden).
5. Self-deactivation prevention for Administrators.
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.security import create_session_token, COOKIE_NAME
from modules.subscriptions.models import SubscriptionPlan


class TestPhase2AdminRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_admin_sub.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        session = self.SessionFactory()
        self.admin = User(username="admin_boss", email="boss@scout.local", role="Admin", is_active=True)
        self.admin.set_password("AdminPass#123")

        self.user = User(username="analyst_joe", email="joe@scout.local", role="User", is_active=True)
        self.user.set_password("JoePass#123")

        self.plan = SubscriptionPlan(
            plan_code="INITIAL-PLAN",
            name="Initial Plan",
            price=19.99,
            duration_value=30,
            is_active=True
        )
        session.add_all([self.admin, self.user, self.plan])
        session.commit()

        self.admin_token = create_session_token(self.admin.id, self.admin.role, self.admin.session_version)
        self.user_token = create_session_token(self.user.id, self.user.role, self.user.session_version)
        self.plan_id = self.plan.id
        session.close()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_access_control_on_admin_routes(self):
        """Verifies 401 for anonymous and 403 for standard user on /api/admin/plans."""
        resp_anon = self.client.get("/api/admin/plans")
        self.assertEqual(resp_anon.status_code, 401)

        resp_user = self.client.get("/api/admin/plans", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(resp_user.status_code, 403)

        resp_admin = self.client.get("/api/admin/plans", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp_admin.status_code, 200)

    def test_02_create_plan_and_duplicate_prevention(self):
        """Verifies creating a plan and rejecting duplicate plan codes."""
        payload = {
            "plan_code": "ENTERPRISE-ELITE",
            "name": "Enterprise Elite Tier",
            "description": "Full unthrottled cyber telemetry",
            "price": 99.0,
            "currency": "USD",
            "duration_value": 60,
            "duration_unit": "days",
            "is_active": True,
            "features": {"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": True}
        }
        resp = self.client.post(
            "/api/admin/plans",
            json=payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["plan"]["plan_code"], "ENTERPRISE-ELITE")
        self.assertEqual(data["plan"]["price"], 99.0)

        # Duplicate submission
        resp_dup = self.client.post(
            "/api/admin/plans",
            json=payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_dup.status_code, 409)

    def test_03_update_plan_and_toggle_status(self):
        """Verifies modifying plan fields and soft-toggling status."""
        update_payload = {
            "name": "Updated Plan Title",
            "price": 29.99,
            "duration_value": 45
        }
        resp_up = self.client.put(
            f"/api/admin/plans/{self.plan_id}",
            json=update_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_up.status_code, 200)
        self.assertEqual(resp_up.get_json()["plan"]["name"], "Updated Plan Title")
        self.assertEqual(resp_up.get_json()["plan"]["price"], 29.99)

        # Deactivate plan
        resp_status = self.client.patch(
            f"/api/admin/plans/{self.plan_id}/status",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_status.status_code, 200)
        self.assertFalse(resp_status.get_json()["is_active"])

    def test_04_list_users_and_toggle_account_status(self):
        """Verifies user search and deactivation with session revocation."""
        resp_users = self.client.get(
            "/api/admin/users?search=joe",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_users.status_code, 200)
        users = resp_users.get_json()["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "analyst_joe")

        # Disable Joe's account
        joe_id = users[0]["id"]
        resp_disable = self.client.patch(
            f"/api/admin/users/{joe_id}/status",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_disable.status_code, 200)

        # Joe's existing token should now fail immediately
        resp_joe = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {self.user_token}"})
        self.assertEqual(resp_joe.status_code, 401)

        # Admin cannot disable own account
        resp_self = self.client.patch(
            f"/api/admin/users/{self.admin.id}/status",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_self.status_code, 400)
        self.assertIn("cannot deactivate their own account", resp_self.get_json()["message"])


if __name__ == "__main__":
    unittest.main()
