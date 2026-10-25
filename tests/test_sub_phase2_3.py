#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 2.3: User Subscription Request & Approval Lifecycle Backend
Validates:
1. Public plan browsing endpoint (/api/plans).
2. User plan request workflow (/api/subscriptions/request).
3. Current subscription status query (/api/subscriptions/my-subscription).
4. Admin activation workflow (/api/admin/subscriptions/<id>/activate).
5. Admin date adjustments (/api/admin/subscriptions/<id>/dates).
6. Admin rejection and cancellation (/api/admin/subscriptions/<id>/reject & /cancel).
7. Audit log generation and query (/api/admin/audit-logs).
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.security import create_session_token
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog


class TestPhase2SubscriptionLifecycle(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_lifecycle.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        session = self.SessionFactory()
        self.admin = User(username="soc_director", email="director@scout.local", role="Admin", is_active=True)
        self.admin.set_password("AdminDirector#123")

        self.user = User(username="analyst_sam", email="sam@scout.local", role="User", is_active=True)
        self.user.set_password("SamPassword#123")

        self.plan = SubscriptionPlan(
            plan_code="PRO-SOC-MONTHLY",
            name="Professional SOC Monthly",
            price=49.0,
            duration_value=30,
            duration_unit="days",
            is_active=True
        )
        self.plan.set_features({"can_live_monitoring": True, "can_port_scan": True})

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

    def test_01_public_plans_and_empty_subscription(self):
        """Verifies public plans listing and empty status for new user."""
        # Public plans endpoint (no auth required)
        resp_plans = self.client.get("/api/plans")
        self.assertEqual(resp_plans.status_code, 200)
        plans = resp_plans.get_json()["plans"]
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["plan_code"], "PRO-SOC-MONTHLY")

        # Unauthenticated my-subscription returns 401
        resp_unauth = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(resp_unauth.status_code, 401)

        # Authenticated user with no sub returns has_subscription: False
        resp_my = self.client.get(
            "/api/subscriptions/my-subscription",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(resp_my.status_code, 200)
        self.assertFalse(resp_my.get_json()["has_subscription"])

    def test_02_complete_subscription_approval_lifecycle(self):
        """Tests: Request -> Admin Query -> Admin Activate -> User Query -> Admin Adjust Dates -> Admin Cancel."""
        # 1. User requests subscription
        req_resp = self.client.post(
            "/api/subscriptions/request",
            json={"plan_id": self.plan_id, "notes": "Need access for penetration testing."},
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(req_resp.status_code, 201)
        sub_data = req_resp.get_json()["subscription"]
        self.assertEqual(sub_data["status"], "pending")
        sub_id = sub_data["id"]

        # 2. Duplicate request rejected
        dup_resp = self.client.post(
            "/api/subscriptions/request",
            json={"plan_id": self.plan_id},
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(dup_resp.status_code, 400)
        self.assertIn("already pending", dup_resp.get_json()["message"])

        # 3. Admin lists pending subscriptions
        admin_list_resp = self.client.get(
            "/api/admin/subscriptions?status=pending",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(admin_list_resp.status_code, 200)
        subs = admin_list_resp.get_json()["subscriptions"]
        self.assertEqual(len(subs), 1)
        self.assertEqual(subs[0]["id"], sub_id)

        # 4. Admin activates subscription
        act_resp = self.client.post(
            f"/api/admin/subscriptions/{sub_id}/activate",
            json={"notes": "Approved for corporate trial."},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(act_resp.status_code, 200)
        activated_sub = act_resp.get_json()["subscription"]
        self.assertEqual(activated_sub["status"], "active")
        self.assertTrue(activated_sub["is_valid_active"])
        self.assertIsNotNone(activated_sub["start_date"])
        self.assertIsNotNone(activated_sub["end_date"])

        # 5. User checks my-subscription -> now active
        user_check = self.client.get(
            "/api/subscriptions/my-subscription",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(user_check.status_code, 200)
        self.assertTrue(user_check.get_json()["has_subscription"])
        self.assertTrue(user_check.get_json()["subscription"]["is_valid_active"])

        # 6. Admin adjusts dates (add 7 grace days)
        new_end = (datetime.now(timezone.utc) + timedelta(days=37)).isoformat()
        adj_resp = self.client.put(
            f"/api/admin/subscriptions/{sub_id}/dates",
            json={"end_date": new_end, "reason": "Added 7-day grace extension."},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(adj_resp.status_code, 200)

        # 7. Admin cancels subscription
        cancel_resp = self.client.post(
            f"/api/admin/subscriptions/{sub_id}/cancel",
            json={"reason": "Customer requested refund."},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(cancel_resp.status_code, 200)
        self.assertEqual(cancel_resp.get_json()["subscription"]["status"], "canceled")

        # 8. Verify audit logs
        audit_resp = self.client.get(
            f"/api/admin/audit-logs?subscription_id={sub_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(audit_resp.status_code, 200)
        logs = audit_resp.get_json()["audit_logs"]
        actions = [log["action"] for log in logs]
        self.assertIn("REQUESTED", actions)
        self.assertIn("ACTIVATED", actions)
        self.assertIn("DATES_MODIFIED", actions)
        self.assertIn("CANCELED", actions)


if __name__ == "__main__":
    unittest.main()
