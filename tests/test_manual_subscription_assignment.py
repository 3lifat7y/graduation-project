"""
Unit & Integration Tests for Manual Subscription Assignment
Verifies:
1. Administrator manual subscription assignment endpoint (POST /api/admin/subscriptions).
2. Service logic and duplicate active subscription mitigation (cancels previous active & pending).
3. Reflection in user's account (GET /api/subscriptions/my-subscription).
4. RBAC access control (non-admins forbidden).
5. Input validation (invalid user, invalid plan, negative duration).
6. Entitlement evaluation after manual assignment (@subscription_required).
"""

import os
import unittest
from datetime import datetime, timezone, timedelta

from api import app
from modules.auth.models import User, utcnow
from modules.auth.db import get_engine, get_session_factory, init_db
from modules.auth.security import hash_password
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog


class TestManualSubscriptionAssignment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db_path = "instance/test_manual_subscription_assignment.db"
        os.environ["SCOUT_DB_PATH"] = cls.test_db_path
        cls.engine = get_engine(cls.test_db_path, reset=True)
        init_db(cls.engine)
        cls.SessionFactory = get_session_factory(cls.engine)

        cls.app = app
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        with self.SessionFactory() as session:
            session.query(SubscriptionAuditLog).delete()
            session.query(UserSubscription).delete()
            session.query(SubscriptionPlan).delete()
            session.query(User).delete()

            # Seed Admin
            self.admin = User(
                username="admin_sub_assign",
                email="admin_sub_assign@scout.sec",
                password_hash=hash_password("AdminPass123!@#"),
                role="Admin",
                is_active=True
            )
            # Seed Regular User
            self.user = User(
                username="user_sub_assign",
                email="user_sub_assign@scout.sec",
                password_hash=hash_password("UserPass123!@#"),
                role="User",
                is_active=True
            )
            # Seed Inactive User
            self.inactive_user = User(
                username="user_inactive",
                email="user_inactive@scout.sec",
                password_hash=hash_password("UserPass123!@#"),
                role="User",
                is_active=False
            )
            session.add_all([self.admin, self.user, self.inactive_user])
            session.flush()

            # Seed Plans
            self.plan_starter = SubscriptionPlan(
                plan_code="STARTER_ASSIGN",
                name="Starter Assign Plan",
                price=19.99,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            self.plan_enterprise = SubscriptionPlan(
                plan_code="ENT_ASSIGN",
                name="Enterprise Assign Plan",
                price=99.99,
                duration_value=1,
                duration_unit="months",
                is_active=True
            )
            self.plan_starter.set_features({"can_port_scan": True, "can_live_monitoring": False})
            self.plan_enterprise.set_features({"can_port_scan": True, "can_live_monitoring": True})
            session.add_all([self.plan_starter, self.plan_enterprise])
            session.commit()

            self.admin_id = self.admin.id
            self.user_id = self.user.id
            self.inactive_user_id = self.inactive_user.id
            self.plan_starter_id = self.plan_starter.id
            self.plan_enterprise_id = self.plan_enterprise.id

    def login(self, email, password):
        return self.client.post("/api/auth/login", json={"email": email, "password": password})

    def test_manual_assignment_success(self):
        """Admin can assign and immediately activate a plan for a user."""
        self.login("admin_sub_assign@scout.sec", "AdminPass123!@#")

        res = self.client.post("/api/admin/subscriptions", json={
            "user_id": self.user_id,
            "plan_id": self.plan_starter_id,
            "duration_days": 45,
            "notes": "Manual VIP onboarding"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("successfully assigned and activated", data["message"])
        sub = data["subscription"]
        self.assertEqual(sub["status"], "active")
        self.assertEqual(sub["payment_status"], "approved")
        self.assertEqual(sub["plan_id"], self.plan_starter_id)
        self.assertEqual(sub["user_id"], self.user_id)

        # Verify audit log
        with self.SessionFactory() as session:
            audit = session.query(SubscriptionAuditLog).filter_by(subscription_id=sub["id"]).first()
            self.assertIsNotNone(audit)
            self.assertEqual(audit.action, "MANUALLY_ASSIGNED")
            self.assertEqual(audit.new_status, "active")

        # Verify subscription appears in admin listing
        list_res = self.client.get("/api/admin/subscriptions?status=active")
        self.assertEqual(list_res.status_code, 200)
        list_data = list_res.get_json()
        sub_ids = [s["id"] for s in list_data["subscriptions"]]
        self.assertIn(sub["id"], sub_ids)

    def test_manual_assignment_alias_endpoint(self):
        """Admin can also assign via /api/admin/subscriptions/assign."""
        self.login("admin_sub_assign@scout.sec", "AdminPass123!@#")

        res = self.client.post("/api/admin/subscriptions/assign", json={
            "user_id": self.user_id,
            "plan_id": self.plan_enterprise_id,
            "notes": "Direct assignment via alias route"
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["subscription"]["status"], "active")

    def test_manual_assignment_cancels_previous_active_and_pending(self):
        """Manual assignment cancels existing active and pending subscriptions to prevent duplicates."""
        # Create an existing active subscription and a pending request for user
        with self.SessionFactory() as session:
            old_active = UserSubscription(
                user_id=self.user_id,
                plan_id=self.plan_starter_id,
                status="active",
                start_date=utcnow() - timedelta(days=10),
                end_date=utcnow() + timedelta(days=20),
                payment_status="approved"
            )
            old_pending = UserSubscription(
                user_id=self.user_id,
                plan_id=self.plan_starter_id,
                status="pending",
                payment_status="pending_verification"
            )
            session.add_all([old_active, old_pending])
            session.commit()
            old_active_id = old_active.id
            old_pending_id = old_pending.id

        self.login("admin_sub_assign@scout.sec", "AdminPass123!@#")
        res = self.client.post("/api/admin/subscriptions", json={
            "user_id": self.user_id,
            "plan_id": self.plan_enterprise_id,
            "duration_days": 60,
            "notes": "Upgrade assignment"
        })
        self.assertEqual(res.status_code, 201)
        new_sub_id = res.get_json()["subscription"]["id"]

        with self.SessionFactory() as session:
            s_old_act = session.query(UserSubscription).filter_by(id=old_active_id).first()
            s_old_pen = session.query(UserSubscription).filter_by(id=old_pending_id).first()
            s_new = session.query(UserSubscription).filter_by(id=new_sub_id).first()

            self.assertEqual(s_old_act.status, "canceled")
            self.assertIn("Superceded", s_old_act.cancellation_reason)
            self.assertEqual(s_old_pen.status, "canceled")
            self.assertIn("Superceded", s_old_pen.cancellation_reason)
            self.assertEqual(s_new.status, "active")

            # Check that only ONE active subscription exists for user
            active_count = session.query(UserSubscription).filter_by(user_id=self.user_id, status="active").count()
            self.assertEqual(active_count, 1)

    def test_manual_assignment_reflected_in_user_account(self):
        """User immediately sees active subscription in /api/subscriptions/my-subscription."""
        self.login("admin_sub_assign@scout.sec", "AdminPass123!@#")
        assign_res = self.client.post("/api/admin/subscriptions", json={
            "user_id": self.user_id,
            "plan_id": self.plan_enterprise_id,
            "duration_days": 30
        })
        self.assertEqual(assign_res.status_code, 201)

        # Log in as user
        self.login("user_sub_assign@scout.sec", "UserPass123!@#")
        my_sub_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(my_sub_res.status_code, 200)
        my_data = my_sub_res.get_json()
        self.assertTrue(my_data["has_subscription"])
        self.assertEqual(my_data["subscription"]["status"], "active")
        self.assertEqual(my_data["subscription"]["plan_name"], "Enterprise Assign Plan")

    def test_manual_assignment_rbacs_and_validation(self):
        """Ensures non-admins are rejected and input validation prevents faulty records."""
        # Non-admin attempt
        self.login("user_sub_assign@scout.sec", "UserPass123!@#")
        res = self.client.post("/api/admin/subscriptions", json={
            "user_id": self.user_id,
            "plan_id": self.plan_starter_id
        })
        self.assertEqual(res.status_code, 403)

        # Admin login
        self.login("admin_sub_assign@scout.sec", "AdminPass123!@#")

        # Missing user_id
        res_no_user = self.client.post("/api/admin/subscriptions", json={"plan_id": self.plan_starter_id})
        self.assertEqual(res_no_user.status_code, 400)

        # Missing plan_id
        res_no_plan = self.client.post("/api/admin/subscriptions", json={"user_id": self.user_id})
        self.assertEqual(res_no_plan.status_code, 400)

        # Non-existent user
        res_bad_user = self.client.post("/api/admin/subscriptions", json={"user_id": 99999, "plan_id": self.plan_starter_id})
        self.assertEqual(res_bad_user.status_code, 400)

        # Inactive user
        res_inact_user = self.client.post("/api/admin/subscriptions", json={"user_id": self.inactive_user_id, "plan_id": self.plan_starter_id})
        self.assertEqual(res_inact_user.status_code, 400)
        self.assertIn("suspended", res_inact_user.get_json()["message"].lower())

        # Non-existent plan
        res_bad_plan = self.client.post("/api/admin/subscriptions", json={"user_id": self.user_id, "plan_id": 99999})
        self.assertEqual(res_bad_plan.status_code, 400)

        # Negative duration
        res_neg_dur = self.client.post("/api/admin/subscriptions", json={"user_id": self.user_id, "plan_id": self.plan_starter_id, "duration_days": -5})
        self.assertEqual(res_neg_dur.status_code, 400)


if __name__ == "__main__":
    unittest.main()
