#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Test Suite for Admin Dashboard Phases 4 & 5:
- Phase 4: Subscription Plans Management & Public Dynamic Catalog
- Phase 5: Subscription Management & Immediate Access Enforcement
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
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, ensure_utc
from scripts.seed_plans import seed_default_subscription_plans


class TestAdminPhase4And5(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.test_db_path = Path(self.temp_dir.name) / "test_admin_p4p5.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed standard default plans
        seed_default_subscription_plans()

        # Create administrator account
        with get_db_session() as session:
            admin = User(
                username="leadadmin",
                email="leadadmin@scout.local",
                password_hash=hash_password("AdminSecure!2026"),
                full_name="Lead Administrator",
                role="Admin",
                is_active=True
            )
            operator = User(
                username="analyst_ops",
                email="analyst@scout.local",
                password_hash=hash_password("AnalystPass!2026"),
                full_name="Field Analyst",
                role="User",
                is_active=True
            )
            session.add_all([admin, operator])
            session.flush()
            self.admin_id = admin.id
            self.operator_id = operator.id

        # Obtain Admin token
        login_res = self.client.post("/api/auth/login", json={
            "username": "leadadmin",
            "password": "AdminSecure!2026"
        })
        self.assertEqual(login_res.status_code, 200)
        self.admin_token = login_res.get_json()["token"]

        # Obtain Operator token
        op_login = self.client.post("/api/auth/login", json={
            "username": "analyst_ops",
            "password": "AnalystPass!2026"
        })
        self.assertEqual(op_login.status_code, 200)
        self.operator_token = op_login.get_json()["token"]

    def tearDown(self):
        try:
            from modules.auth.db import get_session_factory
            get_session_factory().close_all()
        except Exception:
            pass
        if hasattr(self, "engine"):
            try:
                self.engine.dispose()
            except Exception:
                pass
        import modules.auth.db as auth_db
        if getattr(auth_db, "_engine", None):
            try:
                auth_db._engine.dispose()
            except Exception:
                pass
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_admin_create_and_update_plan(self):
        """Test Admin plan creation and updating with proper duration and currency fields."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Create a new plan
        create_payload = {
            "plan_code": "SCOUT-ULTRA",
            "name": "SCOUT Ultra Tier",
            "description": "Full-spectrum AI defensive operations",
            "price": 129.99,
            "currency": "USD",
            "duration_value": 60,
            "duration_unit": "days",
            "is_active": True,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "max_concurrent_scans": 10
            }
        }
        res = self.client.post("/api/admin/plans", headers=headers, json=create_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        plan_id = data["plan"]["id"]
        self.assertEqual(data["plan"]["plan_code"], "SCOUT-ULTRA")
        self.assertEqual(data["plan"]["duration_value"], 60)
        self.assertEqual(data["plan"]["duration_unit"], "days")

        # 2. Update the plan
        update_payload = {
            "name": "SCOUT Ultra Enterprise",
            "price": 149.00,
            "currency": "EUR",
            "duration_value": 90,
            "duration_unit": "days",
            "description": "Updated ultra description",
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "max_concurrent_scans": 20
            }
        }
        update_res = self.client.put(f"/api/admin/plans/{plan_id}", headers=headers, json=update_payload)
        self.assertEqual(update_res.status_code, 200)
        up_data = update_res.get_json()["plan"]
        self.assertEqual(up_data["name"], "SCOUT Ultra Enterprise")
        self.assertEqual(up_data["price"], 149.00)
        self.assertEqual(up_data["currency"], "EUR")
        self.assertEqual(up_data["duration_value"], 90)

    def test_plan_deletion_and_safe_archival_policy(self):
        """Test deleting unused plans vs safe archival when subscriptions exist."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Create a plan with zero subscribers
        res = self.client.post("/api/admin/plans", headers=headers, json={
            "plan_code": "TEMP-TEST",
            "name": "Temporary Test Plan",
            "description": "Temporary plan for deletion",
            "price": 19.99,
            "duration_value": 7,
            "duration_unit": "days"
        })
        self.assertEqual(res.status_code, 201)
        temp_id = res.get_json()["plan"]["id"]

        # Deleting plan with 0 subscribers must permanently delete it
        del_res = self.client.delete(f"/api/admin/plans/{temp_id}", headers=headers)
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.get_json()["action"], "deleted")

        with get_db_session() as session:
            p = session.query(SubscriptionPlan).filter_by(id=temp_id).first()
            self.assertIsNone(p)

        # 2. Plan with associated subscriptions (active or historical)
        with get_db_session() as session:
            pro_plan = session.query(SubscriptionPlan).filter_by(plan_code="SCOUT-PRO").first()
            self.assertIsNotNone(pro_plan)
            sub = UserSubscription(
                user_id=self.operator_id,
                plan_id=pro_plan.id,
                status="active",
                start_date=ensure_utc(datetime.now(timezone.utc)),
                end_date=ensure_utc(datetime.now(timezone.utc) + timedelta(days=30))
            )
            session.add(sub)
            session.flush()
            pro_plan_id = pro_plan.id

        # Deleting plan with subscribers must archive (is_active = False), NOT delete
        archive_res = self.client.delete(f"/api/admin/plans/{pro_plan_id}", headers=headers)
        self.assertEqual(archive_res.status_code, 200)
        self.assertEqual(archive_res.get_json()["action"], "archived")
        self.assertFalse(archive_res.get_json()["is_active"])

        # Verify plan still exists in database as inactive
        with get_db_session() as session:
            archived = session.query(SubscriptionPlan).filter_by(id=pro_plan_id).first()
            self.assertIsNotNone(archived)
            self.assertFalse(archived.is_active)

    def test_public_homepage_plans_dynamic_catalog(self):
        """Test public endpoints return only active plans and reflect updates."""
        # Anonymous visitor calls /api/plans and /api/subscriptions/plans
        res1 = self.client.get("/api/plans")
        self.assertEqual(res1.status_code, 200)
        plans1 = res1.get_json()["plans"]

        res2 = self.client.get("/api/subscriptions/plans")
        self.assertEqual(res2.status_code, 200)
        plans2 = res2.get_json()["plans"]
        self.assertEqual(len(plans1), len(plans2))

        # Create new active plan
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        create_res = self.client.post("/api/admin/plans", headers=headers, json={
            "plan_code": "SCOUT-PREMIUM-PUBLIC",
            "name": "SCOUT Premium Public",
            "description": "Public catalog dynamic tier",
            "price": 89.00,
            "duration_value": 30,
            "duration_unit": "days",
            "is_active": True
        })
        self.assertEqual(create_res.status_code, 201)

        # Newly created plan must appear immediately on public endpoint
        res3 = self.client.get("/api/subscriptions/plans")
        codes = [p["plan_code"] for p in res3.get_json()["plans"]]
        self.assertIn("SCOUT-PREMIUM-PUBLIC", codes)

        # Deactivate plan
        plan_id = create_res.get_json()["plan"]["id"]
        self.client.patch(f"/api/admin/plans/{plan_id}/status", headers=headers, json={"is_active": False})

        # Deactivated plan must be omitted from public catalog
        res4 = self.client.get("/api/subscriptions/plans")
        codes4 = [p["plan_code"] for p in res4.get_json()["plans"]]
        self.assertNotIn("SCOUT-PREMIUM-PUBLIC", codes4)

    def test_homepage_html_pricing_section_and_mindmap_isolation(self):
        """Verify #public-pricing is present on the public homepage and Mind Map is exclusive to public view."""
        # Public homepage (use anonymous test client to avoid authenticated session redirect)
        anon_client = app.test_client()
        home_res = anon_client.get("/")
        self.assertEqual(home_res.status_code, 200)
        html = home_res.get_data(as_text=True)

        self.assertIn('id="public-pricing"', html)
        self.assertIn('id="publicHomepagePlansGrid"', html)
        self.assertIn('id="system-architecture"', html)

        # Verify Mind Map is NOT placed inside network_discovery template
        nd_res = self.client.get("/network-discovery")
        self.assertEqual(nd_res.status_code, 200)
        nd_html = nd_res.get_data(as_text=True)
        self.assertNotIn('id="system-architecture"', nd_html)
        self.assertNotIn('class="mindmap-wrapper-card"', nd_html)

    def test_subscription_search_and_filtering(self):
        """Test searching subscriptions by username, user ID, and filtering by status."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            now = ensure_utc(datetime.now(timezone.utc))
            sub1 = UserSubscription(
                user_id=self.operator_id,
                plan_id=plan.id,
                status="active",
                start_date=now - timedelta(days=5),
                end_date=now + timedelta(days=25)
            )
            sub2 = UserSubscription(
                user_id=self.operator_id,
                plan_id=plan.id,
                status="expired",
                start_date=now - timedelta(days=40),
                end_date=now - timedelta(days=10)
            )
            session.add_all([sub1, sub2])
            session.flush()
            sub1_id = sub1.id
            sub2_id = sub2.id

        # Search by username
        res_search = self.client.get("/api/admin/subscriptions?search=analyst", headers=headers)
        self.assertEqual(res_search.status_code, 200)
        subs = res_search.get_json()["subscriptions"]
        self.assertGreaterEqual(len(subs), 2)
        for s in subs:
            self.assertIn("analyst", s["username"].lower())

        # Search by specific sub ID
        res_id = self.client.get(f"/api/admin/subscriptions?search={sub1_id}", headers=headers)
        self.assertEqual(res_id.status_code, 200)
        id_subs = res_id.get_json()["subscriptions"]
        self.assertEqual(len(id_subs), 1)
        self.assertEqual(id_subs[0]["id"], sub1_id)

        # Filter by status = expired
        res_exp = self.client.get("/api/admin/subscriptions?status=expired", headers=headers)
        self.assertEqual(res_exp.status_code, 200)
        for s in res_exp.get_json()["subscriptions"]:
            self.assertEqual(s["status"], "expired")

    def test_subscription_renew_and_extend(self):
        """Test administrative renewal of expired subscriptions and extension of active subscriptions."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            now = ensure_utc(datetime.now(timezone.utc))
            exp_sub = UserSubscription(
                user_id=self.operator_id,
                plan_id=plan.id,
                status="expired",
                start_date=now - timedelta(days=60),
                end_date=now - timedelta(days=30)
            )
            session.add(exp_sub)
            session.flush()
            exp_sub_id = exp_sub.id

        # 1. Admin renews expired subscription
        renew_res = self.client.post(
            f"/api/admin/subscriptions/{exp_sub_id}/renew",
            headers=headers,
            json={"notes": "Authorized renewal by lead admin"}
        )
        self.assertEqual(renew_res.status_code, 200)
        renew_data = renew_res.get_json()["subscription"]
        self.assertEqual(renew_data["status"], "active")
        self.assertIsNotNone(renew_data["start_date"])
        self.assertIsNotNone(renew_data["end_date"])

        # Verify audit log was recorded
        with get_db_session() as session:
            audit = session.query(SubscriptionAuditLog).filter_by(
                subscription_id=exp_sub_id, action="RENEWED"
            ).first()
            self.assertIsNotNone(audit)
            self.assertEqual(audit.actor_id, self.admin_id)

        # 2. Admin extends the active subscription by 45 days
        extend_res = self.client.post(
            f"/api/admin/subscriptions/{exp_sub_id}/extend",
            headers=headers,
            json={
                "duration_value": 45,
                "duration_unit": "days",
                "notes": "Extension courtesy grant"
            }
        )
        self.assertEqual(extend_res.status_code, 200)
        ext_data = extend_res.get_json()["subscription"]
        self.assertEqual(ext_data["status"], "active")

        # Verify audit log for extension
        with get_db_session() as session:
            ext_audit = session.query(SubscriptionAuditLog).filter_by(
                subscription_id=exp_sub_id, action="EXTENDED"
            ).first()
            self.assertIsNotNone(ext_audit)
            self.assertEqual(ext_audit.actor_id, self.admin_id)

    def test_immediate_access_enforcement(self):
        """
        Verify immediate authorization policy enforcement:
        1. An active subscription allows access to @subscription_required endpoints.
        2. Once canceled, access is immediately rejected with 403 Forbidden.
        3. Once user is disabled, access is immediately rejected.
        """
        op_headers = {"Authorization": f"Bearer {self.operator_token}"}
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            now = ensure_utc(datetime.now(timezone.utc))
            sub = UserSubscription(
                user_id=self.operator_id,
                plan_id=plan.id,
                status="active",
                start_date=now,
                end_date=now + timedelta(days=30)
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        # With active subscription, operator can access protected operational endpoints
        status_res = self.client.get("/api/scan-rescan", headers=op_headers)
        self.assertEqual(status_res.status_code, 200)

        # Admin cancels the subscription
        cancel_res = self.client.post(
            f"/api/admin/subscriptions/{sub_id}/cancel",
            headers=admin_headers,
            json={"reason": "Security policy violation"}
        )
        self.assertEqual(cancel_res.status_code, 200)

        # Operator immediately attempts access -> MUST receive 403 Forbidden
        blocked_res = self.client.get("/api/scan-rescan", headers=op_headers)
        self.assertEqual(blocked_res.status_code, 403)
        self.assertEqual(blocked_res.get_json()["code"], "SUBSCRIPTION_REQUIRED")

        # Re-activate subscription
        with get_db_session() as session:
            s = session.query(UserSubscription).filter_by(id=sub_id).first()
            s.status = "active"
            session.flush()

        # Suspend operator account
        suspend_res = self.client.post(
            f"/api/admin/users/{self.operator_id}/status",
            headers=admin_headers,
            json={"is_active": False}
        )
        self.assertEqual(suspend_res.status_code, 200)

        # Suspended operator attempts access -> immediately rejected (401/403)
        suspended_blocked = self.client.get("/api/scan-rescan", headers=op_headers)
        self.assertIn(suspended_blocked.status_code, [401, 403])


if __name__ == "__main__":
    unittest.main()
