#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT - Comprehensive Subscription Management and Application Functionality Audit Test Suite
Validates Subscription Plans, All Subscriptions, Date Adjustments, Extensions, Renewals,
Audit Trails, RBAC, Platform Metrics, and Frontend Markup/Logic Integrity.
"""

import json
import os
import sys
import unittest
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User, utcnow
from modules.auth.security import hash_password
from modules.auth.db import get_engine, init_db, get_session_factory, get_db_session
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, ensure_utc
from scripts.seed_plans import seed_default_subscription_plans


class TestSubscriptionAndAdminAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_sub_audit.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        seed_default_subscription_plans()

        with get_db_session() as session:
            self.admin = User(
                username="audit_lead_admin",
                email="admin_audit@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Lead Auditor Admin",
                role="Admin",
                is_active=True
            )
            self.user = User(
                username="audit_operator_1",
                email="operator1@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Operator One",
                role="User",
                is_active=True
            )
            session.add_all([self.admin, self.user])
            session.flush()
            self.admin_id = self.admin.id
            self.user_id = self.user.id

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

    def login_as_admin(self):
        """Authenticates as the test administrator."""
        res = self.client.post("/api/auth/login", json={
            "username": "audit_lead_admin",
            "password": "AdminPass123!"
        })
        self.assertEqual(res.status_code, 200)

    def login_as_regular(self):
        """Authenticates as a regular non-admin operator."""
        res = self.client.post("/api/auth/login", json={
            "username": "audit_operator_1",
            "password": "UserPass123!"
        })
        self.assertEqual(res.status_code, 200)

    # ==========================================================================
    # Part 1: Subscription Plans Catalog Audit
    # ==========================================================================

    def test_01_plan_creation_validation_and_persistence(self):
        """Verify plan creation with valid data, duplicate code prevention, and validation rules."""
        self.login_as_admin()

        unique_code = f"AUDIT-TIER-{int(datetime.now().timestamp())}"
        payload = {
            "plan_code": unique_code,
            "name": "Audit Security Pro Tier",
            "description": "Comprehensive defense analytics and packet capture.",
            "price": 89.99,
            "currency": "USD",
            "duration_value": 45,
            "duration_unit": "days",
            "is_active": True,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True
            }
        }

        # 1. Successful Creation
        res = self.client.post("/api/admin/plans", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        plan_id = data["plan"]["id"]
        self.assertEqual(data["plan"]["plan_code"], unique_code)
        self.assertEqual(data["plan"]["price"], 89.99)
        self.assertEqual(data["plan"]["duration_value"], 45)
        self.assertTrue(data["plan"]["is_active"])

        # 2. Duplicate Plan Code Rejection (HTTP 409)
        dup_res = self.client.post("/api/admin/plans", json=payload)
        self.assertEqual(dup_res.status_code, 409)

        # 3. Invalid Price Validation
        invalid_price_res = self.client.post("/api/admin/plans", json={
            "plan_code": f"INV-{int(datetime.now().timestamp())}",
            "name": "Invalid Price Plan",
            "price": -10.0,
            "duration_value": 30
        })
        self.assertEqual(invalid_price_res.status_code, 400)

    def test_02_plan_details_and_editing(self):
        """Verify fetching plan specifications and updating pricing, duration, and feature flags."""
        self.login_as_admin()

        code = f"EDIT-PLAN-{int(datetime.now().timestamp())}"
        c_res = self.client.post("/api/admin/plans", json={
            "plan_code": code,
            "name": "Original Name",
            "description": "Original Desc",
            "price": 19.99,
            "duration_value": 30,
            "duration_unit": "days",
            "is_active": True,
            "features": {"can_live_monitoring": True, "can_port_scan": False, "can_network_discovery": False}
        })
        self.assertEqual(c_res.status_code, 201)
        plan_id = c_res.get_json()["plan"]["id"]

        # 1. Fetch details
        d_res = self.client.get(f"/api/admin/plans/{plan_id}")
        self.assertEqual(d_res.status_code, 200)
        p_data = d_res.get_json()["plan"]
        self.assertEqual(p_data["name"], "Original Name")
        self.assertIn("metrics", p_data)
        self.assertIn("recent_subscriptions", p_data)

        # 2. Update Plan
        u_res = self.client.put(f"/api/admin/plans/{plan_id}", json={
            "name": "Updated Elite SOC Tier",
            "description": "Updated Description with extra capabilities",
            "price": 39.99,
            "duration_value": 60,
            "duration_unit": "days",
            "features": {"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": True}
        })
        self.assertEqual(u_res.status_code, 200)
        updated = u_res.get_json()["plan"]
        self.assertEqual(updated["name"], "Updated Elite SOC Tier")
        self.assertEqual(updated["price"], 39.99)
        self.assertEqual(updated["duration_value"], 60)
        self.assertTrue(updated["features"]["can_port_scan"])
        self.assertTrue(updated["features"]["can_network_discovery"])

    def test_03_plan_activation_deactivation_and_deletion_safety(self):
        """Verify soft-archival / restore toggle and deletion safety (referential integrity)."""
        self.login_as_admin()

        code = f"LIFECYCLE-{int(datetime.now().timestamp())}"
        c_res = self.client.post("/api/admin/plans", json={
            "plan_code": code,
            "name": "Lifecycle Test Plan",
            "price": 25.0,
            "duration_value": 30,
            "is_active": True
        })
        plan_id = c_res.get_json()["plan"]["id"]

        # 1. Deactivate / Archive
        t_res1 = self.client.patch(f"/api/admin/plans/{plan_id}/status", json={"is_active": False})
        self.assertEqual(t_res1.status_code, 200)
        self.assertFalse(t_res1.get_json()["is_active"])

        # 2. Restore / Activate
        t_res2 = self.client.patch(f"/api/admin/plans/{plan_id}/status", json={"is_active": True})
        self.assertEqual(t_res2.status_code, 200)
        self.assertTrue(t_res2.get_json()["is_active"])

        # 3. Associate a subscription to verify deletion safety
        with get_db_session() as session:
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan_id,
                status="active",
                start_date=utcnow(),
                end_date=utcnow() + timedelta(days=30)
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        # 4. Attempt deletion: must refuse hard deletion and safely archive (is_active=False)
        del_res = self.client.delete(f"/api/admin/plans/{plan_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.get_json()["action"], "archived")
        self.assertFalse(del_res.get_json()["is_active"])

        # Verify plan record still exists in DB as inactive
        with get_db_session() as session:
            p_check = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
            self.assertIsNotNone(p_check)
            self.assertFalse(p_check.is_active)

        # 5. Clean up associated subscription to test permanent deletion on unused plan
        with get_db_session() as session:
            sub_to_del = session.query(UserSubscription).filter_by(id=sub_id).first()
            if sub_to_del:
                session.delete(sub_to_del)
                session.flush()

        # Attempt deletion again with 0 subscribers: should be permanently deleted
        del_res2 = self.client.delete(f"/api/admin/plans/{plan_id}")
        self.assertEqual(del_res2.status_code, 200)
        self.assertEqual(del_res2.get_json()["action"], "deleted")

        with get_db_session() as session:
            self.assertIsNone(session.query(SubscriptionPlan).filter_by(id=plan_id).first())

    def test_04_plan_catalog_search_and_status_filtering(self):
        """Verify search and status filters on GET /api/admin/plans."""
        self.login_as_admin()

        # Query all
        res_all = self.client.get("/api/admin/plans")
        self.assertEqual(res_all.status_code, 200)
        plans = res_all.get_json()["plans"]
        self.assertIsInstance(plans, list)

        # Query active only
        res_active = self.client.get("/api/admin/plans?status=active")
        self.assertEqual(res_active.status_code, 200)
        for p in res_active.get_json()["plans"]:
            self.assertTrue(p["is_active"])

        # Query archived only
        res_archived = self.client.get("/api/admin/plans?status=archived")
        self.assertEqual(res_archived.status_code, 200)
        for p in res_archived.get_json()["plans"]:
            self.assertFalse(p["is_active"])

    # ==========================================================================
    # Part 2: All Subscriptions Management Audit
    # ==========================================================================

    def test_05_subscription_details_and_notes_persistence(self):
        """Verify subscription details retrieval, user/plan relationships, and notes persistence."""
        self.login_as_admin()

        with get_db_session() as session:
            plan = SubscriptionPlan(
                plan_code=f"SUB-TEST-{int(datetime.now().timestamp())}",
                name="Subscription Audit Tier",
                price=50.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            session.add(plan)
            session.flush()

            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="active",
                start_date=utcnow(),
                end_date=utcnow() + timedelta(days=30),
                admin_notes="Initial test notes"
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        # 1. Fetch Subscription Details
        res = self.client.get(f"/api/admin/subscriptions/{sub_id}")
        self.assertEqual(res.status_code, 200)
        s_data = res.get_json()["subscription"]
        self.assertEqual(s_data["id"], sub_id)
        self.assertEqual(s_data["user"]["id"], self.user_id)
        self.assertEqual(s_data["plan"]["id"], plan.id)
        self.assertEqual(s_data["status"], "active")
        self.assertEqual(s_data["admin_notes"], "Initial test notes")

        # 2. Update Operational Notes
        n_res = self.client.put(f"/api/admin/subscriptions/{sub_id}", json={
            "admin_notes": "Updated SLA notes by lead security officer"
        })
        self.assertEqual(n_res.status_code, 200)
        self.assertEqual(n_res.get_json()["subscription"]["admin_notes"], "Updated SLA notes by lead security officer")

        # Verify audit log recorded for notes update
        with get_db_session() as session:
            log = session.query(SubscriptionAuditLog).filter_by(
                subscription_id=sub_id,
                action="NOTES_UPDATED"
            ).first()
            self.assertIsNotNone(log)
            self.assertIn("Updated SLA notes", log.details)

    def test_06_subscription_dates_adjustment_and_validation(self):
        """Verify date adjustments, validation (end must be after start), and audit trail."""
        self.login_as_admin()

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="active",
                start_date=utcnow(),
                end_date=utcnow() + timedelta(days=30)
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        # 1. Negative Validation: End date before start date
        invalid_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/adjust-dates", json={
            "start_date": "2027-01-15T00:00:00Z",
            "end_date": "2027-01-10T00:00:00Z",
            "reason": "Test invalid range"
        })
        self.assertEqual(invalid_res.status_code, 400)
        self.assertIn("later than the start date", invalid_res.get_json()["message"])

        # 2. Valid Date Adjustment
        new_start = "2027-02-01T00:00:00Z"
        new_end = "2027-03-01T00:00:00Z"
        valid_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/adjust-dates", json={
            "start_date": new_start,
            "end_date": new_end,
            "reason": "Authorized contract alignment"
        })
        self.assertEqual(valid_res.status_code, 200)
        updated = valid_res.get_json()["subscription"]
        self.assertTrue(updated["start_date"].startswith("2027-02-01"))
        self.assertTrue(updated["end_date"].startswith("2027-03-01"))

        # Verify audit log entry
        with get_db_session() as session:
            audit = session.query(SubscriptionAuditLog).filter_by(
                subscription_id=sub_id,
                action="DATES_MODIFIED"
            ).first()
            self.assertIsNotNone(audit)
            self.assertIn("Authorized contract alignment", audit.details)

    def test_07_subscription_extension_workflow(self):
        """Verify extending active subscription, calculating new expiration date, and audit trail."""
        self.login_as_admin()

        now = utcnow()
        initial_end = now + timedelta(days=15)

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="active",
                start_date=now - timedelta(days=5),
                end_date=initial_end
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        # 1. Validation: Non-positive extension rejected
        bad_ext = self.client.post(f"/api/admin/subscriptions/{sub_id}/extend", json={
            "extension_days": 0
        })
        self.assertEqual(bad_ext.status_code, 400)

        # 2. Valid Extension: Append 30 days
        ext_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/extend", json={
            "extension_days": 30,
            "notes": "VIP Courtesy Grant"
        })
        self.assertEqual(ext_res.status_code, 200)
        s_dict = ext_res.get_json()["subscription"]
        self.assertEqual(s_dict["status"], "active")

        # Stored end date must equal initial_end + 30 days (+- 2 seconds tolerance)
        expected_end = initial_end + timedelta(days=30)
        actual_end = datetime.fromisoformat(s_dict["end_date"].replace("Z", "+00:00"))
        delta_seconds = abs((actual_end - ensure_utc(expected_end)).total_seconds())
        self.assertLess(delta_seconds, 3)

        # Verify audit log
        with get_db_session() as session:
            audit = session.query(SubscriptionAuditLog).filter_by(
                subscription_id=sub_id,
                action="EXTENDED"
            ).first()
            self.assertIsNotNone(audit)
            self.assertIn("VIP Courtesy Grant", audit.details)

    def test_08_subscription_renewal_workflow(self):
        """Verify renewing an expired subscription starting from current UTC time."""
        self.login_as_admin()

        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="expired",
                start_date=utcnow() - timedelta(days=60),
                end_date=utcnow() - timedelta(days=10)
            )
            session.add(sub)
            session.flush()
            sub_id = sub.id

        renew_res = self.client.post(f"/api/admin/subscriptions/{sub_id}/renew", json={
            "duration_days": 60,
            "notes": "Annual contract renewal"
        })
        self.assertEqual(renew_res.status_code, 200)
        data = renew_res.get_json()["subscription"]
        self.assertEqual(data["status"], "active")
        self.assertTrue(data["is_valid_active"])

        # Start date should be current (within last 5 seconds)
        start_dt = datetime.fromisoformat(data["start_date"].replace("Z", "+00:00"))
        self.assertLess(abs((utcnow() - start_dt).total_seconds()), 5)

    def test_09_subscription_lifecycle_approvals_rejections_and_cancellations(self):
        """Verify state transitions: Pending -> Active (Approve), Pending -> Rejected, Active -> Canceled."""
        self.login_as_admin()

        # 1. Approve Request
        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).filter_by(is_active=True).first()
            pending_sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="pending"
            )
            session.add(pending_sub)
            session.flush()
            pending_id = pending_sub.id

        appr_res = self.client.post(f"/api/admin/subscriptions/{pending_id}/approve", json={
            "notes": "Approved for field exercise"
        })
        self.assertEqual(appr_res.status_code, 200)
        self.assertEqual(appr_res.get_json()["subscription"]["status"], "active")

        # 2. Cancel Active Subscription
        canc_res = self.client.post(f"/api/admin/subscriptions/{pending_id}/cancel", json={
            "reason": "Project concluded early"
        })
        self.assertEqual(canc_res.status_code, 200)
        self.assertEqual(canc_res.get_json()["subscription"]["status"], "canceled")

        # 3. Reject Pending Request
        with get_db_session() as session:
            reject_sub = UserSubscription(
                user_id=self.user_id,
                plan_id=plan.id,
                status="pending"
            )
            session.add(reject_sub)
            session.flush()
            reject_id = reject_sub.id

        rej_res = self.client.post(f"/api/admin/subscriptions/{reject_id}/reject", json={
            "reason": "Missing administrative authorization"
        })
        self.assertEqual(rej_res.status_code, 200)
        self.assertEqual(rej_res.get_json()["subscription"]["status"], "rejected")

        # 4. Verify Cannot Extend Rejected Subscription
        rej_ext = self.client.post(f"/api/admin/subscriptions/{reject_id}/extend", json={
            "extension_days": 30
        })
        self.assertEqual(rej_ext.status_code, 400)

    def test_10_rbac_restrictions_on_non_admin_users(self):
        """Verify standard users are strictly denied from all admin subscription and plan endpoints."""
        self.login_as_regular()

        # Plan create
        self.assertEqual(self.client.post("/api/admin/plans", json={"name": "Hacked Plan"}).status_code, 403)
        # Plan update
        self.assertEqual(self.client.put("/api/admin/plans/1", json={"price": 0}).status_code, 403)
        # Plan status
        self.assertEqual(self.client.patch("/api/admin/plans/1/status", json={"is_active": False}).status_code, 403)
        # Plan delete
        self.assertEqual(self.client.delete("/api/admin/plans/1").status_code, 403)
        # Subscriptions list
        self.assertEqual(self.client.get("/api/admin/subscriptions").status_code, 403)
        # Subscription dates
        self.assertEqual(self.client.post("/api/admin/subscriptions/1/adjust-dates", json={}).status_code, 403)
        # Subscription extend
        self.assertEqual(self.client.post("/api/admin/subscriptions/1/extend", json={}).status_code, 403)
        # Subscription approve
        self.assertEqual(self.client.post("/api/admin/subscriptions/1/approve", json={}).status_code, 403)

    def test_11_audit_logs_retrieval_and_metrics(self):
        """Verify audit trail list endpoint and platform overview metrics endpoint."""
        self.login_as_admin()

        # 1. Audit logs
        a_res = self.client.get("/api/admin/audit-logs")
        self.assertEqual(a_res.status_code, 200)
        logs = a_res.get_json()["audit_logs"]
        self.assertIsInstance(logs, list)

        # 2. Platform Metrics
        m_res = self.client.get("/api/admin/metrics")
        self.assertEqual(m_res.status_code, 200)
        m = m_res.get_json()["metrics"]
        self.assertIn("total_users", m)
        self.assertIn("active_subscriptions", m)
        self.assertIn("pending_subscriptions", m)
        self.assertIn("available_plans", m)
        self.assertIn("total_plans", m)

    # ==========================================================================
    # Part 3: Frontend Integrity & Interactive Markup Verification
    # ==========================================================================

    def test_12_frontend_template_and_javascript_controls(self):
        """Verify frontend ddos.html markup and main.js controllers contain all required interactive elements."""
        template_path = os.path.join(os.path.dirname(__file__), "..", "templates", "ddos.html")
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "main.js")
        css_path = os.path.join(os.path.dirname(__file__), "..", "static", "style.css")

        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

        with open(js_path, "r", encoding="utf-8") as f:
            js_content = f.read()

        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()

        # 1. Plan Catalog Controls in ddos.html
        self.assertIn('id="adminPlanSearchInput"', template_content)
        self.assertIn('id="adminPlanStatusFilter"', template_content)
        self.assertIn('id="refreshPlansBtn"', template_content)
        self.assertIn('id="adminCreatePlanBtn"', template_content)

        # 2. Date Adjustment Reason in ddos.html
        self.assertIn('id="dateAdjustmentReason"', template_content)

        # 3. Dynamic Calculation Preview Box in ddos.html
        self.assertIn('id="extendPreviewBox"', template_content)
        self.assertIn('id="extendCurrentExpiryDisplay"', template_content)
        self.assertIn('id="extendDeltaDisplay"', template_content)
        self.assertIn('id="extendNewExpiryDisplay"', template_content)

        # 4. Strict UTC date formatting and preview logic in main.js
        self.assertIn('timeZone: "UTC"', js_content)
        self.assertIn("updateExtendCalculationPreview", js_content)
        self.assertIn("toUtcDatetimeLocal", js_content)
        self.assertIn("fromUtcDatetimeLocal", js_content)

        # 5. CSS Styling for extend-preview-box
        self.assertIn(".extend-preview-box", css_content)


if __name__ == "__main__":
    unittest.main()
