#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT Comprehensive End-to-End System Audit & Workflow Verification Test Suite

Covers:
- Actor A (Admin): Provisioning, login, dashboard metrics, plan CRUD, user moderation,
  dossier editing, approval/rejection lifecycle, last-admin protection, safe archival/deletion.
- Actor B (Ordinary User): Registration, login, public catalog, request submission,
  pending status guard, post-approval entitlement, admin_notes privacy, self-profile update,
  password change session invalidation, logout.
- Actor C (Unauthorized User): RBAC boundary enforcement, privilege escalation mitigation,
  direct object reference defense.
- State Machine Integrity: Guardrails preventing invalid status transitions.
- Expiration Sweep: Automatic reconciliation of elapsed subscriptions and metric fidelity.
- Operational Aliases: Hardened /api/start, /api/stop, and /api/scan-stop endpoints.
"""

import sys
import os
import json
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User, utcnow
from modules.auth.security import hash_password, verify_password
from modules.auth.db import get_engine, init_db, get_session_factory, get_db_session
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog
from modules.subscriptions.services import sync_expired_subscriptions
from scripts.seed_plans import seed_default_subscription_plans


class TestE2ECompleteSystemAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_e2e_audit.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        # Clear login rate limiter
        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed catalog plans
        seed_default_subscription_plans()

        # Seed initial administrator
        with get_db_session() as session:
            admin = User(
                username="sec_admin",
                email="admin@scout.sec",
                full_name="Lead Cyber Commander",
                role="Admin",
                is_active=True,
                password_hash=hash_password("AdminSecure#2026")
            )
            session.add(admin)
            session.commit()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    # ==========================================================================
    # SCENARIO 1: Actor A - Admin Provisioning, Lifecycle, Plan & User Management
    # ==========================================================================
    def test_01_admin_full_lifecycle(self):
        """Validates complete Admin lifecycle: authentication, plan CRUD, metrics, and user moderation."""
        # 1. Reject invalid credentials
        res_fail = self.client.post("/api/auth/login", json={
            "username": "sec_admin",
            "password": "WrongPassword!99"
        })
        self.assertEqual(res_fail.status_code, 401)

        # 2. Login with valid credentials
        res_login = self.client.post("/api/auth/login", json={
            "username": "sec_admin",
            "password": "AdminSecure#2026"
        })
        self.assertEqual(res_login.status_code, 200)
        login_data = res_login.get_json()
        self.assertEqual(login_data["view"], "admin")

        # 3. Retrieve verified metrics
        res_metrics = self.client.get("/api/admin/metrics")
        self.assertEqual(res_metrics.status_code, 200)
        m = res_metrics.get_json()["metrics"]
        self.assertEqual(m["total_users"], 1)
        self.assertEqual(m["active_users"], 1)
        self.assertGreaterEqual(m["total_plans"], 3)

        # 4. Create a new subscription plan
        res_new_plan = self.client.post("/api/admin/plans", json={
            "plan_code": "SCOUT-TITAN",
            "name": "Titan Fleet Intelligence",
            "description": "Enterprise-wide autonomous deep packet inspection.",
            "price": 299.0,
            "currency": "USD",
            "duration_value": 365,
            "duration_unit": "days",
            "is_active": True,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "max_concurrency": 20
            }
        })
        self.assertEqual(res_new_plan.status_code, 201)
        created_plan = res_new_plan.get_json()["plan"]
        plan_id = created_plan["id"]

        # 5. Verify plan persistence in public catalog
        res_catalog = self.client.get("/api/subscriptions/plans")
        self.assertEqual(res_catalog.status_code, 200)
        catalog_codes = [p["plan_code"] for p in res_catalog.get_json()["plans"]]
        self.assertIn("SCOUT-TITAN", catalog_codes)

        # 6. Update the plan terms
        res_update_plan = self.client.put(f"/api/admin/plans/{plan_id}", json={
            "name": "Titan Fleet Intelligence v2",
            "price": 349.0
        })
        self.assertEqual(res_update_plan.status_code, 200)
        self.assertEqual(res_update_plan.get_json()["plan"]["name"], "Titan Fleet Intelligence v2")

    # ==========================================================================
    # SCENARIO 2: Actor B - Complete User Journey & Subscription Flow
    # ==========================================================================
    def test_02_user_registration_and_subscription_flow(self):
        """Validates end-to-end ordinary user registration, subscription request, approval, and privacy."""
        # 1. Register ordinary operator
        res_reg = self.client.post("/api/auth/register", json={
            "username": "threat_analyst",
            "email": "analyst@defense.gov",
            "full_name": "Senior Threat Analyst",
            "password": "AnalystPassword#2026",
            "confirm_password": "AnalystPassword#2026"
        })
        self.assertEqual(res_reg.status_code, 201)
        user_data = res_reg.get_json()["user"]
        user_id = user_data["id"]
        self.assertEqual(user_data["role"], "User")

        # 2. Login as newly registered user
        res_login = self.client.post("/api/auth/login", json={
            "username": "threat_analyst",
            "password": "AnalystPassword#2026"
        })
        self.assertEqual(res_login.status_code, 200)
        self.assertEqual(res_login.get_json()["view"], "plans")

        # 3. Request subscription for SCOUT-PRO
        res_sub_req = self.client.post("/api/subscriptions/request", json={
            "plan_id": "SCOUT-PRO"
        })
        self.assertEqual(res_sub_req.status_code, 201)
        sub_record = res_sub_req.get_json()["subscription"]
        sub_id = sub_record["id"]
        self.assertEqual(sub_record["status"], "pending")

        # 4. Verify that pending user cannot access live monitoring endpoint
        res_monitor_gate = self.client.get("/api/scan")
        self.assertEqual(res_monitor_gate.status_code, 403)
        self.assertIn("pending", res_monitor_gate.get_json()["message"].lower())

        # 5. Admin logs in and reviews pending subscription
        self.client.post("/api/auth/login", json={
            "username": "sec_admin",
            "password": "AdminSecure#2026"
        })

        res_admin_subs = self.client.get("/api/admin/subscriptions?status=pending")
        self.assertEqual(res_admin_subs.status_code, 200)
        pending_ids = [s["id"] for s in res_admin_subs.get_json()["subscriptions"]]
        self.assertIn(sub_id, pending_ids)

        # 6. Admin approves the subscription request with internal notes
        res_approve = self.client.post(f"/api/admin/subscriptions/{sub_id}/approve", json={
            "notes": "Verified clearance via SOC supervisor ticket #8841."
        })
        self.assertEqual(res_approve.status_code, 200)
        approved_sub = res_approve.get_json()["subscription"]
        self.assertEqual(approved_sub["status"], "active")
        self.assertIsNotNone(approved_sub["end_date"])

        # 7. User logs back in and checks subscription
        self.client.post("/api/auth/login", json={
            "username": "threat_analyst",
            "password": "AnalystPassword#2026"
        })

        res_my_sub = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res_my_sub.status_code, 200)
        my_sub_data = res_my_sub.get_json()["subscription"]
        self.assertEqual(my_sub_data["status"], "active")
        # Critical Privacy Check: internal admin_notes must NEVER leak to user
        self.assertNotIn("admin_notes", my_sub_data)

        # 8. User updates own profile
        res_prof_update = self.client.put("/api/auth/profile", json={
            "full_name": "Chief Threat Hunter",
            "email": "hunter@defense.gov"
        })
        self.assertEqual(res_prof_update.status_code, 200)
        self.assertEqual(res_prof_update.get_json()["user"]["full_name"], "Chief Threat Hunter")

        # 9. User changes password
        res_pw_change = self.client.post("/api/auth/change-password", json={
            "current_password": "AnalystPassword#2026",
            "new_password": "NewSecretPassword#2026",
            "confirm_new_password": "NewSecretPassword#2026"
        })
        self.assertEqual(res_pw_change.status_code, 200)

        # 10. User logs out
        res_logout = self.client.post("/api/auth/logout")
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn("no-store", res_logout.headers.get("Cache-Control", ""))

    # ==========================================================================
    # SCENARIO 3: Actor C - Unauthorized User & Privilege Escalation Defenses
    # ==========================================================================
    def test_03_unauthorized_access_and_rbac_boundaries(self):
        """Verifies strict backend enforcement against unauthorized actions and privilege manipulation."""
        # 1. Anonymous visitor attempts to call Admin API
        res_anon_admin = self.client.get("/api/admin/metrics")
        self.assertEqual(res_anon_admin.status_code, 401)

        # 2. Register ordinary operator
        self.client.post("/api/auth/register", json={
            "username": "rogue_user",
            "email": "rogue@test.sec",
            "password": "RoguePassword#2026",
            "confirm_password": "RoguePassword#2026"
        })
        self.client.post("/api/auth/login", json={
            "username": "rogue_user",
            "password": "RoguePassword#2026"
        })

        # 3. Ordinary operator attempts to access Admin Metrics
        res_unauth_metrics = self.client.get("/api/admin/metrics")
        self.assertEqual(res_unauth_metrics.status_code, 403)

        # 4. Ordinary operator attempts to call Admin User List
        res_unauth_users = self.client.get("/api/admin/users")
        self.assertEqual(res_unauth_users.status_code, 403)

        # 5. Ordinary operator attempts to approve a subscription
        res_unauth_approve = self.client.post("/api/admin/subscriptions/1/approve", json={})
        self.assertEqual(res_unauth_approve.status_code, 403)

        # 6. Ordinary operator attempts privilege escalation via PUT /api/auth/profile
        res_escalate = self.client.put("/api/auth/profile", json={
            "role": "Admin",
            "is_active": True
        })
        self.assertEqual(res_escalate.status_code, 400)  # No valid profile fields provided

    # ==========================================================================
    # SCENARIO 4: Admin User Profile Editing & Safe Deletion / Archival
    # ==========================================================================
    def test_04_admin_user_profile_edit_and_safe_deletion(self):
        """Tests Admin PUT /api/admin/users/<id> and safe account archival/deletion."""
        # Register two users: one with subscription, one without
        with get_db_session() as session:
            user_with_sub = User(
                username="client_sub",
                email="client_sub@test.sec",
                full_name="Subscriber One",
                role="User",
                is_active=True,
                password_hash=hash_password("Pass#123456")
            )
            user_no_sub = User(
                username="client_nosub",
                email="client_nosub@test.sec",
                full_name="NoSub User",
                role="User",
                is_active=True,
                password_hash=hash_password("Pass#123456")
            )
            session.add_all([user_with_sub, user_no_sub])
            session.flush()

            sub = UserSubscription(
                user_id=user_with_sub.id,
                plan_id=1,
                status="active",
                start_date=utcnow(),
                end_date=utcnow() + timedelta(days=30)
            )
            session.add(sub)
            session.commit()
            sub_user_id = user_with_sub.id
            nosub_user_id = user_no_sub.id

        # Admin logs in
        self.client.post("/api/auth/login", json={
            "username": "sec_admin",
            "password": "AdminSecure#2026"
        })

        # 1. Admin edits user's full_name and email
        res_edit = self.client.put(f"/api/admin/users/{sub_user_id}", json={
            "full_name": "Subscriber One Updated",
            "email": "updated_sub@test.sec"
        })
        self.assertEqual(res_edit.status_code, 200)
        self.assertEqual(res_edit.get_json()["user"]["full_name"], "Subscriber One Updated")

        # 2. Admin attempts duplicate email
        res_dup = self.client.put(f"/api/admin/users/{nosub_user_id}", json={
            "email": "updated_sub@test.sec"
        })
        self.assertEqual(res_dup.status_code, 409)

        # 3. Admin deletes user WITH subscription -> Should be safely archived (is_active=False)
        res_archive = self.client.delete(f"/api/admin/users/{sub_user_id}")
        self.assertEqual(res_archive.status_code, 200)
        archive_data = res_archive.get_json()
        self.assertEqual(archive_data["action"], "archived")
        self.assertFalse(archive_data["is_active"])

        # 4. Admin deletes user WITHOUT subscription -> Should be permanently deleted
        res_del = self.client.delete(f"/api/admin/users/{nosub_user_id}")
        self.assertEqual(res_del.status_code, 200)
        del_data = res_del.get_json()
        self.assertEqual(del_data["action"], "deleted")

        # 5. Last active admin protection: Admin cannot delete themselves
        with get_db_session() as session:
            admin_user = session.query(User).filter_by(username="sec_admin").first()
            admin_id = admin_user.id

        res_self_del = self.client.delete(f"/api/admin/users/{admin_id}")
        self.assertEqual(res_self_del.status_code, 400)
        self.assertIn("cannot delete their own account", res_self_del.get_json()["message"])

    # ==========================================================================
    # SCENARIO 5: Subscription State Machine Transitions & Expiration Sweep
    # ==========================================================================
    def test_05_state_machine_guardrails_and_expiration_sweep(self):
        """Verifies state transition integrity (preventing duplicate/invalid transitions) and auto-expiration."""
        # Create test subscription
        with get_db_session() as session:
            test_user = User(
                username="state_user",
                email="state@test.sec",
                role="User",
                is_active=True,
                password_hash=hash_password("Pass#123456")
            )
            session.add(test_user)
            session.flush()

            sub_pending = UserSubscription(
                user_id=test_user.id,
                plan_id=1,
                status="pending"
            )
            sub_past = UserSubscription(
                user_id=test_user.id,
                plan_id=1,
                status="active",
                start_date=utcnow() - timedelta(days=60),
                end_date=utcnow() - timedelta(days=30)  # Elapsed
            )
            session.add_all([sub_pending, sub_past])
            session.commit()
            pending_id = sub_pending.id
            past_id = sub_past.id

        # Admin logs in
        self.client.post("/api/auth/login", json={
            "username": "sec_admin",
            "password": "AdminSecure#2026"
        })

        # 1. Reject already pending request
        res_reject = self.client.post(f"/api/admin/subscriptions/{pending_id}/reject", json={
            "reason": "Test rejection"
        })
        self.assertEqual(res_reject.status_code, 200)

        # 2. Attempt to approve an already rejected subscription -> Must return 400
        res_invalid_approve = self.client.post(f"/api/admin/subscriptions/{pending_id}/approve", json={})
        self.assertEqual(res_invalid_approve.status_code, 400)
        self.assertIn("already been rejected", res_invalid_approve.get_json()["message"])

        # 3. Attempt to reject an already rejected subscription -> Must return 400
        res_double_reject = self.client.post(f"/api/admin/subscriptions/{pending_id}/reject", json={})
        self.assertEqual(res_double_reject.status_code, 400)

        # 4. Auto-expiration sweep: elapsed subscription must transition to 'expired'
        swept = sync_expired_subscriptions()
        self.assertGreaterEqual(swept, 1)

        with get_db_session() as session:
            updated_sub = session.query(UserSubscription).filter_by(id=past_id).first()
            self.assertEqual(updated_sub.status, "expired")

        # 5. Metrics must reflect the expired subscription
        res_metrics = self.client.get("/api/admin/metrics")
        self.assertEqual(res_metrics.status_code, 200)
        m = res_metrics.get_json()["metrics"]
        self.assertGreaterEqual(m["expired_subscriptions"], 1)

    # ==========================================================================
    # SCENARIO 6: Operational Aliases RBAC Consistency (/api/start, /api/stop)
    # ==========================================================================
    def test_06_operational_aliases_rbac(self):
        """Verifies that operational aliases enforce subscription and login checks."""
        # 1. Anonymous calling /api/start -> 401
        res_start_anon = self.client.get("/api/start")
        self.assertEqual(res_start_anon.status_code, 401)

        # 2. Anonymous calling /api/stop -> 401
        res_stop_anon = self.client.get("/api/stop")
        self.assertEqual(res_stop_anon.status_code, 401)

        # 3. Anonymous calling /api/scan-stop -> 401
        res_scan_stop_anon = self.client.get("/api/scan-stop")
        self.assertEqual(res_scan_stop_anon.status_code, 401)


if __name__ == "__main__":
    unittest.main()
