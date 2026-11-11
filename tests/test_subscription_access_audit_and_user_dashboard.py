#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Test Suite: Subscription Access Audit & User Dashboard Improvement
Validates:
1. Complete subscription lifecycle (User request -> Admin approval -> Active -> Permissions loaded).
2. Entitlements consistency across backend decorators and my-subscription serialization.
3. Loading states and serialization: my-subscription returns plan object with feature entitlements.
4. Dynamic expiration handling and expired subscription restriction.
5. Suspended account blocking.
6. Dashboard HTML structure and absence of hardcoded fake statistics in the user dashboard.
7. Quick access buttons and feature-level permission rules.
"""

import os
import sys
import unittest
import tempfile
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User, utcnow
from modules.auth.security import create_session_token, COOKIE_NAME
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, ensure_utc
from modules.subscriptions.services import activate_subscription, request_subscription
from modules.subscriptions.decorators import evaluate_user_entitlement


class TestSubscriptionAccessAuditAndUserDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "scout-audit-dashboard-test-2026"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_audit_dash.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed Admin, Standard User, and Plans
        with self.SessionFactory() as session:
            self.admin_user = User(
                username="admin_soc",
                email="admin_soc@scout.local",
                full_name="Admin Chief",
                phone_number="+201011112222",
                role="Admin",
                is_active=True
            )
            self.admin_user.set_password("12345678")

            self.standard_user = User(
                username="analyst_jane",
                email="jane@scout.local",
                full_name="Jane Doe",
                phone_number="+201033334444",
                role="User",
                is_active=True
            )
            self.standard_user.set_password("87654321")

            # Plan A: Full tools plan (all features True)
            self.plan_full = SubscriptionPlan(
                plan_code="FULL_TIER",
                name="Complete Defense SOC Tier",
                description="All operational cybersecurity capabilities.",
                price=50.0,
                currency="USD",
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            self.plan_full.set_features({
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "can_export_reports": True
            })

            # Plan B: Partial tools plan (only Live Monitoring, no Port Scanner or ND)
            self.plan_partial = SubscriptionPlan(
                plan_code="MONITOR_ONLY",
                name="Monitoring Only Tier",
                description="Live monitoring passive interception only.",
                price=20.0,
                currency="USD",
                duration_value=14,
                duration_unit="days",
                is_active=True
            )
            self.plan_partial.set_features({
                "can_live_monitoring": True,
                "can_port_scan": False,
                "can_network_discovery": False,
                "can_export_reports": False
            })

            session.add_all([self.admin_user, self.standard_user, self.plan_full, self.plan_partial])
            session.commit()
            self.admin_id = self.admin_user.id
            self.user_id = self.standard_user.id
            self.plan_full_id = self.plan_full.id
            self.plan_partial_id = self.plan_partial.id

    def tearDown(self):
        if hasattr(self, "engine"):
            self.engine.dispose()
        if self.old_db_path is not None:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _login(self, user_id: int):
        with self.SessionFactory() as session:
            user = session.query(User).filter_by(id=user_id).first()
            role = user.role
            session_version = getattr(user, "session_version", 1)
            token = create_session_token(user.id, role, session_version)
        self.client.set_cookie(COOKIE_NAME, token)
        return token

    def test_complete_subscription_lifecycle_and_immediate_entitlement(self):
        """
        Scenario 1: User submits request -> Admin approves -> Subscription becomes active.
        User fetches my-subscription -> receives full plan details and feature dictionary.
        User immediately gains access to permitted operational endpoints.
        """
        self._login(self.user_id)

        # 1. Initially user has no subscription
        res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["has_subscription"])
        self.assertIsNone(data["subscription"])

        # Operational tools must be blocked
        res_scan = self.client.get("/api/scan-status")
        self.assertEqual(res_scan.status_code, 403)

        # 2. User submits request for Full Tier
        res_req = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_full_id})
        self.assertEqual(res_req.status_code, 201)
        sub_id = res_req.get_json()["subscription"]["id"]

        # Check my-subscription during pending state
        res_sub = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res_sub.status_code, 200)
        pending_data = res_sub.get_json()
        self.assertFalse(pending_data["has_subscription"])
        self.assertEqual(pending_data["subscription"]["status"], "pending")
        self.assertEqual(pending_data["subscription"]["plan_name"], "Complete Defense SOC Tier")

        # 3. Admin approves and activates subscription
        success, msg, sub_dict = activate_subscription(subscription_id=sub_id, admin_id=self.admin_id)
        self.assertTrue(success)
        self.assertEqual(sub_dict["status"], "active")

        # 4. User refreshes/queries my-subscription immediately
        res_active = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res_active.status_code, 200)
        active_data = res_active.get_json()
        self.assertTrue(active_data["has_subscription"])
        sub_info = active_data["subscription"]
        self.assertEqual(sub_info["status"], "active")
        self.assertTrue(sub_info["is_valid_active"])
        self.assertEqual(sub_info["plan_name"], "Complete Defense SOC Tier")
        self.assertIsNotNone(sub_info["plan"])
        self.assertEqual(sub_info["plan"]["name"], "Complete Defense SOC Tier")
        self.assertTrue(sub_info["features"]["can_live_monitoring"])
        self.assertTrue(sub_info["features"]["can_port_scan"])
        self.assertTrue(sub_info["features"]["can_network_discovery"])
        self.assertGreater(sub_info["days_remaining"], 0)

        # 5. Permitted operational tools are immediately accessible
        res_tools = self.client.get("/api/scan-status")
        self.assertEqual(res_tools.status_code, 200)
        res_attacks = self.client.get("/api/detected-attacks")
        self.assertEqual(res_attacks.status_code, 200)
        res_port = self.client.get("/api/port-scan/status")
        self.assertEqual(res_port.status_code, 200)
        res_nd = self.client.get("/api/network-discovery/status")
        self.assertEqual(res_nd.status_code, 200)

    def test_feature_permissions_granular_isolation(self):
        """
        Scenario 2: Plan with partial features (Live Monitoring only).
        Live Monitoring is unlocked, while Port Scanner and Network Discovery remain restricted.
        """
        self._login(self.user_id)
        res_req = self.client.post("/api/subscriptions/request", json={"plan_id": self.plan_partial_id})
        self.assertEqual(res_req.status_code, 201)
        sub_id = res_req.get_json()["subscription"]["id"]

        # Admin activates the partial plan
        success, _, _ = activate_subscription(subscription_id=sub_id, admin_id=self.admin_id)
        self.assertTrue(success)

        # Live Monitoring must succeed
        res_scan = self.client.get("/api/scan-status")
        self.assertEqual(res_scan.status_code, 200)
        res_attacks = self.client.get("/api/detected-attacks")
        self.assertEqual(res_attacks.status_code, 200)

        # Port Scanner must be restricted (403 with feature_restricted reason)
        res_port = self.client.get("/api/port-scan/status")
        self.assertEqual(res_port.status_code, 403)
        port_json = res_port.get_json()
        self.assertIn("Monitoring Only Tier", port_json["message"])

        # Network Discovery must be restricted (403 with feature_restricted reason)
        res_nd = self.client.get("/api/network-discovery/status")
        self.assertEqual(res_nd.status_code, 403)
        nd_json = res_nd.get_json()
        self.assertIn("Monitoring Only Tier", nd_json["message"])

    def test_dynamic_expiration_sync_and_access_revocation(self):
        """
        Scenario 3: Subscription past its end_date is marked expired dynamically.
        my-subscription returns has_subscription: False and status: 'expired'.
        Operational access is revoked.
        """
        # Create an active subscription with past end_date
        past_start = utcnow() - timedelta(days=60)
        past_end = utcnow() - timedelta(days=30)
        with self.SessionFactory() as session:
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=self.plan_full_id,
                status="active",
                start_date=past_start,
                end_date=past_end
            )
            session.add(sub)
            session.commit()

        self._login(self.user_id)

        # Fetch my-subscription -> must recognize dynamic expiration
        res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["has_subscription"])
        self.assertEqual(data["subscription"]["status"], "expired")
        self.assertFalse(data["subscription"]["is_valid_active"])

        # Protected tools must reject expired subscription
        res_scan = self.client.get("/api/scan-status")
        self.assertEqual(res_scan.status_code, 403)
        self.assertIn("expired", res_scan.get_json()["message"].lower())

    def test_suspended_account_blocks_restricted_access(self):
        """
        Scenario 4: Suspended user cannot access operational tools, even with active subscription.
        """
        with self.SessionFactory() as session:
            user = session.query(User).filter_by(id=self.user_id).first()
            user.is_active = False
            sub = UserSubscription(
                user_id=self.user_id,
                plan_id=self.plan_full_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub)
            session.commit()

        self._login(self.user_id)

        # /api/auth/me returns 403 ACCOUNT_DISABLED
        res_me = self.client.get("/api/auth/me")
        self.assertEqual(res_me.status_code, 403)

        # Tool endpoint returns 403
        res_scan = self.client.get("/api/scan-status")
        self.assertEqual(res_scan.status_code, 403)
        self.assertIn("suspended", res_scan.get_json()["message"].lower())

    def test_dashboard_html_structure_and_no_fake_statistics(self):
        """
        Scenario 5: User dashboard HTML element IDs match JavaScript bindings.
        No hardcoded fake percentages like '99.86%' or hardcoded '15' in the user dashboard threat card.
        """
        template_path = PROJECT_ROOT / "templates" / "ddos.html"
        self.assertTrue(template_path.exists())
        content = template_path.read_text(encoding="utf-8")

        # Essential header element IDs
        self.assertIn('id="userDashGreeting"', content)
        self.assertIn('id="userDashAvatar"', content)
        self.assertIn('id="userDashEmail"', content)
        self.assertIn('id="userDashRoleBadge"', content)
        self.assertIn('id="userDashPlanName"', content)
        self.assertIn('id="userDashStatusPill"', content)
        self.assertIn('id="userDashCountdown"', content)

        # Tool launchpad IDs
        self.assertIn('id="dashToolMonitorCard"', content)
        self.assertIn('id="dashMonitorEntitlementBadge"', content)
        self.assertIn('id="dashLaunchMonitorBtn"', content)
        self.assertIn('id="dashToolPortCard"', content)
        self.assertIn('id="dashPortEntitlementBadge"', content)
        self.assertIn('id="dashLaunchPortBtn"', content)
        self.assertIn('id="dashToolNdCard"', content)
        self.assertIn('id="dashNdEntitlementBadge"', content)
        self.assertIn('id="dashLaunchNdBtn"', content)

        # Secondary row subscription validity IDs
        self.assertIn('id="userDashDetailTier"', content)
        self.assertIn('id="userDashDetailStatus"', content)
        self.assertIn('id="userDashDetailStartDate"', content)
        self.assertIn('id="userDashDetailEndDate"', content)
        self.assertIn('id="userDashDetailRemaining"', content)

        # Telemetry snapshot real IDs
        self.assertIn('id="userDashThreatCount"', content)
        self.assertIn('id="userDashCaptureState"', content)
        self.assertIn('id="userDashRecentEventTime"', content)
        self.assertIn('id="userDashTelemetryStatus"', content)
        self.assertIn('id="userDashRecentEventsContainer"', content)

        # Verify NO hardcoded fake stats in the user dashboard
        start_idx = content.find('id="user-dashboard"')
        self.assertNotEqual(start_idx, -1)
        end_idx = content.find('</section>', start_idx)
        dash_section = content[start_idx:end_idx]

        self.assertNotIn("99.86%", dash_section)
        self.assertNotIn("Class Multi-Vector", dash_section)
        self.assertNotIn("userDashRecallRate", dash_section)

    def test_main_js_dashboard_controller_integrity(self):
        """
        Scenario 6: static/main.js correctly queries userDashGreeting, userDashPlanName,
        userDashCountdown, dashMonitorEntitlementBadge, and handles feature entitlements.
        """
        js_path = PROJECT_ROOT / "static" / "main.js"
        self.assertTrue(js_path.exists())
        js_code = js_path.read_text(encoding="utf-8")

        # JavaScript handles userDashGreeting and userDashPlanName
        self.assertIn('userDashGreeting', js_code)
        self.assertIn('userDashPlanName', js_code)
        self.assertIn('userDashStatusPill', js_code)
        self.assertIn('userDashCountdown', js_code)
        self.assertIn('dashMonitorEntitlementBadge', js_code)
        self.assertIn('userDashCaptureState', js_code)
        self.assertIn('userDashRecentEventsContainer', js_code)

        # Ensures loadUserDashboard is called when subscription is fetched while dashboard is visible
        self.assertIn('fetchCurrentUserSubscription', js_code)
        self.assertIn('loadUserDashboard()', js_code)


if __name__ == "__main__":
    unittest.main()
