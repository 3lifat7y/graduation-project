#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Test Suite: Subscription-Based Access Control & Dynamic User Navigation in SCOUT
Validates all 11 core verification scenarios required by SCOUT platform specifications:
1. Active user with active subscription (Dashboard + all operational tools accessible, sidebar items displayed).
2. Active user without any subscription (Dashboard + tools locked, redirected to plans, plans + profile accessible).
3. Active user with expired subscription (Operational access revoked, redirected to plans with expired alert).
4. User with pending subscription request (Pending status displayed, operational features remain locked).
5. Banned user with no subscription (Account blocked 403 ACCOUNT_DISABLED, plans and tools locked).
6. Banned user with active subscription (Account blocked 403, active sub does NOT grant access).
7. Suspended user with expired subscription (Account blocked 403, renewals and plans blocked).
8. User whose subscription is renewed/activated (Operational access immediately restored).
9. Administrator account (Full access to Admin Console and operational tools without subscription restrictions).
10. Direct URL access to protected pages (Server-side redirect or 401/403 responses).
11. Direct API access to protected endpoints (/api/scan-status, /api/detected-attacks, /api/port-scan/status, etc.).
"""

import os
import sys
import unittest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.security import create_session_token, COOKIE_NAME
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, utcnow
from modules.subscriptions.services import activate_subscription, determine_user_landing_view


class TestSubscriptionAccessControl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "scout-access-control-test-key-2026"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_access_control.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed Database
        with self.SessionFactory() as session:
            # Plan 1: Full Pro
            self.plan_pro = SubscriptionPlan(
                plan_code="SCOUT-PRO-ENTERPRISE",
                name="SCOUT Enterprise Suite",
                description="Complete cyber defense toolkit",
                price=99.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            self.plan_pro.set_features({
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "max_concurrent_scans": 5
            })

            # Plan 2: Basic Tier (Monitoring only)
            self.plan_basic = SubscriptionPlan(
                plan_code="SCOUT-BASIC-TIER",
                name="SCOUT Basic Monitoring",
                description="Live telemetry only",
                price=19.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            self.plan_basic.set_features({
                "can_live_monitoring": True,
                "can_port_scan": False,
                "can_network_discovery": False,
                "max_concurrent_scans": 1
            })

            session.add_all([self.plan_pro, self.plan_basic])
            session.commit()

            # 1. Admin
            self.admin_user = User(
                username="admin_sec",
                email="admin@scout.local",
                role="Admin",
                is_active=True
            )
            self.admin_user.set_password("AdminSecurePass!1")

            # 2. Active User with Active Pro Subscription
            self.user_active = User(
                username="user_active_sub",
                email="active_sub@scout.local",
                role="User",
                is_active=True
            )
            self.user_active.set_password("UserActivePass!1")

            # 3. Active User with No Subscription
            self.user_none = User(
                username="user_no_sub",
                email="no_sub@scout.local",
                role="User",
                is_active=True
            )
            self.user_none.set_password("UserNoSubPass!1")

            # 4. Active User with Expired Subscription
            self.user_expired = User(
                username="user_expired_sub",
                email="expired_sub@scout.local",
                role="User",
                is_active=True
            )
            self.user_expired.set_password("UserExpiredPass!1")

            # 5. Active User with Pending Subscription Request
            self.user_pending = User(
                username="user_pending_sub",
                email="pending_sub@scout.local",
                role="User",
                is_active=True
            )
            self.user_pending.set_password("UserPendingPass!1")

            # 6. Banned/Suspended User with No Subscription
            self.user_banned_none = User(
                username="banned_no_sub",
                email="banned_none@scout.local",
                role="User",
                is_active=False
            )
            self.user_banned_none.set_password("BannedUserPass!1")

            # 7. Banned/Suspended User with an Active Subscription Record
            self.user_banned_active = User(
                username="banned_active_sub",
                email="banned_active@scout.local",
                role="User",
                is_active=False
            )
            self.user_banned_active.set_password("BannedActivePass!1")

            # 8. Banned/Suspended User with Expired Subscription
            self.user_banned_expired = User(
                username="banned_expired_sub",
                email="banned_expired@scout.local",
                role="User",
                is_active=False
            )
            self.user_banned_expired.set_password("BannedExpiredPass!1")

            session.add_all([
                self.admin_user,
                self.user_active,
                self.user_none,
                self.user_expired,
                self.user_pending,
                self.user_banned_none,
                self.user_banned_active,
                self.user_banned_expired
            ])
            session.commit()

            # Add subscriptions
            now = utcnow()

            # Active Pro sub
            sub_active = UserSubscription(
                user_id=self.user_active.id,
                plan_id=self.plan_pro.id,
                status="active",
                start_date=now - timedelta(days=2),
                end_date=now + timedelta(days=28)
            )

            # Expired sub
            sub_expired = UserSubscription(
                user_id=self.user_expired.id,
                plan_id=self.plan_pro.id,
                status="expired",
                start_date=now - timedelta(days=35),
                end_date=now - timedelta(days=5)
            )

            # Pending sub
            sub_pending = UserSubscription(
                user_id=self.user_pending.id,
                plan_id=self.plan_pro.id,
                status="pending"
            )

            # Banned user with active sub record
            sub_banned_active = UserSubscription(
                user_id=self.user_banned_active.id,
                plan_id=self.plan_pro.id,
                status="active",
                start_date=now - timedelta(days=1),
                end_date=now + timedelta(days=29)
            )

            # Banned user with expired sub record
            sub_banned_expired = UserSubscription(
                user_id=self.user_banned_expired.id,
                plan_id=self.plan_pro.id,
                status="expired",
                start_date=now - timedelta(days=40),
                end_date=now - timedelta(days=10)
            )

            session.add_all([
                sub_active,
                sub_expired,
                sub_pending,
                sub_banned_active,
                sub_banned_expired
            ])
            session.commit()

            # Keep IDs
            self.admin_id = self.admin_user.id
            self.user_active_id = self.user_active.id
            self.user_none_id = self.user_none.id
            self.user_expired_id = self.user_expired.id
            self.user_pending_id = self.user_pending.id
            self.user_banned_none_id = self.user_banned_none.id
            self.user_banned_active_id = self.user_banned_active.id
            self.user_banned_expired_id = self.user_banned_expired.id

    def tearDown(self):
        if hasattr(self, 'engine'):
            self.engine.dispose()
        if self.old_db_path is not None:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        elif "SCOUT_DB_PATH" in os.environ:
            del os.environ["SCOUT_DB_PATH"]
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _get_token(self, user_id, role="User", session_version=1):
        return create_session_token(user_id, role, session_version)

    def _auth_headers(self, user_id, role="User", session_version=1):
        token = self._get_token(user_id, role, session_version)
        return {
            "Authorization": f"Bearer {token}",
            "Cookie": f"{COOKIE_NAME}={token}"
        }

    # =========================================================================
    # Scenario 1: Active User with Active Subscription
    # =========================================================================
    def test_scenario_1_active_user_with_active_subscription(self):
        """Active user with active subscription can access Dashboard and operational tools."""
        headers = self._auth_headers(self.user_active_id)

        # 1. API: Auth me verifies active subscription and landing on dashboard
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["has_active_subscription"])
        self.assertEqual(data["subscription_status"], "active")
        self.assertEqual(data["view"], "dashboard")
        self.assertEqual(data["landing_url"], "/?view=dashboard")

        # 2. Page: Direct access to dashboard view
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 200)

        # 3. Page: Direct access to network discovery page
        res = self.client.get("/network-discovery", headers=headers)
        self.assertEqual(res.status_code, 200)

        # 4. APIs: Operational monitoring endpoints succeed
        res = self.client.get("/api/scan-status", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/detected-attacks", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/port-scan/status", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/network-discovery/status", headers=headers)
        self.assertEqual(res.status_code, 200)

    # =========================================================================
    # Scenario 2: Active User without Any Subscription
    # =========================================================================
    def test_scenario_2_active_user_without_subscription(self):
        """Active user without subscription: operational tools locked, redirected to plans."""
        headers = self._auth_headers(self.user_none_id)

        # 1. API: Auth me shows no subscription and landing on plans
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["has_active_subscription"])
        self.assertEqual(data["subscription_status"], "none")
        self.assertEqual(data["view"], "plans")
        self.assertEqual(data["landing_url"], "/?view=plans")

        # 2. Page: Direct access to dashboard redirects to plans
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/?view=plans", res.headers.get("Location", ""))

        # 3. Page: Direct access to /dashboard redirects to plans
        res = self.client.get("/dashboard", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/?view=plans", res.headers.get("Location", ""))

        # 4. Page: Direct access to network discovery redirects to plans
        res = self.client.get("/network-discovery", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/?view=plans", res.headers.get("Location", ""))

        # 5. APIs: Operational endpoints return 403 SUBSCRIPTION_REQUIRED
        for endpoint in ["/api/scan-status", "/api/detected-attacks", "/api/port-scan/status", "/api/network-discovery/status"]:
            res = self.client.get(endpoint, headers=headers)
            self.assertEqual(res.status_code, 403)
            data = res.get_json()
            self.assertEqual(data["code"], "SUBSCRIPTION_REQUIRED")
            self.assertIn("active subscription", data["message"].lower())

        # 6. Plans catalog remains accessible
        res = self.client.get("/api/plans", headers=headers)
        self.assertEqual(res.status_code, 200)

    # =========================================================================
    # Scenario 3: Active User with Expired Subscription
    # =========================================================================
    def test_scenario_3_active_user_with_expired_subscription(self):
        """Active user with expired subscription: operational tools locked, redirected with expired notice."""
        headers = self._auth_headers(self.user_expired_id)

        # 1. API: Auth me shows expired status and landing on plans
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["has_active_subscription"])
        self.assertEqual(data["subscription_status"], "expired")
        self.assertIn("status=expired", data["landing_url"])

        # 2. Page: Direct access to dashboard redirects to plans with status=expired
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("status=expired", res.headers.get("Location", ""))

        # 3. Page: Direct access to network discovery redirects to plans with status=expired
        res = self.client.get("/network-discovery", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("status=expired", res.headers.get("Location", ""))

        # 4. APIs: Operational endpoints return 403 SUBSCRIPTION_EXPIRED
        res = self.client.get("/api/scan-status", headers=headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "SUBSCRIPTION_EXPIRED")
        self.assertIn("expired", data["message"].lower())

    # =========================================================================
    # Scenario 4: User with Pending Subscription Request
    # =========================================================================
    def test_scenario_4_user_with_pending_subscription_request(self):
        """User with pending subscription request: operational tools remain locked."""
        headers = self._auth_headers(self.user_pending_id)

        # 1. API: Auth me shows pending status
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["has_active_subscription"])
        self.assertEqual(data["subscription_status"], "pending")
        self.assertIn("status=pending", data["landing_url"])

        # 2. Operational API calls return 403 SUBSCRIPTION_PENDING
        res = self.client.get("/api/scan-status", headers=headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "SUBSCRIPTION_PENDING")
        self.assertIn("awaiting administrator approval", data["message"].lower())

        # 3. Direct access to dashboard redirects to plans with status=pending
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("status=pending", res.headers.get("Location", ""))

    # =========================================================================
    # Scenario 5: Banned User with No Subscription
    # =========================================================================
    def test_scenario_5_banned_user_with_no_subscription(self):
        """Banned user without subscription: blocked with 403 ACCOUNT_DISABLED across all endpoints."""
        headers = self._auth_headers(self.user_banned_none_id)

        # 1. Auth me returns 403 ACCOUNT_DISABLED
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "ACCOUNT_DISABLED")
        self.assertIn("suspended", data["message"].lower())

        # 2. Cannot view public plans catalog while authenticated as banned
        res = self.client.get("/api/plans", headers=headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "ACCOUNT_DISABLED")

        # 3. Cannot submit subscription request
        res = self.client.post("/api/subscriptions/request", headers=headers, json={"plan_id": self.plan_pro.id})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "ACCOUNT_DISABLED")

        # 4. Navigating to plans redirects to suspended view
        res = self.client.get("/?view=plans", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("view=suspended", res.headers.get("Location", ""))

    # =========================================================================
    # Scenario 6: Banned User with Active Subscription Record
    # =========================================================================
    def test_scenario_6_banned_user_with_active_subscription(self):
        """Account suspension strictly overrides active subscription: blocked with 403 ACCOUNT_DISABLED."""
        headers = self._auth_headers(self.user_banned_active_id)

        # 1. Auth me returns 403 ACCOUNT_DISABLED
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "ACCOUNT_DISABLED")
        self.assertIn("suspended", data["message"].lower())

        # 2. Operational endpoints are completely blocked despite active subscription in DB
        for endpoint in ["/api/scan-status", "/api/detected-attacks", "/api/port-scan/status", "/api/network-discovery/status"]:
            res = self.client.get(endpoint, headers=headers)
            self.assertEqual(res.status_code, 403)
            data = res.get_json()
            self.assertEqual(data["code"], "ACCOUNT_DISABLED")
            self.assertIn("suspended", data["message"].lower())

        # 3. Direct page access redirects to suspended view
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("view=suspended", res.headers.get("Location", ""))

        res = self.client.get("/network-discovery", headers=headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("view=suspended", res.headers.get("Location", ""))

    # =========================================================================
    # Scenario 7: Suspended User with Expired Subscription
    # =========================================================================
    def test_scenario_7_suspended_user_with_expired_subscription(self):
        """Suspended user with expired subscription: blocked from plans and renewal actions."""
        headers = self._auth_headers(self.user_banned_expired_id)

        # 1. Submitting renewal request blocked with 403 ACCOUNT_DISABLED
        res = self.client.post("/api/subscriptions/request", headers=headers, json={"plan_id": self.plan_pro.id})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["code"], "ACCOUNT_DISABLED")

        # 2. Browsing plans returns 403 ACCOUNT_DISABLED
        res = self.client.get("/api/plans", headers=headers)
        self.assertEqual(res.status_code, 403)

    # =========================================================================
    # Scenario 8: Subscription Renewal and Activation Restores Access
    # =========================================================================
    def test_scenario_8_subscription_renewal_and_activation(self):
        """When an expired or pending user is approved/renewed, access is immediately restored."""
        # Step 1: user_expired currently blocked
        headers = self._auth_headers(self.user_expired_id)
        res = self.client.get("/api/scan-status", headers=headers)
        self.assertEqual(res.status_code, 403)

        # Step 2: Administrator activates new subscription
        admin_headers = self._auth_headers(self.admin_id, role="Admin")
        with self.SessionFactory() as session:
            # Create a pending renewal
            new_sub = UserSubscription(
                user_id=self.user_expired_id,
                plan_id=self.plan_pro.id,
                status="pending"
            )
            session.add(new_sub)
            session.commit()
            new_sub_id = new_sub.id

        # Activate via admin API
        res = self.client.post(
            f"/api/admin/subscriptions/{new_sub_id}/activate",
            headers=admin_headers,
            json={"admin_notes": "Renewed and approved by SecOps"}
        )
        self.assertEqual(res.status_code, 200)

        # Step 3: User immediately has restored operational access
        res = self.client.get("/api/scan-status", headers=headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/network-discovery/status", headers=headers)
        self.assertEqual(res.status_code, 200)

        # Direct navigation succeeds
        res = self.client.get("/?view=dashboard", headers=headers)
        self.assertEqual(res.status_code, 200)

    # =========================================================================
    # Scenario 9: Administrator Account Has Unrestricted Access
    # =========================================================================
    def test_scenario_9_administrator_account_unrestricted(self):
        """Administrators bypass subscription restrictions and have full tool and console access."""
        admin_headers = self._auth_headers(self.admin_id, role="Admin")

        # 1. API: Auth me indicates Admin landing on admin view
        res = self.client.get("/api/auth/me", headers=admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["user"]["role"], "Admin")
        self.assertEqual(data["view"], "admin")
        self.assertEqual(data["landing_url"], "/?view=admin")

        # 2. Access Admin Management Console Metrics
        res = self.client.get("/api/admin/metrics", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        # 3. Access operational endpoints without any subscription record
        res = self.client.get("/api/scan-status", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/port-scan/status", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/network-discovery/status", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        # 4. Access network discovery page directly
        res = self.client.get("/network-discovery", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

    # =========================================================================
    # Scenario 10: Direct URL Access Protection & Redirection
    # =========================================================================
    def test_scenario_10_direct_url_access_protection(self):
        """Unauthenticated or unauthorized visitors cannot bypass UI gating via direct URLs."""
        # 1. Unauthenticated direct access to /network-discovery redirects to /login
        res = self.client.get("/network-discovery")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

        # 2. Unauthenticated direct access to /dashboard redirects to /login
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

        # 3. Unauthenticated direct access to /?view=dashboard redirects to /login
        res = self.client.get("/?view=dashboard")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

        # 4. Unauthenticated direct access to /?view=monitoring redirects to /login
        res = self.client.get("/?view=monitoring")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers.get("Location", ""))

        # 5. Non-subscribed user direct access to /?view=monitoring redirects to plans
        user_headers = self._auth_headers(self.user_none_id)
        res = self.client.get("/?view=monitoring", headers=user_headers)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/?view=plans", res.headers.get("Location", ""))

    # =========================================================================
    # Scenario 11: Direct API Access Protection & Detailed Error Responses
    # =========================================================================
    def test_scenario_11_direct_api_access_protection(self):
        """All operational endpoints require authentication and valid subscription entitlement."""
        endpoints = [
            "/api/scan-status",
            "/api/detected-attacks",
            "/api/port-scan/status",
            "/api/network-discovery/status",
            "/api/monitoring/dependencies",
            "/api/port-scan/network-info",
            "/api/network-discovery/network-info"
        ]

        # 1. Unauthenticated requests return 401 AUTH_REQUIRED
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 401, f"Expected 401 for anonymous access to {ep}")
            data = res.get_json()
            self.assertIn(data["status"], ("error", "unauthorized"))
            self.assertEqual(data["code"], "AUTH_REQUIRED")

        # 2. Authenticated but non-subscribed user receives 403 SUBSCRIPTION_REQUIRED with informative message
        headers = self._auth_headers(self.user_none_id)
        for ep in endpoints:
            res = self.client.get(ep, headers=headers)
            self.assertEqual(res.status_code, 403, f"Expected 403 for non-subscribed access to {ep}")
            data = res.get_json()
            self.assertIn(data["status"], ("forbidden", "error"))
            self.assertEqual(data["code"], "SUBSCRIPTION_REQUIRED")
            self.assertIn("active subscription", data["message"].lower())

    # =========================================================================
    # Sidebar & Template Verification
    # =========================================================================
    def test_sidebar_and_template_structure(self):
        """Verify templates and JS contain all required navigation elements, sections, and IDs."""
        ddos_path = PROJECT_ROOT / "templates" / "ddos.html"
        nd_path = PROJECT_ROOT / "templates" / "network_discovery.html"
        js_path = PROJECT_ROOT / "static" / "main.js"

        self.assertTrue(ddos_path.exists())
        self.assertTrue(nd_path.exists())
        self.assertTrue(js_path.exists())

        ddos_content = ddos_path.read_text(encoding="utf-8")
        nd_content = nd_path.read_text(encoding="utf-8")
        js_content = js_path.read_text(encoding="utf-8")

        # 1. ddos.html template assertions
        self.assertIn('id="sidebarProfileNavItem"', ddos_content)
        self.assertIn('data-nav="profile"', ddos_content)
        self.assertIn('id="sidebarSuspendedNavItem"', ddos_content)
        self.assertIn('id="sidebarSignOutNavItem"', ddos_content)
        self.assertIn('data-nav="signout"', ddos_content)
        self.assertIn('id="sidebarUserPendingBadge"', ddos_content)
        self.assertIn('id="sidebarMonitoringNavItem"', ddos_content)
        self.assertIn('id="sidebarPortScannerNavItem"', ddos_content)
        self.assertIn('id="sidebarNetworkDiscoveryNavItem"', ddos_content)
        self.assertIn('id="userProfileSection"', ddos_content)
        self.assertIn('id="accountSuspendedSection"', ddos_content)
        self.assertIn('id="suspendedSignOutBtn"', ddos_content)

        # 2. network_discovery.html assertions
        self.assertIn('id="sidebarProfileNavItem"', nd_content)
        self.assertIn('id="sidebarSuspendedNavItem"', nd_content)
        self.assertIn('id="sidebarSignOutNavItem"', nd_content)
        self.assertIn('id="sidebarMonitoringNavItem"', nd_content)
        self.assertIn('id="sidebarPortScannerNavItem"', nd_content)
        self.assertIn('id="sidebarNetworkDiscoveryNavItem"', nd_content)

        # 3. main.js dynamic sidebar logic assertions
        self.assertIn("function updateDynamicSidebar", js_content)
        self.assertIn("ACCOUNT_DISABLED", js_content)
        self.assertIn("suspendedSignOutBtn", js_content)
        self.assertIn("Account Restricted", js_content)
        self.assertIn("loadStandaloneProfile", js_content)


if __name__ == "__main__":
    unittest.main()
