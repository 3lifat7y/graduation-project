#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Dashboard Separation & Routing Architecture
Validates:
1. Public Homepage: Serves anonymous visitors; denies unauthenticated access to /admin and /dashboard.
2. Admin Dashboard & Metrics: Direct redirect to admin on login; returns exact database platform metrics.
3. Ordinary User Dashboard:
   - Without subscription: redirects to /plans.
   - Pending subscription: routes to plans/status.
   - Active subscription: redirects to /dashboard.
4. Registration and Subscription Flow: Registration returns redirect to /plans. Plan selection requires admin approval.
5. Routing & Security: Backend route guards for /admin, /dashboard, and /api/admin/metrics. Direct URL tampering prevention.
6. Public View Bypass: /?public=1 allows authenticated users to view the public site without session termination.
"""

import sys
import os
import time
import json
import unittest
import tempfile
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


class TestDashboardSeparationAndRouting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_dash_routing.db"
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

        # Seed Admin user
        with get_db_session() as session:
            admin = User(
                username="admin_scout",
                email="admin@scout.sec",
                full_name="Lead Security Architect",
                role="Admin",
                is_active=True,
                password_hash=hash_password("AdminPass#2026")
            )
            session.add(admin)

            # Seed Ordinary user without subscription
            user_no_sub = User(
                username="analyst_nosub",
                email="nosub@scout.sec",
                full_name="Junior Analyst",
                role="User",
                is_active=True,
                password_hash=hash_password("AnalystPass#2026")
            )
            session.add(user_no_sub)

            # Seed Inactive/Suspended user
            inactive_user = User(
                username="suspended_user",
                email="suspended@scout.sec",
                full_name="Suspended Operator",
                role="User",
                is_active=False,
                password_hash=hash_password("SuspendedPass#2026")
            )
            session.add(inactive_user)
            session.commit()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    # ------------------------------------------------------------------------
    # 1. Public Homepage Tests
    # ------------------------------------------------------------------------
    def test_01_public_homepage_for_anonymous_visitor(self):
        """Anonymous visitor GET / returns 200 with public homepage and no redirect."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        content = res.data.decode("utf-8")
        self.assertIn("SCOUT", content)
        self.assertIn("user-dashboard", content)

    def test_02_anonymous_visitor_blocked_from_admin_and_dashboard(self):
        """Anonymous visitor cannot access /admin or /dashboard directly."""
        res_admin = self.client.get("/admin")
        self.assertIn(res_admin.status_code, [401, 302])

        res_dash = self.client.get("/dashboard")
        self.assertIn(res_dash.status_code, [401, 302])

        res_metrics = self.client.get("/api/admin/metrics")
        self.assertEqual(res_metrics.status_code, 401)

    # ------------------------------------------------------------------------
    # 2. Admin Dashboard & Real Database Metrics Tests
    # ------------------------------------------------------------------------
    def test_03_admin_login_redirect_and_routing(self):
        """Admin login returns view='admin' and redirect='/?view=admin', /admin redirects appropriately."""
        res = self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["view"], "admin")
        self.assertEqual(data["redirect"], "/?view=admin")

        # Admin access to /admin redirects to /?view=admin
        res_admin = self.client.get("/admin")
        self.assertEqual(res_admin.status_code, 302)
        self.assertEqual(res_admin.headers["Location"], "/?view=admin")

        # Admin access to / (default) redirects to /?view=admin
        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 302)
        self.assertEqual(res_home.headers["Location"], "/?view=admin")

        # Admin access to /?public=1 bypasses redirect to view public page
        res_public = self.client.get("/?public=1")
        self.assertEqual(res_public.status_code, 200)

    def test_04_admin_metrics_returns_exact_database_platform_activity(self):
        """Admin GET /api/admin/metrics returns 100% verified database platform metrics (zero mock data)."""
        # Login as Admin
        self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })

        res = self.client.get("/api/admin/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("metrics", data)
        m = data["metrics"]

        # In setUp: 3 users total (2 active: admin_scout, analyst_nosub; 1 inactive: suspended_user)
        self.assertEqual(m["total_users"], 3)
        self.assertEqual(m["active_users"], 2)
        self.assertEqual(m["inactive_users"], 1)

        # Plans seeded by default: SCOUT-COMMUNITY, SCOUT-PRO, SCOUT-ENTERPRISE
        self.assertGreaterEqual(m["available_plans"], 3)
        self.assertEqual(m["pending_subscriptions"], 0)
        self.assertEqual(m["active_subscriptions"], 0)
        self.assertEqual(m["expired_subscriptions"], 0)

    # ------------------------------------------------------------------------
    # 3. Ordinary User Dashboard Tests
    # ------------------------------------------------------------------------
    def test_05_ordinary_user_without_subscription_routing(self):
        """Ordinary user without active subscription logs in -> redirects to /plans."""
        res = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["view"], "plans")
        self.assertEqual(data["redirect"], "/?view=plans")

        # Accessing /dashboard redirects to /?view=plans
        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 302)
        self.assertEqual(res_dash.headers["Location"], "/?view=plans")

        # Accessing /admin is forbidden (403)
        res_admin = self.client.get("/admin")
        self.assertEqual(res_admin.status_code, 403)

        # Accessing /api/admin/metrics is forbidden (403)
        res_metrics = self.client.get("/api/admin/metrics")
        self.assertEqual(res_metrics.status_code, 403)

    def test_06_ordinary_user_with_pending_subscription_routing(self):
        """Ordinary user requests plan -> pending status -> routes to /plans awaiting approval."""
        # Login
        self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })

        # Request subscription
        res_req = self.client.post("/api/subscriptions/request", json={
            "plan_id": "SCOUT-COMMUNITY"
        })
        self.assertEqual(res_req.status_code, 201)

        # Login again
        res_login = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        data = res_login.get_json()
        self.assertEqual(data["view"], "plans")
        self.assertEqual(data["redirect"], "/?view=plans&status=pending")

        # Check /api/subscriptions/my-subscription returns pending
        res_my = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(res_my.status_code, 200)
        my_data = res_my.get_json()
        self.assertIsNotNone(my_data["subscription"])
        self.assertEqual(my_data["subscription"]["status"], "pending")

    def test_07_ordinary_user_with_active_subscription_routing(self):
        """When admin approves pending subscription, user login and /dashboard route to user dashboard."""
        # Step 1: User requests plan
        self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        res_req = self.client.post("/api/subscriptions/request", json={
            "plan_id": "SCOUT-PRO"
        })
        self.assertEqual(res_req.status_code, 201)

        # Get pending sub ID
        with get_db_session() as session:
            sub = session.query(UserSubscription).filter_by(status="pending").first()
            self.assertIsNotNone(sub)
            sub_id = sub.id

        # Step 2: Admin activates subscription
        self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })
        res_act = self.client.post(f"/api/admin/subscriptions/{sub_id}/activate")
        self.assertEqual(res_act.status_code, 200)

        # Check metrics updated accurately in DB!
        res_metrics = self.client.get("/api/admin/metrics")
        m = res_metrics.get_json()["metrics"]
        self.assertEqual(m["active_subscriptions"], 1)
        self.assertEqual(m["pending_subscriptions"], 0)

        # Step 3: User logs in again -> now has active subscription!
        res_login = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        data = res_login.get_json()
        self.assertEqual(data["view"], "dashboard")
        self.assertEqual(data["redirect"], "/?view=dashboard")

        # Accessing /dashboard redirects to /?view=dashboard
        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 302)
        self.assertEqual(res_dash.headers["Location"], "/?view=dashboard")

        # Accessing / (default) redirects to /?view=dashboard
        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 302)
        self.assertEqual(res_home.headers["Location"], "/?view=dashboard")

        # Accessing /?public=1 renders public page
        res_pub = self.client.get("/?public=1")
        self.assertEqual(res_pub.status_code, 200)

    # ------------------------------------------------------------------------
    # 4. Registration and Subscription Flow Tests
    # ------------------------------------------------------------------------
    def test_08_registration_redirects_to_plans(self):
        """Registering a new account returns redirect to /?view=plans."""
        res = self.client.post("/api/auth/register", json={
            "email": f"recruit_{int(time.time())}@scout.sec",
            "phone_number": f"+1555{int(time.time() * 1000) % 10000000:07d}",
            "full_name": "New Security Recruit",
            "password": "RecruitPassword#2026",
            "confirm_password": "RecruitPassword#2026"
        })

        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["redirect"], "/?view=plans")

    # ------------------------------------------------------------------------
    # 5. Mind Map Public Homepage Restriction Tests
    # ------------------------------------------------------------------------
    def test_09_public_homepage_renders_mindmap(self):
        """Verify that anonymous GET / and authenticated GET /?public=1 contain the Mind Map."""
        res_anon = self.client.get("/")
        self.assertEqual(res_anon.status_code, 200)
        anon_html = res_anon.get_data(as_text=True)
        self.assertIn('id="system-architecture"', anon_html)
        self.assertIn('id="mindmapWrapper"', anon_html)
        self.assertIn('src="/static/mindmap.js"', anon_html)

        # Authenticate as user with active subscription
        with get_db_session() as session:
            user = session.query(User).filter_by(username="analyst_nosub").first()
            plan = session.query(SubscriptionPlan).first()
            sub = UserSubscription(
                user_id=user.id,
                plan_id=plan.id,
                status="active"
            )
            session.add(sub)
            session.commit()

        login_res = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)

        # Accessing /?public=1 allows viewing the public homepage with the Mind Map
        res_pub = self.client.get("/?public=1")
        self.assertEqual(res_pub.status_code, 200)
        pub_html = res_pub.get_data(as_text=True)
        self.assertIn('id="system-architecture"', pub_html)
        self.assertIn('id="mindmapWrapper"', pub_html)

    def test_10_network_discovery_endpoint_has_no_mindmap(self):
        """Verify that GET /network-discovery contains no Mind Map markup or scripts."""
        res = self.client.get("/network-discovery")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertNotIn('id="system-architecture"', html)
        self.assertNotIn('class="system-architecture-section"', html)
        self.assertNotIn('mindmap.js', html)
        self.assertNotIn('mindmapWrapper', html)

    # ------------------------------------------------------------------------
    # 6. Additional Requirement: Public Homepage & Auth Navigation Acceptance Tests
    # ------------------------------------------------------------------------
    def test_11_anonymous_homepage_navigation_elements(self):
        """1. Anonymous visitor opens Homepage: public layout, no sidebar groups, Login & Register CTAs."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # Login and Register buttons present
        self.assertIn('id="headerSignInBtn"', html)
        self.assertIn('id="headerGetStartedBtn"', html)
        self.assertIn('id="publicAuthActions"', html)

        # Dynamic Dashboard CTAs and container exist in template
        self.assertIn('id="publicDashboardCtaWrap"', html)
        self.assertIn('id="publicDashboardCta"', html)
        self.assertIn('id="heroDynamicDashboardBtn"', html)

        # Mind map present on public homepage
        self.assertIn('id="system-architecture"', html)

        # Old toolbar home buttons removed
        self.assertNotIn('id="breadcrumbHomeLink"', html)
        self.assertNotIn('id="dedicatedViewToggleBtn"', html)
        self.assertIn('id="breadcrumbDashboardLink"', html)

    def test_12_admin_login_and_homepage_navigation_preserves_session(self):
        """2, 3, 4. Admin logs in, opens admin console, visits homepage without session loss, dashboard CTA links to admin."""
        login_res = self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)
        data = login_res.get_json()
        self.assertEqual(data["view"], "admin")
        self.assertEqual(data["user"]["role"], "Admin")

        # Admin navigates to the public Homepage via /?public=1
        home_res = self.client.get("/?public=1")
        self.assertEqual(home_res.status_code, 200)
        html = home_res.get_data(as_text=True)

        # Elements for dynamic admin dashboard CTA exist
        self.assertIn('id="publicDashboardCtaWrap"', html)
        self.assertIn('id="publicDashboardCta"', html)
        self.assertIn('id="heroDynamicDashboardBtn"', html)

        # Session remains completely valid
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.get_json()
        self.assertEqual(me_data["user"]["role"], "Admin")

        # Admin direct access to /admin redirects to /?view=admin (never to user dashboard)
        admin_redirect = self.client.get("/admin")
        self.assertEqual(admin_redirect.status_code, 302)
        self.assertEqual(admin_redirect.headers["Location"], "/?view=admin")

    def test_13_user_with_active_subscription_homepage_navigation(self):
        """5, 6. User with active subscription visits homepage: session preserved, CTA points to user dashboard."""
        with get_db_session() as session:
            user = session.query(User).filter_by(username="analyst_nosub").first()
            plan = session.query(SubscriptionPlan).first()
            sub = UserSubscription(
                user_id=user.id,
                plan_id=plan.id,
                status="active"
            )
            session.add(sub)
            session.commit()

        login_res = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)

        # User visits public Homepage
        home_res = self.client.get("/?public=1")
        self.assertEqual(home_res.status_code, 200)

        # Session is preserved
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.get_json()
        self.assertEqual(me_data["user"]["username"], "analyst_nosub")

        # Subscription verified active
        sub_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(sub_res.status_code, 200)
        sub_data = sub_res.get_json()
        self.assertEqual(sub_data["subscription"]["status"], "active")

        # Direct access to /dashboard opens /?view=dashboard
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 302)
        self.assertEqual(dash_res.headers["Location"], "/?view=dashboard")

    def test_14_user_without_subscription_directed_to_plans(self):
        """7. User without active subscription visits homepage and is directed to plans."""
        login_res = self.client.post("/api/auth/login", json={
            "username": "analyst_nosub",
            "password": "AnalystPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)

        # Sub is null
        sub_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(sub_res.status_code, 200)
        sub_data = sub_res.get_json()
        self.assertIsNone(sub_data["subscription"])

        # Accessing /dashboard redirects user without subscription to /?view=plans
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 302)
        self.assertEqual(dash_res.headers["Location"], "/?view=plans")

    def test_15_logout_behavior_and_session_revocation(self):
        """8, 9. Logout invalidates server-side session, clears cookie, emits anti-cache headers, rejects protected APIs."""
        login_res = self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)

        # Grab token to test reuse attempt (simulating browser Back button with cached credentials)
        saved_cookies = [h for h in login_res.headers.getlist("Set-Cookie") if "scout_session" in h]
        self.assertTrue(len(saved_cookies) > 0)
        token_cookie = saved_cookies[0].split(";")[0].split("=")[1]

        # Call logout
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)
        logout_data = logout_res.get_json()
        self.assertEqual(logout_data["status"], "success")

        # Cookie cleared
        cookie_headers = [h for h in logout_res.headers.getlist("Set-Cookie") if "scout_session" in h]
        self.assertTrue(any("Expires=" in h or "Max-Age=0" in h for h in cookie_headers))

        # Anti-cache headers on logout response
        self.assertIn("no-store", logout_res.headers.get("Cache-Control", ""))
        self.assertIn("no-cache", logout_res.headers.get("Cache-Control", ""))

        # Current client can no longer access /api/auth/me
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 401)

        # Current client can no longer access protected admin metrics
        metrics_res = self.client.get("/api/admin/metrics")
        self.assertEqual(metrics_res.status_code, 401)

        # Attempt to access with old revoked session token (replay / back-button scenario)
        self.client.set_cookie("scout_session", token_cookie)
        replay_res = self.client.get("/api/auth/me")
        self.assertEqual(replay_res.status_code, 401)

    def test_16_anti_cache_headers_on_protected_views_and_apis(self):
        """9. Anti-cache headers are attached to all /api/ requests and protected dashboard requests."""
        # API request
        api_res = self.client.get("/api/auth/me")
        self.assertIn("no-store", api_res.headers.get("Cache-Control", ""))
        self.assertIn("no-cache", api_res.headers.get("Cache-Control", ""))

        # Protected view request
        dash_res = self.client.get("/?view=admin")
        self.assertIn("no-store", dash_res.headers.get("Cache-Control", ""))


if __name__ == "__main__":
    unittest.main()

