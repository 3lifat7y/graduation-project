"""
SCOUT - Dynamic Subscription Features & Global Cards UI/UX Test Suite
Validates:
1. Dynamic Plan Feature Configurations (1 feature, 2 features, 3 features, 0 features).
2. Backend API Entitlement Enforcement matching exact plan configurations.
3. Immediate Entitlement Propagation when Admin edits plan features.
4. Frontend Rendering Rules (only selected features displayed, unselected features omitted).
5. Global Cards UI/UX & Responsive Grids (consistent borders, border-radius, pinned footers, empty state).
"""

import os
import tempfile
import unittest
from pathlib import Path
from datetime import timedelta

from api import app
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.models import User, utcnow
from modules.auth.security import create_session_token, COOKIE_NAME
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan, UserSubscription

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STYLE_CSS_PATH = os.path.join(WORKSPACE_DIR, "static", "style.css")
MAIN_JS_PATH = os.path.join(WORKSPACE_DIR, "static", "main.js")
DDOS_HTML_PATH = os.path.join(WORKSPACE_DIR, "templates", "ddos.html")


class TestDynamicSubscriptionFeaturesAndGlobalCards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "scout-dynamic-features-test-2026"
        with open(STYLE_CSS_PATH, "r", encoding="utf-8") as f:
            cls.css_content = f.read()
        with open(MAIN_JS_PATH, "r", encoding="utf-8") as f:
            cls.js_content = f.read()
        with open(DDOS_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_dynamic.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

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

    def _create_user(self, username, role="Operator", is_active=True):
        with self.SessionFactory() as session:
            u = User(
                username=username,
                email=f"{username}@example.com",
                full_name=f"{username.capitalize()} User",
                role=role,
                is_active=is_active,
                session_version=1
            )
            u.set_password("Secret123!")
            session.add(u)
            session.commit()
            return u.id

    def _login(self, user_id):
        with self.SessionFactory() as session:
            user = session.query(User).filter_by(id=user_id).first()
            role = user.role
            session_version = getattr(user, "session_version", 1)
            token = create_session_token(user.id, role, session_version)
        self.client.set_cookie(COOKIE_NAME, token)
        return token

    def test_css_card_styling_and_pinning(self):
        """Global card UI/UX: standard border-radius, pinned footers, and responsive tool grid."""
        # 1. User Dashboard Tools Grid must be responsive CSS Grid
        self.assertIn("grid-template-columns: repeat(auto-fit, minmax(280px, 1fr))", self.css_content)

        # 2. Tool cards must have standard radius and flex column
        self.assertIn("border-radius: var(--radius-md, 12px)", self.css_content)

        # 3. Pinned footers across cards
        self.assertIn(".plan-card-footer", self.css_content)
        self.assertIn(".public-plan-card-footer", self.css_content)

        # 4. Empty state card styling for dashboard when 0 tools enabled
        self.assertIn(".user-dash-no-tools-card", self.css_content)
        self.assertIn("dashNoToolsCard", self.html_content)

    def test_frontend_canonical_features_and_dynamic_rendering(self):
        """Frontend contains canonical operational feature definitions and renders only selected features."""
        # Canonical features in main.js
        self.assertIn("Live Network Monitoring", self.js_content)
        self.assertIn("Port Scanner", self.js_content)
        self.assertIn("Network Discovery", self.js_content)

        # Verify shared helpers exist
        self.assertIn("function getSelectedPlanFeatures", self.js_content)
        self.assertIn("function renderPlanFeaturesListHtml", self.js_content)

        # Verify loadUserDashboard dynamically hides unselected cards and shows empty state when none
        self.assertIn("dashNoToolsCard", self.js_content)
        self.assertIn("monitorCard.style.display = \"none\"", self.js_content)
        self.assertIn("portCard.style.display = \"none\"", self.js_content)
        self.assertIn("ndCard.style.display = \"none\"", self.js_content)

    def test_plan_feature_matrix_and_backend_entitlements(self):
        """
        Verify:
        - 1 selected feature plan
        - 2 selected features plan
        - 3 selected features plan
        - 0 selected features plan
        Enforce access permissions strictly on the backend.
        """
        admin_id = self._create_user("admin_root", role="Admin")
        self._login(admin_id)

        # 1. Create Plan with 1 feature: Live Monitoring only
        res1 = self.client.post("/api/admin/plans", json={
            "plan_code": "PLAN-1FEAT",
            "name": "Live Telemetry Only",
            "price": 29.0,
            "duration_value": 30,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": False,
                "can_network_discovery": False
            }
        })
        self.assertEqual(res1.status_code, 201)
        plan1_id = res1.get_json()["plan"]["id"]

        # 2. Create Plan with 2 features: Port Scan + Network Discovery
        res2 = self.client.post("/api/admin/plans", json={
            "plan_code": "PLAN-2FEAT",
            "name": "Scanner and Discovery",
            "price": 49.0,
            "duration_value": 30,
            "features": {
                "can_live_monitoring": False,
                "can_port_scan": True,
                "can_network_discovery": True
            }
        })
        self.assertEqual(res2.status_code, 201)
        plan2_id = res2.get_json()["plan"]["id"]

        # 3. Create Plan with all 3 features
        res3 = self.client.post("/api/admin/plans", json={
            "plan_code": "PLAN-3FEAT",
            "name": "Complete Defense Suite",
            "price": 99.0,
            "duration_value": 30,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True
            }
        })
        self.assertEqual(res3.status_code, 201)
        plan3_id = res3.get_json()["plan"]["id"]

        # 4. Create Plan with 0 features: Basic Platform
        res4 = self.client.post("/api/admin/plans", json={
            "plan_code": "PLAN-0FEAT",
            "name": "Basic Platform Access",
            "price": 0.0,
            "is_free": True,
            "duration_value": 30,
            "features": {
                "can_live_monitoring": False,
                "can_port_scan": False,
                "can_network_discovery": False
            }
        })
        self.assertEqual(res4.status_code, 201)
        plan4_id = res4.get_json()["plan"]["id"]

        # Verify /api/plans returns exact feature configurations
        plans_res = self.client.get("/api/plans")
        self.assertEqual(plans_res.status_code, 200)
        catalog = {p["plan_code"]: p["features"] for p in plans_res.get_json()["plans"]}
        self.assertTrue(catalog["PLAN-1FEAT"]["can_live_monitoring"])
        self.assertFalse(catalog["PLAN-1FEAT"]["can_port_scan"])
        self.assertFalse(catalog["PLAN-1FEAT"]["can_network_discovery"])

        self.assertFalse(catalog["PLAN-2FEAT"]["can_live_monitoring"])
        self.assertTrue(catalog["PLAN-2FEAT"]["can_port_scan"])
        self.assertTrue(catalog["PLAN-2FEAT"]["can_network_discovery"])

        self.assertTrue(catalog["PLAN-3FEAT"]["can_live_monitoring"])
        self.assertTrue(catalog["PLAN-3FEAT"]["can_port_scan"])
        self.assertTrue(catalog["PLAN-3FEAT"]["can_network_discovery"])

        self.assertFalse(catalog["PLAN-0FEAT"]["can_live_monitoring"])
        self.assertFalse(catalog["PLAN-0FEAT"]["can_port_scan"])
        self.assertFalse(catalog["PLAN-0FEAT"]["can_network_discovery"])

        # Test User 1 with Plan 1 (1 feature: can_live_monitoring)
        user1_id = self._create_user("user_mon_only")
        with self.SessionFactory() as session:
            sub1 = UserSubscription(
                user_id=user1_id,
                plan_id=plan1_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub1)
            session.commit()

        self._login(user1_id)
        # Monitoring endpoint: allowed
        res_mon = self.client.get("/api/scan-status")
        self.assertEqual(res_mon.status_code, 200)
        # Port scan endpoint: feature restricted (403)
        res_port = self.client.get("/api/port-scan/status")
        self.assertEqual(res_port.status_code, 403)
        self.assertEqual(res_port.get_json().get("code"), "FEATURE_NOT_INCLUDED")
        # Network discovery endpoint: feature restricted (403)
        res_nd = self.client.get("/api/network-discovery/status")
        self.assertEqual(res_nd.status_code, 403)
        self.assertEqual(res_nd.get_json().get("code"), "FEATURE_NOT_INCLUDED")

        # Test User 2 with Plan 2 (2 features: Port scan + Network Discovery)
        user2_id = self._create_user("user_port_nd")
        with self.SessionFactory() as session:
            sub2 = UserSubscription(
                user_id=user2_id,
                plan_id=plan2_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub2)
            session.commit()

        self._login(user2_id)
        # Monitoring endpoint: feature restricted (403)
        res_mon2 = self.client.get("/api/scan-status")
        self.assertEqual(res_mon2.status_code, 403)
        self.assertEqual(res_mon2.get_json().get("code"), "FEATURE_NOT_INCLUDED")
        # Port scan endpoint: allowed
        res_port2 = self.client.get("/api/port-scan/status")
        self.assertEqual(res_port2.status_code, 200)
        # Network discovery endpoint: allowed
        res_nd2 = self.client.get("/api/network-discovery/status")
        self.assertEqual(res_nd2.status_code, 200)

        # Test User 3 with Plan 3 (3 features: All)
        user3_id = self._create_user("user_all_feats")
        with self.SessionFactory() as session:
            sub3 = UserSubscription(
                user_id=user3_id,
                plan_id=plan3_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub3)
            session.commit()

        self._login(user3_id)
        # All 3 endpoints: allowed
        self.assertEqual(self.client.get("/api/scan-status").status_code, 200)
        self.assertEqual(self.client.get("/api/port-scan/status").status_code, 200)
        self.assertEqual(self.client.get("/api/network-discovery/status").status_code, 200)

        # Test User 4 with Plan 4 (0 features: Basic Platform)
        user4_id = self._create_user("user_zero_feats")
        with self.SessionFactory() as session:
            sub4 = UserSubscription(
                user_id=user4_id,
                plan_id=plan4_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub4)
            session.commit()

        self._login(user4_id)
        # All operational tools feature restricted
        self.assertEqual(self.client.get("/api/scan-status").status_code, 403)
        self.assertEqual(self.client.get("/api/port-scan/status").status_code, 403)
        self.assertEqual(self.client.get("/api/network-discovery/status").status_code, 403)

    def test_dynamic_plan_edit_propagates_immediately(self):
        """When Admin edits a plan's features, existing active subscribers immediately receive updated permissions."""
        admin_id = self._create_user("admin_editor", role="Admin")
        self._login(admin_id)

        # 1. Create a plan with only can_live_monitoring
        res = self.client.post("/api/admin/plans", json={
            "plan_code": "DYNAMIC-TEST",
            "name": "Dynamic Plan",
            "price": 35.0,
            "duration_value": 30,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": False,
                "can_network_discovery": False
            }
        })
        self.assertEqual(res.status_code, 201)
        plan_id = res.get_json()["plan"]["id"]

        # 2. User subscribes to this plan
        user_id = self._create_user("subscriber_user")
        with self.SessionFactory() as session:
            sub = UserSubscription(
                user_id=user_id,
                plan_id=plan_id,
                status="active",
                start_date=utcnow() - timedelta(days=1),
                end_date=utcnow() + timedelta(days=29)
            )
            session.add(sub)
            session.commit()

        # User is restricted from port scanner
        self._login(user_id)
        self.assertEqual(self.client.get("/api/port-scan/status").status_code, 403)

        # 3. Admin edits plan to add can_port_scan
        self._login(admin_id)
        edit_res = self.client.put(f"/api/admin/plans/{plan_id}", json={
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": False
            }
        })
        self.assertEqual(edit_res.status_code, 200)

        # 4. User immediately accesses port scanner without needing new subscription
        self._login(user_id)
        self.assertEqual(self.client.get("/api/port-scan/status").status_code, 200)

        # /api/subscriptions/my-subscription reflects the newly enabled feature
        my_sub_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(my_sub_res.status_code, 200)
        feats = my_sub_res.get_json()["subscription"]["features"]
        self.assertTrue(feats["can_live_monitoring"])
        self.assertTrue(feats["can_port_scan"])
        self.assertFalse(feats["can_network_discovery"])


if __name__ == "__main__":
    unittest.main()
