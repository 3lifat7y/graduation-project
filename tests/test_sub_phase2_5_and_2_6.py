import os
import tempfile
from pathlib import Path
import unittest
from api import app
from modules.auth.db import get_engine, get_session_factory, init_db
from modules.auth.models import User
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, ensure_utc


class TestSubscriptionFrontendAndIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key-phase2-5-6"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_phase2_5_6.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        # Seed initial plans and admin
        with self.SessionFactory() as session:
            p1 = SubscriptionPlan(
                plan_code="SCOUT-COMMUNITY",
                name="Community Tier",
                description="Standard local detection",
                price=0.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            p1.set_features({"can_live_monitoring": True, "can_port_scan": False, "can_network_discovery": False})

            p2 = SubscriptionPlan(
                plan_code="SCOUT-PRO",
                name="SCOUT Professional",
                description="Comprehensive threat intelligence",
                price=49.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            p2.set_features({"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": False})

            admin = User(
                username="admin_p25",
                email="admin_p25@scout.local",
                role="Admin",
                is_active=True
            )
            admin.set_password("AdminSecurePass!123")
            session.add_all([p1, p2, admin])
            session.commit()
            self.p2_id = p2.id

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_01_template_contains_subscription_and_admin_sections(self):
        """Verify templates/ddos.html renders with subscription plans and admin console markup."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")

        # Subscription section & status card
        self.assertIn('id="subscription-plans"', html)
        self.assertIn('id="userSubStatusCard"', html)
        self.assertIn('id="plansCatalogGrid"', html)

        # Admin console section & panels
        self.assertIn('id="admin-console"', html)
        self.assertIn('id="adminPanelRequests"', html)
        self.assertIn('id="adminPanelSubscriptions"', html)
        self.assertIn('id="adminPanelUsers"', html)
        self.assertIn('id="adminPanelPlans"', html)
        self.assertIn('id="adminPanelAudit"', html)

        # Admin modals
        self.assertIn('id="adminPlanModal"', html)
        self.assertIn('id="adminDateModal"', html)

    def test_02_network_discovery_contains_plans_nav(self):
        """Verify network_discovery.html includes Subscription Plans in navigation."""
        res = self.client.get("/network-discovery")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn('data-nav="plans"', html)
        self.assertIn('Subscription Plans', html)

    def test_03_static_assets_contain_sub_and_admin_definitions(self):
        """Verify static/style.css and static/main.js include required styles and controllers."""
        base_dir = os.path.dirname(os.path.dirname(__file__))
        css_path = os.path.join(base_dir, "static", "style.css")
        js_path = os.path.join(base_dir, "static", "main.js")

        with open(css_path, "r", encoding="utf-8") as f:
            css = f.read()
            self.assertIn(".subscription-plans-section", css)
            self.assertIn(".sub-status-card", css)
            self.assertIn(".plan-card", css)
            self.assertIn(".admin-console-section", css)
            self.assertIn(".admin-table", css)

        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()
            self.assertIn("loadUserSubscription", js)
            self.assertIn("loadPlansCatalog", js)
            self.assertIn("requestSubscription", js)
            self.assertIn("loadAdminDashboard", js)
            self.assertIn("loadAdminRequests", js)
            self.assertIn("loadAdminSubscriptions", js)
            self.assertIn("loadAdminUsers", js)
            self.assertIn("loadAdminPlans", js)
            self.assertIn("loadAdminAuditLogs", js)

    def test_04_full_user_and_admin_subscription_flow(self):
        """Verify end-to-end user registration -> redirect -> plan request -> admin activation."""
        user_client = app.test_client()
        admin_client = app.test_client()

        # 1. Register User
        reg_res = user_client.post("/api/auth/register", json={
            "full_name": "Operator P25",
            "phone_number": "+1 (555) 250-0199",
            "username": "operator_p25",
            "email": "operator_p25@scout.local",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        })
        self.assertEqual(reg_res.status_code, 201)
        reg_data = reg_res.get_json()
        self.assertEqual(reg_data["status"], "success")
        self.assertEqual(reg_data["redirect"], "/?view=plans")

        # 2. Check My Subscription (Should be none)
        my_sub_res = user_client.get("/api/subscriptions/my-subscription")
        self.assertEqual(my_sub_res.status_code, 200)
        self.assertFalse(my_sub_res.get_json()["has_subscription"])

        # 3. User requests plan using plan_id (matches p2_id or plan_code)
        req_res = user_client.post("/api/subscriptions/request", json={"plan_id": self.p2_id})
        self.assertEqual(req_res.status_code, 201)
        sub_id = req_res.get_json()["subscription"]["id"]
        self.assertEqual(req_res.get_json()["subscription"]["status"], "pending")

        # 4. User cannot access protected operational tool while pending
        scan_res = user_client.post("/api/port-scan/start", json={"target": "127.0.0.1", "ports": "80"})
        self.assertEqual(scan_res.status_code, 403)
        self.assertEqual(scan_res.get_json()["code"], "SUBSCRIPTION_REQUIRED")

        # 5. Admin logs in
        login_res = admin_client.post("/api/auth/login", json={
            "username": "admin_p25",
            "password": "AdminSecurePass!123"
        })
        self.assertEqual(login_res.status_code, 200)

        # 6. Admin inspects pending requests
        pending_res = admin_client.get("/api/admin/subscriptions?status=pending")
        self.assertEqual(pending_res.status_code, 200)
        pending_list = pending_res.get_json()["subscriptions"]
        self.assertTrue(any(s["id"] == sub_id for s in pending_list))

        # 7. Admin approves and activates subscription
        act_res = admin_client.post(f"/api/admin/subscriptions/{sub_id}/activate")
        self.assertEqual(act_res.status_code, 200)
        self.assertEqual(act_res.get_json()["subscription"]["status"], "active")

        # 8. User checks subscription again -> now active
        user_check_res = user_client.get("/api/subscriptions/my-subscription")
        self.assertEqual(user_check_res.status_code, 200)
        self.assertTrue(user_check_res.get_json()["has_subscription"])
        self.assertEqual(user_check_res.get_json()["subscription"]["status"], "active")

        # 9. User now succeeds accessing authorized port-scan tool
        post_act_scan = user_client.post("/api/port-scan/start", json={"target": "127.0.0.1", "ports": "80"})
        self.assertEqual(post_act_scan.status_code, 200)

        # 10. Audit log recorded
        audit_res = admin_client.get("/api/admin/audit-logs")
        self.assertEqual(audit_res.status_code, 200)
        actions = [log["action"] for log in audit_res.get_json()["audit_logs"]]
        self.assertIn("ACTIVATED", actions)


if __name__ == "__main__":
    unittest.main()
