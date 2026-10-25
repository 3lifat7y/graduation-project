import os
import tempfile
from pathlib import Path
import unittest
from datetime import datetime, timezone, timedelta

from api import app
from modules.auth.db import get_engine, get_session_factory, init_db
from modules.auth.models import User
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, ensure_utc


class TestE2EScoutPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "e2e-scout-cybersecurity-secret-key-2026"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_e2e.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        # Seed initial plans
        with self.SessionFactory() as session:
            p_comm = SubscriptionPlan(
                plan_code="SCOUT-COMMUNITY",
                name="SCOUT Community Baseline",
                description="Standard live telemetry",
                price=0.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            p_comm.set_features({"can_live_monitoring": True, "can_port_scan": False, "can_network_discovery": False})

            p_pro = SubscriptionPlan(
                plan_code="SCOUT-PRO",
                name="SCOUT Professional Threat Hunter",
                description="Live telemetry & active port scanning",
                price=49.0,
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            p_pro.set_features({"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": False})

            p_ent = SubscriptionPlan(
                plan_code="SCOUT-ENTERPRISE",
                name="SCOUT Enterprise Sovereign",
                description="Full cybersecurity reconnaissance suite",
                price=499.0,
                duration_value=365,
                duration_unit="days",
                is_active=True
            )
            p_ent.set_features({"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": True})

            admin = User(
                username="scout_master_admin",
                email="admin@scout.cyber",
                role="Admin",
                is_active=True
            )
            admin.set_password("AdminSuperPass#2026")

            session.add_all([p_comm, p_pro, p_ent, admin])
            session.commit()
            self.pro_plan_id = p_pro.id
            self.ent_plan_id = p_ent.id

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

    def test_complete_platform_lifecycle_and_entitlement_enforcement(self):
        """Complete platform E2E test covering Auth, RBAC, Subscriptions, Entitlement Enforcement and Moderation."""
        anon_client = app.test_client()
        analyst_client = app.test_client()
        admin_client = app.test_client()

        # Step 1: Anonymous Access Controls
        # Public pages must load
        home_res = anon_client.get("/")
        self.assertEqual(home_res.status_code, 200)
        self.assertIn("SCOUT — Autonomous Cyber Threat Defense", home_res.data.decode("utf-8"))

        # Anonymous calls to operational endpoints must be blocked with 401
        self.assertEqual(anon_client.post("/api/scan", json={"interface": "lo"}).status_code, 401)
        self.assertEqual(anon_client.post("/api/port-scan/start", json={"target": "127.0.0.1"}).status_code, 401)
        self.assertEqual(anon_client.post("/api/network-discovery/start", json={}).status_code, 401)

        # Step 2: User Registration & Initial State
        reg_res = analyst_client.post("/api/auth/register", json={
            "username": "threat_analyst_01",
            "email": "analyst01@soc.local",
            "full_name": "Senior SOC Analyst",
            "password": "AnalystPass#2026",
            "confirm_password": "AnalystPass#2026"
        })
        self.assertEqual(reg_res.status_code, 201)
        self.assertEqual(reg_res.get_json()["redirect"], "/?view=plans")

        # Verify identity
        me_res = analyst_client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.get_json()["user"]["username"], "threat_analyst_01")
        self.assertEqual(me_res.get_json()["user"]["role"], "User")

        # Step 3: Newly registered user has no active subscription -> Operational tools return 403 SUBSCRIPTION_REQUIRED
        sub_check = analyst_client.get("/api/subscriptions/my-subscription")
        self.assertFalse(sub_check.get_json()["has_subscription"])

        scan_blocked = analyst_client.post("/api/port-scan/start", json={"target": "127.0.0.1", "ports": "80"})
        self.assertEqual(scan_blocked.status_code, 403)
        self.assertEqual(scan_blocked.get_json()["code"], "SUBSCRIPTION_REQUIRED")

        # Step 4: Analyst requests SCOUT-PRO plan -> state becomes 'pending'
        req_res = analyst_client.post("/api/subscriptions/request", json={"plan_id": self.pro_plan_id})
        self.assertEqual(req_res.status_code, 201)
        sub_id = req_res.get_json()["subscription"]["id"]
        self.assertEqual(req_res.get_json()["subscription"]["status"], "pending")

        # Still blocked while pending
        self.assertEqual(analyst_client.post("/api/port-scan/start", json={"target": "127.0.0.1"}).status_code, 403)

        # Step 5: Admin Login and Activation
        admin_login = admin_client.post("/api/auth/login", json={
            "username": "scout_master_admin",
            "password": "AdminSuperPass#2026"
        })
        self.assertEqual(admin_login.status_code, 200)

        # Admin reviews pending requests
        pending_res = admin_client.get("/api/admin/subscriptions?status=pending")
        self.assertEqual(pending_res.status_code, 200)
        self.assertTrue(any(s["id"] == sub_id for s in pending_res.get_json()["subscriptions"]))

        # Admin activates subscription
        act_res = admin_client.post(f"/api/admin/subscriptions/{sub_id}/activate")
        self.assertEqual(act_res.status_code, 200)
        self.assertEqual(act_res.get_json()["subscription"]["status"], "active")

        # Step 6: Analyst now has ACTIVE Pro subscription
        active_check = analyst_client.get("/api/subscriptions/my-subscription")
        self.assertEqual(active_check.status_code, 200)
        self.assertTrue(active_check.get_json()["has_subscription"])
        self.assertEqual(active_check.get_json()["subscription"]["status"], "active")

        # Authorized feature (Port Scan) -> PASSES with 200
        port_scan_res = analyst_client.post("/api/port-scan/start", json={"target": "127.0.0.1", "ports": "80"})
        self.assertEqual(port_scan_res.status_code, 200)

        # Unauthorized feature (Network Discovery, reserved for Enterprise) -> BLOCKED with 403 FEATURE_NOT_INCLUDED
        nd_res = analyst_client.post("/api/network-discovery/start", json={"timeout": 0.5})
        self.assertEqual(nd_res.status_code, 403)
        self.assertEqual(nd_res.get_json()["code"], "FEATURE_NOT_INCLUDED")

        # Step 7: Dynamic Expiration Enforcement
        # Admin sets expiration date to the past (yesterday)
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        adj_res = admin_client.post(f"/api/admin/subscriptions/{sub_id}/adjust-dates", json={
            "end_date": past_date
        })
        self.assertEqual(adj_res.status_code, 200)

        # Now when analyst attempts port scan, backend dynamically marks expired and blocks
        expired_scan = analyst_client.post("/api/port-scan/start", json={"target": "127.0.0.1", "ports": "80"})
        self.assertEqual(expired_scan.status_code, 403)
        self.assertEqual(expired_scan.get_json()["code"], "SUBSCRIPTION_REQUIRED")
        self.assertEqual(expired_scan.get_json()["context"]["status"], "expired")

        # Step 8: Account Moderation / Suspension
        with self.SessionFactory() as session:
            user_rec = session.query(User).filter_by(username="threat_analyst_01").first()
            user_id = user_rec.id

        susp_res = admin_client.post(f"/api/admin/users/{user_id}/status", json={"is_active": False})
        self.assertEqual(susp_res.status_code, 200)

        # Existing session token is immediately invalidated (401 Not Authenticated)
        suspended_req = analyst_client.get("/api/auth/me")
        self.assertEqual(suspended_req.status_code, 401)
        self.assertFalse(suspended_req.get_json().get("authenticated", True))

        # Attempting to log back in is blocked with 403 ACCOUNT_DISABLED
        relogin_res = analyst_client.post("/api/auth/login", json={
            "username": "threat_analyst_01",
            "password": "AnalystPass#2026"
        })
        self.assertEqual(relogin_res.status_code, 403)
        self.assertEqual(relogin_res.get_json()["code"], "ACCOUNT_DISABLED")

        # Step 9: Audit Trail Integrity
        audit_res = admin_client.get("/api/admin/audit-logs")
        self.assertEqual(audit_res.status_code, 200)
        logs = audit_res.get_json()["audit_logs"]
        action_names = [l["action"] for l in logs]
        self.assertIn("REQUESTED", action_names)
        self.assertIn("ACTIVATED", action_names)
        self.assertIn("DATES_MODIFIED", action_names)


if __name__ == "__main__":
    unittest.main()
