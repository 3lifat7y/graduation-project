#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 2.4: Centralized Backend Entitlement Enforcement
Validates:
1. Operational endpoints reject anonymous visitors with 401.
2. Users without active subscriptions receive 403 with code='SUBSCRIPTION_REQUIRED'.
3. Pending subscriptions are blocked with status='pending'.
4. Expired subscriptions are blocked and dynamically updated in DB.
5. Granular feature entitlements (e.g. Community tier blocked from Network Discovery).
6. Active subscribers with required features pass successfully.
7. Admin bypass works without subscription.
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.security import create_session_token
from modules.subscriptions.models import SubscriptionPlan, UserSubscription


class TestPhase2EntitlementEnforcement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_entitlement.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        session = self.SessionFactory()
        now = datetime.now(timezone.utc)

        # Users
        self.admin = User(username="admin_hero", email="admin@hero.com", role="Admin", is_active=True)
        self.admin.set_password("AdminHero#123")

        self.user_no_sub = User(username="user_nosub", email="nosub@scout.com", role="User", is_active=True)
        self.user_no_sub.set_password("UserPass#123")

        self.user_pending = User(username="user_pending", email="pending@scout.com", role="User", is_active=True)
        self.user_pending.set_password("UserPass#123")

        self.user_expired = User(username="user_expired", email="expired@scout.com", role="User", is_active=True)
        self.user_expired.set_password("UserPass#123")

        self.user_community = User(username="user_comm", email="comm@scout.com", role="User", is_active=True)
        self.user_community.set_password("UserPass#123")

        self.user_pro = User(username="user_pro", email="pro@scout.com", role="User", is_active=True)
        self.user_pro.set_password("UserPass#123")

        # Plans
        self.plan_comm = SubscriptionPlan(
            plan_code="COMMUNITY",
            name="Community Tier",
            price=0.0,
            duration_value=30
        )
        self.plan_comm.set_features({"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": False})

        self.plan_pro = SubscriptionPlan(
            plan_code="PRO",
            name="Pro Tier",
            price=49.0,
            duration_value=30
        )
        self.plan_pro.set_features({"can_live_monitoring": True, "can_port_scan": True, "can_network_discovery": True})

        session.add_all([
            self.admin, self.user_no_sub, self.user_pending, self.user_expired,
            self.user_community, self.user_pro, self.plan_comm, self.plan_pro
        ])
        session.commit()

        # Subscriptions
        sub_pending = UserSubscription(user_id=self.user_pending.id, plan_id=self.plan_pro.id, status="pending")

        sub_expired = UserSubscription(
            user_id=self.user_expired.id,
            plan_id=self.plan_pro.id,
            status="active",
            start_date=now - timedelta(days=35),
            end_date=now - timedelta(days=5)
        )

        sub_comm = UserSubscription(
            user_id=self.user_community.id,
            plan_id=self.plan_comm.id,
            status="active",
            start_date=now - timedelta(days=2),
            end_date=now + timedelta(days=28)
        )

        sub_pro = UserSubscription(
            user_id=self.user_pro.id,
            plan_id=self.plan_pro.id,
            status="active",
            start_date=now - timedelta(days=2),
            end_date=now + timedelta(days=28)
        )

        session.add_all([sub_pending, sub_expired, sub_comm, sub_pro])
        session.commit()

        # Tokens
        self.admin_token = create_session_token(self.admin.id, "Admin", 1)
        self.no_sub_token = create_session_token(self.user_no_sub.id, "User", 1)
        self.pending_token = create_session_token(self.user_pending.id, "User", 1)
        self.expired_token = create_session_token(self.user_expired.id, "User", 1)
        self.comm_token = create_session_token(self.user_community.id, "User", 1)
        self.pro_token = create_session_token(self.user_pro.id, "User", 1)
        session.close()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_anonymous_operational_call_rejected_401(self):
        """Verifies anonymous call to /api/port-scan/start returns 401."""
        resp = self.client.post("/api/port-scan/start", json={"scan_type": "localhost"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["code"], "AUTH_REQUIRED")

    def test_02_user_without_subscription_blocked_403(self):
        """Verifies user without subscription receives 403 SUBSCRIPTION_REQUIRED."""
        resp = self.client.post(
            "/api/port-scan/start",
            json={"scan_type": "localhost"},
            headers={"Authorization": f"Bearer {self.no_sub_token}"}
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["code"], "SUBSCRIPTION_REQUIRED")
        self.assertEqual(data["context"]["status"], "none")

    def test_03_user_with_pending_subscription_blocked_403(self):
        """Verifies user with pending request receives 403 with status='pending'."""
        resp = self.client.post(
            "/api/port-scan/start",
            json={"scan_type": "localhost"},
            headers={"Authorization": f"Bearer {self.pending_token}"}
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["code"], "SUBSCRIPTION_REQUIRED")
        self.assertEqual(data["context"]["status"], "pending")

    def test_04_user_with_expired_subscription_blocked_and_updated(self):
        """Verifies user with expired subscription receives 403 and status updated in DB."""
        resp = self.client.post(
            "/api/port-scan/start",
            json={"scan_type": "localhost"},
            headers={"Authorization": f"Bearer {self.expired_token}"}
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["code"], "SUBSCRIPTION_REQUIRED")
        self.assertEqual(data["context"]["status"], "expired")

        # Verify DB record is now expired
        session = self.SessionFactory()
        sub = session.query(UserSubscription).filter_by(user_id=self.user_expired.id).first()
        self.assertEqual(sub.status, "expired")
        session.close()

    def test_05_granular_feature_entitlement_enforcement(self):
        """Verifies Community tier can port scan but cannot network discover."""
        # 1. Port scan allowed (returns 200 or 400 for payload validation, NOT 403!)
        resp_port = self.client.post(
            "/api/port-scan/start",
            json={"scan_type": "localhost", "target": "127.0.0.1"},
            headers={"Authorization": f"Bearer {self.comm_token}"}
        )
        self.assertNotEqual(resp_port.status_code, 403)

        # 2. Network discovery blocked with feature_restricted
        resp_nd = self.client.post(
            "/api/network-discovery/start",
            json={"subnet": "192.168.1.0/24"},
            headers={"Authorization": f"Bearer {self.comm_token}"}
        )
        self.assertEqual(resp_nd.status_code, 403)
        data = resp_nd.get_json()
        self.assertEqual(data["code"], "FEATURE_NOT_INCLUDED")
        self.assertEqual(data["context"]["status"], "feature_restricted")
        self.assertIn("can_network_discovery", data["context"]["missing_feature"])

    def test_06_pro_subscriber_allowed_for_all_tools(self):
        """Verifies Pro tier is permitted for network discovery and port scan."""
        resp_nd = self.client.post(
            "/api/network-discovery/start",
            json={"subnet": "192.168.1.0/24"},
            headers={"Authorization": f"Bearer {self.pro_token}"}
        )
        self.assertNotEqual(resp_nd.status_code, 403)

    def test_07_admin_bypass_without_subscription(self):
        """Verifies Admin accesses all operational tools without needing a subscription."""
        resp = self.client.post(
            "/api/network-discovery/start",
            json={"subnet": "192.168.1.0/24"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertNotEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
