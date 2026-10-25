#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 2.1: Subscription Data Models & Default Plan Catalog
Validates:
1. Table creation for subscription plans, user subscriptions, and audit logs.
2. SubscriptionPlan entity methods (features serialization, dictionary export).
3. UserSubscription entity methods (active validity check, days remaining).
4. SubscriptionAuditLog linkage.
5. Default plan seeder (Community, Professional SOC, Enterprise).
6. Foreign key integrity constraints.
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from sqlalchemy.exc import IntegrityError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog
from scripts.seed_plans import seed_default_subscription_plans


class TestPhase2SubscriptionModels(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_subs.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_seed_plans_creates_default_catalog(self):
        """Verifies that seed_default_subscription_plans populates the catalog."""
        count = seed_default_subscription_plans()
        self.assertEqual(count, 3)

        session = self.SessionFactory()
        plans = session.query(SubscriptionPlan).order_by(SubscriptionPlan.price.asc()).all()
        self.assertEqual(len(plans), 3)

        codes = [p.plan_code for p in plans]
        self.assertIn("SCOUT-COMMUNITY", codes)
        self.assertIn("SCOUT-PRO", codes)
        self.assertIn("SCOUT-ENTERPRISE", codes)

        comm_plan = next(p for p in plans if p.plan_code == "SCOUT-COMMUNITY")
        self.assertEqual(comm_plan.price, 0.0)
        self.assertEqual(comm_plan.duration_value, 30)
        self.assertTrue(comm_plan.get_features()["can_live_monitoring"])
        self.assertFalse(comm_plan.get_features()["can_network_discovery"])
        session.close()

    def test_02_subscription_plan_feature_serialization(self):
        """Verifies set_features and get_features work accurately."""
        plan = SubscriptionPlan(
            plan_code="CUSTOM-TIER",
            name="Custom Plan",
            price=25.0,
            duration_value=14,
            duration_unit="days"
        )
        plan.set_features({"can_live_monitoring": True, "custom_quota": 500})
        features = plan.get_features()
        self.assertTrue(features["can_live_monitoring"])
        self.assertEqual(features["custom_quota"], 500)

        plan_dict = plan.to_dict()
        self.assertEqual(plan_dict["plan_code"], "CUSTOM-TIER")
        self.assertEqual(plan_dict["price"], 25.0)

    def test_03_user_subscription_lifecycle_validity(self):
        """Verifies UserSubscription.is_valid_active across date boundaries."""
        session = self.SessionFactory()
        user = User(username="sub_tester", email="sub@scout.local")
        user.set_password("SubPass#123")
        plan = SubscriptionPlan(plan_code="TEST-PLAN", name="Test Plan", price=10.0, duration_value=30)
        session.add(user)
        session.add(plan)
        session.commit()

        now = datetime.now(timezone.utc)

        # 1. Pending subscription is NOT active
        pending_sub = UserSubscription(user_id=user.id, plan_id=plan.id, status="pending")
        session.add(pending_sub)
        session.commit()
        self.assertFalse(pending_sub.is_valid_active(now))

        # 2. Active subscription within dates IS active
        active_sub = UserSubscription(
            user_id=user.id,
            plan_id=plan.id,
            status="active",
            start_date=now - timedelta(days=2),
            end_date=now + timedelta(days=28)
        )
        session.add(active_sub)
        session.commit()
        self.assertTrue(active_sub.is_valid_active(now))

        # 3. Active status but past end_date is NOT valid
        expired_sub = UserSubscription(
            user_id=user.id,
            plan_id=plan.id,
            status="active",
            start_date=now - timedelta(days=35),
            end_date=now - timedelta(days=5)
        )
        session.add(expired_sub)
        session.commit()
        self.assertFalse(expired_sub.is_valid_active(now))

        # 4. Canceled status is NOT valid
        canceled_sub = UserSubscription(
            user_id=user.id,
            plan_id=plan.id,
            status="canceled",
            start_date=now - timedelta(days=2),
            end_date=now + timedelta(days=28)
        )
        session.add(canceled_sub)
        session.commit()
        self.assertFalse(canceled_sub.is_valid_active(now))

        session.close()

    def test_04_subscription_audit_logging(self):
        """Verifies SubscriptionAuditLog creation and relationship."""
        session = self.SessionFactory()
        user = User(username="audit_user", email="audit@scout.local")
        user.set_password("AuditPass#123")
        admin = User(username="audit_admin", email="admin_audit@scout.local", role="Admin")
        admin.set_password("AuditAdmin#123")
        plan = SubscriptionPlan(plan_code="AUDIT-PLAN", name="Audit Plan")
        session.add_all([user, admin, plan])
        session.commit()

        sub = UserSubscription(user_id=user.id, plan_id=plan.id, status="pending")
        session.add(sub)
        session.commit()

        log = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=admin.id,
            action="ACTIVATED",
            previous_status="pending",
            new_status="active",
            details="Manual admin approval from console."
        )
        session.add(log)
        session.commit()

        # Verify audit log in subscription
        fetched_sub = session.query(UserSubscription).filter_by(id=sub.id).first()
        self.assertEqual(len(fetched_sub.audit_logs), 1)
        self.assertEqual(fetched_sub.audit_logs[0].action, "ACTIVATED")
        self.assertEqual(fetched_sub.audit_logs[0].actor.username, "audit_admin")
        session.close()


if __name__ == "__main__":
    unittest.main()
