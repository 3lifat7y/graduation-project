#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT Subscription Plans Catalog Seeder
Seeds default initial subscription tiers into the database if not present.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.auth.db import init_db, get_db_session
from modules.subscriptions.models import SubscriptionPlan

DEFAULT_PLANS = [
    {
        "plan_code": "SCOUT-COMMUNITY",
        "name": "Community Analyst",
        "description": "Essential real-time traffic monitoring and local port enumeration for researchers.",
        "price": 0.0,
        "currency": "USD",
        "duration_value": 30,
        "duration_unit": "days",
        "is_active": True,
        "features": {
            "can_live_monitoring": True,
            "can_port_scan": True,
            "can_network_discovery": False,
            "can_export_reports": False
        }
    },
    {
        "plan_code": "SCOUT-PRO",
        "name": "Professional SOC Analyst",
        "description": "Full access to Live Traffic Intrusion Detection, Subnet Reconnaissance, and Target Port Audits.",
        "price": 49.0,
        "currency": "USD",
        "duration_value": 30,
        "duration_unit": "days",
        "is_active": True,
        "features": {
            "can_live_monitoring": True,
            "can_port_scan": True,
            "can_network_discovery": True,
            "can_export_reports": True
        }
    },
    {
        "plan_code": "SCOUT-ENTERPRISE",
        "name": "Enterprise Defense Fleet",
        "description": "Annual enterprise cybersecurity tier with continuous multi-class attack classification and complete telemetry.",
        "price": 499.0,
        "currency": "USD",
        "duration_value": 365,
        "duration_unit": "days",
        "is_active": True,
        "features": {
            "can_live_monitoring": True,
            "can_port_scan": True,
            "can_network_discovery": True,
            "can_export_reports": True,
            "unlimited_telemetry": True
        }
    }
]


def seed_default_subscription_plans() -> int:
    """Seeds default subscription plans if the catalog is empty."""
    init_db()
    created_count = 0

    with get_db_session() as session:
        for plan_def in DEFAULT_PLANS:
            existing = session.query(SubscriptionPlan).filter_by(plan_code=plan_def["plan_code"]).first()
            if not existing:
                plan = SubscriptionPlan(
                    plan_code=plan_def["plan_code"],
                    name=plan_def["name"],
                    description=plan_def["description"],
                    price=plan_def["price"],
                    currency=plan_def["currency"],
                    duration_value=plan_def["duration_value"],
                    duration_unit=plan_def["duration_unit"],
                    is_active=plan_def["is_active"]
                )
                plan.set_features(plan_def["features"])
                session.add(plan)
                created_count += 1

    return created_count


def main():
    print("=" * 70)
    print("      SCOUT — Subscription Plan Catalog Seeder")
    print("=" * 70)
    count = seed_default_subscription_plans()
    if count > 0:
        print(f"✅ Successfully seeded {count} new subscription plans into the database.")
    else:
        print("ℹ️ Subscription plans already present in database. No new plans created.")
    print("=" * 70)


if __name__ == "__main__":
    main()
