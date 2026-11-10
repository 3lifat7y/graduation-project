#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: Subscription Plan Required-Field Validation Bug and Content Container Padding
Validates:
1. Creation of subscription plan with valid Plan Code Identifier and Plan Display Name succeeds (HTTP 201).
2. Database persistence verification (fields accurately saved in subscription_plans SQLite table).
3. Handling of both 'plan_code' and 'code' payload keys for full frontend-backend interoperability.
4. Handling of both 'duration_value' and 'duration_days'.
5. Rejection of empty plan_code or name with HTTP 400 and message 'Plan code and name are required.'
6. Rejection of whitespace-only plan_code or name with HTTP 400 and message 'Plan code and name are required.'
7. Automatic trimming of leading and trailing whitespace.
8. Rejection of duplicate plan code with HTTP 409 Conflict.
9. Rejection of negative price with HTTP 400.
10. Rejection of invalid duration with HTTP 400.
11. Update of subscription plan via PUT /api/admin/plans/<id>.
12. CSS container padding inspection (.full-page-management-view, .management-card, media queries).
13. HTML template element and ID inspection in templates/ddos.html.
14. JavaScript form submission payload inspection in static/main.js.
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.security import create_session_token, COOKIE_NAME
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.rate_limiter import login_rate_limiter
from modules.subscriptions.models import SubscriptionPlan


class TestPlanCreationValidationAndPadding(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SECRET_KEY"] = "scout-test-plan-validation-key-2026"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_plan_validation.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Create Admin User
        with self.SessionFactory() as session:
            self.admin = User(
                username="admin_plan_tester",
                email="admin_plan@scout.local",
                role="Admin",
                is_active=True
            )
            self.admin.set_password("AdminSecurePass!1")
            session.add(self.admin)
            session.commit()
            self.admin_id = self.admin.id

        self.token = create_session_token(self.admin_id, "Admin", 1)
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        self.client.set_cookie(key=COOKIE_NAME, value=self.token)

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

    # =========================================================================
    # 1. Successful Plan Creation with Valid Plan Code and Plan Name
    # =========================================================================
    def test_01_create_plan_with_valid_plan_code_and_name(self):
        """Entering valid plan_code and name successfully creates plan with HTTP 201."""
        payload = {
            "plan_code": "basic-plan",
            "name": "Basic",
            "description": "Essential network protection for home lab or small office.",
            "price": 19.99,
            "currency": "USD",
            "duration_value": 30,
            "duration_unit": "days",
            "is_active": True,
            "features": {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": False,
                "max_concurrent_scans": 2
            }
        }
        res = self.client.post("/api/admin/plans", headers=self.headers, json=payload)
        self.assertEqual(res.status_code, 201, f"Expected 201, got {res.status_code}: {res.get_data(as_text=True)}")
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("created successfully", data["message"])
        self.assertIn("plan", data)
        self.assertEqual(data["plan"]["plan_code"], "BASIC-PLAN")
        self.assertEqual(data["plan"]["name"], "Basic")
        self.assertEqual(data["plan"]["price"], 19.99)

        # Verify DB record directly
        with self.SessionFactory() as session:
            db_plan = session.query(SubscriptionPlan).filter_by(plan_code="BASIC-PLAN").first()
            self.assertIsNotNone(db_plan)
            self.assertEqual(db_plan.name, "Basic")
            self.assertEqual(db_plan.price, 19.99)
            self.assertTrue(db_plan.is_active)
            features = db_plan.get_features()
            self.assertTrue(features.get("can_live_monitoring"))
            self.assertTrue(features.get("can_port_scan"))
            self.assertFalse(features.get("can_network_discovery"))

    # =========================================================================
    # 2. Interoperability: Creation using 'code' & 'duration_days' (Frontend format)
    # =========================================================================
    def test_02_create_plan_with_frontend_code_key(self):
        """Frontend sending 'code' and 'duration_days' is accepted seamlessly by backend."""
        payload = {
            "code": "pro-tier",
            "name": "Professional Tier",
            "description": "Full telemetry and scan capabilities",
            "price": 49.00,
            "duration_days": 60,
            "is_active": True,
            "features": {
                "can_monitor": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "max_scans_per_day": 5
            }
        }
        res = self.client.post("/api/admin/plans", headers=self.headers, json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["plan"]["plan_code"], "PRO-TIER")
        self.assertEqual(data["plan"]["code"], "PRO-TIER")
        self.assertEqual(data["plan"]["duration_value"], 60)
        self.assertEqual(data["plan"]["duration_days"], 60)

        # Verify feature alias normalization
        with self.SessionFactory() as session:
            db_plan = session.query(SubscriptionPlan).filter_by(plan_code="PRO-TIER").first()
            self.assertIsNotNone(db_plan)
            f = db_plan.get_features()
            self.assertTrue(f.get("can_live_monitoring"))
            self.assertTrue(f.get("can_monitor"))
            self.assertEqual(f.get("max_concurrent_scans"), 5)

    # =========================================================================
    # 3. Empty Plan Code or Name Rejection
    # =========================================================================
    def test_03_empty_plan_code_or_name_rejected(self):
        """Genuinely empty required fields return HTTP 400 with 'Plan code and name are required.'"""
        # Missing plan_code
        res = self.client.post("/api/admin/plans", headers=self.headers, json={"name": "Basic Only"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Plan code and name are required.")

        # Missing name
        res = self.client.post("/api/admin/plans", headers=self.headers, json={"plan_code": "code-only"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Plan code and name are required.")

        # Both empty
        res = self.client.post("/api/admin/plans", headers=self.headers, json={"plan_code": "", "name": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Plan code and name are required.")

    # =========================================================================
    # 4. Whitespace-Only Plan Code or Name Rejection
    # =========================================================================
    def test_04_whitespace_only_plan_code_or_name_rejected(self):
        """Whitespace-only values are treated as empty and rejected with HTTP 400."""
        res = self.client.post("/api/admin/plans", headers=self.headers, json={
            "plan_code": "   ",
            "name": "   "
        })
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["message"], "Plan code and name are required.")

    # =========================================================================
    # 5. Leading and Trailing Whitespace Sanitized
    # =========================================================================
    def test_05_whitespace_sanitization(self):
        """Leading/trailing spaces on valid inputs are cleanly trimmed."""
        payload = {
            "plan_code": "  enterprise-soc  ",
            "name": "  Enterprise SOC Tier  ",
            "price": 199.00
        }
        res = self.client.post("/api/admin/plans", headers=self.headers, json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["plan"]["plan_code"], "ENTERPRISE-SOC")
        self.assertEqual(data["plan"]["name"], "Enterprise SOC Tier")

        with self.SessionFactory() as session:
            db_plan = session.query(SubscriptionPlan).filter_by(plan_code="ENTERPRISE-SOC").first()
            self.assertIsNotNone(db_plan)
            self.assertEqual(db_plan.name, "Enterprise SOC Tier")

    # =========================================================================
    # 6. Duplicate Plan Code Rejection
    # =========================================================================
    def test_06_duplicate_plan_code_returns_conflict_409(self):
        """Duplicate plan_code returns HTTP 409 Conflict with informative error message."""
        payload = {"plan_code": "DUPLICATE-TEST", "name": "Initial Plan"}
        res1 = self.client.post("/api/admin/plans", headers=self.headers, json=payload)
        self.assertEqual(res1.status_code, 201)

        # Attempt to create again with same code (case-insensitive)
        payload2 = {"plan_code": "duplicate-test", "name": "Second Plan"}
        res2 = self.client.post("/api/admin/plans", headers=self.headers, json=payload2)
        self.assertEqual(res2.status_code, 409)
        data = res2.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("already exists", data["message"])

    # =========================================================================
    # 7. Price and Duration Validation
    # =========================================================================
    def test_07_price_and_duration_validation(self):
        """Negative price or zero/negative duration are rejected with appropriate messages."""
        # Negative price
        res = self.client.post("/api/admin/plans", headers=self.headers, json={
            "plan_code": "VALID-CODE-1",
            "name": "Valid Name",
            "price": -10.0
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Price cannot be negative", res.get_json()["message"])

        # Zero duration
        res = self.client.post("/api/admin/plans", headers=self.headers, json={
            "plan_code": "VALID-CODE-2",
            "name": "Valid Name",
            "duration_value": 0
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Duration must be greater than zero", res.get_json()["message"])

    # =========================================================================
    # 8. Plan Update Verification (PUT /api/admin/plans/<id>)
    # =========================================================================
    def test_08_plan_update_via_put(self):
        """Updating plan via PUT accepts both plan_code/code and duration_value/duration_days."""
        # Create initial
        res = self.client.post("/api/admin/plans", headers=self.headers, json={
            "plan_code": "ORIGINAL-CODE",
            "name": "Original Name",
            "price": 25.0
        })
        self.assertEqual(res.status_code, 201)
        plan_id = res.get_json()["plan"]["id"]

        # Update using frontend keys
        update_payload = {
            "code": "UPDATED-CODE",
            "name": "Updated Name",
            "price": 35.0,
            "duration_days": 90,
            "features": {
                "can_monitor": True,
                "can_port_scan": True,
                "can_network_discovery": True
            }
        }
        res_up = self.client.put(f"/api/admin/plans/{plan_id}", headers=self.headers, json=update_payload)
        self.assertEqual(res_up.status_code, 200)
        up_data = res_up.get_json()
        self.assertEqual(up_data["plan"]["plan_code"], "UPDATED-CODE")
        self.assertEqual(up_data["plan"]["name"], "Updated Name")
        self.assertEqual(up_data["plan"]["price"], 35.0)
        self.assertEqual(up_data["plan"]["duration_value"], 90)

    # =========================================================================
    # 9. UI Inspection: HTML Template Structure
    # =========================================================================
    def test_09_html_template_elements_and_ids(self):
        """Verify templates/ddos.html contains all required elements, IDs, and classes."""
        html_path = PROJECT_ROOT / "templates" / "ddos.html"
        self.assertTrue(html_path.exists())
        content = html_path.read_text(encoding="utf-8")

        # Container
        self.assertIn('id="adminPagePlanCreate"', content)
        self.assertIn('class="admin-panel full-page-management-view"', content)

        # Form Inputs
        self.assertIn('id="fpCreatePlanCode"', content)
        self.assertIn('id="fpCreatePlanName"', content)
        self.assertIn('id="fpCreatePlanPrice"', content)
        self.assertIn('id="fpCreatePlanDuration"', content)
        self.assertIn('id="fpCreatePlanDescription"', content)
        self.assertIn('id="fpCreatePlanMaxScans"', content)
        self.assertIn('id="fpCreatePlanTrafficLimit"', content)
        self.assertIn('id="fpCreatePlanFeatMonitoring"', content)
        self.assertIn('id="fpCreatePlanFeatPortScan"', content)
        self.assertIn('id="fpCreatePlanFeatDiscovery"', content)
        self.assertIn('id="fpCreatePlanIsActive"', content)

        # Alert and Buttons
        self.assertIn('id="fullPagePlanCreateAlert"', content)
        self.assertIn('id="fpCreatePlanSubmitBtn"', content)

        # Section Headings
        self.assertIn("Plan Specifications & Pricing", content)
        self.assertIn("Feature Entitlements & Quotas", content)

    # =========================================================================
    # 10. UI Inspection: CSS Container Padding and Responsive Spacing
    # =========================================================================
    def test_10_css_container_padding_and_responsive_rules(self):
        """Verify static/style.css applies consistent, comfortable padding to parent container."""
        css_path = PROJECT_ROOT / "static" / "style.css"
        self.assertTrue(css_path.exists())
        css = css_path.read_text(encoding="utf-8")

        # Parent Container Padding: must NOT be zero-padded on horizontal edges
        self.assertIn(".full-page-management-view", css)
        # Verify padding contains generous horizontal padding (e.g. 32px)
        self.assertIn("padding: 28px 32px 40px 32px;", css)

        # Management Card Padding
        self.assertIn(".management-card", css)
        self.assertIn("padding: 26px 28px;", css)

        # Breadcrumb Bar Spacing
        self.assertIn(".management-breadcrumb-bar", css)
        self.assertIn("margin-bottom: 24px;", css)

        # Responsive media queries for full-page management view
        self.assertIn("@media (max-width: 1024px)", css)
        self.assertIn("@media (max-width: 768px)", css)

        # Dark and Light Mode support
        self.assertIn('[data-theme="light"] .management-card', css)
        self.assertIn('[data-theme="light"] .management-breadcrumb-bar', css)

    # =========================================================================
    # 11. Frontend JavaScript Handler Inspection
    # =========================================================================
    def test_11_javascript_handler_payload_inspection(self):
        """Verify static/main.js sends both plan_code and code in JSON payload."""
        js_path = PROJECT_ROOT / "static" / "main.js"
        self.assertTrue(js_path.exists())
        js = js_path.read_text(encoding="utf-8")

        # Create Plan Handler
        self.assertIn("fpCreatePlanSubmitBtn", js)
        self.assertIn("plan_code: code", js)
        self.assertIn("code: code", js)
        self.assertIn("duration_value: isNaN(duration)", js)
        self.assertIn("duration_days: isNaN(duration)", js)
        self.assertIn("fullPagePlanCreateAlert", js)

        # Edit Plan Handler
        self.assertIn("fpEditPlanSubmitBtn", js)
        self.assertIn("switchView(\"admin-plans\")", js)


if __name__ == "__main__":
    unittest.main()
