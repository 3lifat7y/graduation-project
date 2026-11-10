#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verification Test Suite: SCOUT Admin Navigation & Users Management Audit & Fix
Tests:
1. Part 1: Horizontal Navigation Bar removal & Sidebar single primary navigation.
2. Part 2: Unified Sidebar Navigation across application (including Network Discovery).
3. Part 3A: User Details modal CSS and data contract (no black/empty screen).
4. Part 3B: Suspend / Reactivate lifecycle, authentication lockout, and guards.
5. Part 3C: Removal of 'Make Admin' button from Users Management UI.
6. Part 3D: Admin Create User endpoint (POST /api/admin/users) & modal elements.
7. Part 3E: Responsive 3-column / 2-column / 1-column user cards layout.
"""

import os
import sys
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


class TestAdminNavigationAndUsersManagementAuditFix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_audit_fix.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        seed_default_subscription_plans()

        with get_db_session() as session:
            self.admin = User(
                username="audit_lead_admin",
                email="admin_audit@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Lead Auditor Admin",
                role="Admin",
                is_active=True
            )
            self.sub_admin = User(
                username="audit_deputy_admin",
                email="deputy_audit@scout.local",
                password_hash=hash_password("AdminPass123!"),
                full_name="Deputy Auditor Admin",
                role="Admin",
                is_active=True
            )
            self.user = User(
                username="audit_operator_1",
                email="operator1@scout.local",
                password_hash=hash_password("UserPass123!"),
                full_name="Operator One",
                role="User",
                is_active=True
            )
            session.add_all([self.admin, self.sub_admin, self.user])
            session.flush()
            self.admin_id = self.admin.id
            self.sub_admin_id = self.sub_admin.id
            self.user_id = self.user.id

    def tearDown(self):
        if hasattr(self, "engine"):
            self.engine.dispose()
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        get_engine(reset=True)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _login_admin(self):
        resp = self.client.post("/api/auth/login", json={
            "username": "audit_lead_admin",
            "password": "AdminPass123!"
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json().get("token")

    def _login_user(self):
        resp = self.client.post("/api/auth/login", json={
            "username": "audit_operator_1",
            "password": "UserPass123!"
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json().get("token")

    # =========================================================================
    # Part 1: Horizontal Navigation Bar Removal
    # =========================================================================
    def test_part1_horizontal_navbar_removed_from_template(self):
        """Verifies horizontal navigation bar is removed from the Admin Dashboard."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # <div class="admin-tabs-bar" ...> must NOT be in the HTML
        self.assertNotIn('<div class="admin-tabs-bar"', html)

        # All 7 sections must remain in sidebarAdminNavGroup
        self.assertIn('data-nav="admin"', html)
        self.assertIn('data-nav="admin-users"', html)
        self.assertIn('data-nav="admin-plans"', html)
        self.assertIn('data-nav="admin-subs"', html)
        self.assertIn('data-nav="admin-requests"', html)
        self.assertIn('data-nav="admin-audit"', html)
        self.assertIn('data-nav="admin-profile"', html)

    def test_part1_css_prevents_horizontal_scrollbar(self):
        """Verifies CSS suppresses admin tabs bar and horizontal scrollbar."""
        css_path = PROJECT_ROOT / "static" / "style.css"
        css_text = css_path.read_text(encoding="utf-8")

        self.assertIn(".admin-tabs-bar", css_text)
        self.assertIn("display: none !important", css_text)

    # =========================================================================
    # Part 2: Unified Sidebar Navigation (Network Discovery)
    # =========================================================================
    def test_part2_network_discovery_sidebar_and_shell(self):
        """Verifies Network Discovery page contains unified sidebar and top navbar shell."""
        resp = self.client.get("/network-discovery")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Contains all 3 role groups
        self.assertIn('id="sidebarAdminNavGroup"', html)
        self.assertIn('id="sidebarUserNavGroup"', html)
        self.assertIn('id="sidebarToolsNavGroup"', html)

        # Admin nav items inside network discovery sidebar
        self.assertIn('href="/?view=admin"', html)
        self.assertIn('href="/?view=admin-users"', html)
        self.assertIn('href="/?view=admin-plans"', html)
        self.assertIn('href="/?view=admin-subs"', html)
        self.assertIn('href="/?view=admin-requests"', html)
        self.assertIn('href="/?view=admin-audit"', html)
        self.assertIn('href="/?view=admin-profile"', html)

        # Top navbar auth actions & user profile menu
        self.assertIn('id="publicAuthActions"', html)
        self.assertIn('id="userProfileMenu"', html)
        self.assertIn('id="userDropdownCard"', html)
        self.assertIn('id="signOutBtn"', html)

        # Network discovery script loads and initializes auth
        nd_js_path = PROJECT_ROOT / "static" / "network_discovery.js"
        nd_js = nd_js_path.read_text(encoding="utf-8")
        self.assertIn("initAuth", nd_js)
        self.assertIn("/api/auth/me", nd_js)

    # =========================================================================
    # Part 3A: User Details Modal & CSS (No Black / Empty Screen)
    # =========================================================================
    def test_part3a_user_details_modal_css_defined(self):
        """Verifies .auth-modal and .auth-modal-dialog are fully styled in CSS."""
        css_path = PROJECT_ROOT / "static" / "style.css"
        css_text = css_path.read_text(encoding="utf-8")

        # .auth-modal must be fixed overlay
        self.assertIn(".auth-modal", css_text)
        self.assertIn("position: fixed", css_text)
        self.assertIn(".auth-modal-dialog", css_text)

    def test_part3a_user_details_api_response(self):
        """Verifies GET /api/admin/users/<id> returns complete dossier data."""
        token = self._login_admin()
        resp = self.client.get(f"/api/admin/users/{self.user_id}", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("user", data)
        u = data["user"]
        self.assertEqual(u["id"], self.user_id)
        self.assertEqual(u["email"], "operator1@scout.local")
        self.assertEqual(u["full_name"], "Operator One")
        self.assertEqual(u["role"], "User")
        self.assertTrue(u["is_active"])
        self.assertIn("subscriptions", u)

    # =========================================================================
    # Part 3B: Suspend / Reactivate User Flow
    # =========================================================================
    def test_part3b_suspend_and_reactivate_user(self):
        """Verifies active user can be suspended, cannot log in, and can be reactivated."""
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Suspend operator
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["is_active"])

        # 2. Verify suspended user cannot authenticate
        login_resp = self.client.post("/api/auth/login", json={
            "username": "audit_operator_1",
            "password": "UserPass123!"
        })
        self.assertEqual(login_resp.status_code, 403)
        self.assertIn("ACCOUNT_DISABLED", login_resp.get_json().get("code", ""))

        # 3. Reactivate operator
        resp = self.client.patch(f"/api/admin/users/{self.user_id}/status", headers=headers, json={"is_active": True})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["is_active"])

        # 4. Verify user can authenticate again
        login_resp = self.client.post("/api/auth/login", json={
            "username": "audit_operator_1",
            "password": "UserPass123!"
        })
        self.assertEqual(login_resp.status_code, 200)

    def test_part3b_guards_prevent_self_suspension_and_last_admin_suspension(self):
        """Verifies admin cannot suspend self or the last active admin."""
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Attempt self-suspension
        resp = self.client.patch(f"/api/admin/users/{self.admin_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Administrators cannot deactivate their own account", resp.get_json().get("message", ""))

        # Suspend deputy admin
        resp = self.client.patch(f"/api/admin/users/{self.sub_admin_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 200)

        # Attempting to deactivate lead_admin now that deputy is disabled -> blocked (cannot deactivate last admin)
        resp = self.client.patch(f"/api/admin/users/{self.admin_id}/status", headers=headers, json={"is_active": False})
        self.assertEqual(resp.status_code, 400)

    # =========================================================================
    # Part 3C: Removal of Make Admin
    # =========================================================================
    def test_part3c_make_admin_button_removed_from_ui(self):
        """Verifies 'Make Admin' button is removed from main.js user card generation."""
        main_js_path = PROJECT_ROOT / "static" / "main.js"
        main_js = main_js_path.read_text(encoding="utf-8")

        # Must not contain Make Admin button in cardActionsHtml
        self.assertNotIn("btn-card-role-promote", main_js)
        self.assertNotIn("btn-card-role-demote", main_js)
        self.assertNotIn("> Make Admin<", main_js)
        self.assertNotIn("dossierToggleRoleBtn", main_js)

    # =========================================================================
    # Part 3D: Create User Endpoint & Modal Elements
    # =========================================================================
    def test_part3d_create_user_endpoint_rbac(self):
        """Verifies unauthorized users cannot access POST /api/admin/users."""
        # Anonymous
        resp = self.client.post("/api/admin/users", json={
            "email": "newuser@scout.local",
            "password": "Password123!"
        })
        self.assertEqual(resp.status_code, 401)

        # Standard User
        user_token = self._login_user()
        resp = self.client.post("/api/admin/users", headers={"Authorization": f"Bearer {user_token}"}, json={
            "email": "newuser@scout.local",
            "password": "Password123!"
        })
        self.assertEqual(resp.status_code, 403)

    def test_part3d_create_user_validation_and_success(self):
        """Verifies POST /api/admin/users validates required fields and creates User."""
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Missing email or password
        resp = self.client.post("/api/admin/users", headers=headers, json={})
        self.assertEqual(resp.status_code, 400)

        # Invalid email format
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "email": "not-an-email",
            "password": "12345678"
        })
        self.assertEqual(resp.status_code, 400)

        # Invalid password (not 8 digits)
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "email": "valid@scout.local",
            "password": "short"
        })
        self.assertEqual(resp.status_code, 400)

        # Invalid password (contains letters)
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "email": "valid@scout.local",
            "password": "1234abcd"
        })
        self.assertEqual(resp.status_code, 400)

        # Password confirmation mismatch
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "email": "valid@scout.local",
            "password": "12345678",
            "confirm_password": "87654321"
        })
        self.assertEqual(resp.status_code, 400)

        # Successful creation of standard User with 8-digit password
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "full_name": "Marcus Wright",
            "email": "marcus@scout.local",
            "phone_number": "+1 555 765 4321",
            "role": "User",
            "password": "12345678",
            "confirm_password": "12345678"
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["email"], "marcus@scout.local")
        self.assertEqual(data["user"]["role"], "User")

        # Newly created user can authenticate
        login_resp = self.client.post("/api/auth/login", json={
            "username": "marcus@scout.local",
            "password": "12345678"
        })
        self.assertEqual(login_resp.status_code, 200)

        # Duplicate email rejected with 409
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "email": "marcus@scout.local",
            "password": "12345678"
        })
        self.assertEqual(resp.status_code, 409)

        # Successful creation of Admin account with 8-digit password
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "full_name": "Sarah Connor",
            "email": "sarah.admin@scout.local",
            "role": "Admin",
            "password": "87654321",
            "confirm_password": "87654321"
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()["user"]["role"], "Admin")

    def test_part3d_create_user_modal_dom_elements(self):
        """Verifies Create User button and modal form elements exist in ddos.html."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn('id="adminCreateUserBtn"', html)
        self.assertIn('id="adminCreateUserModal"', html)
        self.assertIn('id="adminCreateFullName"', html)
        self.assertIn('id="adminCreateEmail"', html)
        self.assertIn('id="adminCreatePhone"', html)
        self.assertIn('id="adminCreateRole"', html)
        self.assertIn('id="adminCreatePassword"', html)
        self.assertIn('id="adminCreateConfirmPassword"', html)
        self.assertIn('id="adminCreateUserSubmitBtn"', html)

    # =========================================================================
    # Part 3E: Responsive Grid & User Cards Layout
    # =========================================================================
    def test_part3e_user_cards_grid_css(self):
        """Verifies CSS responsive 3-column grid for user cards."""
        css_path = PROJECT_ROOT / "static" / "style.css"
        css_text = css_path.read_text(encoding="utf-8")

        self.assertIn("grid-template-columns: repeat(3, 1fr)", css_text)
        self.assertIn("grid-template-columns: repeat(2, 1fr)", css_text)
        self.assertIn(".admin-user-card", css_text)
        self.assertIn("height: 100%", css_text)


if __name__ == "__main__":
    unittest.main()
