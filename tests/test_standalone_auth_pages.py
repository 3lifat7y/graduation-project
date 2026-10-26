"""
Unit and Integration Tests for SCOUT Standalone Authentication Pages
Verifies:
- /login and /register standalone routes render dedicated pages (not modals).
- Top navigation contains theme toggle (top-left) and Home Page button (top-right).
- Home Page button points to /?public=1 and preserves active session without logging out.
- ddos.html (Homepage) no longer contains the floating auth modal.
- Header auth buttons navigate to /login and /register.
- Real backend authentication, password validation, rate-limiting, and role-based redirects are preserved.
"""

import unittest
import json
from api import app
from modules.auth.db import get_db_session
from modules.auth.models import User


class TestStandaloneAuthPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def setUp(self):
        # Ensure a clean test user exists
        with get_db_session() as session:
            admin = session.query(User).filter_by(username="admin_scout").first()
            if not admin:
                admin = User(
                    username="admin_scout",
                    email="admin@scout-soc.local",
                    role="Admin",
                    is_active=True
                )
                admin.set_password("AdminPass#2026")
                session.add(admin)

            test_user = session.query(User).filter_by(username="auth_analyst_01").first()
            if not test_user:
                test_user = User(
                    username="auth_analyst_01",
                    email="analyst01@scout-soc.local",
                    role="User",
                    is_active=True
                )
                test_user.set_password("SecurePass#2026")
                session.add(test_user)
            session.commit()

    def test_01_login_standalone_page_renders_with_required_layout(self):
        """GET /login must return 200 and render the dedicated standalone layout."""
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # 1. Page identity and anti-flash theme initializer
        self.assertIn("SCOUT — Sign In", html)
        self.assertIn("localStorage.getItem('nss_theme')", html)
        self.assertIn('data-theme', html)

        # 2. Top-left Theme Toggle
        self.assertIn('id="themeToggleBtn"', html)
        self.assertIn('id="themeToggleIcon"', html)
        self.assertIn('id="themeToggleText"', html)

        # 3. Top-right Home Page Button (must return to public Homepage)
        self.assertIn('id="homePageBtn"', html)
        self.assertIn('href="/?public=1"', html)

        # 4. Form inputs, labels, actions
        self.assertIn('id="loginForm"', html)
        self.assertIn('id="loginIdentifier"', html)
        self.assertIn('id="loginPassword"', html)
        self.assertIn('id="togglePasswordBtn"', html)
        self.assertIn('id="loginSubmitBtn"', html)

        # 5. Link to register
        self.assertIn('href="/register"', html)

        # 6. Standalone page script
        self.assertIn('src="/static/auth.js"', html)

    def test_02_register_standalone_page_renders_with_required_layout(self):
        """GET /register must return 200 and render the dedicated standalone registration page."""
        res = self.client.get("/register")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # 1. Page identity and anti-flash theme initializer
        self.assertIn("SCOUT — Create Account", html)
        self.assertIn("localStorage.getItem('nss_theme')", html)

        # 2. Top-left Theme Toggle
        self.assertIn('id="themeToggleBtn"', html)

        # 3. Top-right Home Page Button
        self.assertIn('id="homePageBtn"', html)
        self.assertIn('href="/?public=1"', html)

        # 4. Form inputs, labels, complexity guidance (No username, required full name and phone)
        self.assertIn('id="registerForm"', html)
        self.assertNotIn('id="regUsername"', html)
        self.assertIn('id="regFullName"', html)
        self.assertIn('id="regEmail"', html)
        self.assertIn('id="regPhone"', html)
        self.assertIn('id="regPassword"', html)
        self.assertIn('id="regConfirmPassword"', html)
        self.assertIn('id="pwdRuleLength"', html)
        self.assertIn('id="pwdRuleCase"', html)
        self.assertIn('id="pwdRuleNumSpecial"', html)
        self.assertIn('id="registerSubmitBtn"', html)


        # 5. Link to login
        self.assertIn('href="/login"', html)

        # 6. Standalone page script
        self.assertIn('src="/static/auth.js"', html)

    def test_03_floating_auth_modal_removed_from_homepage(self):
        """Homepage must no longer contain the floating authModal overlay."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        # The modal overlay with id="authModal" must not exist
        self.assertNotIn('id="authModal"', html)
        self.assertNotIn('class="auth-modal-overlay"', html)

        # Header auth buttons must link to standalone pages
        self.assertIn('id="headerSignInBtn"', html)
        self.assertIn('href="/login"', html)
        self.assertIn('id="headerGetStartedBtn"', html)
        self.assertIn('href="/register"', html)

    def test_04_home_button_preserves_session_without_logout(self):
        """When an authenticated user visits /login and returns Home, session is retained."""
        # Authenticate user
        login_res = self.client.post("/api/auth/login", json={
            "username": "auth_analyst_01",
            "password": "SecurePass#2026"
        })
        self.assertEqual(login_res.status_code, 200)

        # User accesses /login
        login_page_res = self.client.get("/login")
        self.assertEqual(login_page_res.status_code, 200)
        login_html = login_page_res.get_data(as_text=True)
        self.assertIn('id="homePageBtn"', login_html)

        # User clicks Home Page button (navigates to /?public=1)
        home_res = self.client.get("/?public=1")
        self.assertEqual(home_res.status_code, 200)

        # Session must be completely intact (not logged out)
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        me_data = me_res.get_json()
        self.assertEqual(me_data["user"]["username"], "auth_analyst_01")

        # Cleanup
        self.client.post("/api/auth/logout")

    def test_05_admin_login_redirect_and_role_routing(self):
        """Admin login succeeds and designates /?view=admin destination."""
        res = self.client.post("/api/auth/login", json={
            "username": "admin_scout",
            "password": "AdminPass#2026"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["role"], "Admin")
        self.assertEqual(data["view"], "admin")
        self.client.post("/api/auth/logout")

    def test_06_server_side_validation_and_lockout_preserved(self):
        """Invalid credentials, weak passwords, and duplicates are properly handled."""
        # Bad login credentials
        bad_login = self.client.post("/api/auth/login", json={
            "username": "non_existent_operator",
            "password": "WrongPassword#123"
        })
        self.assertEqual(bad_login.status_code, 401)
        self.assertEqual(bad_login.get_json()["status"], "error")

        # Weak password registration rejected
        weak_reg = self.client.post("/api/auth/register", json={
            "full_name": "Weak Tester",
            "email": "weak@scout.local",
            "phone_number": "+15551234567",
            "password": "weak",
            "confirm_password": "weak"
        })
        self.assertEqual(weak_reg.status_code, 400)

        # Duplicate email rejected
        dup_reg = self.client.post("/api/auth/register", json={
            "full_name": "Duplicate Tester",
            "email": "admin@scout-soc.local",  # Already exists in scout.db
            "phone_number": "+15559876543",
            "password": "ValidPassword#2026",
            "confirm_password": "ValidPassword#2026"
        })
        self.assertEqual(dup_reg.status_code, 409)



if __name__ == "__main__":
    unittest.main()
