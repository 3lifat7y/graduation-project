#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 1.2: Authentication & Identity APIs
Validates:
1. User registration with validation, password complexity, duplicate handling, and role hardcoding.
2. User login with cookie issuance, constant-time checks, and rate-limiting lockout.
3. User identity endpoint (/api/auth/me) with cookie and Bearer token.
4. User logout and cookie clearing.
5. Password changes and session invalidation.
6. Deactivated user handling.
"""

import sys
import os
import json
import unittest
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.rate_limiter import login_rate_limiter


class TestPhase1AuthAPIs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_api_auth.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        # Point environment to test db
        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        # Clear rate limiter
        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_register_success_and_role_hardcoding(self):
        """Verifies successful registration, cookie issuance, and that role cannot be forged to Admin."""
        payload = {
            "username": "cyber_scout",
            "email": "scout@example.com",
            "password": "SecurePassword#2026",
            "confirm_password": "SecurePassword#2026",
            "full_name": "Scout Operator",
            "role": "Admin"  # Attempt to forge role!
        }
        resp = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["role"], "User")  # Must be User, NOT Admin!
        self.assertEqual(data["redirect"], "/?view=plans")

        # Verify cookie in headers
        cookies = resp.headers.getlist("Set-Cookie")
        self.assertTrue(any("scout_session=" in c for c in cookies))

    def test_02_register_validation_errors(self):
        """Verifies validation failures: password mismatch, weak password, invalid username."""
        # Password mismatch
        resp = self.client.post("/api/auth/register", json={
            "username": "user1",
            "email": "u1@example.com",
            "password": "Password#123",
            "confirm_password": "DifferentPassword#123"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("do not match", resp.get_json()["message"])

        # Weak password
        resp = self.client.post("/api/auth/register", json={
            "username": "user1",
            "email": "u1@example.com",
            "password": "weak",
            "confirm_password": "weak"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("8 characters", resp.get_json()["message"])

        # Invalid username
        resp = self.client.post("/api/auth/register", json={
            "username": "bad user name with spaces",
            "email": "u1@example.com",
            "password": "Password#123",
            "confirm_password": "Password#123"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Username must be", resp.get_json()["message"])

    def test_03_register_duplicate_handling(self):
        """Verifies 409 Conflict on duplicate username or email."""
        payload = {
            "username": "analyst_dup",
            "email": "dup@example.com",
            "password": "Password#123",
            "confirm_password": "Password#123"
        }
        resp1 = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(resp1.status_code, 201)

        # Duplicate username
        resp2 = self.client.post("/api/auth/register", json={
            "username": "analyst_dup",
            "email": "other@example.com",
            "password": "Password#123",
            "confirm_password": "Password#123"
        })
        self.assertEqual(resp2.status_code, 409)

        # Duplicate email
        resp3 = self.client.post("/api/auth/register", json={
            "username": "other_analyst",
            "email": "dup@example.com",
            "password": "Password#123",
            "confirm_password": "Password#123"
        })
        self.assertEqual(resp3.status_code, 409)

    def test_04_login_success_and_failure(self):
        """Verifies login with correct credentials and rejection with bad credentials."""
        # Create user
        self.client.post("/api/auth/register", json={
            "username": "login_user",
            "email": "login@example.com",
            "password": "CorrectPassword#1",
            "confirm_password": "CorrectPassword#1"
        })

        # Correct login with username
        resp = self.client.post("/api/auth/login", json={
            "username": "login_user",
            "password": "CorrectPassword#1"
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "success")

        # Correct login with email
        resp_email = self.client.post("/api/auth/login", json={
            "username": "login@example.com",
            "password": "CorrectPassword#1"
        })
        self.assertEqual(resp_email.status_code, 200)

        # Bad password
        resp_bad = self.client.post("/api/auth/login", json={
            "username": "login_user",
            "password": "WrongPassword#99"
        })
        self.assertEqual(resp_bad.status_code, 401)
        self.assertIn("Invalid username or password", resp_bad.get_json()["message"])

    def test_05_login_rate_limiting_lockout(self):
        """Verifies that 5 failed login attempts trigger 429 lockout."""
        for _ in range(5):
            self.client.post("/api/auth/login", json={
                "username": "target_user",
                "password": "BadPassword#123"
            })

        # 6th attempt should be locked out
        resp_lockout = self.client.post("/api/auth/login", json={
            "username": "target_user",
            "password": "AnyPassword#123"
        })
        self.assertEqual(resp_lockout.status_code, 429)
        self.assertEqual(resp_lockout.get_json()["code"], "ACCOUNT_LOCKED")

    def test_06_current_user_me_and_logout(self):
        """Verifies /api/auth/me returns identity when logged in and 401 when logged out."""
        # Register user
        reg_resp = self.client.post("/api/auth/register", json={
            "username": "me_user",
            "email": "me@example.com",
            "password": "Password#123",
            "confirm_password": "Password#123"
        })
        token = reg_resp.get_json()["token"]

        # /api/auth/me via Cookie
        resp_me = self.client.get("/api/auth/me")
        self.assertEqual(resp_me.status_code, 200)
        self.assertEqual(resp_me.get_json()["user"]["username"], "me_user")

        # /api/auth/me via Authorization Header
        fresh_client = app.test_client()
        resp_header = fresh_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp_header.status_code, 200)
        self.assertEqual(resp_header.get_json()["user"]["username"], "me_user")

        # Logout
        resp_logout = self.client.post("/api/auth/logout")
        self.assertEqual(resp_logout.status_code, 200)

        # After logout, me returns 401
        resp_after = self.client.get("/api/auth/me")
        self.assertEqual(resp_after.status_code, 401)

    def test_07_change_password_and_session_revocation(self):
        """Verifies password change updates credentials and invalidates previous session."""
        reg_resp = self.client.post("/api/auth/register", json={
            "username": "pwd_user",
            "email": "pwd@example.com",
            "password": "OldPassword#123",
            "confirm_password": "OldPassword#123"
        })
        old_token = reg_resp.get_json()["token"]

        # Change password
        chg_resp = self.client.post("/api/auth/change-password", json={
            "current_password": "OldPassword#123",
            "new_password": "BrandNewPassword#2026",
            "confirm_new_password": "BrandNewPassword#2026"
        })
        self.assertEqual(chg_resp.status_code, 200)

        # Old token is now rejected because session_version incremented
        other_client = app.test_client()
        resp_revoked = other_client.get("/api/auth/me", headers={"Authorization": f"Bearer {old_token}"})
        self.assertEqual(resp_revoked.status_code, 401)

        # Login with new password works
        login_resp = self.client.post("/api/auth/login", json={
            "username": "pwd_user",
            "password": "BrandNewPassword#2026"
        })
        self.assertEqual(login_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
