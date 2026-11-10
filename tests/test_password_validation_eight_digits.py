#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dedicated Test Suite: SCOUT Exactly 8-Digit Password Validation Policy
Verifies:
1. Core validation rules in `scripts.create_admin.validate_password_strength`:
   - Must contain exactly 8 characters.
   - Accepts numeric digits only (0-9).
   - Rejects uppercase and lowercase letters.
   - Rejects special characters.
   - Rejects spaces and whitespace.
   - Rejects fewer than 8 digits (< 8).
   - Rejects more than 8 digits (> 8).
2. Registration endpoint (`POST /api/auth/register`):
   - Rejects non-8-digit passwords with clear validation messages.
   - Rejects letters and special characters with clear validation messages.
   - Enforces password confirmation match.
   - Accepts valid 8-digit numeric password.
   - Securely hashes password via scrypt (never plain text).
   - User can authenticate with the 8-digit password.
3. Admin Create User endpoint (`POST /api/admin/users`):
   - Rejects non-8-digit passwords with 400.
   - Enforces password confirmation match.
   - Accepts valid 8-digit numeric password.
4. Password Change endpoint (`POST /api/auth/change-password`):
   - Rejects non-8-digit new passwords.
   - Rejects letters/special characters.
   - Enforces new password confirmation match.
   - Changes password to valid 8-digit numeric string and revokes sessions.
5. Frontend Templates & UI Requirements:
   - `templates/register.html` displays "Exactly 8 digits" and "Numbers only (0–9)".
   - `templates/register.html` does NOT display "Uppercase & lowercase letters" or "Number & special character".
   - `templates/ddos.html` displays "Exactly 8 digits" and "Numbers only (0–9)".
   - Placeholders indicate 8 digits (0-9).
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.security import hash_password, verify_password
from modules.auth.db import get_engine, init_db, get_session_factory, get_db_session
from modules.auth.rate_limiter import login_rate_limiter
from scripts.create_admin import validate_password_strength, create_admin_user


class TestPasswordValidationEightDigits(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_password_rules.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed test admin
        with get_db_session() as session:
            self.admin = User(
                username="pwd_admin",
                email="admin_pwd@scout.local",
                password_hash=hash_password("88888888"),
                full_name="Password Policy Admin",
                role="Admin",
                is_active=True
            )
            session.add(self.admin)
            session.flush()
            self.admin_id = self.admin.id

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
            "username": "admin_pwd@scout.local",
            "password": "88888888"
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json().get("token")

    # =========================================================================
    # 1. Core Rule Unit Tests (scripts.create_admin.validate_password_strength)
    # =========================================================================
    def test_01_core_validator_accepts_exactly_eight_digits(self):
        """Verifies that 8-digit numeric strings pass validation."""
        valid_samples = ["12345678", "00000000", "99999999", "87654321", "55512345"]
        for sample in valid_samples:
            valid, msg = validate_password_strength(sample)
            self.assertTrue(valid, f"Expected '{sample}' to pass validation: {msg}")
            self.assertIn("exactly 8 digits", msg.lower())

    def test_02_core_validator_rejects_fewer_or_more_than_eight_digits(self):
        """Verifies that lengths != 8 are strictly rejected with length message."""
        valid, msg = validate_password_strength("")
        self.assertFalse(valid)
        self.assertIn("required", msg.lower())

        too_short = ["1", "12", "1234", "1234567"]
        for sample in too_short:
            valid, msg = validate_password_strength(sample)
            self.assertFalse(valid, f"Expected '{sample}' to be rejected")
            self.assertIn("exactly 8 digits long", msg)

        too_long = ["123456789", "1234567890", "000000000000"]
        for sample in too_long:
            valid, msg = validate_password_strength(sample)
            self.assertFalse(valid, f"Expected '{sample}' to be rejected")
            self.assertIn("exactly 8 digits long", msg)

    def test_03_core_validator_rejects_letters(self):
        """Verifies that uppercase and lowercase letters are rejected."""
        samples_with_letters = [
            "1234567a", "1234567A", "a1234567", "A1234567",
            "1234a567", "abcdefgh", "ABCDEFGH", "AbCdEfGh"
        ]
        for sample in samples_with_letters:
            valid, msg = validate_password_strength(sample)
            self.assertFalse(valid, f"Expected '{sample}' to be rejected")
            self.assertIn("numbers only (0-9)", msg)

    def test_04_core_validator_rejects_special_characters_and_spaces(self):
        """Verifies that special characters and whitespace are strictly rejected."""
        samples_with_specials = [
            "1234567!", "1234#567", "@1234567", "1234-567",
            "1234_567", "1234.567", "1234$567", "1234%567"
        ]
        for sample in samples_with_specials:
            valid, msg = validate_password_strength(sample)
            self.assertFalse(valid, f"Expected '{sample}' to be rejected")
            self.assertIn("numbers only (0-9)", msg)

        samples_with_spaces = ["1234 567", " 1234567", "1234567 ", "12  5678"]
        for sample in samples_with_spaces:
            valid, msg = validate_password_strength(sample)
            self.assertFalse(valid, f"Expected '{sample}' to be rejected")
            self.assertIn("numbers only (0-9)", msg)

    # =========================================================================
    # 2. Registration API Validation (POST /api/auth/register)
    # =========================================================================
    def test_05_register_rejects_invalid_passwords_and_mismatches(self):
        """Verifies /api/auth/register validates 8 digits and confirmation."""
        # Confirmation mismatch
        resp = self.client.post("/api/auth/register", json={
            "full_name": "Test Operator",
            "email": "testop@scout.local",
            "phone_number": "+15551234567",
            "password": "12345678",
            "confirm_password": "87654321"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("match", resp.get_json()["message"].lower())

        # Too short password
        resp = self.client.post("/api/auth/register", json={
            "full_name": "Test Operator",
            "email": "testop@scout.local",
            "phone_number": "+15551234567",
            "password": "12345",
            "confirm_password": "12345"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exactly 8 digits", resp.get_json()["message"])

        # Letters in password
        resp = self.client.post("/api/auth/register", json={
            "full_name": "Test Operator",
            "email": "testop@scout.local",
            "phone_number": "+15551234567",
            "password": "1234abcd",
            "confirm_password": "1234abcd"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("numbers only (0-9)", resp.get_json()["message"])

        # Special characters in password
        resp = self.client.post("/api/auth/register", json={
            "full_name": "Test Operator",
            "email": "testop@scout.local",
            "phone_number": "+15551234567",
            "password": "1234567!",
            "confirm_password": "1234567!"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("numbers only (0-9)", resp.get_json()["message"])

    def test_06_register_success_with_eight_digits_and_scrypt_hashing(self):
        """Verifies valid registration creates user with scrypt hash and can log in."""
        resp = self.client.post("/api/auth/register", json={
            "full_name": "Valid Operator",
            "email": "valid.operator@scout.local",
            "phone_number": "+15551234567",
            "password": "24681357",
            "confirm_password": "24681357"
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

        # Verify password in database is NOT plain text
        with get_db_session() as session:
            db_user = session.query(User).filter_by(email="valid.operator@scout.local").first()
            self.assertIsNotNone(db_user)
            self.assertNotEqual(db_user.password_hash, "24681357")
            self.assertTrue(db_user.password_hash.startswith("scrypt:"))
            self.assertTrue(verify_password(db_user.password_hash, "24681357"))

        # Verify user can log in with the 8-digit password
        login_resp = self.client.post("/api/auth/login", json={
            "identifier": "valid.operator@scout.local",
            "password": "24681357"
        })
        self.assertEqual(login_resp.status_code, 200)

    # =========================================================================
    # 3. Admin Create User API Validation (POST /api/admin/users)
    # =========================================================================
    def test_07_admin_create_user_enforces_eight_digits(self):
        """Verifies /api/admin/users enforces 8-digit password rule."""
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Letters in 8-char password rejected
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "full_name": "Admin Created User",
            "email": "admincreated@scout.local",
            "role": "User",
            "password": "1234abcd",
            "confirm_password": "1234abcd"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("numbers only (0-9)", resp.get_json()["message"])

        # 7 digits rejected
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "full_name": "Admin Created User",
            "email": "admincreated@scout.local",
            "role": "User",
            "password": "1234567",
            "confirm_password": "1234567"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exactly 8 digits", resp.get_json()["message"])

        # 8 digits success
        resp = self.client.post("/api/admin/users", headers=headers, json={
            "full_name": "Admin Created User",
            "email": "admincreated@scout.local",
            "role": "User",
            "password": "98765432",
            "confirm_password": "98765432"
        })
        self.assertEqual(resp.status_code, 201)

    # =========================================================================
    # 4. Password Change API Validation (POST /api/auth/change-password)
    # =========================================================================
    def test_08_change_password_enforces_eight_digits_and_revokes_sessions(self):
        """Verifies change-password enforces 8 digits and revokes previous sessions."""
        token = self._login_admin()
        headers = {"Authorization": f"Bearer {token}"}

        # Invalid new password (< 8 digits)
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "88888888",
            "new_password": "1234",
            "confirm_new_password": "1234"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exactly 8 digits", resp.get_json()["message"])

        # Invalid new password (contains letters)
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "88888888",
            "new_password": "1234abcd",
            "confirm_new_password": "1234abcd"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("numbers only (0-9)", resp.get_json()["message"])

        # Valid 8-digit new password
        resp = self.client.post("/api/auth/change-password", headers=headers, json={
            "current_password": "88888888",
            "new_password": "11223344",
            "confirm_new_password": "11223344"
        })
        self.assertEqual(resp.status_code, 200)

        # Old password no longer works
        old_login = self.client.post("/api/auth/login", json={
            "identifier": "admin_pwd@scout.local",
            "password": "88888888"
        })
        self.assertEqual(old_login.status_code, 401)

        # New 8-digit password works
        new_login = self.client.post("/api/auth/login", json={
            "identifier": "admin_pwd@scout.local",
            "password": "11223344"
        })
        self.assertEqual(new_login.status_code, 200)

    # =========================================================================
    # 5. Frontend Templates & UI Markup Inspection
    # =========================================================================
    def test_09_register_html_ui_requirements(self):
        """Verifies templates/register.html has updated guidance and removed old rules."""
        reg_path = PROJECT_ROOT / "templates" / "register.html"
        html = reg_path.read_text(encoding="utf-8")

        # Must contain new requirements
        self.assertIn("Exactly 8 digits", html)
        self.assertIn("Numbers only (0–9)", html)
        self.assertIn('id="pwdRuleLength"', html)
        self.assertIn('id="pwdRuleDigits"', html)

        # Must NOT contain removed old requirements
        self.assertNotIn("Uppercase &amp; lowercase letters", html)
        self.assertNotIn("Uppercase & lowercase", html)
        self.assertNotIn("Number &amp; special character", html)
        self.assertNotIn("Number & special character", html)

    def test_10_ddos_html_ui_guidance_and_placeholders(self):
        """Verifies templates/ddos.html placeholders and admin guidance reflect 8 digits."""
        ddos_path = PROJECT_ROOT / "templates" / "ddos.html"
        html = ddos_path.read_text(encoding="utf-8")

        # Admin password guidance
        self.assertIn('id="adminPwdRuleLength"', html)
        self.assertIn('id="adminPwdRuleDigits"', html)
        self.assertNotIn('id="adminPwdRuleCase"', html)
        self.assertNotIn('id="adminPwdRuleNumSpecial"', html)

        # Inputs specify 8 digits (0-9)
        self.assertIn('id="adminCreatePassword"', html)
        self.assertIn('placeholder="Exactly 8 digits (0-9)"', html)
        self.assertIn('id="adminNewPasswordInput"', html)
        self.assertIn('id="userDashNewPassword"', html)


if __name__ == "__main__":
    unittest.main()
