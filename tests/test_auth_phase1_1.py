#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 1.1: Core Database & User Identity
Validates:
1. SQLite database initialization and table schema generation.
2. User model password hashing with scrypt.
3. Verification of correct and incorrect passwords.
4. Enforcement of unique constraints for username and email.
5. Session version incrementation for token revocation.
6. Admin provisioning logic and password complexity validation.
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path
from sqlalchemy.exc import IntegrityError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.auth.models import User, Base
from modules.auth.db import get_engine, init_db, get_session_factory
from scripts.create_admin import validate_password_strength, create_admin_user


class TestPhase1DatabaseAndUser(unittest.TestCase):

    def setUp(self):
        """Set up an isolated temporary SQLite database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()

    def tearDown(self):
        """Clean up temporary test database."""
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_user_model_password_hashing(self):
        """Verifies that User.set_password uses scrypt and check_password works accurately."""
        user = User(username="analyst_alice", email="alice@scout.local", role="User")
        user.set_password("SecurePassword#2026")

        # Must be hashed and not stored in plaintext
        self.assertNotEqual(user.password_hash, "SecurePassword#2026")
        self.assertTrue(user.password_hash.startswith("scrypt:"))

        # Check correct password
        self.assertTrue(user.check_password("SecurePassword#2026"))

        # Check incorrect password
        self.assertFalse(user.check_password("WrongPassword#2026"))
        self.assertFalse(user.check_password(""))

    def test_02_password_length_constraint(self):
        """Ensures that passwords under 8 characters are rejected."""
        user = User(username="analyst_bob", email="bob@scout.local")
        with self.assertRaises(ValueError):
            user.set_password("short1!")

    def test_03_unique_constraints(self):
        """Verifies that duplicate usernames and emails raise IntegrityError."""
        session = self.SessionFactory()
        try:
            u1 = User(username="operator1", email="op1@scout.local")
            u1.set_password("ComplexPass#123")
            session.add(u1)
            session.commit()

            # Duplicate username
            u2 = User(username="operator1", email="different@scout.local")
            u2.set_password("ComplexPass#123")
            session.add(u2)
            with self.assertRaises(IntegrityError):
                session.commit()
            session.rollback()

            # Duplicate email
            u3 = User(username="different_op", email="op1@scout.local")
            u3.set_password("ComplexPass#123")
            session.add(u3)
            with self.assertRaises(IntegrityError):
                session.commit()
            session.rollback()
        finally:
            session.close()

    def test_04_session_revocation(self):
        """Verifies session_version incrementing."""
        user = User(username="analyst_carol", email="carol@scout.local", session_version=1)
        self.assertEqual(user.session_version, 1)
        user.revoke_sessions()
        self.assertEqual(user.session_version, 2)

    def test_05_password_strength_validation(self):
        """Verifies enterprise password complexity rules."""
        # Valid password
        valid, msg = validate_password_strength("ScoutSec#2026")
        self.assertTrue(valid)

        # Missing uppercase
        valid, _ = validate_password_strength("scoutsec#2026")
        self.assertFalse(valid)

        # Missing lowercase
        valid, _ = validate_password_strength("SCOUTSEC#2026")
        self.assertFalse(valid)

        # Missing digit
        valid, _ = validate_password_strength("ScoutSec#None")
        self.assertFalse(valid)

        # Missing special char
        valid, _ = validate_password_strength("ScoutSec2026NoSpecial")
        self.assertFalse(valid)

        # Too short (< 8 chars)
        valid, _ = validate_password_strength("Sc#2026")
        self.assertFalse(valid)

    def test_06_admin_provisioning_helper(self):
        """Tests scripts.create_admin.create_admin_user creates an Admin in the database."""
        # Point SCOUT_DB_PATH to our test database
        old_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)
        try:
            success, msg = create_admin_user(
                username="scout_admin",
                email="admin@scout.local",
                password="AdminMaster#2026",
                full_name="Lead SOC Architect"
            )
            self.assertTrue(success, f"create_admin_user failed: {msg}")

            # Verify Admin in DB
            session = self.SessionFactory()
            admin = session.query(User).filter_by(username="scout_admin").first()
            self.assertIsNotNone(admin)
            self.assertEqual(admin.role, "Admin")
            self.assertEqual(admin.email, "admin@scout.local")
            self.assertTrue(admin.is_active)
            self.assertTrue(admin.check_password("AdminMaster#2026"))
            session.close()

            # Attempting to re-create duplicate admin fails gracefully
            success2, msg2 = create_admin_user(
                username="scout_admin",
                email="admin2@scout.local",
                password="AdminMaster#2026"
            )
            self.assertFalse(success2)
            self.assertIn("already exists", msg2)
        finally:
            if old_path:
                os.environ["SCOUT_DB_PATH"] = old_path
            else:
                os.environ.pop("SCOUT_DB_PATH", None)


if __name__ == "__main__":
    unittest.main()
