#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 1.5: Security Boundaries & Hardening Verification
Validates:
1. Cryptographic token tampering and signature forgery detection.
2. Expired session token rejection.
3. Immediate session revocation via session_version invalidation.
4. Immediate rejection of deactivated accounts on subsequent API calls.
5. Role elevation immunity (registering with "role": "Admin" stripped and forced to "User").
6. Parameter tampering and direct API call protection on administrative routes.
"""

import sys
import os
import time
import unittest
import tempfile
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.security import (
    create_session_token, verify_session_token,
    COOKIE_NAME, TOKEN_SALT
)


class TestPhase1SecurityBoundaries(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_sec_bounds.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        session = self.SessionFactory()
        self.user = User(
            username="analyst_test",
            email="test@scout.local",
            role="User",
            is_active=True,
            session_version=1
        )
        self.user.set_password("ComplexPass#123")

        self.admin = User(
            username="admin_test",
            email="admin@scout.local",
            role="Admin",
            is_active=True,
            session_version=1
        )
        self.admin.set_password("AdminComplex#123")

        session.add(self.user)
        session.add(self.admin)
        session.commit()
        self.user_id = self.user.id
        self.admin_id = self.admin.id
        session.close()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_forged_signature_token_rejected(self):
        """Verifies that a token signed with an unauthorized external secret key is rejected."""
        fake_serializer = URLSafeTimedSerializer("attacker_secret_key_12345", salt=TOKEN_SALT)
        forged_token = fake_serializer.dumps({"uid": self.admin_id, "role": "Admin", "ver": 1, "iat": time.time()})

        # Test verification directly
        self.assertIsNone(verify_session_token(forged_token))

        # Test against API
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
        self.assertEqual(resp.status_code, 401)

    def test_02_expired_token_rejected(self):
        """Verifies that expired session tokens are rejected."""
        # Create token with max_age = -1 (already expired)
        token = create_session_token(self.user_id, "User", 1)
        self.assertIsNone(verify_session_token(token, max_age=-1))

    def test_03_session_revocation_invalidates_issued_tokens(self):
        """Verifies that incrementing session_version immediately revokes outstanding tokens."""
        token_v1 = create_session_token(self.user_id, "User", session_version=1)

        # Valid with version 1
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        self.assertEqual(resp.status_code, 200)

        # Revoke sessions in database
        session = self.SessionFactory()
        user_db = session.query(User).filter_by(id=self.user_id).first()
        user_db.revoke_sessions()  # version becomes 2
        session.commit()
        session.close()

        # Token v1 is now rejected on the very next request
        resp_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_v1}"})
        self.assertEqual(resp_after.status_code, 401)
        self.assertIn("revoked", resp_after.get_json()["message"])

    def test_04_deactivated_account_blocked_immediately(self):
        """Verifies that disabling an account immediately revokes access even with valid token."""
        token = create_session_token(self.user_id, "User", session_version=1)

        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)

        # Deactivate account
        session = self.SessionFactory()
        user_db = session.query(User).filter_by(id=self.user_id).first()
        user_db.is_active = False
        session.commit()
        session.close()

        # Next request must be rejected
        resp_disabled = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp_disabled.status_code, 401)
        self.assertIn("disabled", resp_disabled.get_json()["message"])

    def test_05_role_tampering_during_registration_strictly_prevented(self):
        """Verifies that an attacker submitting role='Admin' is still created strictly as 'User'."""
        resp = self.client.post("/api/auth/register", json={
            "username": "attacker",
            "email": "attacker@evil.corp",
            "password": "AttackPassword#2026",
            "confirm_password": "AttackPassword#2026",
            "role": "Admin",  # Injected field
            "is_admin": True,
            "permissions": ["all"]
        })
        self.assertEqual(resp.status_code, 201)
        created_user = resp.get_json()["user"]
        self.assertEqual(created_user["role"], "User")

        # Verify DB directly
        session = self.SessionFactory()
        u = session.query(User).filter_by(username="attacker").first()
        self.assertEqual(u.role, "User")
        session.close()

    def test_06_direct_api_admin_bypass_blocked(self):
        """Verifies that directly calling Admin APIs without an Admin session is blocked."""
        # Anonymous
        resp_anon = self.client.post("/api/detected-attacks/clear")
        self.assertEqual(resp_anon.status_code, 401)

        # Standard User
        user_token = create_session_token(self.user_id, "User", 1)
        resp_user = self.client.post("/api/detected-attacks/clear", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(resp_user.status_code, 403)


if __name__ == "__main__":
    unittest.main()
