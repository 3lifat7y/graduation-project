#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Test Suite for Phase 1.3: RBAC Middleware & Guard Decorators
Validates:
1. Unauthenticated requests to @admin_required endpoints return 401 Unauthorized.
2. Standard User (role="User") requests to @admin_required endpoints return 403 Forbidden.
3. Administrator (role="Admin") requests pass authorization and execute successfully.
"""

import sys
import os
import unittest
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api import app
from modules.auth.models import User
from modules.auth.db import get_engine, init_db, get_session_factory
from modules.auth.security import create_session_token, COOKIE_NAME


class TestPhase1RBACDecorators(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_rbac.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        # Seed 1 standard User and 1 Admin
        session = self.SessionFactory()
        self.standard_user = User(
            username="analyst_user",
            email="user@scout.local",
            role="User",
            is_active=True
        )
        self.standard_user.set_password("StandardPass#123")

        self.admin_user = User(
            username="soc_director",
            email="director@scout.local",
            role="Admin",
            is_active=True
        )
        self.admin_user.set_password("AdminDirector#123")

        session.add(self.standard_user)
        session.add(self.admin_user)
        session.commit()

        self.user_token = create_session_token(self.standard_user.id, self.standard_user.role, self.standard_user.session_version)
        self.admin_token = create_session_token(self.admin_user.id, self.admin_user.role, self.admin_user.session_version)
        session.close()

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        self.engine.dispose()
        self.temp_dir.cleanup()

    def test_01_unauthenticated_request_rejected(self):
        """Verifies that an unauthenticated caller receives 401 on @admin_required route."""
        resp = self.client.post("/api/detected-attacks/clear")
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertEqual(data["status"], "unauthorized")
        self.assertEqual(data["code"], "AUTH_REQUIRED")

    def test_02_standard_user_rejected_from_admin_route(self):
        """Verifies that an authenticated standard user receives 403 Forbidden on Admin route."""
        resp = self.client.post(
            "/api/detected-attacks/clear",
            headers={"Authorization": f"Bearer {self.user_token}"}
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["status"], "forbidden")
        self.assertEqual(data["code"], "ROLE_UNAUTHORIZED")
        self.assertIn("Requires one of roles: Admin", data["message"])

    def test_03_admin_user_allowed_on_admin_route(self):
        """Verifies that an authenticated Admin successfully accesses the protected route."""
        resp = self.client.post(
            "/api/detected-attacks/clear",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")

    def test_04_cookie_based_admin_auth(self):
        """Verifies that the session cookie properly identifies the Admin user."""
        self.client.set_cookie(COOKIE_NAME, self.admin_token)
        resp = self.client.post("/api/detected-attacks/clear")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
