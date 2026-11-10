#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite: User Platform Role Update and Database Persistence in SCOUT
Validates:
1. USER -> ADMIN promotion via PUT /api/admin/users/<id> and PATCH /api/admin/users/<id>/role
2. ADMIN -> USER demotion via PUT /api/admin/users/<id> and PATCH /api/admin/users/<id>/role
3. Idempotent role updates (USER -> USER, ADMIN -> ADMIN)
4. Case-insensitivity support ('USER', 'ADMIN', 'User', 'Admin', 'user', 'admin')
5. Rejection of invalid roles ('SuperUser', 'Guest', 'root', etc.) with HTTP 400
6. Protection against demoting the last active Administrator on the system
7. Non-admin authorization enforcement (HTTP 403 Forbidden for operators, 401 for anonymous)
8. Direct database record persistence verification in SQLite users table
9. Session invalidation on role change (session_version incremented)
10. Profile data integrity (full_name, email, phone_number preserved during role update)
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
from modules.auth.security import hash_password, create_session_token, verify_session_token, COOKIE_NAME
from modules.auth.db import get_engine, init_db, get_session_factory, get_db_session
from modules.auth.rate_limiter import login_rate_limiter


class TestUserRoleUpdatePersistence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_role_persistence.db"
        self.engine = get_engine(db_path=self.test_db_path)
        init_db(engine_override=self.engine)
        self.SessionFactory = get_session_factory()
        self.client = app.test_client()

        self.old_db_path = os.environ.get("SCOUT_DB_PATH")
        os.environ["SCOUT_DB_PATH"] = str(self.test_db_path)

        with login_rate_limiter._lock:
            login_rate_limiter._attempts.clear()
            login_rate_limiter._lockouts.clear()

        # Seed initial test users:
        # 1. Primary Admin (admin_primary)
        # 2. Secondary Admin (admin_secondary)
        # 3. Standard Operator (operator_one)
        with get_db_session() as session:
            admin1 = User(
                username="admin_primary",
                email="admin1@scout.local",
                phone_number="+15551111111",
                role="Admin",
                full_name="Lead Administrator",
                is_active=True,
                session_version=1
            )
            admin1.set_password("12345678")

            admin2 = User(
                username="admin_secondary",
                email="admin2@scout.local",
                phone_number="+15552222222",
                role="Admin",
                full_name="Secondary Administrator",
                is_active=True,
                session_version=1
            )
            admin2.set_password("12345678")

            op1 = User(
                username="operator_one",
                email="operator1@scout.local",
                phone_number="+15553333333",
                role="User",
                full_name="Standard Operator",
                is_active=True,
                session_version=1
            )
            op1.set_password("12345678")

            session.add_all([admin1, admin2, op1])
            session.flush()

            self.admin1_id = admin1.id
            self.admin2_id = admin2.id
            self.op1_id = op1.id

    def tearDown(self):
        if self.old_db_path:
            os.environ["SCOUT_DB_PATH"] = self.old_db_path
        else:
            os.environ.pop("SCOUT_DB_PATH", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _login(self, username="admin_primary", password="12345678"):
        resp = self.client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["token"]

    # =========================================================================
    # 1. USER -> ADMIN Promotion via PUT /api/admin/users/<id>
    # =========================================================================
    def test_user_to_admin_promotion_put(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Check operator initial session version & role
        with get_db_session() as session:
            op_before = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_before.role, "User")
            initial_version = op_before.session_version

        # Promote operator_one to ADMIN via PUT /api/admin/users/<id>
        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=headers,
            json={
                "full_name": "Standard Operator",
                "email": "operator1@scout.local",
                "phone_number": "+15553333333",
                "role": "Admin"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["role"], "Admin")

        # Verify DB record directly
        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "Admin")
            self.assertEqual(op_db.session_version, initial_version + 1)
            self.assertEqual(op_db.full_name, "Standard Operator")
            self.assertEqual(op_db.email, "operator1@scout.local")

        # Verify subsequent GET /api/admin/users/<id> reflects ADMIN
        get_resp = self.client.get(f"/api/admin/users/{self.op1_id}", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json()["user"]["role"], "Admin")

    # =========================================================================
    # 2. ADMIN -> USER Demotion via PUT /api/admin/users/<id>
    # =========================================================================
    def test_admin_to_user_demotion_put(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Verify admin2 is initially Admin
        with get_db_session() as session:
            admin2_before = session.query(User).filter_by(id=self.admin2_id).first()
            self.assertEqual(admin2_before.role, "Admin")
            initial_ver = admin2_before.session_version

        # Demote admin_secondary to USER via PUT /api/admin/users/<id>
        resp = self.client.put(
            f"/api/admin/users/{self.admin2_id}",
            headers=headers,
            json={
                "full_name": "Secondary Administrator",
                "email": "admin2@scout.local",
                "phone_number": "+15552222222",
                "role": "User"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["role"], "User")

        # Verify DB record directly
        with get_db_session() as session:
            admin2_db = session.query(User).filter_by(id=self.admin2_id).first()
            self.assertEqual(admin2_db.role, "User")
            self.assertEqual(admin2_db.session_version, initial_ver + 1)

        # Verify subsequent GET /api/admin/users/<id> reflects USER
        get_resp = self.client.get(f"/api/admin/users/{self.admin2_id}", headers=headers)
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.get_json()["user"]["role"], "User")

    # =========================================================================
    # 3. Idempotent Role Updates (USER -> USER, ADMIN -> ADMIN)
    # =========================================================================
    def test_idempotent_role_updates_no_session_bump(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # USER -> USER
        with get_db_session() as session:
            op = session.query(User).filter_by(id=self.op1_id).first()
            ver_before = op.session_version

        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=headers,
            json={"role": "User"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "User")

        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "User")
            # Session version should not bump for no-op role update
            self.assertEqual(op_db.session_version, ver_before)

        # ADMIN -> ADMIN
        with get_db_session() as session:
            ad2 = session.query(User).filter_by(id=self.admin2_id).first()
            ver_ad2_before = ad2.session_version

        resp = self.client.put(
            f"/api/admin/users/{self.admin2_id}",
            headers=headers,
            json={"role": "Admin"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "Admin")

        with get_db_session() as session:
            ad2_db = session.query(User).filter_by(id=self.admin2_id).first()
            self.assertEqual(ad2_db.role, "Admin")
            self.assertEqual(ad2_db.session_version, ver_ad2_before)

    # =========================================================================
    # 4. Case-Insensitive Role Input ('USER', 'ADMIN', 'user', 'admin')
    # =========================================================================
    def test_case_insensitive_role_normalization(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 'ADMIN' uppercase
        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=headers,
            json={"role": "ADMIN"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "Admin")

        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "Admin")

        # 'user' lowercase
        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=headers,
            json={"role": "user"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "User")

        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "User")

        # 'USER' uppercase via /role endpoint
        resp = self.client.patch(
            f"/api/admin/users/{self.admin2_id}/role",
            headers=headers,
            json={"role": "USER"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "User")

        # 'ADMIN' uppercase via /role endpoint
        resp = self.client.patch(
            f"/api/admin/users/{self.admin2_id}/role",
            headers=headers,
            json={"role": "ADMIN"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "Admin")

    # =========================================================================
    # 5. Invalid Roles Rejected with HTTP 400
    # =========================================================================
    def test_invalid_role_values_rejected(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        invalid_roles = ["SuperAdmin", "root", "Guest", "Moderator", "", "123", "User; DROP TABLE users;"]
        for bad_role in invalid_roles:
            resp = self.client.put(
                f"/api/admin/users/{self.op1_id}",
                headers=headers,
                json={"role": bad_role}
            )
            self.assertEqual(resp.status_code, 400, f"Expected 400 for bad role '{bad_role}'")
            self.assertIn("Invalid role", resp.get_json()["message"])

            # Verify role in DB was not altered
            with get_db_session() as session:
                op_db = session.query(User).filter_by(id=self.op1_id).first()
                self.assertEqual(op_db.role, "User")

    # =========================================================================
    # 6. Guard: Demoting the Last Active Administrator is Blocked
    # =========================================================================
    def test_last_active_admin_demotion_guard(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # First demote admin_secondary -> leaving only 1 active admin (admin_primary)
        resp1 = self.client.put(
            f"/api/admin/users/{self.admin2_id}",
            headers=headers,
            json={"role": "User"}
        )
        self.assertEqual(resp1.status_code, 200)

        # Now attempt to demote admin_primary (last active administrator)
        resp2 = self.client.put(
            f"/api/admin/users/{self.admin1_id}",
            headers=headers,
            json={"role": "User"}
        )
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Cannot demote the last active Administrator", resp2.get_json()["message"])

        # Confirm admin_primary is STILL Admin in DB
        with get_db_session() as session:
            admin_db = session.query(User).filter_by(id=self.admin1_id).first()
            self.assertEqual(admin_db.role, "Admin")

        # Attempt same through /role endpoint
        resp3 = self.client.patch(
            f"/api/admin/users/{self.admin1_id}/role",
            headers=headers,
            json={"role": "User"}
        )
        self.assertEqual(resp3.status_code, 400)
        self.assertIn("Cannot demote the last active Administrator", resp3.get_json()["message"])

    # =========================================================================
    # 7. Authorization & Security Guards (Non-Admin / Anonymous Rejection)
    # =========================================================================
    def test_unauthorized_role_modification_rejected(self):
        # 1. Anonymous request -> 401
        anon_resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            json={"role": "Admin"}
        )
        self.assertEqual(anon_resp.status_code, 401)

        # 2. Operator user trying to assign themselves Admin -> 403 Forbidden
        op_token = self._login("operator_one")
        op_headers = {"Authorization": f"Bearer {op_token}"}

        op_resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=op_headers,
            json={"role": "Admin"}
        )
        self.assertEqual(op_resp.status_code, 403)
        self.assertIn("ROLE_UNAUTHORIZED", op_resp.get_json()["code"])

        # Verify operator is still User in DB
        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "User")

    # =========================================================================
    # 8. Unrelated Fields Preserved During Role Modification
    # =========================================================================
    def test_unrelated_fields_preserved_during_role_update(self):
        admin_token = self._login("admin_primary")
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Update ONLY role, leaving full_name, email, phone None in payload
        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers=headers,
            json={"role": "Admin"}
        )
        self.assertEqual(resp.status_code, 200)

        with get_db_session() as session:
            op_db = session.query(User).filter_by(id=self.op1_id).first()
            self.assertEqual(op_db.role, "Admin")
            self.assertEqual(op_db.full_name, "Standard Operator")
            self.assertEqual(op_db.email, "operator1@scout.local")
            self.assertEqual(op_db.phone_number, "+15553333333")
            self.assertTrue(op_db.is_active)

    # =========================================================================
    # 9. Session Revocation Enforced for Updated User
    # =========================================================================
    def test_session_revocation_enforced_after_role_change(self):
        # 1. Operator logs in and gets an active token
        op_token = self._login("operator_one")

        # Verify token works for /api/auth/me
        me_resp1 = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {op_token}"})
        self.assertEqual(me_resp1.status_code, 200)
        self.assertEqual(me_resp1.get_json()["user"]["role"], "User")

        # 2. Admin promotes operator to Admin
        admin_token = self._login("admin_primary")
        resp = self.client.put(
            f"/api/admin/users/{self.op1_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": "Admin"}
        )
        self.assertEqual(resp.status_code, 200)

        # 3. Old operator token must be rejected because session_version was revoked
        me_resp2 = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {op_token}"})
        self.assertEqual(me_resp2.status_code, 401)
        self.assertIn("Session has been revoked", me_resp2.get_json()["message"])

        # 4. Operator logs in afresh -> gets brand new token with Admin role
        op_new_token = self._login("operator_one")
        me_resp3 = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {op_new_token}"})
        self.assertEqual(me_resp3.status_code, 200)
        self.assertEqual(me_resp3.get_json()["user"]["role"], "Admin")

    # =========================================================================
    # 10. Self-Demotion by Administrator (Safe Session Cookie Refresh & Access Revocation)
    # =========================================================================
    def test_self_demotion_admin_receives_refreshed_user_token(self):
        # admin_secondary demotes themselves (admin_primary remains active admin)
        admin2_token = self._login("admin_secondary")
        self.client.set_cookie(COOKIE_NAME, admin2_token)

        resp = self.client.put(
            f"/api/admin/users/{self.admin2_id}",
            json={"role": "User"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["role"], "User")

        # Confirm cookie was updated in response
        cookie = resp.headers.get("Set-Cookie", "")
        self.assertIn(COOKIE_NAME, cookie)

        # Now when admin_secondary accesses /api/auth/me, they are authenticated as 'User'
        me_resp = self.client.get("/api/auth/me")
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.get_json()["user"]["role"], "User")

        # And admin_secondary can NO LONGER access /api/admin/users
        admin_access_resp = self.client.get("/api/admin/users")
        self.assertEqual(admin_access_resp.status_code, 403)
        self.assertIn("ROLE_UNAUTHORIZED", admin_access_resp.get_json()["code"])


if __name__ == "__main__":
    unittest.main()
