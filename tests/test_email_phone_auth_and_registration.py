"""
Acceptance Test Suite for SCOUT Registration Fields & Unified Email/Phone Login.
Covers all 12 required acceptance criteria:
1. Register with valid Full Name, Email, Phone Number, and Password.
2. Reject duplicate email (case-insensitive).
3. Reject duplicate phone number.
4. Reject invalid email and phone formats.
5. Reject mismatched passwords.
6. Log in using registered email and password.
7. Log out and log in using registered phone number and same password.
8. Verify that both methods authenticate the same user ID.
9. Verify that the account's subscriptions and permissions remain unchanged.
10. Verify that invalid credentials are rejected with generic messaging (no enumeration).
11. Verify that suspended accounts cannot bypass account restrictions.
12. Verify that existing accounts continue to work after database migration.
"""

import time
import unittest
from flask import Flask
from api import app
from modules.auth.db import init_db, get_db_session
from modules.auth.models import User
from modules.auth.security import normalize_phone_number, is_valid_phone_number, is_valid_email
from modules.subscriptions.models import SubscriptionPlan, UserSubscription


class TestEmailPhoneAuthAndRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_phone_normalization_utility(self):
        """Validates international and local phone number normalization logic."""
        # US / North America with punctuation
        self.assertEqual(normalize_phone_number("+1 (555) 123-4567"), "+15551234567")
        self.assertEqual(normalize_phone_number("1-555-123-4567"), "15551234567")

        # UK / International with 00 prefix
        self.assertEqual(normalize_phone_number("0044 20 7946 0919"), "+442079460919")

        # Egypt / International
        self.assertEqual(normalize_phone_number("+20 100 123 4567"), "+201001234567")
        self.assertEqual(normalize_phone_number("0100 123 4567"), "01001234567")

        # Germany / Japan standard
        self.assertEqual(normalize_phone_number("+49 (0) 30 123456"), "+49030123456")
        self.assertEqual(normalize_phone_number("+81 3 1234 5678"), "+81312345678")

        # Invalid formats
        self.assertIsNone(normalize_phone_number("12345"))  # Too short (< 7 digits)
        self.assertIsNone(normalize_phone_number("12345678901234567890"))  # Too long (> 15 digits)
        self.assertIsNone(normalize_phone_number("phone_number_here"))  # Letters
        self.assertIsNone(normalize_phone_number(""))  # Empty
        self.assertIsNone(normalize_phone_number(None))  # None

        # Boolean validator
        self.assertTrue(is_valid_phone_number("+15551234567"))
        self.assertFalse(is_valid_phone_number("invalid-phone"))

    def test_02_registration_success_and_acceptance_criteria_1_to_5(self):
        """
        Tests Acceptance Criteria 1 to 5:
        1. Register with valid Full Name, Email, Phone Number, Password.
        2. Reject duplicate email (case-insensitive).
        3. Reject duplicate phone number.
        4. Reject invalid email and phone formats.
        5. Reject mismatched passwords.
        """
        ts = int(time.time() * 1000)
        valid_email = f"operator_{ts}@scout-defense.io"
        valid_phone = f"+1555{ts % 10000000:07d}"
        valid_pw = "SecurePass#2026!"
        valid_name = "Alex Security Analyst"

        # 4. Reject invalid email format
        bad_email_resp = self.client.post("/api/auth/register", json={
            "full_name": valid_name,
            "email": "not-a-valid-email",
            "phone_number": valid_phone,
            "password": valid_pw,
            "confirm_password": valid_pw
        })
        self.assertEqual(bad_email_resp.status_code, 400)
        self.assertIn("Invalid email", bad_email_resp.get_json()["message"])

        # 4. Reject invalid phone format (letters, too short, etc.)
        bad_phone_resp = self.client.post("/api/auth/register", json={
            "full_name": valid_name,
            "email": valid_email,
            "phone_number": "123",  # Too short
            "password": valid_pw,
            "confirm_password": valid_pw
        })
        self.assertEqual(bad_phone_resp.status_code, 400)
        self.assertIn("Invalid phone number", bad_phone_resp.get_json()["message"])

        # 5. Reject mismatched passwords
        mismatch_resp = self.client.post("/api/auth/register", json={
            "full_name": valid_name,
            "email": valid_email,
            "phone_number": valid_phone,
            "password": valid_pw,
            "confirm_password": "DifferentPassword#2026"
        })
        self.assertEqual(mismatch_resp.status_code, 400)
        self.assertIn("do not match", mismatch_resp.get_json()["message"])

        # 1. Register with valid Full Name, Email, Phone Number, and Password
        reg_resp = self.client.post("/api/auth/register", json={
            "full_name": valid_name,
            "email": valid_email,
            "phone_number": valid_phone,
            "password": valid_pw,
            "confirm_password": valid_pw
        })
        self.assertEqual(reg_resp.status_code, 201)
        reg_data = reg_resp.get_json()
        self.assertEqual(reg_data["status"], "success")
        self.assertEqual(reg_data["user"]["full_name"], valid_name)
        self.assertEqual(reg_data["user"]["email"], valid_email.lower())
        self.assertEqual(reg_data["user"]["phone_number"], normalize_phone_number(valid_phone))
        created_user_id = reg_data["user"]["id"]

        # Verify no password hash or plaintext leaked in user response
        self.assertNotIn("password_hash", reg_data["user"])
        self.assertNotIn("password", reg_data["user"])

        # Logout registered user session
        self.client.post("/api/auth/logout")

        # 2. Reject duplicate email (case-insensitive check)
        dup_email_resp = self.client.post("/api/auth/register", json={
            "full_name": "Another Operator",
            "email": valid_email.upper(),  # Different case, must still be rejected
            "phone_number": f"+1555{((ts + 1) % 10000000):07d}",
            "password": valid_pw,
            "confirm_password": valid_pw
        })
        self.assertEqual(dup_email_resp.status_code, 409)
        self.assertIn("email address already exists", dup_email_resp.get_json()["message"])

        # 3. Reject duplicate phone number
        dup_phone_resp = self.client.post("/api/auth/register", json={
            "full_name": "Third Operator",
            "email": f"operator_alt_{ts}@scout-defense.io",
            "phone_number": valid_phone,  # Same phone number
            "password": valid_pw,
            "confirm_password": valid_pw
        })
        self.assertEqual(dup_phone_resp.status_code, 409)
        self.assertIn("phone number already exists", dup_phone_resp.get_json()["message"])

    def test_03_login_with_email_and_phone_acceptance_criteria_6_to_9(self):
        """
        Tests Acceptance Criteria 6 to 9:
        6. Log in using registered email and password.
        7. Log out and log in using registered phone number and same password.
        8. Verify both methods authenticate the same user ID.
        9. Verify account subscriptions and permissions remain unchanged.
        """
        ts = int(time.time() * 1000) + 100
        test_email = f"dual_auth_{ts}@scout.local"
        test_phone_raw = f"+44 20 7946 {ts % 10000:04d}"
        norm_phone = normalize_phone_number(test_phone_raw)
        password = "DualAuthPass#2026!"
        full_name = "Morgan Vance"

        # Register account
        reg_res = self.client.post("/api/auth/register", json={
            "full_name": full_name,
            "email": test_email,
            "phone_number": test_phone_raw,
            "password": password,
            "confirm_password": password
        })
        self.assertEqual(reg_res.status_code, 201)
        original_user_id = reg_res.get_json()["user"]["id"]
        self.client.post("/api/auth/logout")

        # Provision a subscription for this user to test subscription integrity (Criterion 9)
        with get_db_session() as session:
            plan = session.query(SubscriptionPlan).first()
            if not plan:
                plan = SubscriptionPlan(
                    name="Standard Defense Tier",
                    slug="standard-tier",
                    price=29.99,
                    billing_period="monthly",
                    tier_level=2,
                    duration_days=30,
                    features="live_monitoring,port_scanner"
                )
                session.add(plan)
                session.flush()

            sub = UserSubscription(
                user_id=original_user_id,
                plan_id=plan.id,
                status="active"
            )

            session.add(sub)
            session.flush()
            sub_id = sub.id

        # 6. Log in using registered email and password
        login_email_res = self.client.post("/api/auth/login", json={
            "identifier": test_email,
            "password": password
        })
        self.assertEqual(login_email_res.status_code, 200)
        email_login_data = login_email_res.get_json()
        self.assertEqual(email_login_data["status"], "success")
        self.assertEqual(email_login_data["user"]["id"], original_user_id)
        self.assertEqual(email_login_data["user"]["email"], test_email)

        # Verify active session identity via /api/auth/me
        me_email = self.client.get("/api/auth/me")
        self.assertEqual(me_email.status_code, 200)
        self.assertEqual(me_email.get_json()["user"]["id"], original_user_id)

        # 7. Log out
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Confirm session is revoked after logout
        me_revoked = self.client.get("/api/auth/me")
        self.assertEqual(me_revoked.status_code, 401)

        # 7. Log in using registered phone number and same password
        # Test with formatted input (spaces/dashes)
        login_phone_res = self.client.post("/api/auth/login", json={
            "identifier": test_phone_raw,
            "password": password
        })
        self.assertEqual(login_phone_res.status_code, 200)
        phone_login_data = login_phone_res.get_json()
        self.assertEqual(phone_login_data["status"], "success")

        # 8. Verify both methods authenticate the exact same user ID
        self.assertEqual(phone_login_data["user"]["id"], original_user_id)
        self.assertEqual(phone_login_data["user"]["id"], email_login_data["user"]["id"])

        # 9. Verify account subscriptions and permissions remain unchanged
        with get_db_session() as session:
            user_sub = session.query(UserSubscription).filter_by(user_id=original_user_id).first()
            self.assertIsNotNone(user_sub)
            self.assertEqual(user_sub.id, sub_id)
            self.assertEqual(user_sub.status, "active")

        # Also test logging in using normalized phone without plus or spaces
        self.client.post("/api/auth/logout")
        digits_phone = norm_phone.replace("+", "")
        login_digits_res = self.client.post("/api/auth/login", json={
            "identifier": digits_phone,
            "password": password
        })
        self.assertEqual(login_digits_res.status_code, 200)
        self.assertEqual(login_digits_res.get_json()["user"]["id"], original_user_id)
        self.client.post("/api/auth/logout")

    def test_04_security_requirements_acceptance_criteria_10_and_11(self):
        """
        Tests Acceptance Criteria 10 and 11:
        10. Reject invalid credentials with generic message (mitigating enumeration).
        11. Reject suspended or disabled accounts.
        """
        ts = int(time.time() * 1000) + 200
        active_email = f"sec_active_{ts}@scout.local"
        active_phone = f"+1555{ts % 10000000:07d}"
        password = "SecurePassword#2026"

        reg_res = self.client.post("/api/auth/register", json={
            "full_name": "Security Test User",
            "email": active_email,
            "phone_number": active_phone,
            "password": password,
            "confirm_password": password
        })
        self.assertEqual(reg_res.status_code, 201)
        user_id = reg_res.get_json()["user"]["id"]
        self.client.post("/api/auth/logout")

        # 10. Invalid credentials: Non-existent identifier (email)
        res_nonexistent_email = self.client.post("/api/auth/login", json={
            "identifier": "non_existent_account@nowhere.io",
            "password": "RandomPassword#123"
        })
        self.assertEqual(res_nonexistent_email.status_code, 401)
        msg_nonexistent = res_nonexistent_email.get_json()["message"]
        # Must be generic "Invalid credentials." and NOT reveal whether account exists
        self.assertIn("Invalid credentials", msg_nonexistent)

        # 10. Invalid credentials: Non-existent identifier (phone number)
        res_nonexistent_phone = self.client.post("/api/auth/login", json={
            "identifier": "+19999999999",
            "password": "RandomPassword#123"
        })
        self.assertEqual(res_nonexistent_phone.status_code, 401)
        self.assertIn("Invalid credentials", res_nonexistent_phone.get_json()["message"])

        # 10. Invalid credentials: Valid user, wrong password
        res_wrong_pw = self.client.post("/api/auth/login", json={
            "identifier": active_email,
            "password": "WrongPassword#999"
        })
        self.assertEqual(res_wrong_pw.status_code, 401)
        # Message must be identical to non-existent account to prevent timing/content enumeration
        self.assertEqual(res_wrong_pw.get_json()["message"], msg_nonexistent)

        # 11. Suspended accounts cannot bypass account restrictions
        with get_db_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            user.is_active = False
            session.flush()

        # Try to log in with email
        suspended_login_email = self.client.post("/api/auth/login", json={
            "identifier": active_email,
            "password": password
        })
        self.assertEqual(suspended_login_email.status_code, 403)
        self.assertEqual(suspended_login_email.get_json()["code"], "ACCOUNT_DISABLED")

        # Try to log in with phone
        suspended_login_phone = self.client.post("/api/auth/login", json={
            "identifier": active_phone,
            "password": password
        })
        self.assertEqual(suspended_login_phone.status_code, 403)
        self.assertEqual(suspended_login_phone.get_json()["code"], "ACCOUNT_DISABLED")

    def test_05_legacy_accounts_continue_to_work_acceptance_criterion_12(self):
        """
        Tests Acceptance Criterion 12:
        Verify that existing accounts created prior to the migration (with legacy usernames
        and without phone numbers) continue to log in seamlessly, access protected routes,
        and retain their roles and IDs.
        """
        # Verify legacy account handling (username + email, phone_number=None)
        with get_db_session() as session:
            legacy_admin = session.query(User).filter(User.username == "admin_legacy_migrated").first()
            if not legacy_admin:
                legacy_admin = User(
                    username="admin_legacy_migrated",
                    email="legacy_admin@scout-migration.local",
                    phone_number=None,
                    role="Admin",
                    full_name="Legacy Admin User",
                    is_active=True
                )
                legacy_admin.set_password("AdminPass#2026")
                session.add(legacy_admin)
                session.flush()
            else:
                legacy_admin.set_password("AdminPass#2026")
                session.flush()

            legacy_username = legacy_admin.username
            legacy_email = legacy_admin.email
            legacy_id = legacy_admin.id
            legacy_role = legacy_admin.role

            # Ensure admin_scout has its standard password
            scout_adm = session.query(User).filter_by(username="admin_scout").first()
            if scout_adm:
                scout_adm.set_password("AdminPass#2026")
                session.flush()

        # 12. Verify legacy account can log in via email
        login_res_email = self.client.post("/api/auth/login", json={
            "identifier": legacy_email,
            "password": "AdminPass#2026"
        })
        self.assertEqual(login_res_email.status_code, 200)
        data = login_res_email.get_json()
        self.assertEqual(data["user"]["id"], legacy_id)
        self.assertEqual(data["user"]["role"], legacy_role)

        self.client.post("/api/auth/logout")

        # 12. Verify legacy account can ALSO log in via legacy username fallback
        login_res_username = self.client.post("/api/auth/login", json={
            "identifier": legacy_username,
            "password": "AdminPass#2026"
        })
        self.assertEqual(login_res_username.status_code, 200)
        self.assertEqual(login_res_username.get_json()["user"]["id"], legacy_id)
        self.client.post("/api/auth/logout")

    def test_06_profile_update_supports_phone_and_uniqueness(self):
        """Verifies that users and admins can update phone number, enforcing format and uniqueness."""
        ts = int(time.time() * 1000) + 300
        u1_email = f"prof1_{ts}@scout.local"
        u1_phone = f"+1555{ts % 10000000:07d}"
        password = "ProfilePassword#2026!"

        u2_email = f"prof2_{ts}@scout.local"
        u2_phone = f"+1555{((ts + 1) % 10000000):07d}"

        # Register User 1
        res1 = self.client.post("/api/auth/register", json={
            "full_name": "Profile User One",
            "email": u1_email,
            "phone_number": u1_phone,
            "password": password,
            "confirm_password": password
        })
        self.assertEqual(res1.status_code, 201)
        self.client.post("/api/auth/logout")

        # Register User 2
        res2 = self.client.post("/api/auth/register", json={
            "full_name": "Profile User Two",
            "email": u2_email,
            "phone_number": u2_phone,
            "password": password,
            "confirm_password": password
        })
        self.assertEqual(res2.status_code, 201)

        # While logged in as User 2, attempt to update phone to User 1's phone (Duplicate check)
        dup_phone_update = self.client.put("/api/auth/profile", json={
            "phone_number": u1_phone
        })
        self.assertEqual(dup_phone_update.status_code, 409)
        self.assertIn("phone number already exists", dup_phone_update.get_json()["message"])

        # Update phone to a new unique valid number
        new_phone = f"+1555{((ts + 5) % 10000000):07d}"
        valid_update = self.client.put("/api/auth/profile", json={
            "full_name": "Updated Name",
            "phone_number": new_phone
        })
        self.assertEqual(valid_update.status_code, 200)
        self.assertEqual(valid_update.get_json()["user"]["phone_number"], normalize_phone_number(new_phone))
        self.client.post("/api/auth/logout")

    def test_07_admin_user_and_subscription_search_by_phone(self):
        """Verifies that the Admin console filters users and subscriptions by phone number."""
        # Log in as an admin using standard credentials
        login_res = self.client.post("/api/auth/login", json={
            "identifier": "admin@scout-soc.local",
            "password": "AdminPass#2026"
        })
        self.assertEqual(login_res.status_code, 200)


        # Register a test target user with a specific unique phone number
        ts = int(time.time() * 1000)
        target_phone = f"+1555{ts % 10000000:07d}"
        target_snippet = target_phone[-5:]
        target_email = f"search_target_{ts}@scout.local"
        with get_db_session() as session:
            target = User(
                username=f"target_{ts}",
                email=target_email,
                phone_number=target_phone,
                full_name="Target Phone User",
                role="User",
                is_active=True
            )
            target.set_password("TargetPass#2026!")
            session.add(target)
            session.flush()

        # Query admin users API with phone snippet
        res = self.client.get(f"/api/admin/users?search={target_snippet}")
        self.assertEqual(res.status_code, 200)
        users = res.get_json().get("users", [])
        matched = [u for u in users if u["phone_number"] == target_phone]
        self.assertTrue(len(matched) > 0, "Admin search by phone number did not match target user.")

        self.client.post("/api/auth/logout")



if __name__ == "__main__":
    unittest.main()
