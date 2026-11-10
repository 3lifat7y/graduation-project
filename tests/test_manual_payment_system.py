"""
Automated Integration Tests for SCOUT Manual Payment System & Payment Methods Management.
Verifies Admin CRUD, Receiving Accounts, Checkout flow, Receipt upload & magic byte validation,
Non-public file access control, Snapshot preservation, and Approval/Rejection lifecycles.
"""

import io
import os
import unittest
from datetime import datetime, timezone, timedelta

from api import app
from modules.auth.models import User, utcnow
from modules.auth.db import get_engine, get_session_factory, init_db
from modules.auth.security import hash_password
from modules.subscriptions.models import SubscriptionPlan, UserSubscription, PaymentMethod, PaymentReceivingAccount
from modules.subscriptions.services_payment import ALLOWED_EXTENSIONS, MAX_RECEIPT_SIZE_BYTES, get_receipts_folder


# Valid PNG sample bytes (1x1 transparent PNG)
VALID_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02"
    b"\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
)

# Valid JPEG sample bytes
VALID_JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00" + (b"\x01" * 64) + b"\xff\xd9"


class TestManualPaymentSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db_path = "instance/test_manual_payment_system.db"
        os.environ["SCOUT_DB_PATH"] = cls.test_db_path
        cls.engine = get_engine(cls.test_db_path, reset=True)
        init_db(cls.engine)
        cls.SessionFactory = get_session_factory(cls.engine)

        cls.app = app
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def setUp(self):
        with self.SessionFactory() as session:
            session.query(UserSubscription).delete()
            session.query(PaymentReceivingAccount).delete()
            session.query(PaymentMethod).delete()
            session.query(SubscriptionPlan).delete()
            session.query(User).delete()

            # Seed Admin
            self.admin = User(
                username="admin_pay",
                email="admin_pay@scout.sec",
                password_hash=hash_password("AdminPass123!@#"),
                role="Admin",
                is_active=True
            )
            # Seed Regular User 1
            self.user1 = User(
                username="operator_pay1",
                email="user1_pay@scout.sec",
                password_hash=hash_password("UserPass123!@#"),
                role="User",
                is_active=True
            )
            # Seed Regular User 2
            self.user2 = User(
                username="operator_pay2",
                email="user2_pay@scout.sec",
                password_hash=hash_password("UserPass123!@#"),
                role="User",
                is_active=True
            )
            session.add_all([self.admin, self.user1, self.user2])
            session.flush()

            # Seed Plans
            self.plan = SubscriptionPlan(
                plan_code="PRO-THREAT",
                name="Pro Threat Hunter",
                description="Comprehensive threat hunting plan with port scanning and telemetry.",
                price=500.0,
                currency="EGP",
                duration_value=30,
                duration_unit="days",
                is_active=True
            )
            session.add(self.plan)
            session.flush()

            # Seed Payment Method with Receiving Accounts
            self.instapay = PaymentMethod(
                name="instapay",
                display_name="InstaPay Egypt",
                description="Instant bank transfer via Egyptian Banks & InstaPay Network.",
                instructions="Transfer to Mobile IPA and upload payment receipt.",
                provider_type="instapay",
                logo_icon="fas fa-bolt",
                is_active=True,
                display_order=1
            )
            session.add(self.instapay)
            session.flush()

            self.acc1 = PaymentReceivingAccount(
                payment_method_id=self.instapay.id,
                account_identifier="01012345678",
                account_holder_name="SCOUT Operations",
                description="Primary Mobile IPA",
                is_active=True,
                display_order=1
            )
            self.acc2 = PaymentReceivingAccount(
                payment_method_id=self.instapay.id,
                account_identifier="scout@instapay",
                account_holder_name="SCOUT Security",
                description="Secondary IPA Handle",
                is_active=True,
                display_order=2
            )
            session.add_all([self.acc1, self.acc2])
            session.commit()

            self.admin_id = self.admin.id
            self.user1_id = self.user1.id
            self.user2_id = self.user2.id
            self.plan_id = self.plan.id
            self.instapay_id = self.instapay.id
            self.acc1_id = self.acc1.id

    def login(self, username, password):
        self.client = self.app.test_client()
        res = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(res.status_code, 200, f"Login failed for {username}")
        return res

    def test_01_admin_payment_methods_crud_and_accounts(self):
        """Test complete administrative CRUD operations for payment methods and receiving accounts."""
        self.login("admin_pay", "AdminPass123!@#")

        # 1. List payment methods
        res = self.client.get("/api/admin/payment-methods")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(len(data["payment_methods"]), 1)
        self.assertEqual(data["payment_methods"][0]["name"], "instapay")

        # 2. Create new payment method (Vodafone Cash)
        res = self.client.post("/api/admin/payment-methods", json={
            "display_name": "Vodafone Cash",
            "name": "vodafone-cash",
            "description": "Mobile wallet transfer",
            "instructions": "Transfer to Vodafone Cash wallet and capture screenshot.",
            "provider_type": "vodafone_cash",
            "logo_icon": "fas fa-wallet",
            "is_active": True,
            "display_order": 2,
            "accounts": [
                {
                    "account_identifier": "01099998888",
                    "account_holder_name": "SCOUT VF Desk",
                    "description": "Corporate VF Account",
                    "is_active": True
                }
            ]
        })
        self.assertEqual(res.status_code, 201)
        vf_data = res.get_json()["payment_method"]
        vf_id = vf_data["id"]
        self.assertEqual(vf_data["display_name"], "Vodafone Cash")
        self.assertEqual(len(vf_data["accounts"]), 1)

        # 3. Add an additional account to Vodafone Cash
        res = self.client.post(f"/api/admin/payment-methods/{vf_id}/accounts", json={
            "account_identifier": "01077776666",
            "account_holder_name": "SCOUT Secondary Desk",
            "description": "Backup account",
            "is_active": True
        })
        self.assertEqual(res.status_code, 201)
        acc_data = res.get_json()["account"]
        new_acc_id = acc_data["id"]

        # 4. Toggle account status
        res = self.client.post(f"/api/admin/receiving-accounts/{new_acc_id}/toggle", json={"is_active": False})
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.get_json()["account"]["is_active"])

        # 5. Update payment method
        res = self.client.put(f"/api/admin/payment-methods/{vf_id}", json={
            "display_name": "Vodafone Cash Egypt",
            "instructions": "Updated payment instructions."
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["payment_method"]["display_name"], "Vodafone Cash Egypt")

        # 6. Delete account
        res = self.client.delete(f"/api/admin/receiving-accounts/{new_acc_id}")
        self.assertEqual(res.status_code, 200)

        # 7. Toggle method status
        res = self.client.post(f"/api/admin/payment-methods/{vf_id}/toggle", json={"is_active": False})
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.get_json()["payment_method"]["is_active"])

    def test_02_public_payment_methods_filtering(self):
        """Verify user endpoint only returns active methods having at least one active receiving account."""
        self.login("admin_pay", "AdminPass123!@#")

        # Create method with no accounts
        res = self.client.post("/api/admin/payment-methods", json={
            "display_name": "Orange Cash Empty",
            "provider_type": "orange_cash",
            "is_active": True
        })
        self.assertEqual(res.status_code, 201)

        # Create method with only inactive accounts
        res = self.client.post("/api/admin/payment-methods", json={
            "display_name": "WE Pay Inactive",
            "provider_type": "we_pay",
            "is_active": True,
            "accounts": [
                {
                    "account_identifier": "01511112222",
                    "account_holder_name": "Inactive Holder",
                    "is_active": False
                }
            ]
        })
        self.assertEqual(res.status_code, 201)

        # Query user endpoint
        res = self.client.get("/api/payment-methods")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        names = [m["display_name"] for m in data["payment_methods"]]
        self.assertIn("InstaPay Egypt", names)
        self.assertNotIn("Orange Cash Empty", names)
        self.assertNotIn("WE Pay Inactive", names)

    def test_03_receipt_upload_validation(self):
        """Test receipt upload validations: missing file, invalid extension, fake magic bytes, and size limit."""
        self.login("operator_pay1", "UserPass123!@#")

        # 1. Missing receipt file
        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id
        }, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertIn("receipt", res.get_json()["message"].lower())

        # 2. Unsupported extension (.exe)
        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "receipt": (io.BytesIO(b"MZ\x90\x00executable content"), "malware.exe")
        }, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertIn("unsupported", res.get_json()["message"].lower())

        # 3. Fake PNG with non-image bytes
        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "receipt": (io.BytesIO(b"Not an actual image payload"), "fake.png")
        }, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertIn("does not match", res.get_json()["message"].lower())

        # 4. Oversized file (> 5MB)
        oversized_data = b"\xff\xd8\xff\xe0" + (b"\x00" * (MAX_RECEIPT_SIZE_BYTES + 1024))
        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "receipt": (io.BytesIO(oversized_data), "huge_receipt.jpg")
        }, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds", res.get_json()["message"].lower())

    def test_04_successful_checkout_and_snapshot_preservation(self):
        """Test valid checkout submission, snapshot preservation, and decoupling from original payment method."""
        self.login("operator_pay1", "UserPass123!@#")

        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "transaction_reference": "TX-INSTA-998822",
            "notes": "Paid from NBE Mobile Banking",
            "receipt": (io.BytesIO(VALID_PNG_BYTES), "my_payment_receipt.png")
        }, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 201)
        sub_data = res.get_json()["subscription"]
        sub_id = sub_data["id"]

        self.assertEqual(sub_data["status"], "pending")
        self.assertEqual(sub_data["payment_status"], "pending_verification")
        self.assertEqual(sub_data["payment_amount"], 500.0)
        self.assertEqual(sub_data["payment_currency"], "EGP")
        self.assertEqual(sub_data["transaction_reference"], "TX-INSTA-998822")
        self.assertEqual(sub_data["payment_notes"], "Paid from NBE Mobile Banking")

        # Verify snapshots
        self.assertEqual(sub_data["payment_method_name"], "InstaPay Egypt")
        self.assertEqual(sub_data["receiving_account_identifier"], "01012345678")
        self.assertEqual(sub_data["receiving_account_holder"], "SCOUT Operations")
        self.assertEqual(sub_data["plan_name"], "Pro Threat Hunter")

        # Now, simulate admin altering and deleting the payment method
        self.login("admin_pay", "AdminPass123!@#")
        del_res = self.client.delete(f"/api/admin/payment-methods/{self.instapay_id}")
        self.assertEqual(del_res.status_code, 200)

        # Inspect subscription request: snapshots MUST still be intact!
        req_res = self.client.get(f"/api/admin/requests/{sub_id}")
        self.assertEqual(req_res.status_code, 200)
        persisted_data = req_res.get_json()["subscription"]
        self.assertEqual(persisted_data["payment_method_name"], "InstaPay Egypt")
        self.assertEqual(persisted_data["receiving_account_identifier"], "01012345678")
        self.assertEqual(persisted_data["receiving_account_holder"], "SCOUT Operations")
        self.assertEqual(persisted_data["plan_name"], "Pro Threat Hunter")
        self.assertIsNotNone(persisted_data["receipt_filename"])

    def test_05_receipt_access_control(self):
        """Test that receipt images cannot be accessed by unauthorized users."""
        self.login("operator_pay1", "UserPass123!@#")

        # Submit request with receipt
        res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "receipt": (io.BytesIO(VALID_JPEG_BYTES), "receipt.jpg")
        }, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 201)
        receipt_filename = res.get_json()["subscription"]["receipt_filename"]

        # Owner can view receipt
        owner_res = self.client.get(f"/api/subscriptions/receipts/{receipt_filename}")
        self.assertEqual(owner_res.status_code, 200)

        # Admin can view receipt
        self.login("admin_pay", "AdminPass123!@#")
        admin_res = self.client.get(f"/api/subscriptions/receipts/{receipt_filename}")
        self.assertEqual(admin_res.status_code, 200)

        # Different regular user CANNOT view receipt (403 Forbidden)
        self.login("operator_pay2", "UserPass123!@#")
        other_res = self.client.get(f"/api/subscriptions/receipts/{receipt_filename}")
        self.assertEqual(other_res.status_code, 403)

        # Unauthenticated request (401 Unauthorized)
        self.client = self.app.test_client()
        unauth_res = self.client.get(f"/api/subscriptions/receipts/{receipt_filename}")
        self.assertEqual(unauth_res.status_code, 401)

    def test_06_admin_review_and_atomic_approval(self):
        """Test admin reviewing pending payment and atomically approving."""
        # 1. User submits request
        self.login("operator_pay1", "UserPass123!@#")
        submit_res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "transaction_reference": "TX-APPROVE-1122",
            "receipt": (io.BytesIO(VALID_PNG_BYTES), "receipt.png")
        }, content_type="multipart/form-data")
        self.assertEqual(submit_res.status_code, 201)
        sub_id = submit_res.get_json()["subscription"]["id"]

        # 2. Admin reviews pending requests
        self.login("admin_pay", "AdminPass123!@#")
        req_res = self.client.get("/api/admin/requests")
        self.assertEqual(req_res.status_code, 200)
        requests = req_res.get_json()["requests"]
        target_req = next((r for r in requests if r["id"] == sub_id), None)
        self.assertIsNotNone(target_req)
        self.assertEqual(target_req["payment_status"], "pending_verification")
        self.assertIsNotNone(target_req["receipt_url"])

        # 3. Admin approves
        approve_res = self.client.post(f"/api/admin/requests/{sub_id}/approve", json={
            "notes": "Verified on NBE terminal"
        })
        self.assertEqual(approve_res.status_code, 200)
        app_sub = approve_res.get_json()["subscription"]
        self.assertEqual(app_sub["status"], "active")
        self.assertEqual(app_sub["payment_status"], "approved")
        self.assertTrue(app_sub["is_valid_active"])

        # 4. Request is removed from pending queue
        req_res2 = self.client.get("/api/admin/requests")
        req_ids = [r["id"] for r in req_res2.get_json()["requests"]]
        self.assertNotIn(sub_id, req_ids)

        # 5. Approved subscription is present in all subscriptions
        subs_res = self.client.get("/api/admin/subscriptions")
        sub_ids = [s["id"] for s in subs_res.get_json()["subscriptions"]]
        self.assertIn(sub_id, sub_ids)

        # 6. Duplicate approval is rejected
        dup_res = self.client.post(f"/api/admin/requests/{sub_id}/approve")
        self.assertEqual(dup_res.status_code, 400)

    def test_07_admin_rejection_and_resubmission(self):
        """Test admin rejecting request with reason, preserving record, and user resubmitting."""
        self.login("operator_pay1", "UserPass123!@#")
        submit_res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "receipt": (io.BytesIO(VALID_PNG_BYTES), "receipt.png")
        }, content_type="multipart/form-data")
        sub_id = submit_res.get_json()["subscription"]["id"]

        # Admin rejects
        self.login("admin_pay", "AdminPass123!@#")
        reject_res = self.client.post(f"/api/admin/requests/{sub_id}/reject", json={
            "reason": "Receipt image is blurry and transaction ID is unreadable."
        })
        self.assertEqual(reject_res.status_code, 200)
        rej_sub = reject_res.get_json()["subscription"]
        self.assertEqual(rej_sub["status"], "rejected")
        self.assertEqual(rej_sub["payment_status"], "rejected")
        self.assertIn("blurry", rej_sub["rejection_reason"])

        # User checks status
        self.login("operator_pay1", "UserPass123!@#")
        status_res = self.client.get("/api/subscriptions/my-subscription")
        self.assertEqual(status_res.status_code, 200)
        curr = status_res.get_json()["subscription"]
        self.assertEqual(curr["status"], "rejected")
        self.assertIn("blurry", curr["rejection_reason"])

        # User can now resubmit a clear receipt
        resubmit_res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "transaction_reference": "TX-NEW-RECEIPT-4455",
            "receipt": (io.BytesIO(VALID_PNG_BYTES), "clear_receipt.png")
        }, content_type="multipart/form-data")
        self.assertEqual(resubmit_res.status_code, 201)
        self.assertEqual(resubmit_res.get_json()["subscription"]["status"], "pending")

    def test_08_edit_and_save_receiving_account_persistence(self):
        """
        Comprehensive test for editing and saving receiving account details:
        Verifies phone number/identifier, holder name, notes, order, and active flag
        persist in the database, return via GET endpoints, and reflect immediately in checkout.
        """
        self.login("admin_pay", "AdminPass123!@#")

        # 1. Update receiving account via PUT
        updated_phone = "01099887766"
        updated_holder = "SCOUT Primary Financial Hub"
        updated_desc = "Updated corporate receiving wallet"
        update_res = self.client.put(f"/api/admin/receiving-accounts/{self.acc1_id}", json={
            "account_identifier": updated_phone,
            "account_holder_name": updated_holder,
            "description": updated_desc,
            "display_order": 5,
            "is_active": True
        })
        self.assertEqual(update_res.status_code, 200)
        acc_payload = update_res.get_json()["account"]
        self.assertEqual(acc_payload["account_identifier"], updated_phone)
        self.assertEqual(acc_payload["account_holder_name"], updated_holder)
        self.assertEqual(acc_payload["description"], updated_desc)
        self.assertEqual(acc_payload["display_order"], 5)
        self.assertTrue(acc_payload["is_active"])

        # 2. Verify direct database persistence across an independent session
        with self.SessionFactory() as session:
            db_acc = session.query(PaymentReceivingAccount).filter_by(id=self.acc1_id).first()
            self.assertIsNotNone(db_acc)
            self.assertEqual(db_acc.account_identifier, updated_phone)
            self.assertEqual(db_acc.account_holder_name, updated_holder)
            self.assertEqual(db_acc.description, updated_desc)
            self.assertEqual(db_acc.display_order, 5)
            self.assertTrue(db_acc.is_active)

        # 3. Verify single account GET endpoint
        get_res = self.client.get(f"/api/admin/receiving-accounts/{self.acc1_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.get_json()["account"]["account_identifier"], updated_phone)

        # 4. Verify admin payment-methods listing reflects the updated account
        admin_methods_res = self.client.get("/api/admin/payment-methods")
        self.assertEqual(admin_methods_res.status_code, 200)
        instapay_method = next(m for m in admin_methods_res.get_json()["payment_methods"] if m["id"] == self.instapay_id)
        instapay_acc = next(a for a in instapay_method["accounts"] if a["id"] == self.acc1_id)
        self.assertEqual(instapay_acc["account_identifier"], updated_phone)
        self.assertEqual(instapay_acc["account_holder_name"], updated_holder)

        # 5. Verify user checkout endpoint reflects the updated receiving details immediately
        user_methods_res = self.client.get("/api/payment-methods")
        self.assertEqual(user_methods_res.status_code, 200)
        pub_instapay = next(m for m in user_methods_res.get_json()["payment_methods"] if m["id"] == self.instapay_id)
        pub_acc = next(a for a in pub_instapay["accounts"] if a["id"] == self.acc1_id)
        self.assertEqual(pub_acc["account_identifier"], updated_phone)
        self.assertEqual(pub_acc["account_holder_name"], updated_holder)

        # 6. Verify user submitting checkout records snapshot with the updated account identifier
        self.login("operator_pay2", "UserPass123!@#")
        checkout_res = self.client.post("/api/subscriptions/checkout/submit", data={
            "plan_id": self.plan_id,
            "payment_method_id": self.instapay_id,
            "receiving_account_id": self.acc1_id,
            "transaction_reference": "TX-VERIFY-UPDATED-PHONE-1",
            "receipt": (io.BytesIO(VALID_PNG_BYTES), "receipt.png")
        }, content_type="multipart/form-data")
        self.assertEqual(checkout_res.status_code, 201)
        sub_data = checkout_res.get_json()["subscription"]
        self.assertEqual(sub_data["receiving_account_identifier"], updated_phone)
        self.assertEqual(sub_data["receiving_account_holder"], updated_holder)

        # 7. Test alias support via PATCH (e.g. 'phone_number')
        self.login("admin_pay", "AdminPass123!@#")
        patch_phone = "01122334455"
        patch_res = self.client.patch(f"/api/admin/receiving-accounts/{self.acc1_id}", json={
            "phone_number": patch_phone
        })
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.get_json()["account"]["account_identifier"], patch_phone)

        # 8. Test validation error when empty identifier is sent
        err_res = self.client.put(f"/api/admin/receiving-accounts/{self.acc1_id}", json={
            "account_identifier": "   "
        })
        self.assertEqual(err_res.status_code, 400)
        self.assertIn("cannot be empty", err_res.get_json()["message"])

    def test_09_payment_methods_edit_dialog_and_modal_contract(self):
        """Verifies HTML modal contracts: submit button types and icon classes."""
        with open("templates/ddos.html", "r", encoding="utf-8") as f:
            html = f.read()

        # Both save buttons must be type="submit" to submit forms reliably
        self.assertIn('id="raModalSaveBtn"', html)
        self.assertIn('<button type="submit" class="btn-auth-submit" id="raModalSaveBtn"', html)
        self.assertIn('id="pmModalSaveBtn"', html)
        self.assertIn('<button type="submit" class="btn-auth-submit" id="pmModalSaveBtn"', html)

        # Header content wrapper must wrap titles
        self.assertIn('id="adminReceivingAccountModalTitle"', html)
        self.assertIn('auth-modal-header-content', html)

        # Icon wrapper must contain auth-input-icon
        self.assertIn('auth-input-icon auth-field-icon', html)


if __name__ == "__main__":
    unittest.main()
