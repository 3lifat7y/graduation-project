"""
SCOUT Manual Payment & Payment Methods Services
Handles administrator configuration of payment methods and receiving accounts,
receipt upload validation (size, extension, magic bytes), storage in instance/receipts,
and submission of manual payment requests with snapshot preservation.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, List
from werkzeug.utils import secure_filename

from flask import current_app
from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session, PROJECT_ROOT
from .models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog, PaymentMethod, PaymentReceivingAccount

# Receipts Storage Directory
DEFAULT_RECEIPTS_DIR = PROJECT_ROOT / "instance" / "receipts"
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_RECEIPT_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


def get_receipts_folder() -> Path:
    """Returns absolute Path to the receipts storage directory, ensuring it exists."""
    folder = DEFAULT_RECEIPTS_DIR
    if current_app:
        configured = current_app.config.get("RECEIPT_UPLOAD_FOLDER")
        if configured:
            folder = Path(configured)
        elif hasattr(current_app, "instance_path") and current_app.instance_path:
            folder = Path(current_app.instance_path) / "receipts"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def validate_image_magic_bytes(header: bytes) -> Tuple[bool, Optional[str]]:
    """
    Validates binary header against image magic bytes.
    Returns (is_valid, detected_format_or_none).
    """
    if not header or len(header) < 12:
        return False, None

    # JPEG magic bytes: FF D8 FF
    if header.startswith(b"\xff\xd8\xff"):
        return True, "image/jpeg"

    # PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return True, "image/png"

    # WEBP magic bytes: RIFF....WEBP
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return True, "image/webp"

    return False, None


def validate_and_save_receipt(file_storage) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates uploaded receipt image file:
    - Verifies file presence and filename.
    - Verifies extension in (.jpg, .jpeg, .png, .webp).
    - Checks file size <= 5 MB.
    - Inspects magic bytes to prevent forged file extensions.
    - Writes file with a cryptographically randomized name outside public web roots.
    """
    if not file_storage or not file_storage.filename:
        return False, "Receipt image file is required.", {}

    original_filename = secure_filename(file_storage.filename)
    if not original_filename:
        original_filename = "receipt.png"

    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file format '{ext}'. Allowed formats: JPG, JPEG, PNG, WEBP.", {}

    # Read binary header for magic bytes verification
    try:
        file_stream = file_storage.stream
        file_stream.seek(0)
        header = file_stream.read(32)
        file_stream.seek(0)
    except Exception as e:
        return False, f"Failed to read upload stream: {str(e)}", {}

    is_valid_magic, detected_mime = validate_image_magic_bytes(header)
    if not is_valid_magic:
        return False, "Invalid image file. File content does not match permitted image formats (JPG, PNG, WEBP).", {}

    # Read content to check file size
    try:
        content = file_storage.read()
        file_size = len(content)
        if file_size == 0:
            return False, "Uploaded receipt file is empty.", {}
        if file_size > MAX_RECEIPT_SIZE_BYTES:
            return False, f"File size exceeds maximum permitted limit of 5 MB (size: {file_size / (1024 * 1024):.2f} MB).", {}

        # Save to disk
        receipts_folder = get_receipts_folder()
        generated_name = f"{uuid.uuid4().hex}{ext}"
        destination_path = receipts_folder / generated_name

        with open(destination_path, "wb") as f:
            f.write(content)

    except Exception as e:
        return False, f"Failed to store receipt file securely: {str(e)}", {}

    return True, "Receipt saved successfully.", {
        "filename": generated_name,
        "original_name": original_filename,
        "content_type": detected_mime or file_storage.content_type or "application/octet-stream",
        "file_size": file_size
    }


def user_can_access_receipt(user: Optional[User], filename: str) -> bool:
    """
    Checks authorization to access receipt file.
    Only administrators and the owner of the subscription request may access.
    """
    if not user or not user.is_active:
        return False

    if user.role == "Admin":
        return True

    with get_db_session() as session:
        sub = session.query(UserSubscription).filter_by(receipt_filename=filename).first()
        if sub and sub.user_id == user.id:
            return True

    return False


# ==============================================================================
# Payment Methods & Accounts Administration Services
# ==============================================================================

def slugify(text: str) -> str:
    """Converts a display string into a clean lowercase identifier slug."""
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", text) or "payment-method"


def list_payment_methods(include_inactive: bool = True, include_inactive_accounts: bool = True) -> List[Dict[str, Any]]:
    """Lists all payment methods sorted by display order."""
    with get_db_session() as session:
        query = session.query(PaymentMethod)
        if not include_inactive:
            query = query.filter_by(is_active=True)
        methods = query.order_by(PaymentMethod.display_order.asc(), PaymentMethod.id.asc()).all()
        return [m.to_dict(include_inactive_accounts=include_inactive_accounts) for m in methods]


def get_active_payment_methods_for_checkout() -> List[Dict[str, Any]]:
    """
    Returns only active payment methods that have at least one active receiving account.
    Excludes inactive accounts from the results.
    """
    with get_db_session() as session:
        methods = (
            session.query(PaymentMethod)
            .filter_by(is_active=True)
            .order_by(PaymentMethod.display_order.asc(), PaymentMethod.id.asc())
            .all()
        )
        result = []
        for m in methods:
            active_accounts = [acc for acc in m.accounts if acc.is_active]
            if active_accounts:
                m_dict = m.to_dict(include_inactive_accounts=False)
                result.append(m_dict)
        return result


def get_payment_method(method_id: int, include_inactive_accounts: bool = True) -> Optional[Dict[str, Any]]:
    """Retrieves single payment method by ID."""
    with get_db_session() as session:
        method = session.query(PaymentMethod).filter_by(id=method_id).first()
        if not method:
            return None
        return method.to_dict(include_inactive_accounts=include_inactive_accounts)


def create_payment_method(data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Creates a new administrator payment method and optional receiving accounts."""
    display_name = str(data.get("display_name") or "").strip()
    if not display_name:
        return False, "Payment Method display name is required.", {}

    name = str(data.get("name") or "").strip()
    if not name:
        name = slugify(display_name)
    else:
        name = slugify(name)

    provider_type = str(data.get("provider_type") or "electronic_wallet").strip().lower()
    description = str(data.get("description") or "").strip()
    instructions = str(data.get("instructions") or "").strip()
    logo_icon = str(data.get("logo_icon") or "fas fa-wallet").strip()
    is_active = bool(data.get("is_active", True))
    display_order = int(data.get("display_order") or 0)

    with get_db_session() as session:
        # Check uniqueness of slug name
        existing = session.query(PaymentMethod).filter_by(name=name).first()
        if existing:
            # Suffix with random hex to avoid collision
            name = f"{name}-{uuid.uuid4().hex[:4]}"

        method = PaymentMethod(
            name=name,
            display_name=display_name,
            description=description,
            instructions=instructions,
            provider_type=provider_type,
            logo_icon=logo_icon,
            is_active=is_active,
            display_order=display_order
        )
        session.add(method)
        session.flush()

        # Optional initial accounts
        accounts_data = data.get("accounts") or []
        for acc in accounts_data:
            identifier = str(acc.get("account_identifier") or "").strip()
            holder = str(acc.get("account_holder_name") or "").strip()
            if identifier and holder:
                session.add(PaymentReceivingAccount(
                    payment_method_id=method.id,
                    account_identifier=identifier,
                    account_holder_name=holder,
                    description=str(acc.get("description") or "").strip(),
                    is_active=bool(acc.get("is_active", True)),
                    display_order=int(acc.get("display_order") or 0)
                ))
        session.flush()
        method_dict = method.to_dict(include_inactive_accounts=True)

    return True, f"Payment method '{display_name}' created successfully.", method_dict


def update_payment_method(method_id: int, data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Updates an existing payment method."""
    with get_db_session() as session:
        method = session.query(PaymentMethod).filter_by(id=method_id).first()
        if not method:
            return False, "Payment method not found.", {}

        if "display_name" in data:
            val = str(data["display_name"]).strip()
            if not val:
                return False, "Payment Method display name cannot be empty.", {}
            method.display_name = val

        if "name" in data:
            new_name = slugify(str(data["name"]).strip())
            if new_name and new_name != method.name:
                collision = session.query(PaymentMethod).filter(PaymentMethod.name == new_name, PaymentMethod.id != method_id).first()
                if collision:
                    return False, f"Slug identifier '{new_name}' is already in use.", {}
                method.name = new_name

        if "description" in data:
            method.description = str(data["description"]).strip()
        if "instructions" in data:
            method.instructions = str(data["instructions"]).strip()
        if "provider_type" in data:
            method.provider_type = str(data["provider_type"]).strip().lower()
        if "logo_icon" in data:
            method.logo_icon = str(data["logo_icon"]).strip()
        if "is_active" in data:
            method.is_active = bool(data["is_active"])
        if "display_order" in data:
            try:
                method.display_order = int(data["display_order"])
            except (ValueError, TypeError):
                pass

        method.updated_at = utcnow()
        session.flush()
        method_dict = method.to_dict(include_inactive_accounts=True)

    return True, f"Payment method '{method_dict['display_name']}' updated successfully.", method_dict


def delete_payment_method(method_id: int) -> Tuple[bool, str]:
    """
    Deletes a payment method and its receiving accounts.
    Existing subscription requests retain historical snapshots.
    """
    with get_db_session() as session:
        method = session.query(PaymentMethod).filter_by(id=method_id).first()
        if not method:
            return False, "Payment method not found."

        name = method.display_name
        session.delete(method)
        session.flush()

    return True, f"Payment method '{name}' and its accounts have been deleted."


def toggle_payment_method(method_id: int, is_active: Optional[bool] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """Toggles active/inactive state of a payment method."""
    with get_db_session() as session:
        method = session.query(PaymentMethod).filter_by(id=method_id).first()
        if not method:
            return False, "Payment method not found.", {}

        if is_active is not None:
            method.is_active = bool(is_active)
        else:
            method.is_active = not method.is_active

        method.updated_at = utcnow()
        session.flush()
        state_str = "activated" if method.is_active else "deactivated"
        method_dict = method.to_dict(include_inactive_accounts=True)

    return True, f"Payment method '{method_dict['display_name']}' {state_str}.", method_dict


# ==============================================================================
# Receiving Accounts Services
# ==============================================================================

def add_receiving_account(method_id: int, data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Adds a receiving account to a payment method."""
    identifier = str(data.get("account_identifier") or "").strip()
    holder = str(data.get("account_holder_name") or "").strip()
    if not identifier:
        return False, "Account identifier (phone number, email, or wallet ID) is required.", {}
    if not holder:
        return False, "Account holder name is required.", {}

    description = str(data.get("description") or "").strip()
    is_active = bool(data.get("is_active", True))
    display_order = int(data.get("display_order") or 0)

    with get_db_session() as session:
        method = session.query(PaymentMethod).filter_by(id=method_id).first()
        if not method:
            return False, "Associated payment method not found.", {}

        account = PaymentReceivingAccount(
            payment_method_id=method_id,
            account_identifier=identifier,
            account_holder_name=holder,
            description=description,
            is_active=is_active,
            display_order=display_order
        )
        session.add(account)
        session.flush()
        acc_dict = account.to_dict()

    return True, f"Receiving account '{identifier}' added successfully.", acc_dict


def update_receiving_account(account_id: int, data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """Updates an existing receiving account."""
    with get_db_session() as session:
        account = session.query(PaymentReceivingAccount).filter_by(id=account_id).first()
        if not account:
            return False, "Receiving account not found.", {}

        if "account_identifier" in data:
            val = str(data["account_identifier"]).strip()
            if not val:
                return False, "Account identifier cannot be empty.", {}
            account.account_identifier = val

        if "account_holder_name" in data:
            val = str(data["account_holder_name"]).strip()
            if not val:
                return False, "Account holder name cannot be empty.", {}
            account.account_holder_name = val

        if "description" in data:
            account.description = str(data["description"]).strip()
        if "is_active" in data:
            account.is_active = bool(data["is_active"])
        if "display_order" in data:
            try:
                account.display_order = int(data["display_order"])
            except (ValueError, TypeError):
                pass

        account.updated_at = utcnow()
        session.flush()
        acc_dict = account.to_dict()

    return True, f"Receiving account '{acc_dict['account_identifier']}' updated successfully.", acc_dict


def delete_receiving_account(account_id: int) -> Tuple[bool, str]:
    """Deletes a receiving account."""
    with get_db_session() as session:
        account = session.query(PaymentReceivingAccount).filter_by(id=account_id).first()
        if not account:
            return False, "Receiving account not found."

        ident = account.account_identifier
        session.delete(account)
        session.flush()

    return True, f"Receiving account '{ident}' deleted."


def toggle_receiving_account(account_id: int, is_active: Optional[bool] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """Toggles active/inactive state of a receiving account."""
    with get_db_session() as session:
        account = session.query(PaymentReceivingAccount).filter_by(id=account_id).first()
        if not account:
            return False, "Receiving account not found.", {}

        if is_active is not None:
            account.is_active = bool(is_active)
        else:
            account.is_active = not account.is_active

        account.updated_at = utcnow()
        session.flush()
        state_str = "activated" if account.is_active else "deactivated"
        acc_dict = account.to_dict()

    return True, f"Receiving account '{acc_dict['account_identifier']}' {state_str}.", acc_dict


# ==============================================================================
# User Checkout & Manual Payment Submission
# ==============================================================================

def submit_manual_payment(
    user_id: int,
    plan_id: int,
    payment_method_id: int,
    receiving_account_id: int,
    receipt_file: Any,
    transaction_reference: Optional[str] = None,
    notes: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Processes manual payment submission:
    - Validates user eligibility (active, not suspended).
    - Checks for conflicting active or pending subscriptions.
    - Validates plan, payment method, and receiving account (must all be active).
    - Validates receipt image (extension, size <= 5MB, magic bytes).
    - Takes immutable snapshots of method, account, and plan attributes.
    - Creates UserSubscription with status='pending', payment_status='pending_verification'.
    - Logs audit trail entry.
    """
    with get_db_session() as session:
        # 1. User validation
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return False, "User account not found.", {}
        if not user.is_active:
            return False, "Your account has been suspended. Please contact the administrator.", {}

        # 2. Check existing active subscription
        existing_active = session.query(UserSubscription).filter(
            UserSubscription.user_id == user_id,
            UserSubscription.status == "active"
        ).first()
        if existing_active and existing_active.is_valid_active():
            return False, f"User already has an active subscription for plan '{existing_active.plan.name}'.", {}

        # 3. Check existing pending subscription request
        existing_pending = session.query(UserSubscription).filter(
            UserSubscription.user_id == user_id,
            UserSubscription.status == "pending"
        ).first()
        if existing_pending:
            return False, "A subscription request is already pending verification. Please await administrator review.", {}

        # 4. Plan validation
        plan = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
        if not plan:
            return False, "Subscription plan not found.", {}
        if not plan.is_active:
            return False, "This subscription plan is retired and not available for purchase.", {}

        # 5. Payment method validation
        method = session.query(PaymentMethod).filter_by(id=payment_method_id).first()
        if not method:
            return False, "Selected payment method not found.", {}
        if not method.is_active:
            return False, "The selected payment method is currently disabled.", {}

        # 6. Receiving account validation
        account = session.query(PaymentReceivingAccount).filter_by(id=receiving_account_id).first()
        if not account or account.payment_method_id != method.id:
            return False, "The selected receiving account is invalid for this payment method.", {}
        if not account.is_active:
            return False, "The selected receiving account is currently inactive.", {}

        # 7. Receipt validation and storage
        ok, msg, receipt_meta = validate_and_save_receipt(receipt_file)
        if not ok:
            return False, msg, {}

        # 8. Create UserSubscription with snapshots
        tx_ref = str(transaction_reference or "").strip() or None
        user_notes = str(notes or "").strip() or None

        sub = UserSubscription(
            user_id=user_id,
            plan_id=plan.id,
            status="pending",
            payment_status="pending_verification",
            payment_method_id=method.id,
            receiving_account_id=account.id,
            payment_amount=float(plan.price),
            payment_currency=plan.currency,
            # Immutable Snapshots
            payment_method_name_snapshot=method.display_name,
            payment_method_type_snapshot=method.provider_type,
            receiving_account_identifier_snapshot=account.account_identifier,
            receiving_account_holder_snapshot=account.account_holder_name,
            plan_name_snapshot=plan.name,
            plan_price_snapshot=float(plan.price),
            # Receipt File Metadata
            receipt_filename=receipt_meta["filename"],
            receipt_original_name=receipt_meta["original_name"],
            receipt_content_type=receipt_meta["content_type"],
            receipt_file_size=receipt_meta["file_size"],
            transaction_reference=tx_ref,
            payment_notes=user_notes,
            admin_notes=user_notes
        )
        session.add(sub)
        session.flush()

        # 9. Audit trail
        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=user_id,
            action="PAYMENT_SUBMITTED",
            previous_status=None,
            new_status="pending",
            details=(
                f"Manual payment submitted for plan '{plan.name}' ({plan.price} {plan.currency}) "
                f"via {method.display_name} -> {account.account_identifier} ({account.account_holder_name}). "
                f"Tx Ref: {tx_ref or 'None'}. Receipt: {receipt_meta['filename']}"
            )
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, "Payment request submitted successfully. An administrator will verify your receipt shortly.", sub_dict
