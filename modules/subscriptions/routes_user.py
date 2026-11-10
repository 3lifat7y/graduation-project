"""
SCOUT User-Facing Subscription REST Endpoints
Provides plan browsing, status queries, and subscription request submissions.
"""

from flask import Blueprint, request, jsonify, send_from_directory, abort

from modules.auth.decorators import login_required
from modules.auth.db import get_db_session
from .models import SubscriptionPlan, UserSubscription
from .services import request_subscription
from .services_payment import (
    get_active_payment_methods_for_checkout,
    submit_manual_payment,
    get_receipts_folder,
    user_can_access_receipt
)

sub_user_bp = Blueprint("sub_user", __name__, url_prefix="/api")


@sub_user_bp.route("/plans", methods=["GET"])
@sub_user_bp.route("/subscriptions/plans", methods=["GET"])
def get_public_plans():
    """Returns all currently active subscription plans available for user selection."""
    from modules.auth.routes import get_current_user_from_request
    user, _ = get_current_user_from_request(allow_disabled=True)
    if user and not user.is_active:
        return jsonify({
            "status": "error",
            "code": "ACCOUNT_DISABLED",
            "message": "Your account has been suspended. Please contact the platform administrator."
        }), 403

    with get_db_session() as session:
        plans = (
            session.query(SubscriptionPlan)
            .filter_by(is_active=True)
            .order_by(SubscriptionPlan.price.asc())
            .all()
        )
        plan_list = [p.to_dict() for p in plans]

    return jsonify({
        "status": "success",
        "plans": plan_list,
        "count": len(plan_list)
    }), 200


@sub_user_bp.route("/subscriptions/my-subscription", methods=["GET"])
@login_required
def get_my_subscription():
    """Returns current active or most recent subscription record for authenticated user."""
    user = request.current_user
    with get_db_session() as session:
        # First check active
        active_sub = (
            session.query(UserSubscription)
            .filter_by(user_id=user.id, status="active")
            .order_by(UserSubscription.end_date.desc())
            .first()
        )
        if active_sub:
            sub_dict = active_sub.to_dict(include_admin_notes=False)
            return jsonify({
                "status": "success",
                "has_subscription": True,
                "subscription": sub_dict
            }), 200

        # If no active, check pending or latest
        latest_sub = (
            session.query(UserSubscription)
            .filter_by(user_id=user.id)
            .order_by(UserSubscription.id.desc())
            .first()
        )
        if latest_sub:
            sub_dict = latest_sub.to_dict(include_admin_notes=False)
            return jsonify({
                "status": "success",
                "has_subscription": False,
                "subscription": sub_dict
            }), 200

    return jsonify({
        "status": "success",
        "has_subscription": False,
        "subscription": None
    }), 200


@sub_user_bp.route("/subscriptions/request", methods=["POST"])
@login_required
def submit_subscription_request():
    """Requests activation of a subscription plan."""
    user = request.current_user
    data = request.get_json(silent=True) or {}
    plan_id = data.get("plan_id")
    notes = data.get("notes")

    if not plan_id:
        return jsonify({"status": "error", "message": "Field 'plan_id' is required."}), 400

    resolved_plan_id = None
    try:
        resolved_plan_id = int(plan_id)
    except (ValueError, TypeError):
        with get_db_session() as session:
            p = session.query(SubscriptionPlan).filter_by(plan_code=str(plan_id)).first()
            if p:
                resolved_plan_id = p.id

    if not resolved_plan_id:
        return jsonify({"status": "error", "message": f"Subscription plan '{plan_id}' not found."}), 400

    success, message, sub_dict = request_subscription(
        user_id=user.id,
        plan_id=resolved_plan_id,
        notes=notes
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 201


# ==============================================================================
# Manual Payment System Endpoints for Users
# ==============================================================================

@sub_user_bp.route("/payment-methods", methods=["GET"])
@sub_user_bp.route("/subscriptions/payment-methods", methods=["GET"])
def get_user_payment_methods():
    """
    Returns active payment methods with active receiving accounts for user checkout.
    Inactive methods and inactive accounts are completely filtered out.
    """
    methods = get_active_payment_methods_for_checkout()
    return jsonify({
        "status": "success",
        "payment_methods": methods,
        "count": len(methods)
    }), 200


@sub_user_bp.route("/subscriptions/checkout/submit", methods=["POST"])
@login_required
def submit_manual_checkout():
    """
    User submits manual payment request with receipt image upload.
    Expects multipart/form-data.
    """
    user = request.current_user
    plan_id = request.form.get("plan_id")
    method_id = request.form.get("payment_method_id")
    account_id = request.form.get("receiving_account_id")
    tx_ref = request.form.get("transaction_reference")
    notes = request.form.get("notes")

    if not plan_id:
        return jsonify({"status": "error", "message": "Subscription plan is required."}), 400
    if not method_id:
        return jsonify({"status": "error", "message": "Payment method selection is required."}), 400
    if not account_id:
        return jsonify({"status": "error", "message": "Receiving account selection is required."}), 400

    try:
        plan_id = int(plan_id)
        method_id = int(method_id)
        account_id = int(account_id)
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid plan, method, or account identifier."}), 400

    if "receipt" not in request.files:
        return jsonify({"status": "error", "message": "Payment receipt image is required."}), 400

    receipt_file = request.files["receipt"]
    if not receipt_file or not receipt_file.filename:
        return jsonify({"status": "error", "message": "Please select a payment receipt image file."}), 400

    success, message, sub_dict = submit_manual_payment(
        user_id=user.id,
        plan_id=plan_id,
        payment_method_id=method_id,
        receiving_account_id=account_id,
        receipt_file=receipt_file,
        transaction_reference=tx_ref,
        notes=notes
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 201


@sub_user_bp.route("/subscriptions/receipts/<path:filename>", methods=["GET"])
@login_required
def get_payment_receipt(filename: str):
    """
    Secure receipt download and inspection.
    Restricted to Administrators or the owner of the subscription request.
    Non-authorized requests receive 403 Forbidden.
    """
    user = request.current_user
    if not user_can_access_receipt(user, filename):
        return jsonify({"status": "error", "message": "Forbidden. You do not have access to view this receipt."}), 403

    receipts_folder = get_receipts_folder()
    file_path = receipts_folder / filename
    if not file_path.is_file():
        return jsonify({"status": "error", "message": "Receipt file not found."}), 404

    return send_from_directory(str(receipts_folder), filename)

