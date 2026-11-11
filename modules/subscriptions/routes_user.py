"""
SCOUT User-Facing Subscription REST Endpoints
Provides plan browsing, status queries, and subscription request submissions.
"""

from flask import Blueprint, request, jsonify, send_from_directory, abort

from modules.auth.decorators import login_required
from modules.auth.db import get_db_session
from modules.auth.models import utcnow
from .models import SubscriptionPlan, UserSubscription, ensure_utc
from .services import (
    request_subscription,
    check_free_plan_eligibility,
    activate_free_subscription
)
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

        # If user is logged in, check free plan eligibility.
        # If the user has already activated or is ineligible, hide free plans from their available plans catalog.
        if user:
            is_eligible, _ = check_free_plan_eligibility(user_id=user.id, session=session)
            if not is_eligible:
                plan_list = [
                    p for p in plan_list
                    if not (p.get("is_free") or p.get("price") == 0.0)
                ]

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
            now = ensure_utc(utcnow())
            end_time = ensure_utc(active_sub.end_date)
            if end_time and end_time < now:
                active_sub.status = "expired"
                session.flush()
                sub_dict = active_sub.to_dict(include_admin_notes=False)
                return jsonify({
                    "status": "success",
                    "has_subscription": False,
                    "subscription": sub_dict
                }), 200

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

    # If the requested plan is a Free Plan, activate immediately without manual payment or admin approval
    with get_db_session() as session:
        target_plan = session.query(SubscriptionPlan).filter_by(id=resolved_plan_id).first()
        is_free_plan = bool(target_plan and (target_plan.is_free or target_plan.price == 0.0))

    if is_free_plan:
        ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip_addr and "," in ip_addr:
            ip_addr = ip_addr.split(",")[0].strip()
        ua_str = request.user_agent.string if request.user_agent else None
        success, message, sub_dict = activate_free_subscription(
            user_id=user.id,
            plan_id=resolved_plan_id,
            ip_address=ip_addr,
            user_agent=ua_str
        )
        if not success:
            return jsonify({"status": "error", "message": message}), 400
        return jsonify({
            "status": "success",
            "message": message,
            "subscription": sub_dict
        }), 201

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


@sub_user_bp.route("/subscriptions/free/activate", methods=["POST"])
@login_required
def activate_free_plan_route():
    """
    Direct user self-activation endpoint for Free Subscription Plans.
    Activates immediately with no manual payment checkout or admin approval.
    Enforces strict one-time lifetime eligibility across user account, email, and phone.
    """
    user = request.current_user
    data = request.get_json(silent=True) or {}
    plan_id = data.get("plan_id")
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

    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_addr and "," in ip_addr:
        ip_addr = ip_addr.split(",")[0].strip()
    ua_str = request.user_agent.string if request.user_agent else None

    success, message, sub_dict = activate_free_subscription(
        user_id=user.id,
        plan_id=resolved_plan_id,
        ip_address=ip_addr,
        user_agent=ua_str
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 201


@sub_user_bp.route("/subscriptions/free/eligibility", methods=["GET"])
@login_required
def check_free_plan_eligibility_route():
    """Returns whether the authenticated user is eligible to claim a free plan."""
    user = request.current_user
    plan_id = request.args.get("plan_id")
    resolved_plan_id = None
    if plan_id:
        try:
            resolved_plan_id = int(plan_id)
        except (ValueError, TypeError):
            pass

    eligible, reason = check_free_plan_eligibility(user_id=user.id, plan_id=resolved_plan_id)
    return jsonify({
        "status": "success",
        "is_eligible": eligible,
        "message": reason
    }), 200


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

