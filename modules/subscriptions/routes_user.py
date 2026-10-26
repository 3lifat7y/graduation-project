"""
SCOUT User-Facing Subscription REST Endpoints
Provides plan browsing, status queries, and subscription request submissions.
"""

from flask import Blueprint, request, jsonify

from modules.auth.decorators import login_required
from modules.auth.db import get_db_session
from .models import SubscriptionPlan, UserSubscription
from .services import request_subscription

sub_user_bp = Blueprint("sub_user", __name__, url_prefix="/api")


@sub_user_bp.route("/plans", methods=["GET"])
@sub_user_bp.route("/subscriptions/plans", methods=["GET"])
def get_public_plans():
    """Returns all currently active subscription plans available for user selection."""
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
