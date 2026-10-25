"""
SCOUT Administrative Subscription & User Management Endpoints
Provides plan catalog CRUD, user account search/moderation, and activation controls.
"""

from typing import Dict, Any
from flask import Blueprint, request, jsonify
from sqlalchemy import func

from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session
from modules.auth.decorators import admin_required
from .models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog

sub_admin_bp = Blueprint("sub_admin", __name__, url_prefix="/api/admin")


# ==============================================================================
# 1. Subscription Plan Catalog Management
# ==============================================================================

@sub_admin_bp.route("/plans", methods=["GET"])
@admin_required
def list_admin_plans():
    """Lists all subscription plans (both active and inactive) with subscription counts."""
    with get_db_session() as session:
        plans = session.query(SubscriptionPlan).order_by(SubscriptionPlan.id.asc()).all()
        plan_list = []
        for p in plans:
            p_dict = p.to_dict()
            p_dict["total_subscribers"] = session.query(UserSubscription).filter_by(plan_id=p.id).count()
            p_dict["active_subscribers"] = session.query(UserSubscription).filter_by(plan_id=p.id, status="active").count()
            plan_list.append(p_dict)

    return jsonify({
        "status": "success",
        "plans": plan_list,
        "count": len(plan_list)
    }), 200


@sub_admin_bp.route("/plans", methods=["POST"])
@admin_required
def create_admin_plan():
    """Creates a new subscription plan."""
    data = request.get_json(silent=True) or {}
    plan_code = str(data.get("plan_code", "")).strip().upper()
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    price = data.get("price", 0.0)
    currency = str(data.get("currency", "USD")).strip().upper()
    duration_value = data.get("duration_value", 30)
    duration_unit = str(data.get("duration_unit", "days")).strip().lower()
    is_active = bool(data.get("is_active", True))
    features = data.get("features", {})

    if not plan_code or not name:
        return jsonify({"status": "error", "message": "Plan code and name are required."}), 400

    try:
        price = float(price)
        if price < 0:
            return jsonify({"status": "error", "message": "Price cannot be negative."}), 400
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid price format."}), 400

    try:
        duration_value = int(duration_value)
        if duration_value <= 0:
            return jsonify({"status": "error", "message": "Duration must be greater than zero."}), 400
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid duration value."}), 400

    with get_db_session() as session:
        existing = session.query(SubscriptionPlan).filter(
            func.upper(SubscriptionPlan.plan_code) == plan_code
        ).first()

        if existing:
            return jsonify({
                "status": "error",
                "message": f"A plan with code '{plan_code}' already exists."
            }), 409

        plan = SubscriptionPlan(
            plan_code=plan_code,
            name=name,
            description=description,
            price=price,
            currency=currency,
            duration_value=duration_value,
            duration_unit=duration_unit,
            is_active=is_active
        )
        plan.set_features(features)
        session.add(plan)
        session.flush()
        plan_dict = plan.to_dict()

    return jsonify({
        "status": "success",
        "message": f"Subscription plan '{name}' created successfully.",
        "plan": plan_dict
    }), 201


@sub_admin_bp.route("/plans/<int:plan_id>", methods=["PUT"])
@admin_required
def update_admin_plan(plan_id: int):
    """Updates an existing subscription plan's terms and features."""
    data = request.get_json(silent=True) or {}
    with get_db_session() as session:
        plan = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
        if not plan:
            return jsonify({"status": "error", "message": "Plan not found."}), 404

        if "name" in data and str(data["name"]).strip():
            plan.name = str(data["name"]).strip()
        if "description" in data:
            plan.description = str(data["description"]).strip()
        if "price" in data:
            try:
                p = float(data["price"])
                if p >= 0:
                    plan.price = p
            except (ValueError, TypeError):
                pass
        if "duration_value" in data:
            try:
                d = int(data["duration_value"])
                if d > 0:
                    plan.duration_value = d
            except (ValueError, TypeError):
                pass
        if "duration_unit" in data and str(data["duration_unit"]).strip():
            plan.duration_unit = str(data["duration_unit"]).strip().lower()
        if "is_active" in data:
            plan.is_active = bool(data["is_active"])
        if "features" in data and isinstance(data["features"], dict):
            plan.set_features(data["features"])

        plan.updated_at = utcnow()
        session.flush()
        plan_dict = plan.to_dict()

    return jsonify({
        "status": "success",
        "message": f"Plan '{plan_dict['name']}' updated successfully.",
        "plan": plan_dict
    }), 200


@sub_admin_bp.route("/plans/<int:plan_id>/status", methods=["PATCH", "POST"])
@admin_required
def toggle_admin_plan_status(plan_id: int):
    """Toggles active/inactive status for soft retirement."""
    data = request.get_json(silent=True) or {}
    if "is_active" not in data:
        return jsonify({"status": "error", "message": "'is_active' boolean field required."}), 400

    new_status = bool(data["is_active"])
    with get_db_session() as session:
        plan = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
        if not plan:
            return jsonify({"status": "error", "message": "Plan not found."}), 404

        plan.is_active = new_status
        plan.updated_at = utcnow()
        session.flush()
        status_label = "activated" if new_status else "deactivated"

    return jsonify({
        "status": "success",
        "message": f"Plan '{plan.name}' has been {status_label}.",
        "plan_id": plan_id,
        "is_active": new_status
    }), 200


# ==============================================================================
# 2. User Account Moderation & Search
# ==============================================================================

@sub_admin_bp.route("/users", methods=["GET"])
@admin_required
def list_admin_users():
    """Lists registered users with search, role, status filters, and active subscription summary."""
    search = request.args.get("search", "").strip().lower()
    role_filter = request.args.get("role", "").strip()
    status_filter = request.args.get("status", "").strip().lower()

    with get_db_session() as session:
        query = session.query(User)
        if search:
            query = query.filter(
                (func.lower(User.username).contains(search)) |
                (func.lower(User.email).contains(search)) |
                (func.lower(User.full_name).contains(search))
            )
        if role_filter:
            query = query.filter_by(role=role_filter)
        if status_filter in ("active", "disabled"):
            query = query.filter_by(is_active=(status_filter == "active"))

        users = query.order_by(User.id.desc()).all()
        user_list = []
        for u in users:
            u_dict = u.to_dict()
            # Fetch latest subscription for user
            latest_sub = session.query(UserSubscription).filter_by(user_id=u.id).order_by(UserSubscription.id.desc()).first()
            if latest_sub:
                u_dict["current_subscription"] = {
                    "id": latest_sub.id,
                    "plan_name": latest_sub.plan.name if latest_sub.plan else None,
                    "status": latest_sub.status,
                    "is_valid_active": latest_sub.is_valid_active(),
                    "end_date": latest_sub.end_date.isoformat() if latest_sub.end_date else None
                }
            else:
                u_dict["current_subscription"] = None
            user_list.append(u_dict)

    return jsonify({
        "status": "success",
        "users": user_list,
        "count": len(user_list)
    }), 200


@sub_admin_bp.route("/users/<int:user_id>/status", methods=["PATCH", "POST"])
@admin_required
def update_user_status(user_id: int):
    """Enables or disables a user account. Disabling revokes active sessions immediately."""
    data = request.get_json(silent=True) or {}
    if "is_active" not in data:
        return jsonify({"status": "error", "message": "'is_active' boolean field required."}), 400

    new_status = bool(data["is_active"])
    current_admin = request.current_user

    if user_id == current_admin.id and not new_status:
        return jsonify({"status": "error", "message": "Administrators cannot deactivate their own account."}), 400

    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        user.is_active = new_status
        if not new_status:
            user.revoke_sessions()
        session.flush()

        action_msg = "activated" if new_status else "disabled (sessions revoked)"

    return jsonify({
        "status": "success",
        "message": f"User account '{user.username}' has been {action_msg}.",
        "user_id": user_id,
        "is_active": new_status
    }), 200


# ==============================================================================
# 3. User Subscriptions Lifecycle Management & Approvals
# ==============================================================================

@sub_admin_bp.route("/subscriptions", methods=["GET"])
@admin_required
def list_admin_subscriptions():
    """Lists subscriptions with optional status and user filters."""
    status_filter = request.args.get("status", "").strip().lower()
    user_id_param = request.args.get("user_id")

    with get_db_session() as session:
        query = session.query(UserSubscription)
        if status_filter:
            query = query.filter_by(status=status_filter)
        if user_id_param:
            try:
                query = query.filter_by(user_id=int(user_id_param))
            except (ValueError, TypeError):
                pass

        subs = query.order_by(UserSubscription.id.desc()).all()
        sub_list = [s.to_dict(include_audit=False) for s in subs]

    return jsonify({
        "status": "success",
        "subscriptions": sub_list,
        "count": len(sub_list)
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/activate", methods=["POST"])
@admin_required
def activate_subscription_route(sub_id: int):
    """Admin approves and activates a pending or expired subscription."""
    data = request.get_json(silent=True) or {}
    duration_override = data.get("duration_override_days")
    notes = data.get("notes")
    current_admin = request.current_user

    from .services import activate_subscription
    success, message, sub_dict = activate_subscription(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        duration_override_days=duration_override,
        notes=notes
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/reject", methods=["POST"])
@admin_required
def reject_subscription_route(sub_id: int):
    """Admin rejects a pending subscription request."""
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "Request rejected by administrator.")).strip()
    current_admin = request.current_user

    from .services import reject_subscription
    success, message, sub_dict = reject_subscription(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        reason=reason
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/cancel", methods=["POST"])
@admin_required
def cancel_subscription_route(sub_id: int):
    """Admin cancels an active subscription."""
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason", "Canceled by administrator.")).strip()
    current_admin = request.current_user

    from .services import cancel_subscription
    success, message, sub_dict = cancel_subscription(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        reason=reason
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/dates", methods=["PUT", "POST"])
@sub_admin_bp.route("/subscriptions/<int:sub_id>/adjust-dates", methods=["PUT", "POST"])
@admin_required
def adjust_subscription_dates_route(sub_id: int):
    """Admin sets or corrects start and end dates under audit policy."""
    data = request.get_json(silent=True) or {}
    start_date_str = data.get("start_date")
    end_date_str = data.get("end_date")
    reason = str(data.get("reason", "Administrative date adjustment.")).strip()
    current_admin = request.current_user

    from datetime import datetime, timezone
    start_dt = None
    end_dt = None
    if start_date_str:
        try:
            start_dt = datetime.fromisoformat(start_date_str.replace("Z", "+00:00"))
        except Exception:
            return jsonify({"status": "error", "message": "Invalid start_date ISO format."}), 400
    if end_date_str:
        try:
            end_dt = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
        except Exception:
            return jsonify({"status": "error", "message": "Invalid end_date ISO format."}), 400

    from .services import adjust_subscription_dates
    success, message, sub_dict = adjust_subscription_dates(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        start_date=start_dt,
        end_date=end_dt,
        reason=reason
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 200


# ==============================================================================
# 4. Subscription Audit Trail
# ==============================================================================

@sub_admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def list_admin_audit_logs():
    """Lists subscription audit logs."""
    sub_id_param = request.args.get("subscription_id")
    actor_id_param = request.args.get("actor_id")

    with get_db_session() as session:
        query = session.query(SubscriptionAuditLog)
        if sub_id_param:
            try:
                query = query.filter_by(subscription_id=int(sub_id_param))
            except (ValueError, TypeError):
                pass
        if actor_id_param:
            try:
                query = query.filter_by(actor_id=int(actor_id_param))
            except (ValueError, TypeError):
                pass

        logs = query.order_by(SubscriptionAuditLog.id.desc()).limit(200).all()
        log_list = [l.to_dict() for l in logs]

    return jsonify({
        "status": "success",
        "audit_logs": log_list,
        "count": len(log_list)
    }), 200
