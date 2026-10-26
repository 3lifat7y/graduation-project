"""
SCOUT Administrative Subscription & User Management Endpoints
Provides plan catalog CRUD, user account search/moderation, and activation controls.
"""

import re
from typing import Dict, Any
from flask import Blueprint, request, jsonify
from sqlalchemy import func

from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session
from modules.auth.decorators import admin_required
from .models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog
from .services import sync_expired_subscriptions

sub_admin_bp = Blueprint("sub_admin", __name__, url_prefix="/api/admin")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ==============================================================================
# 0. Administrative Platform Activity Overview Metrics
# ==============================================================================

@sub_admin_bp.route("/metrics", methods=["GET"])
@admin_required
def get_admin_metrics():
    """
    Returns verified, genuine database activity statistics.
    Provides exact counts for users, subscription states, and plans without mock data.
    """
    sync_expired_subscriptions()
    with get_db_session() as session:
        total_users = session.query(User).count()
        active_users = session.query(User).filter_by(is_active=True).count()
        inactive_users = session.query(User).filter_by(is_active=False).count()

        total_subscribers = session.query(func.count(func.distinct(UserSubscription.user_id))).scalar() or 0
        active_subscribers = session.query(func.count(func.distinct(UserSubscription.user_id))).filter(UserSubscription.status == "active").scalar() or 0

        pending_subs = session.query(UserSubscription).filter_by(status="pending").count()
        active_subs = session.query(UserSubscription).filter_by(status="active").count()
        expired_subs = session.query(UserSubscription).filter_by(status="expired").count()
        canceled_subs = session.query(UserSubscription).filter_by(status="canceled").count()

        available_plans = session.query(SubscriptionPlan).filter_by(is_active=True).count()
        inactive_plans = session.query(SubscriptionPlan).filter_by(is_active=False).count()
        total_plans = session.query(SubscriptionPlan).count()

    return jsonify({
        "status": "success",
        "metrics": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "total_subscribers": total_subscribers,
            "active_subscribers": active_subscribers,
            "pending_subscriptions": pending_subs,
            "active_subscriptions": active_subs,
            "expired_subscriptions": expired_subs,
            "canceled_subscriptions": canceled_subs,
            "available_plans": available_plans,
            "active_plans": available_plans,
            "inactive_plans": inactive_plans,
            "total_plans": total_plans
        }
    }), 200


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
            p_dict["subscribers_count"] = p_dict["total_subscribers"]
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
        if "currency" in data and str(data["currency"]).strip():
            plan.currency = str(data["currency"]).strip().upper()
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


@sub_admin_bp.route("/plans/<int:plan_id>", methods=["DELETE"])
@admin_required
def delete_admin_plan(plan_id: int):
    """
    Safely deletes or archives a subscription plan.
    If the plan has associated subscriptions (active or historical), hard deletion is refused
    to maintain referential integrity, and the plan is safely archived (is_active = False).
    If 0 subscriptions are associated, the plan record is permanently removed.
    """
    with get_db_session() as session:
        plan = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
        if not plan:
            return jsonify({"status": "error", "message": "Plan not found."}), 404

        subscriber_count = session.query(UserSubscription).filter_by(plan_id=plan_id).count()

        if subscriber_count > 0:
            plan.is_active = False
            plan.updated_at = utcnow()
            session.flush()
            return jsonify({
                "status": "success",
                "action": "archived",
                "message": f"Plan '{plan.name}' has {subscriber_count} associated subscription record(s). It has been safely deactivated and archived to preserve history.",
                "plan_id": plan_id,
                "is_active": False,
                "subscribers_count": subscriber_count
            }), 200

        plan_name = plan.name
        session.delete(plan)
        session.flush()

    return jsonify({
        "status": "success",
        "action": "deleted",
        "message": f"Plan '{plan_name}' has been permanently deleted.",
        "plan_id": plan_id
    }), 200


# ==============================================================================
# 2. User Account Moderation & Search
# ==============================================================================

@sub_admin_bp.route("/users", methods=["GET"])
@admin_required
def list_admin_users():
    """Lists registered users with search, role, status filters, subscription status filter, and pagination."""
    search = request.args.get("search", "").strip().lower()
    role_filter = request.args.get("role", "").strip()
    status_filter = request.args.get("status", "").strip().lower()
    sub_status_filter = request.args.get("sub_status", "").strip().lower()

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)

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
        if status_filter in ("active", "disabled", "inactive"):
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

            if sub_status_filter:
                current_sub_status = latest_sub.status if latest_sub else "none"
                if sub_status_filter == "none":
                    if latest_sub is not None:
                        continue
                elif current_sub_status != sub_status_filter:
                    continue

            user_list.append(u_dict)

        total_matching = len(user_list)
        if per_page > 0 and page > 0:
            start_idx = (page - 1) * per_page
            paged_users = user_list[start_idx : start_idx + per_page]
        else:
            paged_users = user_list

    return jsonify({
        "status": "success",
        "users": paged_users,
        "count": len(paged_users),
        "total_count": total_matching,
        "page": page,
        "per_page": per_page
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

        # Guard: Cannot deactivate the last active administrator
        if user.role == "Admin" and user.is_active and not new_status:
            active_admin_count = session.query(User).filter_by(role="Admin", is_active=True).count()
            if active_admin_count <= 1:
                return jsonify({
                    "status": "error",
                    "message": "Cannot deactivate the last active Administrator on the platform."
                }), 400

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


@sub_admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_admin_user_details(user_id: int):
    """
    Returns complete profile and full subscription history for a specific user.
    Includes active subscription, historical subscriptions, and audit events.
    """
    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        user_data = user.to_dict()

        # All subscriptions for user, newest first
        subscriptions = (
            session.query(UserSubscription)
            .filter_by(user_id=user_id)
            .order_by(UserSubscription.id.desc())
            .all()
        )
        user_data["subscriptions"] = [s.to_dict(include_audit=True) for s in subscriptions]

        # Latest subscription summary
        latest_sub = subscriptions[0] if subscriptions else None
        if latest_sub:
            user_data["current_subscription"] = {
                "id": latest_sub.id,
                "plan_name": latest_sub.plan.name if latest_sub.plan else None,
                "status": latest_sub.status,
                "is_valid_active": latest_sub.is_valid_active(),
                "end_date": latest_sub.end_date.isoformat() if latest_sub.end_date else None
            }
        else:
            user_data["current_subscription"] = None

    return jsonify({
        "status": "success",
        "user": user_data
    }), 200


@sub_admin_bp.route("/users/<int:user_id>", methods=["PUT", "PATCH"])
@admin_required
def update_admin_user_profile(user_id: int):
    """
    Administrative profile modification for any user account.
    Updates display full_name and email with syntax & duplicate validation.
    """
    data = request.get_json(silent=True) or {}
    new_full_name = data.get("full_name")
    new_email = data.get("email")

    if new_email is None and new_full_name is None:
        return jsonify({"status": "error", "message": "No profile fields provided to update."}), 400

    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        if new_email is not None:
            email_cleaned = str(new_email).strip().lower()
            if not email_cleaned:
                return jsonify({"status": "error", "message": "Email address cannot be empty."}), 400
            if not EMAIL_REGEX.match(email_cleaned):
                return jsonify({"status": "error", "message": "Invalid email address format."}), 400

            duplicate = session.query(User).filter(
                func.lower(User.email) == email_cleaned,
                User.id != user.id
            ).first()
            if duplicate:
                return jsonify({"status": "error", "message": "An account with this email address already exists."}), 409

            user.email = email_cleaned

        if new_full_name is not None:
            user.full_name = str(new_full_name).strip() or None

        session.flush()
        user_dict = user.to_dict()

    return jsonify({
        "status": "success",
        "message": f"User profile for '{user_dict['username']}' updated successfully.",
        "user": user_dict
    }), 200


@sub_admin_bp.route("/users/<int:user_id>/role", methods=["PATCH", "POST"])
@admin_required
def update_user_role(user_id: int):
    """
    Promotes or demotes an operator between 'User' and 'Admin'.
    Guards against demoting the last active administrator on the system.
    """
    data = request.get_json(silent=True) or {}
    new_role = str(data.get("role", "")).strip()

    if new_role not in ("User", "Admin"):
        return jsonify({
            "status": "error",
            "message": "Invalid role specified. Supported roles are exactly 'User' and 'Admin'."
        }), 400

    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        if user.role == new_role:
            return jsonify({
                "status": "success",
                "message": f"User '{user.username}' is already in role '{new_role}'.",
                "user": user.to_dict()
            }), 200

        # Guard: Check last active admin if demoting an Admin
        if user.role == "Admin" and new_role != "Admin":
            active_admin_count = session.query(User).filter_by(role="Admin", is_active=True).count()
            if active_admin_count <= 1:
                return jsonify({
                    "status": "error",
                    "message": "Cannot demote the last active Administrator on the platform."
                }), 400

        user.role = new_role
        user.revoke_sessions()
        session.flush()
        user_dict = user.to_dict()

    return jsonify({
        "status": "success",
        "message": f"User role for '{user.username}' updated to '{new_role}'. Active sessions revoked.",
        "user": user_dict
    }), 200


@sub_admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_admin_user(user_id: int):
    """
    Controlled administrative account removal / archival.
    - Prevents self-deletion by the calling admin.
    - Prevents deletion of the platform's last active Administrator.
    - Preserves historical integrity: If user has associated subscription records,
      the account is deactivated (is_active=False) and sessions revoked (safe archive).
    - If no subscription history exists, removes the user record permanently.
    """
    current_admin = request.current_user
    if user_id == current_admin.id:
        return jsonify({"status": "error", "message": "Administrators cannot delete their own account."}), 400

    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        # Guard: Check last active admin if deleting an Admin
        if user.role == "Admin" and user.is_active:
            active_admin_count = session.query(User).filter_by(role="Admin", is_active=True).count()
            if active_admin_count <= 1:
                return jsonify({
                    "status": "error",
                    "message": "Cannot delete the last active Administrator on the platform."
                }), 400

        sub_count = session.query(UserSubscription).filter_by(user_id=user_id).count()
        if sub_count > 0:
            user.is_active = False
            user.revoke_sessions()
            session.flush()
            return jsonify({
                "status": "success",
                "action": "archived",
                "message": f"User '{user.username}' has {sub_count} associated subscription record(s). Account has been safely deactivated and archived to preserve audit history.",
                "user_id": user_id,
                "is_active": False
            }), 200
        else:
            session.delete(user)
            session.flush()
            return jsonify({
                "status": "success",
                "action": "deleted",
                "message": f"User '{user.username}' has been permanently deleted.",
                "user_id": user_id
            }), 200


# ==============================================================================
# 3. User Subscriptions Lifecycle Management & Approvals
# ==============================================================================

@sub_admin_bp.route("/subscriptions", methods=["GET"])
@admin_required
def list_admin_subscriptions():
    """Lists subscriptions with optional status, search, and user filters."""
    sync_expired_subscriptions()
    status_filter = request.args.get("status", "").strip().lower()
    user_id_param = request.args.get("user_id")
    search = request.args.get("search", "").strip().lower()

    with get_db_session() as session:
        query = session.query(UserSubscription).join(User, UserSubscription.user_id == User.id)
        if status_filter:
            query = query.filter(UserSubscription.status == status_filter)
        if user_id_param:
            try:
                query = query.filter(UserSubscription.user_id == int(user_id_param))
            except (ValueError, TypeError):
                pass
        if search:
            if search.isdigit():
                query = query.filter(
                    (UserSubscription.id == int(search)) |
                    (func.lower(User.username).contains(search)) |
                    (func.lower(User.email).contains(search)) |
                    (func.lower(User.full_name).contains(search))
                )
            else:
                query = query.filter(
                    (func.lower(User.username).contains(search)) |
                    (func.lower(User.email).contains(search)) |
                    (func.lower(User.full_name).contains(search))
                )

        subs = query.order_by(UserSubscription.id.desc()).all()
        sub_list = [s.to_dict(include_audit=False) for s in subs]

    return jsonify({
        "status": "success",
        "subscriptions": sub_list,
        "count": len(sub_list)
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/activate", methods=["POST"])
@sub_admin_bp.route("/subscriptions/<int:sub_id>/approve", methods=["POST"])
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


@sub_admin_bp.route("/subscriptions/<int:sub_id>/renew", methods=["POST"])
@admin_required
def renew_subscription_route(sub_id: int):
    """Admin renews an expired or active subscription, starting from now for the plan duration or override."""
    data = request.get_json(silent=True) or {}
    duration_days = data.get("duration_days")
    notes = data.get("notes")
    current_admin = request.current_user

    calc_days = None
    if duration_days is not None:
        try:
            calc_days = int(duration_days)
            if calc_days <= 0:
                return jsonify({"status": "error", "message": "Duration days must be a positive integer."}), 400
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Invalid duration_days format."}), 400

    from .services import renew_subscription
    success, message, sub_dict = renew_subscription(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        duration_days=calc_days,
        notes=notes
    )

    if not success:
        return jsonify({"status": "error", "message": message}), 400

    return jsonify({
        "status": "success",
        "message": message,
        "subscription": sub_dict
    }), 200


@sub_admin_bp.route("/subscriptions/<int:sub_id>/extend", methods=["POST"])
@admin_required
def extend_subscription_route(sub_id: int):
    """Admin extends an active subscription from current expiry (or now if expired) by specified days."""
    data = request.get_json(silent=True) or {}
    extension_days = data.get("extension_days")
    notes = data.get("notes")
    current_admin = request.current_user

    if extension_days is None:
        duration_val = data.get("duration_value")
        if duration_val is not None:
            unit = data.get("duration_unit", "days")
            try:
                val = int(duration_val)
                if unit == "months":
                    extension_days = val * 30
                elif unit == "years":
                    extension_days = val * 365
                else:
                    extension_days = val
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid duration value format."}), 400

    if extension_days is None:
        return jsonify({"status": "error", "message": "'extension_days' or 'duration_value' field is required."}), 400

    try:
        days_val = int(extension_days)
        if days_val <= 0:
            return jsonify({"status": "error", "message": "'extension_days' must be a positive integer."}), 400
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Invalid 'extension_days' format."}), 400

    from .services import extend_subscription
    success, message, sub_dict = extend_subscription(
        subscription_id=sub_id,
        admin_id=current_admin.id,
        extension_days=days_val,
        notes=notes
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
        log_list = []
        for l in logs:
            ld = l.to_dict()
            if l.subscription:
                sub = l.subscription
                ld["subject_user"] = sub.user.username if sub.user else f"User #{sub.user_id}"
                ld["subject_email"] = sub.user.email if sub.user else ""
                ld["plan_name"] = sub.plan.name if sub.plan else f"Plan #{sub.plan_id}"
            else:
                ld["subject_user"] = "—"
                ld["subject_email"] = ""
                ld["plan_name"] = "—"
            log_list.append(ld)

    return jsonify({
        "status": "success",
        "audit_logs": log_list,
        "count": len(log_list)
    }), 200
