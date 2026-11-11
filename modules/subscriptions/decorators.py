"""
SCOUT Subscription Entitlement Evaluator & Guard Decorators
Provides a single, centralized backend entitlement enforcement policy:
evaluates account status, active subscription, date bounds, dynamic expiration,
and granular feature flags.
"""

from functools import wraps
from typing import Callable, Any, Optional, Tuple, Dict
from flask import request, jsonify

from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session
from modules.auth.decorators import login_required
from .models import UserSubscription, ensure_utc


def evaluate_user_entitlement(
    user_id: int,
    required_feature: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Single unified authorization policy.
    Returns: (is_authorized: bool, reason_message: str, context: dict)
    """
    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user or not user.is_active:
            return False, "Your account has been suspended. Please contact the platform administrator.", {"status": "suspended"}

        # Administrators bypass subscription constraints
        if user.role == "Admin":
            return True, "Administrator privilege confirmed.", {"role": "Admin", "status": "active"}

        now = ensure_utc(utcnow())

        # Check current active subscription
        active_sub = (
            session.query(UserSubscription)
            .filter_by(user_id=user_id, status="active")
            .order_by(UserSubscription.end_date.desc())
            .first()
        )

        if active_sub:
            # Dynamic expiration check
            end_time = ensure_utc(active_sub.end_date)
            if end_time and end_time < now:
                active_sub.status = "expired"
                session.flush()
                return False, "Your subscription has expired. Renew or select a plan to restore access.", {
                    "status": "expired",
                    "expired_at": end_time.isoformat()
                }

            # Check feature entitlement
            if required_feature:
                features = active_sub.plan.get_features() if active_sub.plan else {}
                has_feat = bool(features.get(required_feature, False) or (required_feature == "can_live_monitoring" and features.get("can_monitor", False)))
                if not has_feat:
                    return False, f"Your current subscription plan ('{active_sub.plan.name}') does not include the '{required_feature}' capability.", {
                        "status": "feature_restricted",
                        "plan_name": active_sub.plan.name,
                        "missing_feature": required_feature
                    }

            return True, "Subscription verified.", {
                "status": "active",
                "subscription_id": active_sub.id,
                "plan_name": active_sub.plan.name,
                "plan_code": active_sub.plan.plan_code,
                "end_date": active_sub.end_date.isoformat() if active_sub.end_date else None
            }

        # No active subscription: check for pending or expired record
        pending_sub = (
            session.query(UserSubscription)
            .filter_by(user_id=user_id, status="pending")
            .order_by(UserSubscription.id.desc())
            .first()
        )
        if pending_sub:
            return False, "Your subscription request is awaiting administrator approval.", {
                "status": "pending",
                "plan_name": pending_sub.plan.name if pending_sub.plan else "Pending Plan"
            }

        expired_sub = (
            session.query(UserSubscription)
            .filter_by(user_id=user_id, status="expired")
            .order_by(UserSubscription.end_date.desc())
            .first()
        )
        if expired_sub:
            return False, "Your subscription has expired. Renew or select a plan to restore access.", {
                "status": "expired",
                "expired_at": expired_sub.end_date.isoformat() if expired_sub.end_date else None
            }

        return False, "You don't have an active subscription. Choose a plan to unlock SCOUT operational features.", {
            "status": "none"
        }


def subscription_required(feature: Optional[str] = None) -> Callable[..., Any]:
    """
    Flask decorator enforcing active subscription entitlement before execution.
    Automatically implies @login_required.
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            import os
            if os.environ.get("SCOUT_DISABLE_AUTH") == "1":
                return f(*args, **kwargs)

            user = request.current_user
            authorized, reason, context = evaluate_user_entitlement(user.id, required_feature=feature)

            if not authorized:
                c_status = context.get("status")
                if c_status in ("suspended", "disabled"):
                    err_code = "ACCOUNT_DISABLED"
                elif c_status == "feature_restricted":
                    err_code = "FEATURE_NOT_INCLUDED"
                elif c_status == "expired":
                    err_code = "SUBSCRIPTION_EXPIRED"
                elif c_status == "pending":
                    err_code = "SUBSCRIPTION_PENDING"
                else:
                    err_code = "SUBSCRIPTION_REQUIRED"

                return jsonify({
                    "status": "forbidden",
                    "code": err_code,
                    "message": reason,
                    "context": context
                }), 403

            request.subscription_context = context
            return f(*args, **kwargs)
        return decorated_function
    return decorator
