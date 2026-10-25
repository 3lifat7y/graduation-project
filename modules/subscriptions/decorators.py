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
            return False, "User account is inactive or disabled.", {"status": "disabled"}

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

        if not active_sub:
            # Check if user has a pending or rejected subscription
            pending_sub = (
                session.query(UserSubscription)
                .filter_by(user_id=user_id, status="pending")
                .first()
            )
            if pending_sub:
                return False, "Your subscription is pending administrative activation.", {
                    "status": "pending",
                    "plan_name": pending_sub.plan.name if pending_sub.plan else "Pending Plan"
                }

            return False, "An active subscription is required to access operational tools. Please select a plan.", {
                "status": "none"
            }

        # Dynamic expiration check
        end_time = ensure_utc(active_sub.end_date)
        if end_time and end_time < now:
            active_sub.status = "expired"
            session.flush()
            return False, f"Your subscription expired on {end_time.strftime('%Y-%m-%d')}. Please renew your plan.", {
                "status": "expired",
                "expired_at": end_time.isoformat()
            }

        # Check feature entitlement
        if required_feature:
            features = active_sub.plan.get_features() if active_sub.plan else {}
            if not features.get(required_feature, False):
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
                err_code = "FEATURE_NOT_INCLUDED" if context.get("status") == "feature_restricted" else "SUBSCRIPTION_REQUIRED"
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
