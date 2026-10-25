"""
SCOUT Subscription Lifecycle Services
Implements state transitions (REQUESTED, ACTIVATED, REJECTED, CANCELED, DATES_MODIFIED)
with mandatory audit logging and referential integrity.
"""

from datetime import datetime, timezone, timedelta
from typing import Tuple, Dict, Any, Optional

from modules.auth.models import User, utcnow
from modules.auth.db import get_db_session
from .models import SubscriptionPlan, UserSubscription, SubscriptionAuditLog


def request_subscription(user_id: int, plan_id: int, notes: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Submits a subscription request for an active plan.
    Transition: None/Expired -> Pending.
    """
    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user or not user.is_active:
            return False, "User account is inactive or not found.", {}

        plan = session.query(SubscriptionPlan).filter_by(id=plan_id).first()
        if not plan:
            return False, "Subscription plan not found.", {}
        if not plan.is_active:
            return False, "This subscription plan is retired and no longer available for new requests.", {}

        # Check existing active or pending subscription
        existing_active = session.query(UserSubscription).filter(
            UserSubscription.user_id == user_id,
            UserSubscription.status == "active"
        ).first()
        if existing_active and existing_active.is_valid_active():
            return False, f"User already has an active subscription for plan '{existing_active.plan.name}'.", {}

        existing_pending = session.query(UserSubscription).filter(
            UserSubscription.user_id == user_id,
            UserSubscription.status == "pending"
        ).first()
        if existing_pending:
            return False, "A subscription request is already pending administrative review.", {}

        sub = UserSubscription(
            user_id=user_id,
            plan_id=plan_id,
            status="pending",
            admin_notes=notes
        )
        session.add(sub)
        session.flush()

        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=user_id,
            action="REQUESTED",
            previous_status=None,
            new_status="pending",
            details=f"User requested subscription for plan '{plan.name}' ({plan.plan_code})."
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, "Subscription request submitted successfully.", sub_dict


def activate_subscription(
    subscription_id: int,
    admin_id: int,
    duration_override_days: Optional[int] = None,
    notes: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Approves and activates a subscription.
    Transition: Pending/Expired -> Active.
    """
    with get_db_session() as session:
        admin = session.query(User).filter_by(id=admin_id).first()
        if not admin or admin.role != "Admin":
            return False, "Only Administrators may activate subscriptions.", {}

        sub = session.query(UserSubscription).filter_by(id=subscription_id).first()
        if not sub:
            return False, "Subscription record not found.", {}

        prev_status = sub.status
        now = utcnow()
        plan = sub.plan

        # Calculate duration in days
        if duration_override_days and duration_override_days > 0:
            duration_days = duration_override_days
        elif plan.duration_unit == "months":
            duration_days = plan.duration_value * 30
        elif plan.duration_unit == "years":
            duration_days = plan.duration_value * 365
        else:
            duration_days = plan.duration_value

        start_date = now
        end_date = start_date + timedelta(days=duration_days)

        sub.status = "active"
        sub.start_date = start_date
        sub.end_date = end_date
        sub.activated_at = now
        sub.activated_by_id = admin_id
        if notes:
            sub.admin_notes = notes

        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=admin_id,
            action="ACTIVATED",
            previous_status=prev_status,
            new_status="active",
            details=f"Admin '{admin.username}' activated subscription. Valid until {end_date.strftime('%Y-%m-%d')} ({duration_days} days)."
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, f"Subscription #{subscription_id} activated successfully.", sub_dict


def reject_subscription(
    subscription_id: int,
    admin_id: int,
    reason: str
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Rejects a pending subscription request.
    Transition: Pending -> Rejected.
    """
    with get_db_session() as session:
        admin = session.query(User).filter_by(id=admin_id).first()
        if not admin or admin.role != "Admin":
            return False, "Only Administrators may reject subscriptions.", {}

        sub = session.query(UserSubscription).filter_by(id=subscription_id).first()
        if not sub:
            return False, "Subscription record not found.", {}

        prev_status = sub.status
        sub.status = "rejected"
        sub.cancellation_reason = reason or "Request rejected by administrator."

        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=admin_id,
            action="REJECTED",
            previous_status=prev_status,
            new_status="rejected",
            details=f"Admin '{admin.username}' rejected request. Reason: {sub.cancellation_reason}"
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, f"Subscription #{subscription_id} rejected.", sub_dict


def cancel_subscription(
    subscription_id: int,
    admin_id: int,
    reason: str
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Revokes/cancels an active subscription immediately.
    Transition: Active/Pending -> Canceled.
    """
    with get_db_session() as session:
        admin = session.query(User).filter_by(id=admin_id).first()
        if not admin or admin.role != "Admin":
            return False, "Only Administrators may cancel subscriptions.", {}

        sub = session.query(UserSubscription).filter_by(id=subscription_id).first()
        if not sub:
            return False, "Subscription record not found.", {}

        prev_status = sub.status
        sub.status = "canceled"
        sub.cancellation_reason = reason or "Canceled by administrator."

        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=admin_id,
            action="CANCELED",
            previous_status=prev_status,
            new_status="canceled",
            details=f"Admin '{admin.username}' canceled subscription. Reason: {sub.cancellation_reason}"
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, f"Subscription #{subscription_id} canceled.", sub_dict


def adjust_subscription_dates(
    subscription_id: int,
    admin_id: int,
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    reason: str
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Updates start and/or end dates under administrative policy with audit log.
    """
    with get_db_session() as session:
        admin = session.query(User).filter_by(id=admin_id).first()
        if not admin or admin.role != "Admin":
            return False, "Only Administrators may adjust subscription dates.", {}

        sub = session.query(UserSubscription).filter_by(id=subscription_id).first()
        if not sub:
            return False, "Subscription record not found.", {}

        old_start = sub.start_date.isoformat() if sub.start_date else "None"
        old_end = sub.end_date.isoformat() if sub.end_date else "None"

        if start_date:
            sub.start_date = start_date
        if end_date:
            sub.end_date = end_date

        audit = SubscriptionAuditLog(
            subscription_id=sub.id,
            actor_id=admin_id,
            action="DATES_MODIFIED",
            previous_status=sub.status,
            new_status=sub.status,
            details=f"Dates adjusted by Admin '{admin.username}'. Old: ({old_start} to {old_end}) -> New: ({sub.start_date} to {sub.end_date}). Reason: {reason}"
        )
        session.add(audit)
        session.flush()
        sub_dict = sub.to_dict()

    return True, "Subscription dates updated successfully.", sub_dict
