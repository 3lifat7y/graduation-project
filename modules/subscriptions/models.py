"""
SCOUT Subscription Models
Declarative SQLAlchemy models for Subscription Plans, User Subscriptions, and Audit Logs.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey
from sqlalchemy.orm import relationship

from modules.auth.models import Base, utcnow


class SubscriptionPlan(Base):
    """
    Catalog of subscription plans offering varying feature entitlements and duration.
    Retains historical integrity: plans are soft-deactivated, never hard-deleted.
    """
    __tablename__ = "subscription_plans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    plan_code = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    price = Column(Float, nullable=False, default=0.0)
    currency = Column(String(3), nullable=False, default="USD")
    duration_value = Column(Integer, nullable=False, default=30)
    duration_unit = Column(String(20), nullable=False, default="days")  # 'days', 'months', 'years'
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    features_json = Column(Text, nullable=True)  # JSON-encoded dict of feature flags
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    subscriptions = relationship("UserSubscription", back_populates="plan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<SubscriptionPlan id={self.id} code='{self.plan_code}' name='{self.name}' active={self.is_active}>"

    def get_features(self) -> Dict[str, Any]:
        """Returns deserialized feature entitlements dictionary."""
        if not self.features_json:
            return {
                "can_live_monitoring": True,
                "can_port_scan": True,
                "can_network_discovery": True,
                "can_export_reports": False
            }
        try:
            return json.loads(self.features_json)
        except Exception:
            return {}

    def set_features(self, features_dict: Dict[str, Any]) -> None:
        """Serializes dictionary of feature entitlements to JSON."""
        self.features_json = json.dumps(features_dict or {})

    def to_dict(self) -> Dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        return {
            "id": self.id,
            "plan_code": self.plan_code,
            "code": self.plan_code,
            "name": self.name,
            "description": self.description or "",
            "price": float(self.price),
            "currency": self.currency,
            "duration_value": int(self.duration_value),
            "duration_days": int(self.duration_value),
            "duration_unit": self.duration_unit,
            "is_active": bool(self.is_active),
            "features": self.get_features(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalizes any datetime (offset-naive or offset-aware) to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class PaymentMethod(Base):
    """
    Administrator-configured payment methods (e.g., InstaPay, Vodafone Cash, WE Pay, etc.).
    Supports multiple receiving accounts, custom instructions, and soft activation/deactivation.
    """
    __tablename__ = "payment_methods"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)  # slug identifier
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    instructions = Column(Text, nullable=True)
    provider_type = Column(String(50), nullable=False, default="electronic_wallet")  # instapay, vodafone_cash, etc.
    logo_icon = Column(String(100), nullable=True)  # fontawesome icon class or image url
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    display_order = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    accounts = relationship(
        "PaymentReceivingAccount",
        back_populates="payment_method",
        cascade="all, delete-orphan",
        order_by="PaymentReceivingAccount.display_order"
    )

    def __repr__(self) -> str:
        return f"<PaymentMethod id={self.id} name='{self.name}' active={self.is_active}>"

    def to_dict(self, include_inactive_accounts: bool = False) -> Dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        if include_inactive_accounts:
            accts = [acc.to_dict() for acc in self.accounts]
        else:
            accts = [acc.to_dict() for acc in self.accounts if acc.is_active]
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description or "",
            "instructions": self.instructions or "",
            "provider_type": self.provider_type,
            "logo_icon": self.logo_icon or "",
            "is_active": bool(self.is_active),
            "display_order": int(self.display_order),
            "accounts": accts,
            "active_accounts_count": sum(1 for acc in self.accounts if acc.is_active),
            "total_accounts_count": len(self.accounts),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PaymentReceivingAccount(Base):
    """
    Receiving account details (account number, phone number, wallet address, or handle)
    belonging to a specific PaymentMethod.
    """
    __tablename__ = "payment_receiving_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    payment_method_id = Column(Integer, ForeignKey("payment_methods.id", ondelete="CASCADE"), nullable=False, index=True)
    account_identifier = Column(String(100), nullable=False)  # Phone number, email, or wallet identifier
    account_holder_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    display_order = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    payment_method = relationship("PaymentMethod", back_populates="accounts")

    def __repr__(self) -> str:
        return f"<PaymentReceivingAccount id={self.id} method_id={self.payment_method_id} identifier='{self.account_identifier}'>"

    def to_dict(self) -> Dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        return {
            "id": self.id,
            "payment_method_id": self.payment_method_id,
            "payment_method_name": self.payment_method.display_name if self.payment_method else None,
            "account_identifier": self.account_identifier,
            "account_holder_name": self.account_holder_name,
            "description": self.description or "",
            "is_active": bool(self.is_active),
            "display_order": int(self.display_order),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class UserSubscription(Base):
    """
    User subscription record tracking lifecycle status (pending, active, expired, canceled, rejected).
    """
    __tablename__ = "user_subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("subscription_plans.id", ondelete="RESTRICT"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending", index=True)  # pending, active, expired, canceled, rejected
    start_date = Column(DateTime(timezone=True), nullable=True)
    end_date = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    activated_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    cancellation_reason = Column(Text, nullable=True)
    admin_notes = Column(Text, nullable=True)

    # Manual Payment & Verification Fields
    payment_method_id = Column(Integer, ForeignKey("payment_methods.id", ondelete="SET NULL"), nullable=True)
    receiving_account_id = Column(Integer, ForeignKey("payment_receiving_accounts.id", ondelete="SET NULL"), nullable=True)
    payment_amount = Column(Float, nullable=True)
    payment_currency = Column(String(10), nullable=True, default="USD")
    payment_status = Column(String(30), nullable=False, default="none")  # none, pending_verification, approved, rejected
    payment_method_name_snapshot = Column(String(100), nullable=True)
    payment_method_type_snapshot = Column(String(50), nullable=True)
    receiving_account_identifier_snapshot = Column(String(100), nullable=True)
    receiving_account_holder_snapshot = Column(String(100), nullable=True)
    plan_name_snapshot = Column(String(100), nullable=True)
    plan_price_snapshot = Column(Float, nullable=True)
    receipt_filename = Column(String(255), nullable=True)
    receipt_original_name = Column(String(255), nullable=True)
    receipt_content_type = Column(String(50), nullable=True)
    receipt_file_size = Column(Integer, nullable=True)
    transaction_reference = Column(String(100), nullable=True)
    payment_notes = Column(Text, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    plan = relationship("SubscriptionPlan", back_populates="subscriptions")
    activated_by = relationship("User", foreign_keys=[activated_by_id])
    audit_logs = relationship("SubscriptionAuditLog", back_populates="subscription", cascade="all, delete-orphan")
    payment_method = relationship("PaymentMethod", foreign_keys=[payment_method_id])
    receiving_account = relationship("PaymentReceivingAccount", foreign_keys=[receiving_account_id])

    def __repr__(self) -> str:
        return f"<UserSubscription id={self.id} user_id={self.user_id} plan_id={self.plan_id} status='{self.status}'>"

    def is_valid_active(self, now: Optional[datetime] = None) -> bool:
        """Evaluates whether the subscription is currently active and within its date bounds."""
        if self.status != "active":
            return False
        current_time = ensure_utc(now or utcnow())
        start = ensure_utc(self.start_date)
        end = ensure_utc(self.end_date)
        if start and current_time < start:
            return False
        if end and current_time > end:
            return False
        return True

    def to_dict(self, include_audit: bool = False, include_admin_notes: bool = True) -> Dict[str, Any]:
        """Returns JSON-serializable representation of the subscription."""
        now = ensure_utc(utcnow())
        is_active_now = self.is_valid_active(now)
        days_remaining = None
        end = ensure_utc(self.end_date)
        if end:
            diff = end - now
            days_remaining = max(0, diff.days + (1 if diff.seconds > 0 else 0))

        data = {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else None,
            "user_email": self.user.email if self.user else None,
            "plan_id": self.plan_id,
            "plan_name": self.plan_name_snapshot or (self.plan.name if self.plan else None),
            "plan_code": self.plan.plan_code if self.plan else None,
            "plan_price": self.plan_price_snapshot if self.plan_price_snapshot is not None else (self.plan.price if self.plan else None),
            "plan_currency": self.payment_currency or (self.plan.currency if self.plan else "USD"),
            "plan_duration": f"{self.plan.duration_value} {self.plan.duration_unit}" if self.plan else None,
            "status": self.status,
            "is_valid_active": is_active_now,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "days_remaining": days_remaining,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "activated_by_id": self.activated_by_id,
            "activated_by_name": self.activated_by.username if self.activated_by else None,
            "cancellation_reason": self.cancellation_reason,
            "features": self.plan.get_features() if self.plan else {},
            # Payment & Snapshot Fields
            "payment_method_id": self.payment_method_id,
            "receiving_account_id": self.receiving_account_id,
            "payment_amount": self.payment_amount if self.payment_amount is not None else (self.plan.price if self.plan else None),
            "payment_currency": self.payment_currency or (self.plan.currency if self.plan else "USD"),
            "payment_status": self.payment_status or "none",
            "payment_method_name": self.payment_method_name_snapshot or (self.payment_method.display_name if self.payment_method else None),
            "payment_method_type": self.payment_method_type_snapshot or (self.payment_method.provider_type if self.payment_method else None),
            "receiving_account_identifier": self.receiving_account_identifier_snapshot or (self.receiving_account.account_identifier if self.receiving_account else None),
            "receiving_account_holder": self.receiving_account_holder_snapshot or (self.receiving_account.account_holder_name if self.receiving_account else None),
            "receipt_filename": self.receipt_filename,
            "receipt_original_name": self.receipt_original_name,
            "receipt_content_type": self.receipt_content_type,
            "receipt_file_size": self.receipt_file_size,
            "receipt_url": f"/api/subscriptions/receipts/{self.receipt_filename}" if self.receipt_filename else None,
            "transaction_reference": self.transaction_reference,
            "payment_notes": self.payment_notes,
            "rejection_reason": self.rejection_reason
        }
        if include_admin_notes:
            data["admin_notes"] = self.admin_notes
        if include_audit:
            data["audit_logs"] = [log.to_dict() for log in self.audit_logs]
        return data


class SubscriptionAuditLog(Base):
    """
    Immutable audit trail recording state transitions, approvals, cancellations, and date edits.
    """
    __tablename__ = "subscription_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    subscription_id = Column(Integer, ForeignKey("user_subscriptions.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(50), nullable=False)  # REQUESTED, ACTIVATED, REJECTED, CANCELED, DATES_MODIFIED
    previous_status = Column(String(20), nullable=True)
    new_status = Column(String(20), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    details = Column(Text, nullable=True)

    # Relationships
    subscription = relationship("UserSubscription", back_populates="audit_logs")
    actor = relationship("User", foreign_keys=[actor_id])

    def __repr__(self) -> str:
        return f"<SubscriptionAuditLog id={self.id} sub_id={self.subscription_id} action='{self.action}'>"

    def to_dict(self) -> Dict[str, Any]:
        """Returns JSON-serializable dictionary representation."""
        return {
            "id": self.id,
            "subscription_id": self.subscription_id,
            "actor_id": self.actor_id,
            "actor_name": self.actor.username if self.actor else "System",
            "action": self.action,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details
        }
