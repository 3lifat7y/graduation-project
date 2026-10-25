"""
SCOUT User and Authentication Models
Declarative SQLAlchemy models for user identity, role-based authorization, and security state.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base
from werkzeug.security import generate_password_hash, check_password_hash

Base = declarative_base()


def utcnow() -> datetime:
    """Returns the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class User(Base):
    """
    User entity representing an operator or administrator in SCOUT.
    Enforces strict role constraints: 'User' (default) or 'Admin'.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="User")  # Exactly 'User' or 'Admin'
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    session_version = Column(Integer, nullable=False, default=1)  # Incremented to revoke existing sessions
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}' active={self.is_active}>"

    def set_password(self, password: str) -> None:
        """Hashes password using scrypt (memory-hard, resistant to hardware brute-force)."""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Verifies candidate password against stored scrypt hash in constant time."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    def revoke_sessions(self) -> None:
        """Increments session_version to invalidate any existing issued tokens/cookies."""
        self.session_version = (self.session_version or 1) + 1

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Returns a sanitized JSON-serializable dictionary representation."""
        data: Dict[str, Any] = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "full_name": self.full_name or "",
            "is_active": bool(self.is_active),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
        if include_sensitive:
            data["session_version"] = self.session_version
        return data
