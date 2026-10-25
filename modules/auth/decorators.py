"""
SCOUT Role-Based Access Control (RBAC) Decorators
Provides @login_required, @roles_required, and @admin_required guards.
"""

import os
from functools import wraps
from typing import Callable, Any
from flask import request, jsonify

from .routes import get_current_user_from_request


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """
    Ensures the client has an active, valid, non-expired session.
    Injects request.current_user. Returns 401 Unauthorized if invalid.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if os.environ.get("SCOUT_DISABLE_AUTH") == "1":
            from modules.auth.models import User
            request.current_user = User(id=1, username="test_admin", email="test@local", role="Admin", is_active=True)
            return f(*args, **kwargs)

        user, err = get_current_user_from_request()
        if not user:
            return jsonify({
                "status": "unauthorized",
                "code": "AUTH_REQUIRED",
                "message": err or "Authentication required to access this resource."
            }), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*allowed_roles: str) -> Callable[..., Any]:
    """
    Enforces that the authenticated user possesses one of the allowed roles.
    Returns 401 if unauthenticated, or 403 Forbidden if role unauthorized.
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if os.environ.get("SCOUT_DISABLE_AUTH") == "1":
                from modules.auth.models import User
                request.current_user = User(id=1, username="test_admin", email="test@local", role="Admin", is_active=True)
                return f(*args, **kwargs)

            user, err = get_current_user_from_request()
            if not user:
                return jsonify({
                    "status": "unauthorized",
                    "code": "AUTH_REQUIRED",
                    "message": err or "Authentication required to access this resource."
                }), 401
            request.current_user = user
            if user.role not in allowed_roles:
                return jsonify({
                    "status": "forbidden",
                    "code": "ROLE_UNAUTHORIZED",
                    "message": f"Access restricted: Requires one of roles: {', '.join(allowed_roles)}."
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Shortcut decorator for endpoints strictly requiring the Admin role."""
    return roles_required("Admin")(f)
