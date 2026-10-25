"""
SCOUT Authentication Blueprint & REST API Endpoints
Provides registration, login, logout, identity query, and password update endpoints.
"""

import re
from typing import Optional, Tuple
from flask import Blueprint, request, jsonify, make_response
from sqlalchemy import func

from .models import User, utcnow
from .db import get_db_session
from .security import (
    create_session_token, verify_session_token, verify_password,
    COOKIE_NAME, SESSION_MAX_AGE_SECONDS
)
from .rate_limiter import login_rate_limiter
from scripts.create_admin import validate_password_strength

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def extract_token_from_request() -> Optional[str]:
    """Extracts session token from HttpOnly cookie or Authorization Bearer header."""
    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token:
        return cookie_token.strip()

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return None


def get_current_user_from_request() -> Tuple[Optional[User], Optional[str]]:
    """
    Validates request session token and retrieves active user from database.
    Returns (User, None) on success or (None, error_message) on failure.
    """
    token = extract_token_from_request()
    if not token:
        return None, "Authentication token missing."

    payload = verify_session_token(token)
    if not payload:
        return None, "Session token invalid or expired."

    user_id = payload.get("uid")
    token_ver = payload.get("ver", 1)

    with get_db_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return None, "User account not found."
        if not user.is_active:
            return None, "User account is disabled."
        if user.session_version != token_ver:
            return None, "Session has been revoked."
        # Expunge to use detached user object safely
        session.expunge(user)
        return user, None


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Registers a new standard User.
    Role is strictly hardcoded to 'User'; any role in payload is ignored.
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", ""))
    full_name = str(data.get("full_name", "")).strip()

    if not username or not email or not password:
        return jsonify({
            "status": "error",
            "message": "Username, email, and password are required fields."
        }), 400

    if not USERNAME_REGEX.match(username):
        return jsonify({
            "status": "error",
            "message": "Username must be 3-30 characters long and contain only letters, numbers, and underscores."
        }), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({
            "status": "error",
            "message": "Invalid email address format."
        }), 400

    if password != confirm_password:
        return jsonify({
            "status": "error",
            "message": "Password and confirmation password do not match."
        }), 400

    valid_pw, pw_msg = validate_password_strength(password)
    if not valid_pw:
        return jsonify({
            "status": "error",
            "message": pw_msg
        }), 400

    with get_db_session() as session:
        # Check duplicate username or email
        existing = session.query(User).filter(
            (func.lower(User.username) == username.lower()) |
            (func.lower(User.email) == email.lower())
        ).first()

        if existing:
            return jsonify({
                "status": "error",
                "message": "An account with this username or email already exists."
            }), 409

        new_user = User(
            username=username,
            email=email,
            full_name=full_name or None,
            role="User",  # Strictly enforced
            is_active=True
        )
        new_user.set_password(password)
        session.add(new_user)
        session.flush()

        user_dict = new_user.to_dict()
        token = create_session_token(new_user.id, new_user.role, new_user.session_version)

    resp = make_response(jsonify({
        "status": "success",
        "message": "Account created successfully.",
        "user": user_dict,
        "token": token,
        "redirect": "/?view=plans"
    }), 201)

    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticates user credentials and issues an HttpOnly session cookie.
    Enforces brute-force lockout and constant-time password verification.
    """
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({
            "status": "error",
            "message": "Username/email and password are required."
        }), 400

    client_ip = request.remote_addr or "127.0.0.1"
    rate_key = f"{client_ip}:{identifier.lower()}"

    is_locked, seconds_left = login_rate_limiter.is_locked(rate_key)
    if is_locked:
        return jsonify({
            "status": "error",
            "code": "ACCOUNT_LOCKED",
            "message": f"Too many failed login attempts. Temporarily locked out for {seconds_left} seconds."
        }), 429

    with get_db_session() as session:
        user = session.query(User).filter(
            (func.lower(User.username) == identifier.lower()) |
            (func.lower(User.email) == identifier.lower())
        ).first()

        if not user:
            # Constant-time dummy verification to mitigate user-enumeration timing attacks
            verify_password(
                "scrypt:32768:8:1$dummy$1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                password
            )
            locked_now, lock_time = login_rate_limiter.record_failure(rate_key)
            msg = f"Account temporarily locked for {lock_time} seconds." if locked_now else "Invalid username or password."
            return jsonify({"status": "error", "message": msg}), 401

        if not user.check_password(password):
            locked_now, lock_time = login_rate_limiter.record_failure(rate_key)
            msg = f"Account temporarily locked for {lock_time} seconds." if locked_now else "Invalid username or password."
            return jsonify({"status": "error", "message": msg}), 401

        if not user.is_active:
            return jsonify({
                "status": "error",
                "code": "ACCOUNT_DISABLED",
                "message": "Your account has been deactivated. Please contact an administrator."
            }), 403

        # Successful authentication: reset rate limiter
        login_rate_limiter.reset(rate_key)
        user.last_login_at = utcnow()
        session.flush()

        user_dict = user.to_dict()
        token = create_session_token(user.id, user.role, user.session_version)

    resp = make_response(jsonify({
        "status": "success",
        "message": "Authentication successful.",
        "user": user_dict,
        "token": token
    }), 200)

    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logs out the active session by clearing the HttpOnly cookie."""
    resp = make_response(jsonify({
        "status": "success",
        "message": "Logged out successfully."
    }), 200)

    resp.delete_cookie(COOKIE_NAME, httponly=True, samesite="Lax")
    return resp


@auth_bp.route("/me", methods=["GET"])
def get_current_user():
    """Returns the current authenticated user's profile and active session status."""
    user, err = get_current_user_from_request()
    if not user:
        resp = make_response(jsonify({
            "status": "unauthorized",
            "authenticated": False,
            "message": err or "Not authenticated."
        }), 401)
        resp.delete_cookie(COOKIE_NAME, httponly=True, samesite="Lax")
        return resp

    return jsonify({
        "status": "success",
        "authenticated": True,
        "user": user.to_dict()
    }), 200


@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    """Allows an authenticated user to change their password and invalidates previous sessions."""
    user, err = get_current_user_from_request()
    if not user:
        return jsonify({"status": "unauthorized", "message": err or "Not authenticated."}), 401

    data = request.get_json(silent=True) or {}
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    confirm_new_password = str(data.get("confirm_new_password", ""))

    if not current_password or not new_password:
        return jsonify({"status": "error", "message": "Current and new password are required."}), 400

    if new_password != confirm_new_password:
        return jsonify({"status": "error", "message": "New passwords do not match."}), 400

    valid_pw, pw_msg = validate_password_strength(new_password)
    if not valid_pw:
        return jsonify({"status": "error", "message": pw_msg}), 400

    with get_db_session() as session:
        db_user = session.query(User).filter_by(id=user.id).first()
        if not db_user or not db_user.check_password(current_password):
            return jsonify({"status": "error", "message": "Incorrect current password."}), 400

        db_user.set_password(new_password)
        db_user.revoke_sessions()
        session.flush()

        new_token = create_session_token(db_user.id, db_user.role, db_user.session_version)

    resp = make_response(jsonify({
        "status": "success",
        "message": "Password changed successfully. All previous sessions revoked."
    }), 200)

    resp.set_cookie(
        COOKIE_NAME,
        new_token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp
