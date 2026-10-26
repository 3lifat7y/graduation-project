"""
SCOUT Authentication Blueprint & REST API Endpoints
Provides registration, login, logout, identity query, and password update endpoints.
"""

import re
import secrets
from typing import Optional, Tuple
from flask import Blueprint, request, jsonify, make_response
from sqlalchemy import func

from .models import User, utcnow
from .db import get_db_session
from .security import (
    create_session_token, verify_session_token, verify_password,
    normalize_phone_number, is_valid_email,
    COOKIE_NAME, SESSION_MAX_AGE_SECONDS
)
from .rate_limiter import login_rate_limiter
from scripts.create_admin import validate_password_strength

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")



def extract_token_from_request() -> Optional[str]:
    """Extracts session token from Authorization Bearer header or HttpOnly cookie."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token:
        return cookie_token.strip()

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
    Requires Full Name, Email Address, Phone Number, Password, and Confirm Password.
    Role is strictly hardcoded to 'User'; any role in payload is ignored.
    """
    data = request.get_json(silent=True) or {}
    full_name = str(data.get("full_name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    phone_raw = str(data.get("phone_number") or data.get("phone") or "").strip()
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", ""))
    legacy_username = str(data.get("username", "")).strip()

    # Validate legacy username if provided
    if legacy_username and not USERNAME_REGEX.match(legacy_username):
        return jsonify({
            "status": "error",
            "message": "Username must be 3-30 characters long and contain only letters, numbers, and underscores."
        }), 400

    if not email or not password:
        return jsonify({
            "status": "error",
            "message": "Email and password are required fields."
        }), 400

    if not is_valid_email(email):
        return jsonify({
            "status": "error",
            "message": "Invalid email address format."
        }), 400

    normalized_phone = None
    if phone_raw:
        normalized_phone = normalize_phone_number(phone_raw)
        if not normalized_phone:
            return jsonify({
                "status": "error",
                "message": "Invalid phone number format. Please provide a valid phone number with 7-15 digits."
            }), 400

    if "confirm_password" in data and password != confirm_password:
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
        # Check duplicate email
        existing_email = session.query(User).filter(
            func.lower(User.email) == email.lower()
        ).first()
        if existing_email:
            return jsonify({
                "status": "error",
                "message": "An account with this email address already exists."
            }), 409

        # Check duplicate phone number if provided
        if normalized_phone:
            phone_variants = [normalized_phone]
            if normalized_phone.startswith("+"):
                phone_variants.append(normalized_phone[1:])
            else:
                phone_variants.append("+" + normalized_phone)

            existing_phone = session.query(User).filter(
                User.phone_number.in_(phone_variants)
            ).first()
            if existing_phone:
                return jsonify({
                    "status": "error",
                    "message": "An account with this phone number already exists."
                }), 409

        # Handle internal username:
        # If legacy_username was passed, validate uniqueness; otherwise auto-generate a unique internal username
        if legacy_username:
            if session.query(User).filter(func.lower(User.username) == legacy_username.lower()).first():
                return jsonify({
                    "status": "error",
                    "message": "An account with this username already exists."
                }), 409
            assigned_username = legacy_username
        else:
            base = re.sub(r"[^a-zA-Z0-9_]", "", email.split("@")[0])[:20] or "user"
            while True:
                candidate = f"{base}_{secrets.token_hex(4)}"
                if not session.query(User).filter(func.lower(User.username) == candidate.lower()).first():
                    assigned_username = candidate
                    break

        new_user = User(
            username=assigned_username,
            email=email,
            phone_number=normalized_phone,
            full_name=full_name or legacy_username or email.split("@")[0],
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
    Authenticates user credentials using Email Address or Phone Number (or legacy Username).
    Enforces brute-force lockout, constant-time dummy verification, and session token issuance.
    """
    data = request.get_json(silent=True) or {}
    identifier = str(
        data.get("identifier") or data.get("username") or data.get("email") or data.get("phone") or ""
    ).strip()
    password = str(data.get("password", ""))

    if not identifier or not password:
        return jsonify({
            "status": "error",
            "message": "Email address or phone number and password are required."
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
        user = None
        if "@" in identifier:
            # Query by email address
            user = session.query(User).filter(
                func.lower(User.email) == identifier.lower()
            ).first()
        else:
            # Query by phone number
            norm_phone = normalize_phone_number(identifier)
            if norm_phone:
                phone_variants = [norm_phone]
                if norm_phone.startswith("+"):
                    phone_variants.append(norm_phone[1:])
                else:
                    phone_variants.append("+" + norm_phone)
                user = session.query(User).filter(
                    User.phone_number.in_(phone_variants)
                ).first()

            # Fallback to username or email (for backward compatibility)
            if not user:
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
            msg = f"Account temporarily locked for {lock_time} seconds." if locked_now else "Invalid credentials: Invalid username or password."
            return jsonify({"status": "error", "message": msg}), 401

        if not user.check_password(password):
            locked_now, lock_time = login_rate_limiter.record_failure(rate_key)
            msg = f"Account temporarily locked for {lock_time} seconds." if locked_now else "Invalid credentials: Invalid username or password."
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

        # Determine dynamic post-login destination URL
        from modules.subscriptions.services import determine_user_landing_view
        view_key, redirect_url = determine_user_landing_view(user)

    resp = make_response(jsonify({
        "status": "success",
        "message": "Authentication successful.",
        "user": user_dict,
        "token": token,
        "redirect": redirect_url,
        "view": view_key
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
    """
    Logs out the active session:
    1. Increments user's session_version in database to invalidate issued tokens server-side.
    2. Deletes the HttpOnly session cookie.
    3. Adds anti-cache headers so browser history navigation cannot expose protected data.
    """
    user, _ = get_current_user_from_request()
    if user:
        with get_db_session() as session:
            db_user = session.query(User).filter_by(id=user.id).first()
            if db_user:
                db_user.revoke_sessions()
                session.flush()

    resp = make_response(jsonify({
        "status": "success",
        "message": "Logged out successfully."
    }), 200)

    resp.delete_cookie(COOKIE_NAME, httponly=True, samesite="Lax")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
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


@auth_bp.route("/profile", methods=["GET", "PUT", "PATCH"])
def update_profile():
    """
    Retrieves or updates the authenticated user's display profile (full_name, email, phone_number).
    Validates email/phone syntax and rejects duplicates.
    Privilege escalation attempts (modifying role, is_active, password) are strictly blocked.
    """
    user, err = get_current_user_from_request()
    if not user:
        return jsonify({"status": "unauthorized", "message": err or "Not authenticated."}), 401

    if request.method == "GET":
        return jsonify({"status": "success", "user": user.to_dict()}), 200

    data = request.get_json(silent=True) or {}
    new_full_name = data.get("full_name")
    new_email = data.get("email")
    new_phone = data.get("phone_number") if "phone_number" in data else data.get("phone")

    if new_email is None and new_full_name is None and new_phone is None:
        return jsonify({"status": "error", "message": "No profile fields provided to update."}), 400

    with get_db_session() as session:
        db_user = session.query(User).filter_by(id=user.id).first()
        if not db_user:
            return jsonify({"status": "error", "message": "User not found."}), 404

        if new_email is not None:
            email_cleaned = str(new_email).strip().lower()
            if not email_cleaned:
                return jsonify({"status": "error", "message": "Email address cannot be empty."}), 400
            if not is_valid_email(email_cleaned):
                return jsonify({"status": "error", "message": "Invalid email address format."}), 400

            # Check duplicate email against other accounts
            duplicate = session.query(User).filter(
                func.lower(User.email) == email_cleaned,
                User.id != db_user.id
            ).first()
            if duplicate:
                return jsonify({"status": "error", "message": "An account with this email address already exists."}), 409

            db_user.email = email_cleaned

        if new_phone is not None:
            raw_phone = str(new_phone).strip()
            if raw_phone:
                norm_phone = normalize_phone_number(raw_phone)
                if not norm_phone:
                    return jsonify({"status": "error", "message": "Invalid phone number format. Please provide a valid phone number with 7-15 digits."}), 400

                phone_variants = [norm_phone]
                if norm_phone.startswith("+"):
                    phone_variants.append(norm_phone[1:])
                else:
                    phone_variants.append("+" + norm_phone)

                dup_phone = session.query(User).filter(
                    User.phone_number.in_(phone_variants),
                    User.id != db_user.id
                ).first()
                if dup_phone:
                    return jsonify({"status": "error", "message": "An account with this phone number already exists."}), 409

                db_user.phone_number = norm_phone
            else:
                db_user.phone_number = None

        if new_full_name is not None:
            name_cleaned = str(new_full_name).strip()
            db_user.full_name = name_cleaned or None

        session.flush()
        user_dict = db_user.to_dict()

    return jsonify({
        "status": "success",
        "message": "Profile updated successfully.",
        "user": user_dict
    }), 200


