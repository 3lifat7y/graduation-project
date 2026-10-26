"""
SCOUT Authentication Security & Cryptographic Token Handler
Provides scrypt password hashing, constant-time verification, and tamper-proof
time-limited session token serialization via itsdangerous.
"""

import os
import re
import time
from typing import Dict, Any, Optional
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


# Default or environment secret key
SECRET_KEY = os.environ.get("SCOUT_SECRET_KEY")
if not SECRET_KEY:
    # Development persistent key cache in instance folder
    instance_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "instance")
    os.makedirs(instance_dir, exist_ok=True)
    key_file = os.path.join(instance_dir, ".secret_key")
    if os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as f:
            SECRET_KEY = f.read().strip()
    if not SECRET_KEY:
        import secrets
        SECRET_KEY = secrets.token_hex(32)
        try:
            with open(key_file, "w", encoding="utf-8") as f:
                f.write(SECRET_KEY)
        except Exception:
            pass

TOKEN_SALT = "scout-session-v1"
SESSION_MAX_AGE_SECONDS = 86400  # 24 hours
COOKIE_NAME = "scout_session"

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=TOKEN_SALT)


def hash_password(password: str) -> str:
    """Hashes password with scrypt."""
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Verifies candidate password in constant time."""
    if not stored_hash or not candidate_password:
        return False
    return check_password_hash(stored_hash, candidate_password)


def create_session_token(user_id: int, role: str, session_version: int) -> str:
    """Creates a cryptographically signed, timestamped session token."""
    payload = {
        "uid": int(user_id),
        "role": str(role),
        "ver": int(session_version),
        "iat": time.time()
    }
    return _serializer.dumps(payload)


def verify_session_token(token: str, max_age: int = SESSION_MAX_AGE_SECONDS) -> Optional[Dict[str, Any]]:
    """
    Validates token signature and expiration.
    Returns payload dict if valid, or None if invalid/expired.
    """
    if not token or not isinstance(token, str):
        return None
    try:
        data = _serializer.loads(token, max_age=max_age)
        if isinstance(data, dict) and "uid" in data and "role" in data:
            return data
        return None
    except (BadSignature, SignatureExpired, Exception):
        return None


def is_valid_email(email: str) -> bool:
    """Validates email format strictly."""
    if not email or not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


def normalize_phone_number(raw_phone: str) -> Optional[str]:
    """
    Normalizes a phone number to an E.164-compatible standard format.
    - Strips whitespace, dashes, dots, and parentheses.
    - Converts leading '00' international prefix to '+'.
    - Accepts optional leading '+'.
    - Validates that the number contains between 7 and 15 digits (ITU-T E.164).
    - Returns normalized string (e.g., '+15551234567' or '01001234567') or None if invalid.
    """
    if not raw_phone or not isinstance(raw_phone, str):
        return None
    cleaned = raw_phone.strip()
    if not cleaned:
        return None

    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    has_plus = cleaned.startswith("+")
    digits_part = cleaned[1:] if has_plus else cleaned

    # Filter allowed formatting characters: spaces, dashes, dots, parentheses
    filtered = re.sub(r"[\s\-\.\(\)]", "", digits_part)

    # Must consist strictly of digits
    if not filtered.isdigit():
        return None

    # E.164 standard: minimum 7 digits up to 15 digits
    if len(filtered) < 7 or len(filtered) > 15:
        return None

    return f"+{filtered}" if has_plus else filtered


def is_valid_phone_number(phone: str) -> bool:
    """Checks whether a phone number can be normalized into a valid E.164 format."""
    return normalize_phone_number(phone) is not None

