"""
SCOUT Authentication Security & Cryptographic Token Handler
Provides scrypt password hashing, constant-time verification, and tamper-proof
time-limited session token serialization via itsdangerous.
"""

import os
import time
from typing import Dict, Any, Optional
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

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
