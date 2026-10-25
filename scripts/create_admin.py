#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT Offline Administrative Account Provisioner
Allows system administrators to provision the initial Admin account directly via console.
Supports interactive masked credential entry as well as command-line arguments for scripting.
"""

import sys
import re
import getpass
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.auth.db import init_db, get_db_session
from modules.auth.models import User

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,}$"
)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validates that password meets enterprise cybersecurity strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"\d", password):
        return False, "Password must include at least one numeric digit (0-9)."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must include at least one special character."
    return True, "Password meets complexity requirements."


def create_admin_user(username: str, email: str, password: str, full_name: str = "SCOUT Administrator") -> tuple[bool, str]:
    """Creates or verifies an Admin account in the database."""
    init_db()

    username = username.strip()
    email = email.strip().lower()

    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long."
    if not re.match(r"^[a-zA-Z0-9_]{3,30}$", username):
        return False, "Username can only contain alphanumeric characters and underscores (3-30 chars)."
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return False, "Invalid email address format."

    valid_pw, pw_msg = validate_password_strength(password)
    if not valid_pw:
        return False, pw_msg

    with get_db_session() as session:
        existing = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing:
            if existing.username.lower() == username.lower():
                return False, f"User with username '{username}' already exists."
            return False, f"User with email '{email}' already exists."

        admin_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role="Admin",
            is_active=True
        )
        admin_user.set_password(password)
        session.add(admin_user)
        session.flush()
        user_id = admin_user.id

    return True, f"Admin account '{username}' (ID: {user_id}) created successfully."


def main():
    parser = argparse.ArgumentParser(description="SCOUT Initial Admin Account Provisioning CLI")
    parser.add_argument("--username", help="Administrator username (3-30 alphanumeric characters)")
    parser.add_argument("--email", help="Administrator email address")
    parser.add_argument("--password", help="Administrator password (optional, prompted securely if omitted)")
    parser.add_argument("--full-name", default="SCOUT System Admin", help="Full name or operational display title")
    args = parser.parse_args()

    print("=" * 70)
    print("      SCOUT — Enterprise Cybersecurity Platform")
    print("      Initial Administrator Account Provisioning Tool")
    print("=" * 70)

    username = args.username
    if not username:
        username = input("Enter Admin Username: ").strip()

    email = args.email
    if not email:
        email = input("Enter Admin Email: ").strip()

    password = args.password
    if not password:
        while True:
            p1 = getpass.getpass("Enter Admin Password: ")
            p2 = getpass.getpass("Confirm Admin Password: ")
            if p1 != p2:
                print("❌ Passwords do not match. Please try again.\n")
                continue
            valid, msg = validate_password_strength(p1)
            if not valid:
                print(f"❌ {msg}\n")
                continue
            password = p1
            break

    success, message = create_admin_user(
        username=username,
        email=email,
        password=password,
        full_name=args.full_name
    )

    if success:
        print(f"\n✅ SUCCESS: {message}")
        print("   The Admin account can now access the administrative console and API.")
        print("=" * 70)
        sys.exit(0)
    else:
        print(f"\n❌ ERROR: {message}")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
