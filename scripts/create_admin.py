#!/usr/bin/env python3
"""
Create the first admin account for Zaiqa Point.

Usage:
    export SECRET_KEY='<long random string>'   # required by app.py
    export ADMIN_USERNAME='owner'
    export ADMIN_PASSWORD='<strong unique password, min 12 chars>'
    python scripts/create_admin.py

This is the ONLY supported way to create an admin account. Public
registration always creates customer accounts, and no default
credentials are seeded anywhere.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User  # noqa: E402  (import needs the path fix above)


def main():
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""

    if not username or not password:
        sys.exit("ERROR: set ADMIN_USERNAME and ADMIN_PASSWORD environment variables first.")
    if len(password) < 12:
        sys.exit("ERROR: ADMIN_PASSWORD must be at least 12 characters long.")

    with app.app_context():
        db.create_all()
        existing = User.query.filter_by(username=username).first()
        if existing:
            if existing.role == "admin":
                print(f"Admin '{username}' already exists. Nothing to do.")
            else:
                sys.exit(f"ERROR: a non-admin user named '{username}' already exists.")
            return

        admin = User(username=username, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Admin '{username}' created successfully.")


if __name__ == "__main__":
    main()
