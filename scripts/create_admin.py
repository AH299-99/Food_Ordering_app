"""Create or update an administrator using explicit environment variables.

Run with SECRET_KEY, ADMIN_USERNAME, and ADMIN_PASSWORD set in the environment.
This script never uses a built-in default password.
"""

import os
import sys

from werkzeug.security import generate_password_hash

from app import User, app, db

username = os.environ.get("ADMIN_USERNAME", "").strip()
password = os.environ.get("ADMIN_PASSWORD", "")

if not username or len(password) < 12:
    raise SystemExit("Set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters")

with app.app_context():
    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username, role="admin")
        db.session.add(user)
    user.role = "admin"
    user.password_hash = generate_password_hash(password)
    db.session.commit()
    print(f"Administrator ready: {username}")
