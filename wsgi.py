"""Production WSGI entry point for Zaiqa Point.

Used by gunicorn on Render: ``gunicorn wsgi:app``.
Local development still uses ``python app.py``.
"""

from app import app, init_db

# Make sure tables + demo menu exist before serving traffic.
# init_db() is idempotent: it only creates missing tables and seeds
# the demo menu when the database is empty.
init_db()

__all__ = ["app"]
