"""
Online Food Ordering System ("Zaiqa Point")
--------------------------------------------
Flask backend: user auth, menu CRUD (admin), cart + checkout, order
history, and an admin dashboard with a "Most Ordered Items" chart.

Security notes (hardened):
- SECRET_KEY comes from the environment; the app refuses to boot without it.
- Public registration can ONLY create customer accounts.
- No default/seeded credentials exist. Create the first admin with
  `scripts/create_admin.py` (reads ADMIN_USERNAME / ADMIN_PASSWORD from env).
- Debug mode is off unless FLASK_DEBUG=1 is set (local dev only).
- All state-changing routes require POST and are CSRF-protected (Flask-WTF).

Run locally:
    pip install -r requirements.txt
    export SECRET_KEY='<long random string>'
    python scripts/create_admin.py   # first admin account
    python app.py
"""

import os
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

import plotly.graph_objects as go
import plotly.io as pio

# ----------------------------------------------------------------------
# App & Database Configuration
# ----------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# The secret key signs session cookies. There is deliberately NO fallback
# default: booting without one would silently weaken every session.
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one (e.g. `python -c \"import secrets; print(secrets.token_hex(32))\"`) "
        "and export it before starting the app. See .env.example."
    )

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(BASE_DIR, "food_ordering.db"),
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Harden the session cookie. SESSION_COOKIE_SECURE can be disabled for plain
# local HTTP dev via SESSION_COOKIE_SECURE=0, but stays on by default.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # CSRF tokens required on every POST form


# ----------------------------------------------------------------------
# Database Models
# ----------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")  # 'admin' or 'customer'

    orders = db.relationship("Order", backref="customer", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class MenuItem(db.Model):
    __tablename__ = "menu_items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    # Photo shown on the menu card. Only http(s) URLs are accepted (see
    # _sanitize_image_url) so a stored `javascript:` URL can never execute.
    image_url = db.Column(db.String(500), nullable=True)
    rating = db.Column(db.Float, nullable=False, default=4.5)
    # Soft-retire flag: retired seed dishes are hidden from the customer
    # menu but kept for old orders (admin dashboard reads order.item).
    active = db.Column(db.Boolean, nullable=False, default=True,
                       server_default="1")

    order_items = db.relationship("Order", backref="item", lazy=True)


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("menu_items.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default="Placed")


# ----------------------------------------------------------------------
# Auth helpers (simple session-based auth, no external login lib needed)
# ----------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("menu"))
        return f(*args, **kwargs)
    return wrapped


def current_user():
    if "user_id" in session:
        return db.session.get(User, session["user_id"])
    return None


@app.context_processor
def inject_cart_count():
    """Navbar cart badge for logged-in customers (0 keeps the badge hidden)."""
    count = 0
    if session.get("role") == "customer":
        for raw_qty in session.get("cart", {}).values():
            count += _parse_int(raw_qty, default=0, minimum=0) or 0
    return {"cart_count": count}


# ----------------------------------------------------------------------
# Input validation helpers
# ----------------------------------------------------------------------

def _parse_int(value, default=None, minimum=None):
    """Parse an int from form input; return `default` when invalid."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and number < minimum:
        return default
    return number


def _parse_float(value, default=None, minimum=None, maximum=None):
    """Parse a float from form input; return `default` when invalid."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and number < minimum:
        return default
    if maximum is not None and number > maximum:
        return default
    return number


def _sanitize_image_url(raw_url):
    """
    Allow only http(s) image URLs. Returns the cleaned URL, or None when
    blank. Returns the sentinel False when a non-blank URL has a dangerous
    or unsupported scheme (so the caller can reject it loudly).
    """
    url = (raw_url or "").strip()
    if not url:
        return None
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        return False
    return url


# ----------------------------------------------------------------------
# Database initialization + dummy seed data
# ----------------------------------------------------------------------

# Canonical menu: 100% Pakistani dishes, every category has at least 3.
# (image_url values are placeholder stock photos so the demo looks
# like a real food-ordering app out of the box -- replace them with
# your own restaurant's photos any time from Admin > Manage Menu)
SEED_MENU_ITEMS = [
    dict(name="Chicken Biryani", price=350, category="Main Course", rating=4.7,
         image_url="https://images.unsplash.com/photo-1589302168068-964664d93dc0?w=600&h=450&fit=crop"),
    dict(name="Chicken Karahi", price=1200, category="Main Course", rating=4.8,
         image_url="https://forksandfigs.com/wp-content/uploads/2025/05/rich_flavorful_chicken_karahi_kb5hp.jpg"),
    dict(name="Beef Chapli Kebab", price=600, category="Main Course", rating=4.7,
         image_url="https://www.remitly.com/blog/wp-content/uploads/2024/08/Chapli-Kebab-pakistan-1024x730.jpg"),
    dict(name="BBQ Platter", price=1500, category="Main Course", rating=4.9,
         image_url="https://punjabimehfil.com/wp-content/uploads/2026/06/punjabimehfil-9-768x768.jpeg"),
    dict(name="Bun Kebab", price=250, category="Fast Food", rating=4.6,
         image_url="https://i0.wp.com/eathealthy365.com/wp-content/uploads/authentic-homemade-bun-kabab-recipe.webp?w=830&h=467&crop=1&quality=60&ssl=1"),
    dict(name="Chicken Shawarma", price=300, category="Fast Food", rating=4.5,
         image_url="https://framerusercontent.com/images/92eSB6xiJFZJjmChoR5OxKtCyAU.png?width=1024&height=1536"),
    dict(name="Chicken Paratha Roll", price=350, category="Fast Food", rating=4.7,
         image_url="https://pizzacottage.pro/images/chicken_pratha_roll_user.webp"),
    dict(name="Doodh Patti", price=120, category="Beverages", rating=4.6,
         image_url="https://www.jcookingodyssey.com/wp-content/uploads/2026/05/doodh-patti-chai-1.jpg"),
    dict(name="Mango Lassi", price=200, category="Beverages", rating=4.5,
         image_url="https://www.vegrecipesofindia.com/wp-content/uploads/2021/05/mango-lassi-recipe-2.jpg"),
    dict(name="Mint Margarita", price=180, category="Beverages", rating=4.4,
         image_url="https://www.acouplecooks.com/wp-content/uploads/2022/04/Mint-Lemonade-006.jpg"),
    dict(name="Samosa (2 pcs)", price=100, category="Sides", rating=4.5,
         image_url="https://www.eitanbernath.com/wp-content/uploads/2019/06/SAMOSA-538-LOW-RES-819x1024.jpg"),
    dict(name="Garlic Naan", price=80, category="Sides", rating=4.5,
         image_url="https://recipesize.com/wp-content/uploads/2026/06/u7196759841_Garlic_Naan_Bread_front_angle_shot_low_angle_shot_k_d9ba3362-74ca-41db-81de-f6ab62690012-768x768.webp"),
    dict(name="Masala Fries", price=250, category="Sides", rating=4.4,
         image_url="https://www.jcookingodyssey.com/wp-content/uploads/2021/09/masala-chips-blog-1.jpg"),
]

# Seed dishes retired from the canonical menu. The row is hidden (not
# deleted) so old orders still resolve, and only when it still matches the
# original seed values -- an admin-customized dish is never touched.
RETIRED_SEED_ITEMS = [
    dict(name="Cold Coffee", price=250, category="Beverages"),
    dict(name="Beef Burger", price=450, category="Fast Food"),
    dict(name="Vegetable Pizza", price=900, category="Fast Food"),
    dict(name="Chicken Zinger Burger", price=380, category="Fast Food"),
    dict(name="French Fries", price=200, category="Sides"),
]

# The old Chicken Karahi photo URL went dead (404). If a database still
# carries it, swap in the working one -- admin-uploaded photos are left alone.
BROKEN_KARAHI_URL = "https://images.unsplash.com/photo-1585937421612-70a008356fa1?w=600&h=450&fit=crop"


def init_db():
    """Create all tables (if they don't exist) and seed placeholder data.

    NOTE: no user accounts are seeded here. The first admin must be created
    explicitly via `scripts/create_admin.py`.
    """
    with app.app_context():
        db.create_all()

        # Migrate existing databases to the new `active` column (create_all
        # never adds columns to tables that already exist). Runs first, so
        # the seed/retire logic below can rely on the column being present.
        from sqlalchemy import inspect, text
        if "active" not in [c["name"] for c in
                            inspect(db.engine).get_columns("menu_items")]:
            with db.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE menu_items ADD COLUMN active BOOLEAN DEFAULT 1"))
            print("Migrated menu_items: added active column.")

        # Idempotent menu seeding: add any missing seed dishes (so redeploys
        # grow the menu on existing databases), retire dishes dropped from
        # the canonical menu, and repair the dead Karahi photo URL.
        # Admin-customized dishes are never touched.
        for spec in SEED_MENU_ITEMS:
            item = MenuItem.query.filter_by(name=spec["name"]).first()
            if item is None:
                db.session.add(MenuItem(**spec))
                print(f"Seeded menu item: {spec['name']}")
            elif item.image_url == BROKEN_KARAHI_URL:
                item.image_url = spec["image_url"]
                print("Repaired Chicken Karahi image URL.")
        # Retire seed dishes dropped from the canonical menu: hide them
        # (active=False) rather than deleting, so old orders still resolve.
        # Only rows that still match the original seed values are touched.
        for retired in RETIRED_SEED_ITEMS:
            stale = MenuItem.query.filter_by(**retired).first()
            if stale is not None and stale.active:
                stale.active = False
                print(f"Retired menu item: {retired['name']}")
        db.session.commit()


        # Seed a few dummy orders so the admin chart isn't empty on first run.
        # Only possible once at least one customer account exists.
        if Order.query.count() == 0:
            cust = User.query.filter_by(role="customer").first()
            items = MenuItem.query.all()
            if cust and items:
                dummy_orders = [
                    Order(user_id=cust.id, item_id=items[0].id, quantity=5),
                    Order(user_id=cust.id, item_id=items[1].id, quantity=3),
                    Order(user_id=cust.id, item_id=items[2].id, quantity=7),
                    Order(user_id=cust.id, item_id=items[3].id, quantity=2),
                    Order(user_id=cust.id, item_id=items[4].id, quantity=4),
                ]
                db.session.add_all(dummy_orders)
                db.session.commit()
                print("Seeded dummy orders (placeholder for demand-prediction data).")


# ----------------------------------------------------------------------
# Routes: Home / Auth
# ----------------------------------------------------------------------

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    # Customers land on the menu (browse) like professional food apps.
    return redirect(url_for("menu"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Public registration can ONLY create customer accounts. Any
        # client-supplied "role" field is deliberately ignored so privilege
        # escalation via crafted POST data is impossible.
        if not username:
            flash("Username is required.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Choose another.", "danger")
            return redirect(url_for("register"))

        user = User(username=username, role="customer")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # Clear any pre-existing session first (session fixation defense)
            # before issuing the authenticated session.
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("home"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Routes: Menu (browse) + Cart + Checkout  (Customer facing)
# ----------------------------------------------------------------------

@app.route("/menu")
@login_required
def menu():
    items = MenuItem.query.filter_by(active=True).all()
    categories = sorted({i.category for i in items})
    # Cart summary for the menu page: per-item quantities (for ADD steppers)
    # plus the sticky cart bar totals.
    price_map = {i.id: i.price for i in items}
    cart = session.get("cart", {})
    cart_qty, cart_count, cart_total = {}, 0, 0
    for key, raw_qty in cart.items():
        try:
            item_id = int(key)
        except (TypeError, ValueError):
            continue
        qty = _parse_int(raw_qty, default=0, minimum=1)
        if not qty or item_id not in price_map:
            continue
        cart_qty[item_id] = qty
        cart_count += qty
        cart_total += price_map[item_id] * qty
    avg_rating = round(sum(i.rating for i in items) / len(items), 1) if items else 0
    return render_template("menu.html", items=items, categories=categories,
                           cart_qty=cart_qty, cart_count=cart_count,
                           cart_total=cart_total, avg_rating=avg_rating)


@app.route("/cart/add/<int:item_id>", methods=["POST"])
@login_required
def add_to_cart(item_id):
    item = db.session.get(MenuItem, item_id)
    if item is None or not item.active:
        abort(404)
    qty = _parse_int(request.form.get("quantity"), default=1, minimum=1)
    cart = session.get("cart", {})
    cart[str(item_id)] = cart.get(str(item_id), 0) + qty
    session["cart"] = cart
    session.modified = True
    flash("Item added to cart.", "success")
    return redirect(url_for("menu"))


@app.route("/cart")
@login_required
def view_cart():
    cart = session.get("cart", {})
    cart_items = []
    total = 0
    for item_id_str, qty in cart.items():
        try:
            item_id = int(item_id_str)
        except (TypeError, ValueError):
            continue
        item = db.session.get(MenuItem, item_id)
        if item:
            qty = _parse_int(qty, default=0, minimum=1)
            if not qty:
                continue
            subtotal = item.price * qty
            total += subtotal
            cart_items.append({"item": item, "qty": qty, "subtotal": subtotal})
    return render_template("cart.html", cart_items=cart_items, total=total)


@app.route("/cart/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_from_cart(item_id):
    cart = session.get("cart", {})
    cart.pop(str(item_id), None)
    session["cart"] = cart
    session.modified = True
    return redirect(url_for("view_cart"))


@app.route("/cart/decrease/<int:item_id>", methods=["POST"])
@login_required
def decrease_in_cart(item_id):
    """Step the menu-page quantity stepper down by one (removes at zero)."""
    cart = session.get("cart", {})
    key = str(item_id)
    qty = _parse_int(cart.get(key), default=0, minimum=1)
    if qty <= 1:
        cart.pop(key, None)
    else:
        cart[key] = qty - 1
    session["cart"] = cart
    session.modified = True
    return redirect(url_for("menu"))


@app.route("/cart/checkout", methods=["POST"])
@login_required
def checkout():
    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("menu"))

    for item_id_str, qty in cart.items():
        try:
            item_id = int(item_id_str)
        except (TypeError, ValueError):
            continue
        qty = _parse_int(qty, default=0, minimum=1)
        if not qty or db.session.get(MenuItem, item_id) is None:
            continue
        order = Order(
            user_id=session["user_id"],
            item_id=item_id,
            quantity=qty,
            status="Placed",
        )
        db.session.add(order)
    db.session.commit()

    session["cart"] = {}
    flash("Order placed successfully!", "success")
    return redirect(url_for("customer_dashboard"))


# ----------------------------------------------------------------------
# Routes: Customer Dashboard
# ----------------------------------------------------------------------

@app.route("/dashboard/customer")
@login_required
def customer_dashboard():
    orders = (
        Order.query.filter_by(user_id=session["user_id"])
        .order_by(Order.order_date.desc())
        .all()
    )
    return render_template("customer_dashboard.html", orders=orders)


# ----------------------------------------------------------------------
# Routes: Admin Dashboard (with Plotly chart)
# ----------------------------------------------------------------------

@app.route("/dashboard/admin")
@login_required
@admin_required
def admin_dashboard():
    all_orders = Order.query.order_by(Order.order_date.desc()).all()
    total_orders = len(all_orders)
    total_revenue = sum(o.item.price * o.quantity for o in all_orders)

    # Aggregate quantity sold per menu item -> "Most Ordered Items"
    # NOTE: This is a simple aggregation used as a placeholder.
    # The real Demand Prediction Module (Scikit-learn) will replace
    # this with a trained model in a later phase.
    totals = {}
    for o in all_orders:
        totals[o.item.name] = totals.get(o.item.name, 0) + o.quantity

    if totals:
        names = list(totals.keys())
        quantities = list(totals.values())
    else:
        # Fallback dummy data so the chart never renders empty
        names = ["Chicken Biryani", "Beef Burger", "Vegetable Pizza"]
        quantities = [5, 3, 7]

    fig = go.Figure(data=[go.Bar(x=names, y=quantities, marker_color="#0d6efd")])
    fig.update_layout(
        title="Most Ordered Items (placeholder for ML Demand Prediction)",
        xaxis_title="Food Item",
        yaxis_title="Quantity Ordered",
        template="plotly_white",
        margin=dict(l=40, r=20, t=60, b=40),
    )
    chart_html = pio.to_html(fig, full_html=False, include_plotlyjs="cdn")

    return render_template(
        "admin_dashboard.html",
        orders=all_orders,
        total_orders=total_orders,
        total_revenue=total_revenue,
        chart_html=chart_html,
    )


# ----------------------------------------------------------------------
# Routes: Admin Menu Management (CRUD)
# ----------------------------------------------------------------------

@app.route("/admin/menu")
@login_required
@admin_required
def admin_menu():
    items = MenuItem.query.all()
    return render_template("admin_menu.html", items=items)


def _menu_item_from_form():
    """Validate admin menu form input. Returns (fields, error_message)."""
    name = (request.form.get("name") or "").strip()
    category = (request.form.get("category") or "").strip()
    price = _parse_float(request.form.get("price"), minimum=0.01)
    rating = _parse_float(request.form.get("rating") or 4.5, default=4.5,
                          minimum=0, maximum=5)
    image_url = _sanitize_image_url(request.form.get("image_url"))

    if not name:
        return None, "Item name is required."
    if not category:
        return None, "Category is required."
    if price is None:
        return None, "Price must be a positive number."
    if rating is None:
        return None, "Rating must be between 0 and 5."
    if image_url is False:
        return None, "Image URL must start with http:// or https://."

    return (
        {"name": name, "price": price, "category": category,
         "image_url": image_url, "rating": rating},
        None,
    )


@app.route("/admin/menu/add", methods=["POST"])
@login_required
@admin_required
def admin_menu_add():
    fields, error = _menu_item_from_form()
    if error:
        flash(error, "danger")
        return redirect(url_for("admin_menu"))

    item = MenuItem(**fields)
    db.session.add(item)
    db.session.commit()
    flash("Menu item added.", "success")
    return redirect(url_for("admin_menu"))


@app.route("/admin/menu/edit/<int:item_id>", methods=["POST"])
@login_required
@admin_required
def admin_menu_edit(item_id):
    item = db.session.get(MenuItem, item_id)
    if item is None:
        abort(404)
    fields, error = _menu_item_from_form()
    if error:
        flash(error, "danger")
        return redirect(url_for("admin_menu"))

    for key, value in fields.items():
        setattr(item, key, value)
    db.session.commit()
    flash("Menu item updated.", "success")
    return redirect(url_for("admin_menu"))


@app.route("/admin/menu/delete/<int:item_id>", methods=["POST"])
@login_required
@admin_required
def admin_menu_delete(item_id):
    item = db.session.get(MenuItem, item_id)
    if item is None:
        abort(404)
    db.session.delete(item)
    db.session.commit()
    flash("Menu item deleted.", "info")
    return redirect(url_for("admin_menu"))


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template("admin_orders.html", orders=orders)


# ----------------------------------------------------------------------
# Context processor - make current_user available in all templates
# ----------------------------------------------------------------------

@app.context_processor
def inject_user():
    return dict(current_user=current_user(), brand_name="Zaiqa Point")


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # Debug mode is OFF by default. Enable only for local development with
    # FLASK_DEBUG=1 -- never in production.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug)
