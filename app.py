"""
Online Food Ordering System with Demand Prediction
----------------------------------------------------
TEST PHASE PROTOTYPE

This file contains the full Flask backend for the test-phase prototype:
- User authentication (Admin / Customer roles)
- Menu management (CRUD for Admin)
- Cart + Order placement (Customer)
- Order history (Customer)
- Admin dashboard with a Plotly chart of "Most Ordered Items"
  (uses real order data once orders exist, falls back to seeded
  dummy data so the chart is never empty -- this is a placeholder
  for the real ML "Demand Prediction Module" that will replace it later)

Run with:
    pip install -r requirements.txt
    python app.py

The SQLite database (food_ordering.db) and all tables are created
automatically the first time the app runs (see init_db()).
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import plotly.graph_objects as go
import plotly.io as pio

# ----------------------------------------------------------------------
# App & Database Configuration
# ----------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "food_ordering.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


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
    # Photo shown on the menu card. Admin can paste any direct image link
    # (their own restaurant photo, or a stock photo URL). If left blank,
    # the template shows a tasteful gradient placeholder instead of a
    # broken image icon.
    image_url = db.Column(db.String(500), nullable=True)
    # Simple static rating used for the professional "real food app" look.
    # Not user-submitted yet -- a placeholder until a review system exists.
    rating = db.Column(db.Float, nullable=False, default=4.5)

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
        return User.query.get(session["user_id"])
    return None


# ----------------------------------------------------------------------
# Database initialization + dummy seed data
# ----------------------------------------------------------------------

def init_db():
    """Create all tables (if they don't exist) and seed placeholder data."""
    with app.app_context():
        db.create_all()

        # Seed a default admin account if no users exist yet
        if User.query.count() == 0:
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            customer = User(username="customer", role="customer")
            customer.set_password("customer123")
            db.session.add_all([admin, customer])
            db.session.commit()
            print("Seeded default users -> admin/admin123 , customer/customer123")

        # Seed a small dummy menu if empty
        # (image_url values are placeholder stock photos so the demo looks
        # like a real food-ordering app out of the box -- replace them with
        # your own restaurant's photos any time from Admin > Manage Menu)
        if MenuItem.query.count() == 0:
            dummy_items = [
                MenuItem(
                    name="Chicken Biryani", price=350, category="Main Course",
                    rating=4.7,
                    image_url="https://images.unsplash.com/photo-1589302168068-964664d93dc0?w=600&h=450&fit=crop",
                ),
                MenuItem(
                    name="Beef Burger", price=450, category="Fast Food",
                    rating=4.4,
                    image_url="https://images.unsplash.com/photo-1568901346375-23c9450c58cd?w=600&h=450&fit=crop",
                ),
                MenuItem(
                    name="Vegetable Pizza", price=900, category="Fast Food",
                    rating=4.6,
                    image_url="https://images.unsplash.com/photo-1513104890138-7c749659a591?w=600&h=450&fit=crop",
                ),
                MenuItem(
                    name="Chicken Karahi", price=1200, category="Main Course",
                    rating=4.8,
                    image_url="https://images.unsplash.com/photo-1585937421612-70a008356fa1?w=600&h=450&fit=crop",
                ),
                MenuItem(
                    name="Cold Coffee", price=250, category="Beverages",
                    rating=4.3,
                    image_url="https://images.unsplash.com/photo-1461023058943-07fcbe16d735?w=600&h=450&fit=crop",
                ),
                MenuItem(
                    name="French Fries", price=200, category="Sides",
                    rating=4.5,
                    image_url="https://images.unsplash.com/photo-1573080496219-bb080dd4f877?w=600&h=450&fit=crop",
                ),
            ]
            db.session.add_all(dummy_items)
            db.session.commit()
            print("Seeded dummy menu items.")

        # Seed a few dummy orders so the admin chart isn't empty on first run
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
    return redirect(url_for("customer_dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role", "customer")

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Choose another.", "danger")
            return redirect(url_for("register"))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("home"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
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
    items = MenuItem.query.all()
    categories = sorted({i.category for i in items})
    return render_template("menu.html", items=items, categories=categories)


@app.route("/cart/add/<int:item_id>", methods=["POST"])
@login_required
def add_to_cart(item_id):
    cart = session.get("cart", {})
    qty = int(request.form.get("quantity", 1))
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
        item = MenuItem.query.get(int(item_id_str))
        if item:
            subtotal = item.price * qty
            total += subtotal
            cart_items.append({"item": item, "qty": qty, "subtotal": subtotal})
    return render_template("cart.html", cart_items=cart_items, total=total)


@app.route("/cart/remove/<int:item_id>")
@login_required
def remove_from_cart(item_id):
    cart = session.get("cart", {})
    cart.pop(str(item_id), None)
    session["cart"] = cart
    session.modified = True
    return redirect(url_for("view_cart"))


@app.route("/cart/checkout", methods=["POST"])
@login_required
def checkout():
    cart = session.get("cart", {})
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("menu"))

    for item_id_str, qty in cart.items():
        order = Order(
            user_id=session["user_id"],
            item_id=int(item_id_str),
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


@app.route("/admin/menu/add", methods=["POST"])
@login_required
@admin_required
def admin_menu_add():
    name = request.form["name"].strip()
    price = float(request.form["price"])
    category = request.form["category"].strip()
    image_url = request.form.get("image_url", "").strip() or None
    rating = float(request.form.get("rating") or 4.5)

    item = MenuItem(name=name, price=price, category=category,
                     image_url=image_url, rating=rating)
    db.session.add(item)
    db.session.commit()
    flash("Menu item added.", "success")
    return redirect(url_for("admin_menu"))


@app.route("/admin/menu/edit/<int:item_id>", methods=["POST"])
@login_required
@admin_required
def admin_menu_edit(item_id):
    item = MenuItem.query.get_or_404(item_id)
    item.name = request.form["name"].strip()
    item.price = float(request.form["price"])
    item.category = request.form["category"].strip()
    item.image_url = request.form.get("image_url", "").strip() or None
    item.rating = float(request.form.get("rating") or item.rating)
    db.session.commit()
    flash("Menu item updated.", "success")
    return redirect(url_for("admin_menu"))


@app.route("/admin/menu/delete/<int:item_id>")
@login_required
@admin_required
def admin_menu_delete(item_id):
    item = MenuItem.query.get_or_404(item_id)
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
    app.run(debug=True)
