"""Basic security regression tests for Zaiqa Point.

Run with:  python -m unittest discover -s tests
Requires:  pip install -r requirements.txt   (and SECRET_KEY set)
"""
import os
import re
import unittest

os.environ.setdefault("SECRET_KEY", "test-only-secret-key")

from app import app, db, User, MenuItem  # noqa: E402


class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,  # focus on routing/auth, not token plumbing
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SESSION_COOKIE_SECURE=False,
        )
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    # -- helpers ---------------------------------------------------------
    def _register(self, username, password, **extra):
        data = {"username": username, "password": password}
        data.update(extra)
        return self.client.post("/register", data=data)

    def _login(self, username, password):
        return self.client.post(
            "/login", data={"username": username, "password": password}
        )

    def _make_admin(self, username="owner", password="supersecret123"):
        admin = User(username=username, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        return admin

    # -- 1. privilege escalation -----------------------------------------
    def test_register_forces_customer_role(self):
        """Even a crafted role=admin POST must create a customer."""
        self._register("mallory", "password123", role="admin")
        user = User.query.filter_by(username="mallory").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.role, "customer")

    def test_register_page_offers_no_admin_option(self):
        resp = self.client.get("/register")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b'value="admin"', resp.data)

    def test_register_rejects_short_password(self):
        self._register("shorty", "123")
        self.assertIsNone(User.query.filter_by(username="shorty").first())

    # -- 2/3. no default credentials --------------------------------------
    def test_no_default_credentials_seeded(self):
        from app import init_db
        init_db()
        for username, password in (("admin", "admin123"),
                                   ("customer", "customer123")):
            resp = self._login(username, password)
            self.assertIn(b"Invalid username or password", resp.data)

    # -- 4b. menu seeding: 3 dishes per category, dead Karahi photo repaired -
    def test_seed_menu_three_per_category(self):
        from app import init_db, BROKEN_KARAHI_URL
        init_db()
        items = MenuItem.query.all()
        self.assertEqual(len(items), 12)
        by_cat = {}
        for i in items:
            by_cat.setdefault(i.category, []).append(i)
        for cat in ("Beverages", "Fast Food", "Main Course", "Sides"):
            self.assertGreaterEqual(len(by_cat.get(cat, [])), 3, cat)
        karahi = MenuItem.query.filter_by(name="Chicken Karahi").first()
        self.assertNotEqual(karahi.image_url, BROKEN_KARAHI_URL)
        for i in items:
            self.assertTrue(i.image_url.startswith("https://"))

    def test_seed_is_idempotent_and_repairs_broken_karahi(self):
        from app import init_db, BROKEN_KARAHI_URL
        db.session.add(MenuItem(name="Chicken Karahi", price=1200,
                                category="Main Course", rating=4.8,
                                image_url=BROKEN_KARAHI_URL))
        db.session.commit()
        init_db()
        init_db()  # second run must not duplicate
        items = MenuItem.query.all()
        self.assertEqual(len(items), 12)
        karahi = MenuItem.query.filter_by(name="Chicken Karahi").first()
        self.assertNotEqual(karahi.image_url, BROKEN_KARAHI_URL)

    # -- 5. state-changing routes reject GET ------------------------------
    def test_logout_requires_post(self):
        self._register("u1", "password123")
        self._login("u1", "password123")
        resp = self.client.get("/logout")
        self.assertEqual(resp.status_code, 405)

    def test_cart_remove_requires_post(self):
        self._register("u2", "password123")
        self._login("u2", "password123")
        resp = self.client.get("/cart/remove/1")
        self.assertEqual(resp.status_code, 405)

    def test_admin_delete_requires_post(self):
        self._make_admin()
        self._login("owner", "supersecret123")
        resp = self.client.get("/admin/menu/delete/1")
        self.assertEqual(resp.status_code, 405)

    def test_admin_routes_require_admin_role(self):
        self._register("cust", "password123")
        self._login("cust", "password123")
        resp = self.client.get("/admin/menu", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)  # bounced to menu

    # -- 6. image_url scheme validation ------------------------------------
    def test_image_url_rejects_javascript_scheme(self):
        self._make_admin()
        self._login("owner", "supersecret123")
        self.client.post("/admin/menu/add", data={
            "name": "Evil Item", "price": "100", "category": "Test",
            "image_url": "javascript:alert(1)",
        })
        item = MenuItem.query.filter_by(name="Evil Item").first()
        self.assertIsNone(item)  # rejected, not stored

    def test_image_url_accepts_https(self):
        self._make_admin()
        self._login("owner", "supersecret123")
        self.client.post("/admin/menu/add", data={
            "name": "Good Item", "price": "100", "category": "Test",
            "image_url": "https://example.com/food.jpg",
        })
        item = MenuItem.query.filter_by(name="Good Item").first()
        self.assertIsNotNone(item)
        self.assertEqual(item.image_url, "https://example.com/food.jpg")

    # -- pro menu behaviour ----------------------------------------------
    def test_home_redirects_customer_to_menu(self):
        self._register("browse", "password123")
        self._login("browse", "password123")
        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/menu"))

    def test_menu_renders_pro_layout(self):
        self._register("viewer", "password123")
        self._login("viewer", "password123")
        html = self.client.get("/menu").get_data(as_text=True)
        self.assertIn("zp-dish", html)
        self.assertIn("zp-catbar", html)
        self.assertIn("zp-dish-search", html)
        self.assertIn("zp-search-btn", html)       # search button present
        self.assertIn('data-cat="__all"', html)    # "All" filter pill
        self.assertIn("data-cat=", html)           # per-category filter pills

    def test_decrease_route_steps_quantity_down(self):
        self._register("stepper", "password123")
        self._login("stepper", "password123")
        item = MenuItem(name="Stepper Biryani", price=350,
                        category="Main Course", rating=4.7)
        db.session.add(item)
        db.session.commit()
        self.client.post(f"/cart/add/{item.id}", data={"quantity": "2"})
        r = self.client.post(f"/cart/decrease/{item.id}",
                             follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        html = self.client.get("/menu").get_data(as_text=True)
        self.assertIn("zp-stepper-qty", html)
        # decrease to zero removes the item -> ADD button returns
        self.client.post(f"/cart/decrease/{item.id}")
        html = self.client.get("/menu").get_data(as_text=True)
        self.assertIn("zp-add-btn", html)

    def test_decrease_requires_post(self):
        resp = self.client.get("/cart/decrease/1")
        self.assertEqual(resp.status_code, 405)


class CsrfPlumbingTestCase(unittest.TestCase):
    """End-to-end form flow WITH CSRF enabled (the production default),
    proving the templates actually render and submit valid tokens.
    (SecurityTestCase disables CSRF to focus on routing/auth.)

    NOTE: setUp deliberately does NOT leave an app context pushed while
    requests run. A lingering pushed context makes all test-client
    requests share one app context (and one flask.g), so Flask-WTF's
    per-request token cache serves a stale token that was never stored
    in later requests' sessions -> false "CSRF session token is missing"
    failures. Real deployments always get a fresh app context per
    request, so the harness must too."""

    def setUp(self):
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=True,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SESSION_COOKIE_SECURE=False,
        )
        with app.app_context():
            db.drop_all()
            db.create_all()
            db.session.add(MenuItem(name="Test Biryani", price=350,
                                    category="Main Course", rating=4.5))
            db.session.commit()
            self._item_id = MenuItem.query.first().id
        self.client = app.test_client()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def _token_for(self, path):
        html = self.client.get(path).get_data(as_text=True)
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(m, f"no csrf hidden input rendered on {path}")
        return m.group(1)

    def test_register_login_add_to_cart_with_real_tokens(self):
        r = self.client.post("/register", data={
            "username": "e2e", "password": "password123",
            "csrf_token": self._token_for("/register")})
        self.assertEqual(r.status_code, 302)  # -> login page

        r = self.client.post("/login", data={
            "username": "e2e", "password": "password123",
            "csrf_token": self._token_for("/login")},
            follow_redirects=False)
        self.assertEqual(r.status_code, 302)  # logged in, redirected

        with app.app_context():
            item = MenuItem.query.first()
            item_id, item_name = item.id, item.name
        r = self.client.post(f"/cart/add/{item_id}", data={
            "quantity": "2", "csrf_token": self._token_for("/menu")})
        self.assertEqual(r.status_code, 302)
        html = self.client.get("/cart").get_data(as_text=True)
        self.assertIn(item_name, html)

    def test_post_without_token_is_rejected(self):
        r = self.client.post("/login",
                             data={"username": "x", "password": "y"})
        self.assertEqual(r.status_code, 400)

    def test_post_with_wrong_token_is_rejected(self):
        r = self.client.post("/login", data={
            "username": "x", "password": "y", "csrf_token": "bogus"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
