# 🍽️ Zaiqa Point - Online Food Ordering System

Online Food Ordering System with Demand Prediction — Test Phase Prototype.
University project banaya gaya Python Flask, SQLite, aur Bootstrap se.

## 🚀 Features
- User Authentication (Admin & Customer roles)
- Admin Dashboard with order trends chart (Plotly)
- Menu Management (Add/Edit/Delete items)
- Customer Menu Browsing, Cart & Order Placement
- Order History tracking
- Auto database setup on first run

## 🛠️ Tech Stack
- **Backend:** Python (Flask)
- **Database:** SQLite (SQLAlchemy ORM)
- **Frontend:** HTML, CSS, Bootstrap 5
- **Visualization:** Plotly

## ⚙️ How to Run

```bash
pip install -r requirements.txt
cp .env.example .env
# Set SECRET_KEY before starting; load the variables in your shell or with your preferred env loader.
python app.py
```

## Secure setup

The application requires `SECRET_KEY` and runs with debug mode disabled by default. New registrations always create customer accounts. Create an administrator explicitly with a strong password:

```bash
SECRET_KEY="your-local-secret" \
ADMIN_USERNAME="admin" \
ADMIN_PASSWORD="use-a-long-unique-password" \
python scripts/create_admin.py
```

Do not commit `.env`, the SQLite database, or real credentials. This project is a prototype and should receive a production WSGI server, deployment configuration, and a full operational review before handling real customer data.
