from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-key")

# ---------------- DATABASE SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- DATABASE INITIALIZATION ----------------
def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            plan TEXT NOT NULL,
            amount INTEGER NOT NULL,
            balance INTEGER NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def init_payments_table():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            reference TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def create_default_admin():
    conn = get_db_connection()
    admin_email = "businessdatainstitute@gmail.com"

    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (admin_email,)
    ).fetchone()

    if not admin:
        conn.execute("""
            INSERT INTO users (
                first_name, last_name, email, phone,
                plan, amount, balance, password, is_admin
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Admin",
            "Lusenaka",
            admin_email,
            "254799104086",
            "premium",
            7500,
            7500,
            generate_password_hash("1111"),
            1
        ))
        conn.commit()

    conn.close()

# 🚨 MUST RUN ON IMPORT (RENDER SAFE)
init_db()
init_payments_table()
create_default_admin()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("plans"))

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        phone = request.form["phone"]
        plan = request.form["plan"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        if plan == "standard":
            amount = 5000
        elif plan == "premium":
            amount = 7500
        else:
            flash("Invalid plan selected", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO users
                (first_name, last_name, email, phone, plan, amount, balance, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                first_name,
                last_name,
                email,
                phone,
                plan,
                amount,
                amount,
                generate_password_hash(password)
            ))
            conn.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists", "danger")
        finally:
            conn.close()

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["is_admin"] = user["is_admin"]

            if user["is_admin"] == 1:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        flash("Invalid email or password", "danger")

    return render_template("login.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))

# ---------------- DASHBOARDS ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")

# ---------------- PAYMENTS ----------------
@app.route("/payments", methods=["GET", "POST"])
def payments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if request.method == "POST":
        amount = int(request.form["amount"])
        reference = request.form["reference"]

        if amount <= 0:
            flash("Invalid amount", "danger")
            return redirect(url_for("payments"))

        conn.execute("""
            INSERT INTO payments (user_id, amount, reference)
            VALUES (?, ?, ?)
        """, (user["id"], amount, reference))
        conn.commit()
        flash("Payment submitted for approval", "success")

    payments = conn.execute(
        "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    conn.close()

    return render_template("payments.html", user=user, payments=payments)

# ---------------- PLANS ----------------
@app.route("/plans")
def plans():
    return render_template("plans.html")

# ---------------- RUN LOCAL ONLY ----------------
if __name__ == "__main__":
    app.run(debug=True)
