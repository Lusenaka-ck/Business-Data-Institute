from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use environment SECRET_KEY (Render safe)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-dev-key")

# Use absolute path for SQLite (Render safe)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Users Table creation
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


# Payment Table creation
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


# default admin
def create_default_admin():
    conn = get_db_connection()

    admin_email = "businessdatainstitute@gmail.com"

    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (admin_email,)
    ).fetchone()

    if not admin:
        hashed_password = generate_password_hash("1111")

        conn.execute("""
            INSERT INTO users (
                first_name,
                last_name,
                email,
                phone,
                plan,
                amount,
                balance,
                password,
                is_admin
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Admin",
            "Lusenaka",
            admin_email,
            "254799104086",
            "premium",
            7500,
            7500,
            hashed_password,
            1
        ))
        conn.commit()

    conn.close()


# IMPORTANT: Run database setup on import (Render safe)
init_db()
init_payments_table()
create_default_admin()


# ---------------- HOME ROUTE ----------------
@app.route("/")
def home():
    return redirect(url_for("plans"))


# ---------------- REGISTER ROUTE ----------------
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

        balance = amount
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
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
                balance,
                hashed_password
            ))
            conn.commit()
            conn.close()

            flash("Registration successful now log in", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already exists", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


# ---------------- LOGIN ROUTE ----------------
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

            flash("Login successful", "success")

            # Admin vs User redirect
            if user["is_admin"] == 1:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))

        flash("Invalid email or password", "danger")

    return render_template("login.html")


# -------- Logout --------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))


# ---------------- DASHBOARD ROUTE ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")


# ADMIN DASHBOARD ROUTE
@app.route("/admin_dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("is_admin") != 1:
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")


# ADMIN PAYMENTS MANAGEMENT ROUTES
@app.route("/admin_payments")
def admin_payments():
    if "user_id" not in session or session.get("is_admin") != 1:
        return redirect(url_for("login"))

    conn = get_db_connection()
    payments = conn.execute("""
        SELECT payments.*, users.email
        FROM payments
        JOIN users ON users.id = payments.user_id
        ORDER BY payments.created_at DESC
    """).fetchall()
    conn.close()

    return render_template("admin_payments.html", payments=payments)


# Approve Payment
@app.route("/admin_payments/approve/<int:payment_id>")
def approve_payment(payment_id):
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))

    conn = get_db_connection()
    payment = conn.execute(
        "SELECT * FROM payments WHERE id = ?", (payment_id,)
    ).fetchone()

    if payment and payment["status"] != "approved":
        conn.execute(
            "UPDATE payments SET status='approved' WHERE id=?",
            (payment_id,)
        )
        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE id=?",
            (payment["amount"], payment["user_id"])
        )
        conn.commit()

    conn.close()
    return redirect(url_for("admin_payments"))


# Disapprove Payment
@app.route("/admin_payments/disapprove/<int:payment_id>")
def disapprove_payment(payment_id):
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))

    conn = get_db_connection()
    payment = conn.execute(
        "SELECT * FROM payments WHERE id = ?", (payment_id,)
    ).fetchone()

    if payment and payment["status"] == "approved":
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id=?",
            (payment["amount"], payment["user_id"])
        )

    conn.execute(
        "UPDATE payments SET status='disapproved' WHERE id=?",
        (payment_id,)
    )
    conn.commit()
    conn.close()

    return redirect(url_for("admin_payments"))


# ADMIN USERS MANAGEMENT ROUTES
@app.route("/admin_users")
def admin_users():
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))

    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    return render_template("admin_users.html", users=users)


# Add User
@app.route("/admin_users/add", methods=["POST"])
def add_user():
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))

    from werkzeug.security import generate_password_hash

    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    email = request.form["email"]
    phone = request.form["phone"]
    plan = request.form["plan"]
    password = generate_password_hash(request.form["password"])

    if plan == "standard":
        amount = 5000
    elif plan == "premium":
        amount = 7500
    else:
        flash("Invalid plan selected", "danger")
        return redirect(url_for("admin_users"))

    balance = amount

    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO users (first_name, last_name, email, phone, plan, amount, balance, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (first_name, last_name, email, phone, plan, amount, balance, password))
        conn.commit()
        flash("User added successfully", "success")
    except sqlite3.IntegrityError:
        flash("Email already exists", "danger")
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


# Delete User
@app.route("/admin_users/delete/<int:user_id>")
def delete_user(user_id):
    if session.get("is_admin") != 1:
        return redirect(url_for("login"))

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_users"))


# User profile
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    return render_template("profile.html", user=user)


# Payment route
@app.route("/payments", methods=["GET", "POST"])
def payments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        amount = int(request.form["amount"])
        reference = request.form["reference"]

        conn.execute("""
            INSERT INTO payments (user_id, amount, reference, status)
            VALUES (?, ?, ?, ?)
        """, (user["id"], amount, reference, "pending"))
        conn.commit()
        conn.close()

        flash("Payment submitted for approval", "success")
        return redirect(url_for("payments"))

    payments = conn.execute(
        "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    conn.close()

    return render_template("payments.html", user=user, payments=payments)


# Check user balance access
def check_balance_access(user):
    return user["balance"] <= (user["amount"] * 0.5)


@app.route('/plans')
def plans():
    return render_template('plans.html')


@app.route('/pastpapers')
def pastpapers():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    if not check_balance_access(user):
        flash("PAY ATLEAST 50% TO ACCESS SERVICES", "danger")
        return redirect(url_for("dashboard"))
    return render_template('pastpapers.html')


@app.route('/videos')
def videos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    if not check_balance_access(user):
        flash("PAY ATLEAST 50% TO ACCESS SERVICES", "danger")
        return redirect(url_for("dashboard"))
    return render_template('videos.html')


@app.route('/classes')
def classes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    if user["plan"] != "premium":
        flash("PREMIUM USERS ONLY", "danger")
        return redirect(url_for("dashboard"))

    if not check_balance_access(user):
        flash("PAY ATLEAST 50% TO ACCESS SERVICES", "danger")
        return redirect(url_for("dashboard"))

    return render_template('classes.html')


# Run the app
if __name__ == "__main__":
    init_db()
    create_default_admin()
    init_payments_table()
    app.run(debug=True)
