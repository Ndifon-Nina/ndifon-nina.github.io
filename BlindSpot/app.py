import os
import secrets
from datetime import datetime, timedelta, UTC
from functools import wraps

import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
import database
from scanner.https_check import check_https
from scanner.headers_check import check_headers
from scanner.exposure_check import check_exposure
from scanner.directory_check import check_directory_listing
from scanner.cookie_check import check_cookies
from scanner.leakage_check import check_error_leakage

SEVERITY_PENALTY = {"HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}

# Each check needs the homepage response, which we fetch once per scan and
# hand to every check that needs it — instead of every check re-fetching
# the homepage itself.
CHECKS = [
    check_https,
    check_headers,
    check_exposure,
    check_directory_listing,
    check_cookies,
    check_error_leakage,
]


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(os.path.join(os.path.dirname(__file__), "instance"), exist_ok=True)

    csrf = CSRFProtect(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])

    with app.app_context():
        database.init_db()
    app.teardown_appcontext(database.close_db)

    # ---------- Self-hardening: BlindSpot practices what it scans for ----------
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    def current_user():
        user_id = session.get("user_id")
        return database.get_user_by_id(user_id) if user_id else None

    @app.context_processor
    def inject_user():
        return {"logged_in_user": current_user()}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def admin_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in first.")
                return redirect(url_for("login"))
            if user["role"] != "ADMIN":
                flash("You don't have permission to view that page.")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped

    def normalize_url(raw_url):
        raw_url = raw_url.strip()
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "https://" + raw_url
        return raw_url

    def run_all_checks(target_url):
        """Fetch the homepage once, then run every check against it."""
        try:
            homepage_response = requests.get(target_url, timeout=8)
        except requests.exceptions.RequestException:
            return None

        findings = []
        for check in CHECKS:
            findings.extend(check(target_url, homepage_response))
        return findings

    def calculate_score(findings):
        score = 100
        for finding in findings:
            score -= SEVERITY_PENALTY.get(finding["severity"], 0)
        return max(score, 0)

    # ---------- Public pages ----------

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/how-it-works")
    def how_it_works():
        return render_template("how_it_works.html")

    @app.route("/security-tips")
    def security_tips():
        return render_template("tips.html")

    # ---------- Auth ----------

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not name or not email or not password:
                flash("Please fill in every field.")
            elif "@" not in email or "." not in email:
                flash("Please enter a valid email address.")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.")
            elif password != confirm:
                flash("Passwords do not match.")
            elif database.get_user_by_email(email):
                flash("An account with that email already exists.")
            else:
                database.create_user(name, email, password)
                flash("Account created. You can log in now.")
                return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            user = database.get_user_by_email(email)
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                flash(f"Welcome back, {user['name']}.")
                return redirect(url_for("dashboard"))

            flash("Incorrect email or password.")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for("home"))

    # ---------- Password reset ----------

    @app.route("/forgot-password", methods=["GET", "POST"])
    @limiter.limit("5 per hour")
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = database.get_user_by_email(email)

            if user:
                token = secrets.token_urlsafe(32)
                expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
                database.create_reset_token(user["id"], token, expires_at)
                reset_link = url_for("reset_password", token=token, _external=True)
                # No email server is set up yet, so the link is shown directly
                # for now — swap this for a real email send in production.
                flash(f"Reset link (would normally be emailed): {reset_link}")
            else:
                flash("If that email has an account, a reset link has been generated.")

            return redirect(url_for("forgot_password"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        record = database.get_reset_token(token)

        if not record or record["used"]:
            flash("That reset link is invalid or has already been used.")
            return redirect(url_for("forgot_password"))

        if datetime.now(UTC) > datetime.fromisoformat(record["expires_at"]):
            flash("That reset link has expired. Please request a new one.")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            new_password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if len(new_password) < 8:
                flash("Password must be at least 8 characters.")
            elif new_password != confirm:
                flash("Passwords do not match.")
            else:
                database.update_password(record["user_id"], new_password)
                database.mark_reset_token_used(token)
                flash("Password updated. You can log in now.")
                return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    # ---------- Dashboard / Scanning ----------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        recent_scans = database.get_scans_for_user(user["id"], limit=5)
        return render_template("dashboard.html", user=user, recent_scans=recent_scans)

    @app.route("/scan", methods=["GET", "POST"])
    @limiter.limit("10 per hour")
    def scan():
        if request.method == "GET":
            return redirect(url_for("home"))

        raw_url = request.form.get("website_url", "")
        permitted = request.form.get("permission_confirmed") == "on" or request.form.get("permission") == "yes"

        if not raw_url.strip():
            flash("Please enter a website URL.")
            return redirect(url_for("home"))

        if not permitted:
            flash("You must confirm you own or have permission to test this website.")
            return redirect(url_for("home"))

        target_url = normalize_url(raw_url)
        findings = run_all_checks(target_url)

        if findings is None:
            flash("BlindSpot couldn't reach that website. Please check the URL and try again.")
            return redirect(url_for("home"))

        score = calculate_score(findings)
        user = current_user()
        scan_id = database.create_scan(user["id"] if user else None, target_url, score)
        for f in findings:
            database.add_finding(scan_id, f["check_type"], f["severity"], f["title"],
                                  f["description"], f["recommendation"])

        return redirect(url_for("results", scan_id=scan_id))

    @app.route("/results/<int:scan_id>")
    def results(scan_id):
        scan_record = database.get_scan(scan_id)
        if not scan_record:
            flash("Scan not found.")
            return redirect(url_for("home"))

        user = current_user()
        is_owner = user and user["id"] == scan_record["user_id"]
        is_admin = user and user["role"] == "ADMIN"
        if scan_record["user_id"] is not None and not is_owner and not is_admin:
            flash("You don't have permission to view that scan.")
            return redirect(url_for("home"))

        findings = database.get_findings_for_scan(scan_id)
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in findings if f["severity"] == "LOW")
        return render_template("results.html", scan=scan_record, findings=findings,
                                high=high, medium=medium, low=low)

    @app.route("/history")
    @login_required
    def history():
        user = current_user()
        scans = database.get_scans_for_user(user["id"])
        return render_template("history.html", scans=scans)

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html", user=current_user())

    # ---------- Admin ----------

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        stats = {
            "users": database.count_users(),
            "scans": database.count_scans(),
            "findings": database.count_findings(),
        }
        return render_template("admin/dashboard.html", stats=stats)

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        return render_template("admin/users.html", users=database.get_all_users())

    @app.route("/admin/scans")
    @admin_required
    def admin_scans():
        return render_template("admin/scans.html", scans=database.get_all_scans())

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=Config.PORT, debug=Config.DEBUG)
