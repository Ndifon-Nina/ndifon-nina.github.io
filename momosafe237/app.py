from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import re
import time
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from content import SAFETY_TIPS, ALREADY_SCAMMED_STEPS

app = Flask(__name__)

# Make a secret key for the app so logins stay secure.
# We save it to a file so it doesn't change every time we restart.
SECRET_KEY_FILE = "secret_key.txt"

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "r") as f:
        app.secret_key = f.read().strip()
else:
    new_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(new_key)
    app.secret_key = new_key

DB_NAME = "database.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
MAX_FILE_SIZE = 3 * 1024 * 1024  # 3 MB
ADMIN_CONTACT_EMAIL = "momosafe237@example.com"  # change to your real email

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.config["SESSION_COOKIE_HTTPONLY"] = True  # JS can't read the login cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # extra login cookie safety

# Protects our forms from being submitted by other websites without
# the user knowing (CSRF attacks).
csrf = CSRFProtect(app)

# Keeps track of failed admin logins so someone can't just keep
# guessing the password. After 5 wrong tries, wait 5 minutes.
failed_login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60


def is_locked_out(ip):
    record = failed_login_attempts.get(ip)
    if not record:
        return False
    count, first_time = record
    if count < MAX_ATTEMPTS:
        return False
    if time.time() - first_time > LOCKOUT_SECONDS:
        failed_login_attempts.pop(ip, None)
        return False
    return True


def record_failed_login(ip):
    count, first_time = failed_login_attempts.get(ip, (0, time.time()))
    failed_login_attempts[ip] = (count + 1, first_time)


def clear_failed_logins(ip):
    failed_login_attempts.pop(ip, None)


# A few extra headers to make the browser behave more safely.
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def is_valid_phone(number):
    # digits only, reasonable length
    return bool(re.fullmatch(r"\d{6,15}", number))


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # so we can use column names like row["name"]
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS numbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            scam_type TEXT,
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            verified_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            scam_type TEXT NOT NULL,
            description TEXT,
            evidence_filename TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS disputes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_filename TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        )
    """)

    # make a default admin account if there isn't one yet
    c.execute("SELECT COUNT(*) FROM admin")
    if c.fetchone()[0] == 0:
        default_password_hash = generate_password_hash("changeme123")
        c.execute(
            "INSERT INTO admin (username, password_hash) VALUES (?, ?)",
            ("admin", default_password_hash),
        )

    conn.commit()
    conn.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def mask_number(number):
    # turns 677123456 into 677***456 for public listings
    if len(number) <= 6:
        return number
    return number[:3] + "***" + number[-3:]


# keywords the message checker looks for, in English and French
WARNING_CATEGORIES = {
    "Urgency": [
        "urgent", "immediately", "act now", "quickly", "within 10 minutes", "hurry",
        "immediatement", "agissez maintenant", "delai limite", "de toute urgence",
    ],
    "Request for PIN": [
        "pin", "password", "secret code",
        "code secret", "mot de passe",
    ],
    "Request for OTP/code": [
        "otp", "verification code", "one time code", "one-time code",
        "code de verification",
    ],
    "USSD instruction": ["dial", "*123#", "ussd", "*", "composez"],
    "Money request": [
        "send money", "transfer", "refund", "payment",
        "envoyez de l'argent", "virement", "remboursement",
    ],
    "Prize / reward": [
        "winner", "prize", "reward", "congratulations",
        "felicitations", "vous avez gagne", "gagnant", "loterie",
    ],
    "Account threat": [
        "account blocked", "account suspended", "account closed",
        "compte sera bloque", "compte suspendu",
    ],
    "Suspicious link": [
        "http://", "bit.ly", "tinyurl", "t.co", "wa.me", "ngrok",
    ],
    "Wrong transfer / send-back request": [
        "accidentally sent", "sent by mistake", "send it back", "sent to your phone by mistake",
        "wrong number", "return the money",
        "envoye par erreur", "envoyé par erreur", "renvoyez l'argent", "mauvais numero",
    ],
    "Fake customs / package delivery fee": [
        # Your international package is held at customs. A clearance fee of 3,500 FCFA
        # is required for home delivery. Pay via this link: [link]
        "held at customs", "customs", "clearance fee", "international package",
        "home delivery", "delivery fee", "package is held", "customs fee",
        "3,500 fcfa", "3500 fcfa", "clearance", "retenu a la douane", "douane",
        "taxe de livraison", "frais de douane", "colis international", "livraison a domicile",
    ],
}


def analyze_message(message):
    # look through the message for each keyword, and add up a score
    text = message.lower()
    found = []
    for category, keywords in WARNING_CATEGORIES.items():
        for kw in keywords:
            if kw in text:
                found.append(category)
                break

    score = min(len(found) * 20, 100)  # each category found = +20 points

    if score >= 60:
        verdict = "high"
    elif score >= 20:
        verdict = "medium"
    else:
        verdict = "low"

    return {"warnings": found, "score": score, "verdict": verdict}


# ----- PUBLIC PAGES -----

@app.route("/")
def home():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM numbers")
    reported_numbers = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM numbers WHERE status = 'confirmed'")
    confirmed_scams = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM reports")
    total_reports = c.fetchone()[0]

    # Get the 5 most recently reported numbers for the homepage feed
    c.execute("SELECT * FROM numbers ORDER BY created_at DESC LIMIT 5")
    recent_reports = c.fetchall()

    conn.close()

    return render_template(
        "index.html",
        reported_numbers=reported_numbers,
        confirmed_scams=confirmed_scams,
        total_reports=total_reports,
        recent_reports=recent_reports,
        mask_number=mask_number,
    )


@app.route("/check-number", methods=["GET", "POST"])
def check_number():
    if request.method == "POST":
        number = request.form.get("phone_number", "").strip()
        if not is_valid_phone(number):
            flash("Please enter a valid phone number (digits only).")
            return redirect(url_for("check_number"))
        return redirect(url_for("number_result", number=number))
    return render_template("check_number.html")


@app.route("/number-result")
def number_result():
    number = request.args.get("number", "").strip()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM numbers WHERE phone_number = ?", (number,))
    record = c.fetchone()
    conn.close()

    return render_template("number_result.html", number=number, record=record, admin_email=ADMIN_CONTACT_EMAIL)


@app.route("/check-message", methods=["GET", "POST"])
def check_message():
    if request.method == "POST":
        message = request.form.get("message", "")
        result = analyze_message(message)
        session["last_checked_message"] = message  # so the Report link can use it
        return render_template("message_result.html", message=message, result=result)
    return render_template("check_message.html")


@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "POST":
        number = request.form.get("phone_number", "").strip()
        scam_type = request.form.get("scam_type", "").strip()
        description = request.form.get("description", "").strip()

        if not number or not scam_type:
            flash("Phone number and scam type are required.")
            return redirect(url_for("report"))

        if not is_valid_phone(number):
            flash("Please enter a valid phone number (digits only).")
            return redirect(url_for("report"))

        evidence_filename = None
        file = request.files.get("evidence")
        if file and file.filename:
            if allowed_file(file.filename):
                evidence_filename = secure_filename(
                    f"{datetime.now().timestamp()}_{file.filename}"
                )
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], evidence_filename))
            else:
                flash("Only .png, .jpg, or .jpeg files are allowed for evidence.")
                return redirect(url_for("report"))

        conn = get_db()
        c = conn.cursor()

        # Save the report itself
        c.execute(
            """INSERT INTO reports (phone_number, scam_type, description, evidence_filename, status, created_at)
               VALUES (?, ?, ?, ?, 'pending', ?)""",
            (number, scam_type, description, evidence_filename, datetime.now().isoformat()),
        )

        # Make sure the number exists in the "numbers" table too
        c.execute("SELECT * FROM numbers WHERE phone_number = ?", (number,))
        existing = c.fetchone()
        if existing:
            c.execute(
                "UPDATE numbers SET report_count = report_count + 1 WHERE phone_number = ?",
                (number,),
            )
        else:
            c.execute(
                """INSERT INTO numbers (phone_number, status, scam_type, report_count, created_at)
                   VALUES (?, 'pending', ?, 1, ?)""",
                (number, scam_type, datetime.now().isoformat()),
            )

        conn.commit()
        conn.close()

        return redirect(url_for("success"))

    prefill_number = request.args.get("number", "").strip()
    prefill_description = session.pop("last_checked_message", "")
    return render_template("report.html", prefill_number=prefill_number, prefill_description=prefill_description)


@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/dispute", methods=["GET", "POST"])
def dispute():
    if request.method == "POST":
        number = request.form.get("phone", "").strip()
        reason = request.form.get("reason", "").strip()

        if not number or not reason:
            flash("Phone number and reason are required.")
            return redirect(url_for("dispute", number=number))

        if not is_valid_phone(number):
            flash("Please enter a valid phone number (digits only).")
            return redirect(url_for("dispute"))

        evidence_filename = None
        file = request.files.get("evidence")
        if file and file.filename:
            if allowed_file(file.filename):
                evidence_filename = secure_filename(
                    f"{datetime.now().timestamp()}_{file.filename}"
                )
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], evidence_filename))
            else:
                flash("Only .png, .jpg, or .jpeg files are allowed for evidence.")
                return redirect(url_for("dispute", number=number))

        conn = get_db()
        c = conn.cursor()
        c.execute(
            """INSERT INTO disputes (phone_number, reason, evidence_filename, status, created_at)
               VALUES (?, ?, ?, 'pending', ?)""",
            (number, reason, evidence_filename, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

        return render_template("dispute_success.html")

    prefill_number = request.args.get("number", "").strip()
    return render_template("dispute.html", prefill_number=prefill_number)


@app.route("/reported-numbers")
def reported_numbers():
    search = request.args.get("search", "").strip()

    conn = get_db()
    c = conn.cursor()
    if search:
        c.execute("SELECT * FROM numbers WHERE phone_number LIKE ? ORDER BY report_count DESC", (f"%{search}%",))
    else:
        c.execute("SELECT * FROM numbers ORDER BY report_count DESC")
    numbers = c.fetchall()
    conn.close()

    return render_template("reported_numbers.html", numbers=numbers, mask_number=mask_number, search=search)


@app.route("/safety-tips")
def safety_tips():
    return render_template("safety.html", tips=SAFETY_TIPS["en"])


@app.route("/already-scammed")
def already_scammed():
    return render_template("already_scammed.html", steps=ALREADY_SCAMMED_STEPS["en"])


# ----- ADMIN PAGES -----

def admin_logged_in():
    return session.get("admin_logged_in", False)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    ip = request.remote_addr or "unknown"

    if request.method == "POST":
        if is_locked_out(ip):
            flash("Too many failed attempts. Please wait 5 minutes before trying again.")
            return redirect(url_for("admin_login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM admin WHERE username = ?", (username,))
        admin = c.fetchone()
        conn.close()

        if admin and check_password_hash(admin["password_hash"], password):
            clear_failed_logins(ip)
            session["admin_logged_in"] = True
            session["admin_username"] = username
            return redirect(url_for("admin_dashboard"))
        else:
            record_failed_login(ip)
            flash("Invalid username or password.")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE status = 'pending' ORDER BY created_at DESC")
    pending_reports = c.fetchall()

    c.execute("SELECT * FROM disputes WHERE status = 'pending' ORDER BY created_at DESC")
    pending_disputes = c.fetchall()

    c.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'")
    pending_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM numbers WHERE status = 'confirmed'")
    confirmed_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM reports")
    total_count = c.fetchone()[0]
    conn.close()

    return render_template(
        "admin_dashboard.html",
        reports=pending_reports,
        disputes=pending_disputes,
        pending_count=pending_count,
        confirmed_count=confirmed_count,
        total_count=total_count,
    )


@app.route("/admin/verify/<int:report_id>")
def admin_verify(report_id):
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    rep = c.fetchone()

    if rep:
        c.execute("UPDATE reports SET status = 'verified' WHERE id = ?", (report_id,))
        c.execute(
            "UPDATE numbers SET status = 'confirmed', verified_at = ? WHERE phone_number = ?",
            (datetime.now().isoformat(), rep["phone_number"]),
        )
        conn.commit()

    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reject/<int:report_id>")
def admin_reject(report_id):
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE reports SET status = 'rejected' WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dispute-approve/<int:dispute_id>")
def admin_dispute_approve(dispute_id):
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,))
    disp = c.fetchone()

    if disp:
        # if the dispute is approved, the number goes back to
        # "pending" so it isn't shown as confirmed anymore
        c.execute(
            "UPDATE numbers SET status = 'pending', verified_at = NULL WHERE phone_number = ?",
            (disp["phone_number"],),
        )
        c.execute("UPDATE disputes SET status = 'approved' WHERE id = ?", (dispute_id,))
        conn.commit()

    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dispute-reject/<int:dispute_id>")
def admin_dispute_reject(dispute_id):
    if not admin_logged_in():
        return redirect(url_for("admin_login"))

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE disputes SET status = 'rejected' WHERE id = ?", (dispute_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


# show a nicer page instead of Flask's plain error screen
@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html", code=404, message="That page doesn't exist."), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", code=500, message="Something went wrong on our side. Please try again."), 500


if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    init_db()
    app.run(debug=True, port=5050)
