import sqlite3
from datetime import datetime, UTC

from flask import g, current_app
from werkzeug.security import generate_password_hash


def get_db():
    """One database connection per request, reused across the request."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            website_url TEXT NOT NULL,
            score INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            check_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    """)
    db.commit()


# ---------- Users ----------

def create_user(name, email, password, role="USER"):
    db = get_db()
    db.execute(
        "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (name, email, generate_password_hash(password), role),
    )
    db.commit()


def get_user_by_email(email):
    return get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def count_users():
    return get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_all_users():
    return get_db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()


def update_password(user_id, new_password):
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id),
    )
    db.commit()


def promote_to_admin(email):
    """Used by make_admin.py — not exposed as a web route."""
    db = get_db()
    db.execute("UPDATE users SET role = 'ADMIN' WHERE email = ?", (email,))
    db.commit()


# ---------- Scans & Findings ----------

def create_scan(user_id, website_url, score):
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (user_id, website_url, score) VALUES (?, ?, ?)",
        (user_id, website_url, score),
    )
    db.commit()
    return cur.lastrowid


def add_finding(scan_id, check_type, severity, title, description, recommendation):
    db = get_db()
    db.execute(
        """INSERT INTO findings
           (scan_id, check_type, severity, title, description, recommendation)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, check_type, severity, title, description, recommendation),
    )
    db.commit()


def get_scan(scan_id):
    return get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def get_findings_for_scan(scan_id):
    return get_db().execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
        "CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END",
        (scan_id,),
    ).fetchall()


def get_scans_for_user(user_id, limit=None):
    query = "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    return get_db().execute(query, (user_id,)).fetchall()


def count_scans():
    return get_db().execute("SELECT COUNT(*) FROM scans").fetchone()[0]


def count_findings():
    return get_db().execute("SELECT COUNT(*) FROM findings").fetchone()[0]


def get_all_scans():
    return get_db().execute(
        """SELECT scans.*, users.name AS user_name
           FROM scans LEFT JOIN users ON scans.user_id = users.id
           ORDER BY scans.created_at DESC LIMIT 100"""
    ).fetchall()


# ---------- Password reset tokens ----------

def create_reset_token(user_id, token, expires_at):
    db = get_db()
    db.execute(
        "INSERT INTO password_resets (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)",
        (user_id, token, expires_at),
    )
    db.commit()


def get_reset_token(token):
    return get_db().execute("SELECT * FROM password_resets WHERE token = ?", (token,)).fetchone()


def mark_reset_token_used(token):
    db = get_db()
    db.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
    db.commit()
