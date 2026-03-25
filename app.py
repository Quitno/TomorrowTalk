
import csv
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO, StringIO
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask, abort, flash, jsonify, redirect, render_template, request,
    send_file, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
APP_DB = BASE_DIR / "app.db"
ADMIN_DB = BASE_DIR / "admin.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_PATH = "69c3de35-f164-832e-ae50-fdf6bc0939f9"
APP_NAME = "David's connect"
ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me-please")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=14)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def connect_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def app_db():
    return connect_db(APP_DB)

def admin_db():
    return connect_db(ADMIN_DB)

def init_admin_db():
    with admin_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                meta TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE SET NULL
            );
            """
        )

def init_app_db():
    with app_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                profile_pic TEXT,
                theme TEXT NOT NULL DEFAULT 'blue',
                font_scale INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                accepted_by INTEGER,
                accepted_at TEXT,
                FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(accepted_by) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                contact_user_id INTEGER NOT NULL,
                alias TEXT,
                pinned INTEGER NOT NULL DEFAULT 0,
                archived INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                muted INTEGER NOT NULL DEFAULT 0,
                last_interaction_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(owner_id, contact_user_id),
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(contact_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                body_enc TEXT NOT NULL,
                created_at TEXT NOT NULL,
                deleted_by_sender INTEGER NOT NULL DEFAULT 0,
                deleted_by_recipient INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        if db.execute("SELECT value FROM settings WHERE key='message_key'").fetchone() is None:
            db.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?)",
                ("message_key", Fernet.generate_key().decode()),
            )
            db.commit()

def get_message_cipher():
    with app_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key='message_key'").fetchone()
        if row is None:
            key = Fernet.generate_key().decode()
            db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", ("message_key", key))
            db.commit()
            return Fernet(key.encode())
        return Fernet(row["value"].encode())

def encrypt_message(text: str) -> str:
    return get_message_cipher().encrypt(text.encode()).decode()

def decrypt_message(token: str) -> str:
    try:
        return get_message_cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        return "[Encrypted message unavailable]"

def admin_exists():
    with admin_db() as db:
        return db.execute("SELECT 1 FROM admins LIMIT 1").fetchone() is not None

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with app_db() as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def get_current_admin():
    aid = session.get("admin_id")
    if not aid:
        return None
    with admin_db() as db:
        return db.execute("SELECT * FROM admins WHERE id = ?", (aid,)).fetchone()

def user_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("users_auth"))
        return fn(*args, **kwargs)
    return wrapper

def admin_login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not get_current_admin():
            return redirect(url_for("admin_entry"))
        return fn(*args, **kwargs)
    return wrapper

def safe_theme(theme):
    return theme if theme in {"blue", "light", "black"} else "blue"

def allowed_image(filename):
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_IMAGE_EXT

def save_profile_pic(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_image(file_storage.filename):
        return None
    ext = Path(file_storage.filename).suffix.lower()
    digest = hashlib.sha256((file_storage.filename + now_iso() + secrets.token_hex(8)).encode()).hexdigest()[:20]
    name = f"{digest}{ext}"
    path = UPLOAD_DIR / name
    file_storage.save(path)
    return f"static/uploads/{name}"

def ensure_contact_pair(user_a, user_b):
    with app_db() as db:
        existing = db.execute(
            "SELECT id FROM contacts WHERE owner_id = ? AND contact_user_id = ?",
            (user_a, user_b),
        ).fetchone()
        if existing is None:
            db.execute(
                """
                INSERT INTO contacts(owner_id, contact_user_id, alias, pinned, archived, blocked, muted, last_interaction_at, created_at)
                VALUES(?, ?, NULL, 0, 0, 0, 0, ?, ?)
                """,
                (user_a, user_b, now_iso(), now_iso()),
            )
        db.commit()

def get_contact_for_owner(owner_id, contact_user_id):
    with app_db() as db:
        return db.execute(
            """
            SELECT c.*, u.display_name AS contact_name, u.profile_pic AS contact_pic, u.email AS contact_email
            FROM contacts c
            JOIN users u ON u.id = c.contact_user_id
            WHERE c.owner_id = ? AND c.contact_user_id = ?
            """,
            (owner_id, contact_user_id),
        ).fetchone()

def user_contact_list(user_id, query=None):
    sql = """
        SELECT c.*, u.id AS contact_id, u.display_name AS contact_name, u.profile_pic AS contact_pic, u.email AS contact_email
        FROM contacts c
        JOIN users u ON u.id = c.contact_user_id
        WHERE c.owner_id = ?
    """
    params = [user_id]
    if query:
        sql += " AND (LOWER(COALESCE(c.alias, u.display_name)) LIKE ? OR LOWER(u.email) LIKE ?)"
        q = f"%{query.lower()}%"
        params.extend([q, q])
    sql += """
        ORDER BY c.pinned DESC,
                 CASE WHEN c.last_interaction_at IS NULL THEN 1 ELSE 0 END,
                 c.last_interaction_at DESC,
                 c.created_at DESC
    """
    with app_db() as db:
        return db.execute(sql, params).fetchall()

def conversation_messages(user_id, contact_id):
    with app_db() as db:
        rows = db.execute(
            """
            SELECT m.*, s.display_name AS sender_name, s.profile_pic AS sender_pic
            FROM messages m
            JOIN users s ON s.id = m.sender_id
            WHERE (m.sender_id = ? AND m.recipient_id = ? AND m.deleted_by_sender = 0)
               OR (m.sender_id = ? AND m.recipient_id = ? AND m.deleted_by_recipient = 0)
            ORDER BY m.created_at ASC, m.id ASC
            """,
            (user_id, contact_id, contact_id, user_id),
        ).fetchall()
    out = []
    for row in rows:
        data = dict(row)
        data["body"] = decrypt_message(data["body_enc"])
        out.append(data)
    return out

def update_contact_touch(owner_id, contact_id):
    with app_db() as db:
        db.execute(
            "UPDATE contacts SET last_interaction_at = ? WHERE owner_id = ? AND contact_user_id = ?",
            (now_iso(), owner_id, contact_id),
        )
        db.commit()

def log_admin(admin_id, action, meta=""):
    with admin_db() as db:
        db.execute(
            "INSERT INTO audit_logs(admin_id, action, meta, created_at) VALUES(?, ?, ?, ?)",
            (admin_id, action, meta, now_iso()),
        )
        db.commit()

def csv_bytes(headers, rows):
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return sio.getvalue().encode("utf-8")

@app.before_request
def setup_db():
    init_admin_db()
    init_app_db()
    session.permanent = True

@app.context_processor
def inject_globals():
    from flask import request
    path = request.path
    return {
        "APP_NAME": APP_NAME,
        "ADMIN_PATH": ADMIN_PATH,
        "current_user": get_current_user(),
        "current_admin": get_current_admin(),
        "enable_pwa": not path.startswith(f"/{ADMIN_PATH}") and not path.startswith("/admin"),
    }

@app.route("/")
def users_auth():
    if get_current_user():
        return redirect(url_for("app_home"))
    return render_template("users.html")

@app.route("/register", methods=["POST"])
def user_register():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    display_name = request.form.get("display_name", "").strip() or email.split("@")[0].title()
    if not email or not password:
        flash("Email and password are required.")
        return redirect(url_for("users_auth"))
    if len(password) < 8:
        flash("Use a stronger password of at least 8 characters.")
        return redirect(url_for("users_auth"))
    profile_pic = save_profile_pic(request.files.get("profile_pic"))
    with app_db() as db:
        try:
            db.execute(
                """
                INSERT INTO users(email, password_hash, display_name, profile_pic, theme, font_scale, created_at, last_seen)
                VALUES(?, ?, ?, ?, 'blue', 100, ?, ?)
                """,
                (email, generate_password_hash(password), display_name, profile_pic, now_iso(), now_iso()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That email is already registered.")
            return redirect(url_for("users_auth"))
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    pending = session.get("pending_invite_code")
    session.clear()
    session["user_id"] = user["id"]
    if pending:
        session["pending_invite_code"] = pending
    pending = session.pop("pending_invite_code", None)
    if pending:
        finalize_invite_for_user(user["id"], pending)
    return redirect(url_for("app_home"))

@app.route("/login", methods=["POST"])
def user_login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    with app_db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.")
            return redirect(url_for("users_auth"))
        db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now_iso(), user["id"]))
        db.commit()
    pending = session.get("pending_invite_code")
    session.clear()
    session["user_id"] = user["id"]
    if pending:
        session["pending_invite_code"] = pending
    pending = session.pop("pending_invite_code", None)
    if pending:
        finalize_invite_for_user(user["id"], pending)
    return redirect(url_for("app_home"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("users_auth"))

def finalize_invite_for_user(user_id, code):
    if not code:
        return
    with app_db() as db:
        invite = db.execute("SELECT * FROM invites WHERE code = ?", (code,)).fetchone()
        if not invite or invite["accepted_by"] is not None:
            return
        inviter = invite["created_by"]
        if inviter == user_id:
            return
        ensure_contact_pair(user_id, inviter)
        ensure_contact_pair(inviter, user_id)
        db.execute(
            "UPDATE invites SET accepted_by = ?, accepted_at = ? WHERE code = ?",
            (user_id, now_iso(), code),
        )
        db.commit()

@app.route("/invite/<code>")
def accept_invite(code):
    user = get_current_user()
    if not user:
        session["pending_invite_code"] = code
        return redirect(url_for("users_auth"))
    finalize_invite_for_user(user["id"], code)
    flash("Invite accepted. The contact was added.")
    return redirect(url_for("app_home"))

@app.route("/app")
@user_login_required
def app_home():
    user = get_current_user()
    q = request.args.get("q", "").strip()
    contacts = user_contact_list(user["id"], q if q else None)
    unread_count = 0
    with app_db() as db:
        for c in contacts:
            count = db.execute(
                """
                SELECT COUNT(*) AS n FROM messages
                WHERE sender_id = ? AND recipient_id = ? AND deleted_by_recipient = 0
                """,
                (c["contact_user_id"], user["id"]),
            ).fetchone()["n"]
            unread_count += count
    return render_template("home.html", contacts=contacts, q=q, unread_count=unread_count)

@app.route("/settings", methods=["GET", "POST"])
@user_login_required
def settings():
    user = get_current_user()
    if request.method == "POST":
        action = request.form.get("action")
        with app_db() as db:
            if action == "profile":
                display_name = request.form.get("display_name", "").strip() or user["display_name"]
                theme = safe_theme(request.form.get("theme", "blue"))
                font_scale = int(request.form.get("font_scale", user["font_scale"]))
                pic = save_profile_pic(request.files.get("profile_pic"))
                if pic:
                    db.execute(
                        "UPDATE users SET display_name = ?, theme = ?, font_scale = ?, profile_pic = ? WHERE id = ?",
                        (display_name, theme, font_scale, pic, user["id"]),
                    )
                else:
                    db.execute(
                        "UPDATE users SET display_name = ?, theme = ?, font_scale = ? WHERE id = ?",
                        (display_name, theme, font_scale, user["id"]),
                    )
                db.commit()
                flash("Profile updated.")
            elif action == "invite":
                code = secrets.token_urlsafe(10)
                db.execute(
                    "INSERT INTO invites(code, created_by, created_at) VALUES(?, ?, ?)",
                    (code, user["id"], now_iso()),
                )
                db.commit()
                session["invite_url"] = request.host_url.rstrip("/") + url_for("accept_invite", code=code)
                flash("Invite link created.")
            elif action == "about":
                flash("Tomorrow Technology Company helps families and friends stay connected with a neat mobile-first experience.")
        return redirect(url_for("settings"))
    invite_url = session.pop("invite_url", None)
    return render_template("settings.html", invite_url=invite_url)

@app.route("/chat/<int:contact_id>")
@user_login_required
def chat(contact_id):
    user = get_current_user()
    contact = get_contact_for_owner(user["id"], contact_id)
    if not contact:
        ensure_contact_pair(user["id"], contact_id)
        contact = get_contact_for_owner(user["id"], contact_id)
    messages = conversation_messages(user["id"], contact_id)
    update_contact_touch(user["id"], contact_id)
    with app_db() as db:
        other = db.execute("SELECT * FROM users WHERE id = ?", (contact_id,)).fetchone()
    if not other:
        abort(404)
    return render_template("chat.html", contact=contact, other=other, messages=messages)

@app.route("/chat/<int:contact_id>/send", methods=["POST"])
@user_login_required
def send_message(contact_id):
    user = get_current_user()
    text = request.form.get("message", "").strip()
    if not text:
        return redirect(url_for("chat", contact_id=contact_id))
    contact = get_contact_for_owner(user["id"], contact_id)
    if not contact:
        ensure_contact_pair(user["id"], contact_id)
        contact = get_contact_for_owner(user["id"], contact_id)
    if contact["blocked"]:
        flash("Unblock this contact to send messages.")
        return redirect(url_for("chat", contact_id=contact_id))
    with app_db() as db:
        db.execute(
            "INSERT INTO messages(sender_id, recipient_id, body_enc, created_at) VALUES(?, ?, ?, ?)",
            (user["id"], contact_id, encrypt_message(text), now_iso()),
        )
        db.commit()
    update_contact_touch(user["id"], contact_id)
    update_contact_touch(contact_id, user["id"])
    return redirect(url_for("chat", contact_id=contact_id))

@app.route("/contact/<int:contact_id>/rename", methods=["POST"])
@user_login_required
def rename_contact(contact_id):
    user = get_current_user()
    alias = request.form.get("alias", "").strip()
    with app_db() as db:
        db.execute(
            "UPDATE contacts SET alias = ?, last_interaction_at = ? WHERE owner_id = ? AND contact_user_id = ?",
            (alias or None, now_iso(), user["id"], contact_id),
        )
        db.commit()
    return redirect(request.referrer or url_for("app_home"))

@app.route("/contact/<int:contact_id>/pin", methods=["POST"])
@user_login_required
def pin_contact(contact_id):
    user = get_current_user()
    with app_db() as db:
        row = db.execute("SELECT pinned FROM contacts WHERE owner_id = ? AND contact_user_id = ?", (user["id"], contact_id)).fetchone()
        if row:
            db.execute(
                "UPDATE contacts SET pinned = ?, last_interaction_at = ? WHERE owner_id = ? AND contact_user_id = ?",
                (0 if row["pinned"] else 1, now_iso(), user["id"], contact_id),
            )
            db.commit()
    return redirect(request.referrer or url_for("app_home"))

@app.route("/contact/<int:contact_id>/archive", methods=["POST"])
@user_login_required
def archive_contact(contact_id):
    user = get_current_user()
    with app_db() as db:
        row = db.execute("SELECT archived FROM contacts WHERE owner_id = ? AND contact_user_id = ?", (user["id"], contact_id)).fetchone()
        if row:
            db.execute(
                "UPDATE contacts SET archived = ?, last_interaction_at = ? WHERE owner_id = ? AND contact_user_id = ?",
                (0 if row["archived"] else 1, now_iso(), user["id"], contact_id),
            )
            db.commit()
    return redirect(request.referrer or url_for("app_home"))

@app.route("/contact/<int:contact_id>/block", methods=["POST"])
@user_login_required
def block_contact(contact_id):
    user = get_current_user()
    with app_db() as db:
        row = db.execute("SELECT blocked FROM contacts WHERE owner_id = ? AND contact_user_id = ?", (user["id"], contact_id)).fetchone()
        if row:
            db.execute(
                "UPDATE contacts SET blocked = ?, last_interaction_at = ? WHERE owner_id = ? AND contact_user_id = ?",
                (0 if row["blocked"] else 1, now_iso(), user["id"], contact_id),
            )
            db.commit()
    return redirect(url_for("chat", contact_id=contact_id))

@app.route("/contact/<int:contact_id>/delete", methods=["POST"])
@user_login_required
def delete_contact(contact_id):
    user = get_current_user()
    with app_db() as db:
        db.execute("DELETE FROM contacts WHERE owner_id = ? AND contact_user_id = ?", (user["id"], contact_id))
        db.commit()
    return redirect(url_for("app_home"))

@app.route("/chat/<int:contact_id>/delete-chat", methods=["POST"])
@user_login_required
def delete_chat(contact_id):
    user = get_current_user()
    with app_db() as db:
        db.execute(
            "UPDATE messages SET deleted_by_sender = 1 WHERE sender_id = ? AND recipient_id = ?",
            (user["id"], contact_id),
        )
        db.execute(
            "UPDATE messages SET deleted_by_recipient = 1 WHERE sender_id = ? AND recipient_id = ?",
            (contact_id, user["id"]),
        )
        db.commit()
    return redirect(url_for("chat", contact_id=contact_id))

@app.route("/chat/<int:contact_id>/rename-user", methods=["POST"])
@user_login_required
def rename_user(contact_id):
    # alias for the three-dots menu wording requested by user
    return rename_contact(contact_id)

@app.route("/chat/<int:contact_id>/toggle-block", methods=["POST"])
@user_login_required
def toggle_block(contact_id):
    return block_contact(contact_id)

@app.route(f"/{ADMIN_PATH}", methods=["GET", "POST"])
def admin_entry():
    if get_current_admin():
        return redirect(url_for("admin_dashboard"))
    exists = admin_exists()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("admin_entry"))
        if len(password) < 10:
            flash("Admin password must be at least 10 characters.")
            return redirect(url_for("admin_entry"))
        with admin_db() as db:
            if not exists:
                try:
                    db.execute(
                        "INSERT INTO admins(email, password_hash, created_at) VALUES(?, ?, ?)",
                        (email, generate_password_hash(password), now_iso()),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    flash("Admin already exists.")
                    return redirect(url_for("admin_entry"))
                admin = db.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
                session.clear()
                session["admin_id"] = admin["id"]
                log_admin(admin["id"], "initial_admin_created", email)
                return redirect(url_for("admin_dashboard"))
            admin = db.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
            if not admin:
                flash("Invalid admin credentials.")
                return redirect(url_for("admin_entry"))
            if admin["locked_until"]:
                if datetime.fromisoformat(admin["locked_until"]) > datetime.now(timezone.utc):
                    flash("This admin account is temporarily locked.")
                    return redirect(url_for("admin_entry"))
            if not check_password_hash(admin["password_hash"], password):
                attempts = admin["failed_attempts"] + 1
                locked_until = None
                if attempts >= 5:
                    locked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                    attempts = 0
                db.execute(
                    "UPDATE admins SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, locked_until, admin["id"]),
                )
                db.commit()
                flash("Invalid admin credentials.")
                return redirect(url_for("admin_entry"))
            db.execute(
                "UPDATE admins SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                (now_iso(), admin["id"]),
            )
            db.commit()
        session.clear()
        session["admin_id"] = admin["id"]
        log_admin(admin["id"], "admin_login", email)
        return redirect(url_for("admin_dashboard"))
    return render_template("admin.html", admin_exists=exists)

@app.route("/admin/logout")
@admin_login_required
def admin_logout():
    session.pop("admin_id", None)
    return redirect(url_for("admin_entry"))

@app.route("/admin/dashboard")
@admin_login_required
def admin_dashboard():
    with app_db() as db:
        users = db.execute(
            """
            SELECT u.*,
                   (SELECT COUNT(*) FROM contacts c WHERE c.owner_id = u.id) AS contacts_count,
                   (SELECT COUNT(*) FROM messages m WHERE m.sender_id = u.id OR m.recipient_id = u.id) AS messages_count
            FROM users u
            ORDER BY u.created_at DESC
            """
        ).fetchall()
        total_users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        total_messages = db.execute("SELECT COUNT(*) AS n FROM messages").fetchone()["n"]
    with admin_db() as db:
        admins = db.execute("SELECT id, email, created_at, last_login_at FROM admins ORDER BY created_at DESC").fetchall()
    return render_template(
        "admin_dashboard.html",
        users=users,
        admins=admins,
        total_users=total_users,
        total_messages=total_messages,
    )

@app.route("/admin/add", methods=["POST"])
@admin_login_required
def add_admin():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        flash("Admin email and password are required.")
        return redirect(url_for("admin_dashboard"))
    if len(password) < 10:
        flash("Admin password must be at least 10 characters.")
        return redirect(url_for("admin_dashboard"))
    with admin_db() as db:
        try:
            db.execute(
                "INSERT INTO admins(email, password_hash, created_at) VALUES(?, ?, ?)",
                (email, generate_password_hash(password), now_iso()),
            )
            db.commit()
            log_admin(session["admin_id"], "admin_added", email)
            flash("New admin added.")
        except sqlite3.IntegrityError:
            flash("This admin email is already in use.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/reports/users.csv")
@admin_login_required
def report_users():
    with app_db() as db:
        rows = db.execute(
            "SELECT id, email, display_name, theme, font_scale, created_at, last_seen FROM users ORDER BY created_at DESC"
        ).fetchall()
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["id", "email", "display_name", "theme", "font_scale", "created_at", "last_seen"])
    for r in rows:
        writer.writerow([r["id"], r["email"], r["display_name"], r["theme"], r["font_scale"], r["created_at"], r["last_seen"]])
    return send_file(
        BytesIO(sio.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="users_report.csv",
    )

@app.route("/admin/reports/messages.csv")
@admin_login_required
def report_messages():
    with app_db() as db:
        rows = db.execute(
            """
            SELECT m.id, s.email AS sender_email, r.email AS recipient_email, m.created_at
            FROM messages m
            JOIN users s ON s.id = m.sender_id
            JOIN users r ON r.id = m.recipient_id
            ORDER BY m.created_at DESC
            """
        ).fetchall()
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["id", "sender_email", "recipient_email", "created_at"])
    for r in rows:
        writer.writerow([r["id"], r["sender_email"], r["recipient_email"], r["created_at"]])
    return send_file(
        BytesIO(sio.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="messages_report.csv",
    )

@app.route("/admin/reports/contacts.csv")
@admin_login_required
def report_contacts():
    with app_db() as db:
        rows = db.execute(
            """
            SELECT c.id, u.email AS owner_email, cu.email AS contact_email, c.alias, c.pinned, c.archived, c.blocked, c.last_interaction_at
            FROM contacts c
            JOIN users u ON u.id = c.owner_id
            JOIN users cu ON cu.id = c.contact_user_id
            ORDER BY c.last_interaction_at DESC
            """
        ).fetchall()
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["id", "owner_email", "contact_email", "alias", "pinned", "archived", "blocked", "last_interaction_at"])
    for r in rows:
        writer.writerow([r["id"], r["owner_email"], r["contact_email"], r["alias"], r["pinned"], r["archived"], r["blocked"], r["last_interaction_at"]])
    return send_file(
        BytesIO(sio.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="contacts_report.csv",
    )

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_login_required
def admin_delete_user(user_id):
    with app_db() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
    log_admin(session["admin_id"], "user_deleted", str(user_id))
    flash("User deleted.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/users/<int:user_id>/reset-theme", methods=["POST"])
@admin_login_required
def admin_reset_user_theme(user_id):
    with app_db() as db:
        db.execute("UPDATE users SET theme = 'blue', font_scale = 100 WHERE id = ?", (user_id,))
        db.commit()
    log_admin(session["admin_id"], "user_reset_theme", str(user_id))
    flash("User theme reset.")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(413)
def too_large(_):
    return "File too large", 413

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)