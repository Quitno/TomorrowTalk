import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask, abort, flash, jsonify, redirect, render_template, request,
    send_from_directory, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = APP_DIR / "instance"
UPLOAD_DIR = APP_DIR / "static" / "uploads"
INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = INSTANCE_DIR / "david_connect.db"
MASTER_KEY_PATH = INSTANCE_DIR / "master.key"

BOOTSTRAP_ADMIN_SECRET = os.environ.get(
    "DAVID_CONNECT_BOOTSTRAP_SECRET",
    "Change-This-Bootstrap-Secret-Once"
)
SESSION_SECRET = os.environ.get(
    "DAVID_CONNECT_SESSION_SECRET",
    "change-this-session-secret-now"
)

app = Flask(__name__)
app.secret_key = SESSION_SECRET
app.config.update(
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    UPLOAD_FOLDER=str(UPLOAD_DIR),
)


def utcnow():
    return datetime.now(timezone.utc)


def iso_now():
    return utcnow().isoformat()


def fmt_ts(value):
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_master_key():
    if MASTER_KEY_PATH.exists():
        return MASTER_KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    MASTER_KEY_PATH.write_bytes(key)
    return key


fernet = Fernet(get_master_key())


def encrypt_text(value: str) -> str:
    if value is None:
        value = ""
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str) -> str:
    if token is None:
        return ""
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[Unable to decrypt]"


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            email_normalized TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar_path TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            invite_email TEXT,
            created_by INTEGER,
            used_by INTEGER,
            used_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(used_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_low INTEGER NOT NULL,
            user_high INTEGER NOT NULL,
            theme TEXT NOT NULL DEFAULT 'navy',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_low, user_high)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'sent',
            created_at TEXT NOT NULL,
            edited_at TEXT,
            deleted_at TEXT,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            detail TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        row = conn.execute("SELECT value FROM settings WHERE key='bootstrap_locked'").fetchone()
        if row is None:
            conn.execute("INSERT INTO settings(key, value) VALUES('bootstrap_locked','0')")
        conn.commit()


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str):
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()


def is_bootstrap_locked() -> bool:
    return get_setting("bootstrap_locked", "0") == "1"


def lock_bootstrap():
    set_setting("bootstrap_locked", "1")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def current_admin():
    uid = session.get("admin_id")
    if not uid:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=? AND is_admin=1", (uid,)).fetchone()


def row_to_dict(row):
    return dict(row) if row is not None else None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("auth"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_admin():
            return redirect(url_for("admin_page"))
        return view(*args, **kwargs)
    return wrapper


def log_event(action, severity="info", detail="", user_id=None):
    user = current_user() or current_admin()
    with db() as conn:
        conn.execute(
            """INSERT INTO audit_logs(user_id, action, severity, detail, ip, user_agent, created_at)
               VALUES(?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id or (user["id"] if user else None),
                action,
                severity,
                detail,
                request.headers.get("X-Forwarded-For", request.remote_addr),
                request.headers.get("User-Agent", ""),
                iso_now(),
            ),
        )
        conn.commit()


def conversation_pair(a, b):
    return (a, b) if a < b else (b, a)


def get_or_create_conversation(user_a, user_b):
    low, high = conversation_pair(user_a, user_b)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM conversations WHERE user_low=? AND user_high=?",
            (low, high),
        ).fetchone()
        if row:
            return row
        conn.execute(
            "INSERT INTO conversations(user_low, user_high, theme, created_at, updated_at) VALUES(?, ?, 'navy', ?, ?)",
            (low, high, iso_now(), iso_now()),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM conversations WHERE user_low=? AND user_high=?",
            (low, high),
        ).fetchone()


def conv_partner_row(conv, me_id):
    partner_id = conv["user_high"] if conv["user_low"] == me_id else conv["user_low"]
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (partner_id,)).fetchone()


def user_conversations(user_id):
    with db() as conn:
        rows = conn.execute(
            """
            SELECT c.*, 
                   CASE WHEN c.user_low=? THEN c.user_high ELSE c.user_low END AS partner_id,
                   u.display_name AS partner_name,
                   u.email AS partner_email,
                   u.avatar_path AS partner_avatar,
                   (
                       SELECT m.created_at
                       FROM messages m
                       WHERE m.conversation_id=c.id
                       ORDER BY m.id DESC
                       LIMIT 1
                   ) AS last_message_at,
                   (
                       SELECT m.ciphertext
                       FROM messages m
                       WHERE m.conversation_id=c.id
                       ORDER BY m.id DESC
                       LIMIT 1
                   ) AS last_message_cipher
            FROM conversations c
            JOIN users u ON u.id = CASE WHEN c.user_low=? THEN c.user_high ELSE c.user_low END
            WHERE c.user_low=? OR c.user_high=?
            ORDER BY COALESCE(last_message_at, c.updated_at) DESC
            """,
            (user_id, user_id, user_id, user_id, user_id),
        ).fetchall()

    result = []
    for r in rows:
        preview = ""
        if r["last_message_cipher"]:
            preview = decrypt_text(r["last_message_cipher"])
            if len(preview) > 48:
                preview = preview[:48] + "…"
        item = dict(r)
        item["last_message_preview"] = preview
        item["last_message_at_human"] = fmt_ts(r["last_message_at"] or r["updated_at"])
        result.append(item)
    return result


def conversation_messages(conv_id):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE conversation_id=? ORDER BY id ASC",
            (conv_id,),
        ).fetchall()

    out = []
    for row in rows:
        deleted = bool(row["deleted_at"])
        out.append({
            "id": row["id"],
            "conversation_id": row["conversation_id"],
            "sender_id": row["sender_id"],
            "content": decrypt_text(row["ciphertext"]) if not deleted else "This message was deleted.",
            "status": row["status"],
            "created_at": row["created_at"],
            "created_at_human": fmt_ts(row["created_at"]),
            "edited_at": row["edited_at"],
            "edited_at_human": fmt_ts(row["edited_at"]),
            "deleted_at": row["deleted_at"],
            "deleted_at_human": fmt_ts(row["deleted_at"]),
            "deleted": deleted,
        })
    return out


def ensure_contact_can_access(conv_id, user_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM conversations WHERE id=?", (conv_id,)).fetchone()
    if not row or (row["user_low"] != user_id and row["user_high"] != user_id):
        abort(404)
    return row


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(self), microphone=(self)"
    return resp


@app.context_processor
def inject_globals():
    me_row = current_user()
    admin_row = current_admin()
    return {
        "me": me_row,
        "admin": admin_row,
        "me_json": row_to_dict(me_row),
        "admin_json": row_to_dict(admin_row),
        "bootstrap_locked": is_bootstrap_locked(),
    }


@app.route("/logo.png")
def logo_alias():
    return send_from_directory(app.static_folder, "logo.png")


@app.route("/")
def auth():
    if current_user():
        return redirect(url_for("app_home"))
    invite = request.args.get("invite", "")
    return render_template("auth.html", invite=invite, title="David's Connect")


@app.route("/join/<code>")
def join_link(code):
    return render_template("auth.html", invite=code, title="David's Connect")


@app.route("/register", methods=["POST"])
def register():
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    display_name = (request.form.get("display_name") or "").strip() or email.split("@")[0]
    invite_code = (request.form.get("invite_code") or "").strip()

    if not email or "@" not in email:
        flash("Enter a valid email address.", "error")
        return redirect(url_for("auth"))
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("auth"))

    with db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email_normalized=?", (email,)).fetchone()
        if existing:
            flash("That email is already taken. Please use a different one.", "error")
            return redirect(url_for("auth"))

        invite_ok = False
        if invite_code:
            inv = conn.execute(
                "SELECT * FROM invites WHERE code=? AND (used_by IS NULL) AND (expires_at IS NULL OR expires_at>?)",
                (invite_code, iso_now()),
            ).fetchone()
            if inv:
                invite_ok = True
        else:
            invite_ok = True

        if not invite_ok:
            flash("Invalid or expired invite code.", "error")
            return redirect(url_for("auth"))

        pw_hash = generate_password_hash(password, method="scrypt")
        conn.execute(
            """INSERT INTO users(email, email_normalized, display_name, password_hash, avatar_path, is_admin, is_active, created_at)
               VALUES(?, ?, ?, ?, NULL, 0, 1, ?)""",
            (request.form.get("email").strip(), email, display_name, pw_hash, iso_now()),
        )
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        if invite_code:
            conn.execute(
                "UPDATE invites SET used_by=?, used_at=? WHERE code=?",
                (uid, iso_now(), invite_code),
            )
        conn.commit()

    session.clear()
    session["user_id"] = uid
    log_event("user_registered", "info", f"Registered {email}", user_id=uid)
    flash("Account created. Welcome to David's Connect.", "success")
    return redirect(url_for("app_home"))


@app.route("/login", methods=["POST"])
def login():
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email_normalized=?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log_event("login_failed", "warning", f"Failed login attempt for {email}")
        flash("Invalid credentials.", "error")
        return redirect(url_for("auth"))
    if not user["is_active"]:
        flash("This account is disabled.", "error")
        return redirect(url_for("auth"))
    with db() as conn:
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (iso_now(), user["id"]))
        conn.commit()
    session.clear()
    session["user_id"] = user["id"]
    log_event("user_login", "info", f"Login for {email}", user_id=user["id"])
    return redirect(url_for("app_home"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth"))


@app.route("/app")
@login_required
def app_home():
    me = current_user()
    return render_template("chat.html", title="David's Connect", me=me)


@app.route("/api/me")
@login_required
def api_me():
    me = current_user()
    return jsonify({
        "id": me["id"],
        "email": me["email"],
        "display_name": me["display_name"],
        "avatar_path": me["avatar_path"],
        "is_admin": bool(me["is_admin"]),
        "last_seen": me["last_seen"],
    })


@app.route("/api/users")
@login_required
def api_users():
    me = current_user()
    q = (request.args.get("q") or "").strip().lower()
    with db() as conn:
        if q:
            users = conn.execute(
                """SELECT id, email, display_name, avatar_path, is_admin
                   FROM users
                   WHERE id != ? AND is_active=1 AND (LOWER(email) LIKE ? OR LOWER(display_name) LIKE ?)
                   ORDER BY display_name ASC""",
                (me["id"], f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            users = conn.execute(
                """SELECT id, email, display_name, avatar_path, is_admin
                   FROM users WHERE id != ? AND is_active=1 ORDER BY display_name ASC""",
                (me["id"],),
            ).fetchall()
    payload = []
    for u in users:
        conv = get_or_create_conversation(me["id"], u["id"])
        payload.append({
            "id": u["id"],
            "email": u["email"],
            "display_name": u["display_name"],
            "avatar_path": u["avatar_path"],
            "is_admin": bool(u["is_admin"]),
            "conversation_id": conv["id"],
        })
    return jsonify(payload)


@app.route("/api/conversations")
@login_required
def api_conversations():
    me = current_user()
    payload = []
    for conv in user_conversations(me["id"]):
        payload.append({
            "id": conv["id"],
            "partner_id": conv["partner_id"],
            "partner_name": conv["partner_name"],
            "partner_email": conv["partner_email"],
            "partner_avatar": conv["partner_avatar"],
            "theme": conv["theme"],
            "last_message_preview": conv["last_message_preview"],
            "last_message_at": conv["last_message_at_human"],
        })
    return jsonify(payload)


@app.route("/api/conversations/<int:conv_id>", methods=["GET"])
@login_required
def api_conversation_detail(conv_id):
    me = current_user()
    conv = ensure_contact_can_access(conv_id, me["id"])
    partner = conv_partner_row(conv, me["id"])
    return jsonify({
        "id": conv["id"],
        "theme": conv["theme"],
        "partner": {
            "id": partner["id"],
            "display_name": partner["display_name"],
            "email": partner["email"],
            "avatar_path": partner["avatar_path"],
        },
        "messages": conversation_messages(conv_id),
    })


@app.route("/api/conversations", methods=["POST"])
@login_required
def api_create_conversation():
    me = current_user()
    partner_email = normalize_email(request.form.get("email"))
    partner_id = request.form.get("user_id")
    with db() as conn:
        if partner_id:
            row = conn.execute(
                "SELECT id FROM users WHERE id=? AND id != ?",
                (partner_id, me["id"]),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id FROM users WHERE email_normalized=? AND id != ?",
                (partner_email, me["id"]),
            ).fetchone()
    if not row:
        return jsonify({"error": "User not found."}), 404
    conv = get_or_create_conversation(me["id"], row["id"])
    return jsonify({"conversation_id": conv["id"]})


@app.route("/api/conversations/<int:conv_id>/messages", methods=["POST"])
@login_required
def api_send_message(conv_id):
    me = current_user()
    ensure_contact_can_access(conv_id, me["id"])
    content = (request.form.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Message cannot be empty."}), 400
    with db() as conn:
        conn.execute(
            """INSERT INTO messages(conversation_id, sender_id, ciphertext, status, created_at)
               VALUES(?, ?, ?, 'sent', ?)""",
            (conv_id, me["id"], encrypt_text(content), iso_now()),
        )
        conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (iso_now(), conv_id))
        conn.commit()
        msg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    log_event("message_sent", "info", f"Message {msg_id} in conversation {conv_id}", user_id=me["id"])
    return jsonify({"ok": True, "message_id": msg_id})


@app.route("/api/messages/<int:msg_id>", methods=["PATCH"])
@login_required
def api_edit_message(msg_id):
    me = current_user()
    content = (request.form.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Message cannot be empty."}), 400
    with db() as conn:
        msg = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
        if not msg:
            return jsonify({"error": "Message not found."}), 404
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (msg["conversation_id"],)).fetchone()
        if me["id"] not in (conv["user_low"], conv["user_high"]):
            return jsonify({"error": "Forbidden."}), 403
        if msg["sender_id"] != me["id"] and not me["is_admin"]:
            return jsonify({"error": "Only the sender can edit this message."}), 403
        conn.execute(
            "UPDATE messages SET ciphertext=?, edited_at=?, status='edited' WHERE id=?",
            (encrypt_text(content), iso_now(), msg_id),
        )
        conn.commit()
    log_event("message_edited", "info", f"Edited message {msg_id}", user_id=me["id"])
    return jsonify({"ok": True})


@app.route("/api/messages/<int:msg_id>", methods=["DELETE"])
@login_required
def api_delete_message(msg_id):
    me = current_user()
    with db() as conn:
        msg = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
        if not msg:
            return jsonify({"error": "Message not found."}), 404
        conv = conn.execute("SELECT * FROM conversations WHERE id=?", (msg["conversation_id"],)).fetchone()
        if me["id"] not in (conv["user_low"], conv["user_high"]):
            return jsonify({"error": "Forbidden."}), 403
        if msg["sender_id"] != me["id"] and not me["is_admin"]:
            return jsonify({"error": "Only the sender can delete this message."}), 403
        conn.execute(
            "UPDATE messages SET ciphertext=?, deleted_at=?, status='deleted' WHERE id=?",
            (encrypt_text("This message was deleted."), iso_now(), msg_id),
        )
        conn.commit()
    log_event("message_deleted", "warning", f"Deleted message {msg_id}", user_id=me["id"])
    return jsonify({"ok": True})


@app.route("/api/conversations/<int:conv_id>", methods=["DELETE"])
@login_required
def api_delete_conversation(conv_id):
    me = current_user()
    ensure_contact_can_access(conv_id, me["id"])
    with db() as conn:
        conn.execute("DELETE FROM messages WHERE conversation_id=?", (conv_id,))
        conn.execute("DELETE FROM conversations WHERE id=?", (conv_id,))
        conn.commit()
    log_event("conversation_deleted", "warning", f"Deleted conversation {conv_id}", user_id=me["id"])
    return jsonify({"ok": True})


@app.route("/api/conversations/<int:conv_id>/theme", methods=["POST"])
@login_required
def api_theme(conv_id):
    me = current_user()
    ensure_contact_can_access(conv_id, me["id"])
    theme = (request.form.get("theme") or "navy").strip()
    if theme not in {"navy", "light", "pure"}:
        theme = "navy"
    with db() as conn:
        conn.execute("UPDATE conversations SET theme=?, updated_at=? WHERE id=?", (theme, iso_now(), conv_id))
        conn.commit()
    return jsonify({"ok": True, "theme": theme})


@app.route("/api/profile", methods=["POST"])
@login_required
def api_profile():
    me = current_user()
    display_name = (request.form.get("display_name") or me["display_name"]).strip()
    avatar = request.files.get("avatar")
    avatar_path = me["avatar_path"]
    if avatar and avatar.filename:
        name = secure_filename(avatar.filename)
        ext = Path(name).suffix.lower() or ".png"
        filename = f"user_{me['id']}_{secrets.token_hex(6)}{ext}"
        target = UPLOAD_DIR / filename
        avatar.save(target)
        avatar_path = f"/static/uploads/{filename}"
    with db() as conn:
        conn.execute(
            "UPDATE users SET display_name=?, avatar_path=?, last_seen=? WHERE id=?",
            (display_name, avatar_path, iso_now(), me["id"])
        )
        conn.commit()
    log_event("profile_updated", "info", "Updated profile", user_id=me["id"])
    return jsonify({"ok": True, "avatar_path": avatar_path, "display_name": display_name})


@app.route("/api/invites", methods=["POST"])
@admin_required
def api_create_invite():
    admin = current_admin()
    email = normalize_email(request.form.get("invite_email"))
    expires_days = request.form.get("expires_days", "14")
    try:
        days = int(expires_days)
    except Exception:
        days = 14
    code = secrets.token_urlsafe(16)
    expires_at = None
    if days > 0:
        expires_at = (utcnow().replace(microsecond=0) + timedelta(days=days)).isoformat()
    with db() as conn:
        conn.execute(
            """INSERT INTO invites(code, invite_email, created_by, expires_at, created_at)
               VALUES(?, ?, ?, ?, ?)""",
            (code, email or None, admin["id"], expires_at, iso_now()),
        )
        conn.commit()
    log_event("invite_created", "info", f"Invite created for {email or 'open invite'}", user_id=admin["id"])
    return jsonify({"ok": True, "code": code, "url": url_for("join_link", code=code, _external=True)})


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    with db() as conn:
        users = conn.execute(
            "SELECT id, email, display_name, avatar_path, is_admin, is_active, created_at, last_seen FROM users ORDER BY created_at DESC"
        ).fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/admin/promote/<int:user_id>", methods=["POST"])
@admin_required
def api_admin_promote(user_id):
    with db() as conn:
        conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
        conn.commit()
    log_event("admin_promoted", "warning", f"Promoted user {user_id} to admin")
    return jsonify({"ok": True})


@app.route("/api/admin/create", methods=["POST"])
@admin_required
def api_admin_create():
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    display_name = (request.form.get("display_name") or "Administrator").strip() or "Administrator"

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400

    with db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE email_normalized=?", (email,)).fetchone()
        if exists:
            return jsonify({"error": "Email already exists"}), 400

        conn.execute(
            """INSERT INTO users(email, email_normalized, display_name, password_hash, avatar_path, is_admin, is_active, created_at)
               VALUES(?, ?, ?, ?, NULL, 1, 1, ?)""",
            (
                request.form.get("email").strip(),
                email,
                display_name,
                generate_password_hash(password, method="scrypt"),
                iso_now(),
            ),
        )
        conn.commit()

    log_event("admin_created", "warning", f"Created new admin: {email}")
    return jsonify({"ok": True})


@app.route("/api/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def api_admin_delete(user_id):
    me = current_admin()
    if me and me["id"] == user_id:
        return jsonify({"error": "You cannot delete the admin account you are currently using."}), 400

    with db() as conn:
        target = conn.execute("SELECT id, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404
        if not target["is_admin"]:
            return jsonify({"error": "That account is not an admin"}), 400

        admin_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin=1").fetchone()["c"]
        if admin_count <= 1:
            return jsonify({"error": "You must keep at least one admin account"}), 400

        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()

    log_event("admin_deleted", "warning", f"Deleted admin user {user_id}")
    return jsonify({"ok": True})


@app.route("/api/admin/toggle/<int:user_id>", methods=["POST"])
@admin_required
def api_admin_toggle(user_id):
    with db() as conn:
        row = conn.execute("SELECT is_active FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        new_val = 0 if row["is_active"] else 1
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_val, user_id))
        conn.commit()
    log_event("admin_toggle", "warning", f"Set user {user_id} active={new_val}")
    return jsonify({"ok": True, "active": bool(new_val)})


@app.route("/api/admin/logs")
@admin_required
def api_admin_logs():
    with db() as conn:
        logs = conn.execute(
            """
            SELECT a.*, u.email AS user_email
            FROM audit_logs a
            LEFT JOIN users u ON u.id=a.user_id
            ORDER BY a.id DESC
            LIMIT 250
            """
        ).fetchall()
    return jsonify([dict(l) for l in logs])


@app.route("/admin", methods=["GET"])
def admin_page():
    admin = current_admin()
    if admin:
        return render_template(
            "admin.html",
            title="Admin · David's Connect",
            admin=admin,
            bootstrap_secret="hidden",
            bootstrap_locked=is_bootstrap_locked(),
        )
    return render_template(
        "admin.html",
        title="Admin · David's Connect",
        admin=None,
        has_admin=False,
        bootstrap_secret=BOOTSTRAP_ADMIN_SECRET,
        bootstrap_locked=is_bootstrap_locked(),
    )


@app.route("/admin/bootstrap", methods=["POST"])
def admin_bootstrap():
    if is_bootstrap_locked():
        abort(403)
    entered = request.form.get("bootstrap_secret", "")
    if entered != BOOTSTRAP_ADMIN_SECRET:
        flash("Invalid bootstrap secret.", "error")
        return redirect(url_for("admin_page"))

    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    display_name = (request.form.get("display_name") or "Administrator").strip() or "Administrator"

    if not email or "@" not in email or len(password) < 10:
        flash("Provide a valid admin email and a strong password (10+ chars).", "error")
        return redirect(url_for("admin_page"))

    with db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE email_normalized=?", (email,)).fetchone()
        if exists:
            flash("That email already exists.", "error")
            return redirect(url_for("admin_page"))

        conn.execute(
            """INSERT INTO users(email, email_normalized, display_name, password_hash, avatar_path, is_admin, is_active, created_at)
               VALUES(?, ?, ?, ?, NULL, 1, 1, ?)""",
            (
                request.form.get("email").strip(),
                email,
                display_name,
                generate_password_hash(password, method="scrypt"),
                iso_now(),
            ),
        )
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()

    lock_bootstrap()
    session.clear()
    session["admin_id"] = uid
    log_event("admin_bootstrap", "warning", f"Bootstrap admin created: {email}", user_id=uid)
    flash("Bootstrap admin created.", "success")
    return redirect(url_for("admin_page"))


@app.route("/admin/login", methods=["POST"])
def admin_login():
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email_normalized=? AND is_admin=1", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log_event("admin_login_failed", "warning", f"Failed admin login for {email}")
        flash("Invalid admin credentials.", "error")
        return redirect(url_for("admin_page"))
    session.clear()
    session["admin_id"] = user["id"]
    log_event("admin_login", "warning", f"Admin login for {email}", user_id=user["id"])
    return redirect(url_for("admin_page"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    return redirect(url_for("admin_page"))


@app.route("/api/call-room", methods=["POST"])
@login_required
def api_call_room():
    me = current_user()
    peer_id = request.form.get("peer_id")
    mode = (request.form.get("mode") or "video").strip()
    if mode not in {"voice", "video"}:
        mode = "video"
    try:
        peer_id = int(peer_id)
    except Exception:
        return jsonify({"error": "Missing peer."}), 400
    conv = get_or_create_conversation(me["id"], peer_id)
    room = f"dc-{conv['id']}-{secrets.token_urlsafe(10)}"
    log_event("call_started", "info", f"{mode} call room {room}", user_id=me["id"])
    return jsonify({"ok": True, "room": room, "mode": mode})


@app.route("/manifest.webmanifest")
def manifest():
    return send_from_directory(app.static_folder, "manifest.webmanifest")


@app.route("/sw.js")
def service_worker():
    return send_from_directory(app.static_folder, "sw.js")


@app.errorhandler(404)
def nf(_):
    return render_template("base_error.html", title="Not found", message="Page not found."), 404


@app.errorhandler(403)
def fb(_):
    return render_template("base_error.html", title="Forbidden", message="Access denied."), 403


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)