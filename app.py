from __future__ import annotations
import os, json, secrets, datetime as dt
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, session, abort, send_from_directory, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App & Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

def bool_from_env(name, default=False):
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1","true","t","yes","y","on")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

# ---- Database (SQLite safe path by default) ----
db_url = os.getenv("DATABASE_URL", "sqlite:///surveycraft.db")
if db_url.startswith("sqlite:///"):
    instance_path = os.path.join(BASE_DIR, "instance")
    os.makedirs(instance_path, exist_ok=True)
    if db_url == "sqlite:///surveycraft.db":
        db_url = "sqlite:///" + os.path.join(instance_path, "surveycraft.db")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool_from_env("SESSION_COOKIE_SECURE", False)

# ---------- Security Headers (CSP) ----------
# Allows Tailwind CDN, Google Fonts, Font Awesome (cdnjs), JSDelivr, UNPKG, images/icons from static and HTTPS CDNs.
csp = {
    "default-src": "'self'",
    "base-uri": "'self'",
    "img-src": ["'self'", "data:", "blob:", "https:"],
    "style-src": [
        "'self'", "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
    ],
    "font-src": [
        "'self'",
        "data:",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
    ],
    "script-src": [
        "'self'", "'unsafe-inline'", "'unsafe-eval'",
        "https://cdn.tailwindcss.com",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://unpkg.com"
    ],
    "connect-src": ["'self'", "https:"],
    "frame-ancestors": "'none'",
    "object-src": "'none'",
    "frame-src": ["'self'", "https:"],
    "form-action": "'self'",
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=bool_from_env("SESSION_COOKIE_SECURE", False),
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin"
)

# ---------- Extensions ----------
db = SQLAlchemy(app)

# (Flask-Limiter v3+ signature)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

login_manager = LoginManager(app)
login_manager.login_view = "login_page"

# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class Survey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(32), default="draft")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), index=True, nullable=False)
    qtype = db.Column(db.String(32), nullable=False)
    text = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text)   # JSON string for MCQ/checkbox/dropdown
    required = db.Column(db.Boolean, default=False)
    ord = db.Column(db.Integer, default=0)

class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    response_limit = db.Column(db.Integer, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(128), nullable=False)
    meta_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

# ---------- Login manager ----------
@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# ---------- Helpers ----------
def log(action: str, meta: dict | None = None):
    try:
        entry = AuditLog(
            user_id=int(current_user.get_id()) if getattr(current_user, "is_authenticated", False) else None,
            action=action,
            meta_json=json.dumps(meta or {})
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

def validate_email(s: str) -> bool:
    return "@" in s and "." in s and 3 <= len(s) <= 255

# ---------- Routes: UI ----------
@app.get("/")
def index():
    return render_template("index.html")

@app.get("/login")
def login_page():
    # Use your dedicated login page (ensure templates/login.html exists)
    return render_template("login.html")

# Common icon & manifest routes (so browsers always find them)
@app.route("/favicon.ico")
def favicon():
    icon_dir = os.path.join(app.root_path, "static")
    path = "favicon.ico" if os.path.exists(os.path.join(icon_dir, "favicon.ico")) else "icons/favicon.ico"
    return send_from_directory(icon_dir, path, mimetype="image/vnd.microsoft.icon")

@app.route("/site.webmanifest")
def webmanifest():
    manifest_dir = os.path.join(app.root_path, "static")
    path = "site.webmanifest" if os.path.exists(os.path.join(manifest_dir, "site.webmanifest")) else "manifest.webmanifest"
    mimetype = "application/manifest+json"
    return send_from_directory(manifest_dir, path, mimetype=mimetype)

@app.route("/apple-touch-icon.png")
def apple_touch_icon():
    icons_dir = os.path.join(app.root_path, "static")
    for candidate in ("apple-touch-icon.png", "icons/apple-touch-icon.png"):
        full = os.path.join(icons_dir, candidate)
        if os.path.exists(full):
            return send_from_directory(icons_dir, candidate, mimetype="image/png")
    abort(404)

# (Optional) serve /assets/* if you keep assets under static/assets/
@app.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(app.root_path, "static", "assets"), filename)

# ---------- Routes: Auth API ----------
@app.post("/auth/signup")
@limiter.limit("5 per minute")
def api_signup():
    data = request.form if request.form else request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not validate_email(email) or len(password) < 8:
        return jsonify({"ok": False, "error": "Invalid input"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "error": "Email already registered"}), 409

    user = User(name=name, email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    log("signup", {"email": email})
    return jsonify({"ok": True})

@app.post("/auth/login")
@limiter.limit("10 per minute")
def api_login():
    data = request.form if request.form else request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        log("login_fail", {"email": email})
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    login_user(user)
    session.permanent = True
    log("login_success", {"email": email})
    return jsonify({"ok": True})

@app.post("/auth/logout")
@login_required
def api_logout():
    log("logout", {})
    logout_user()
    return jsonify({"ok": True})

# ---------- Routes: Surveys API ----------
@app.get("/api/kpis")
@login_required
def api_kpis():
    total_surveys = Survey.query.filter_by(owner_id=current_user.id).count()
    resp = {
        "surveys": total_surveys,
        "responses": 0,
        "completion_rate": 0,
        "active_now": 0
    }
    return jsonify(resp)

@app.post("/api/surveys")
@login_required
def create_survey():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"ok": False, "error": "Title required"}), 400
    s = Survey(title=title, owner_id=current_user.id, status="draft")
    db.session.add(s)
    db.session.commit()
    log("survey_create", {"survey_id": s.id})
    return jsonify({"ok": True, "survey": {"id": s.id, "title": s.title, "status": s.status}}), 201

@app.get("/api/surveys")
@login_required
def list_surveys():
    rows = Survey.query.filter_by(owner_id=current_user.id).order_by(Survey.created_at.desc()).all()
    return jsonify({"ok": True, "surveys": [
        {"id": s.id, "title": s.title, "status": s.status, "created_at": s.created_at.isoformat()}
        for s in rows
    ]})

@app.post("/api/share/generate")
@login_required
def share_generate():
    data = request.get_json(silent=True) or {}
    survey_id = data.get("survey_id")
    if not survey_id:
        return jsonify({"ok": False, "error": "survey_id required"}), 400
    s = Survey.query.filter_by(id=survey_id, owner_id=current_user.id).first()
    if not s:
        return jsonify({"ok": False, "error": "Survey not found"}), 404
    token = secrets.token_urlsafe(16)
    link = ShareLink(survey_id=s.id, token=token, created_by=current_user.id)
    db.session.add(link)
    db.session.commit()
    log("share_link_generate", {"survey_id": s.id, "token": token})
    return jsonify({"ok": True, "link": f"/s/{token}"}), 201

@app.get("/s/<token>")
def public_survey(token):
    sl = ShareLink.query.filter_by(token=token).first()
    if not sl:
        abort(404)
    # Render a public view (for now reuse index.html)
    return render_template("index.html", public=True, token=token, survey_id=sl.survey_id)

# ---------- Error Handlers ----------
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests"}), 429

@app.errorhandler(401)
def unauthorized(e):
    if request.accept_mimetypes.accept_json:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return redirect(url_for("login_page"))

# Helpful: cache static files a bit
@app.after_request
def add_cache_headers(resp):
    if request.path.startswith("/static/"):
        resp.cache_control.max_age = 3600
    return resp

# ---------- CLI ----------
@app.cli.command("init-db")
def init_db_cmd():
    """Initialize the database tables."""
    db.create_all()
    print("✔ Database initialized")

if __name__ == '__main__':
    # Change this line to enable debug mode
    app.run(host='0.0.0.0', port=5000, debug=True)
