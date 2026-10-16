"""يوميات — Flask application entry point."""
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()
login_manager = LoginManager()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RATE_LIMIT_BUCKETS = defaultdict(deque)
_RATE_LIMIT_LOCK = threading.Lock()
_PLACEHOLDER_KEYS = {
    "", "change-me", "replace-with-a-long-random-secret",
    "local-development-only-change-me", "secret", "password",
}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="employee")
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    employees = db.relationship("User", backref="company", lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, default="")
    status = db.Column(db.String(30), nullable=False, default="todo")
    priority = db.Column(db.String(20), nullable=False, default="normal")
    due_date = db.Column(db.Date, nullable=True)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    creator = db.relationship("User", foreign_keys=[creator_id])


class WorkSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text, default="")
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    employee = db.relationship("User")


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_key = db.Column(db.String(500), nullable=False)
    mime_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


def _consume_rate_limit(key, limit, window_seconds, now=None):
    """In-process sliding-window limiter. No proxy headers are trusted."""
    now = time.monotonic() if now is None else now
    with _RATE_LIMIT_LOCK:
        attempts = _RATE_LIMIT_BUCKETS[key]
        while attempts and now - attempts[0] >= window_seconds:
            attempts.popleft()
        if len(attempts) >= limit:
            retry_after = max(1, int(window_seconds - (now - attempts[0])))
            return False, retry_after
        attempts.append(now)
        return True, 0


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    cookie_secure_raw = os.environ.get("COOKIE_SECURE", "0").strip().lower()
    if cookie_secure_raw not in {"0", "1", "false", "true", "no", "yes"}:
        raise RuntimeError("COOKIE_SECURE must be one of 0/1, false/true, or no/yes.")
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", "sqlite:///" + os.path.join(app.instance_path, "yawmiyat.db")
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure_raw in {"1", "true", "yes"},
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,
        LOGIN_RATE_LIMIT=5,
        LOGIN_RATE_WINDOW=15 * 60,
        REGISTER_RATE_LIMIT=5,
        REGISTER_RATE_WINDOW=60 * 60,
    )
    if test_config:
        app.config.update(test_config)

    environment = str(
        app.config.get("APP_ENV") or os.environ.get("APP_ENV")
        or os.environ.get("FLASK_ENV") or app.config.get("ENVIRONMENT") or ""
    ).strip().lower()
    production = environment == "production"
    secret_key = app.config.get("SECRET_KEY")
    if production:
        if not isinstance(secret_key, str) or len(secret_key) < 32 or secret_key.strip().lower() in _PLACEHOLDER_KEYS:
            raise RuntimeError(
                "Production startup refused: set SECRET_KEY to a stable, randomly generated value of at least 32 characters."
            )
        if not app.config.get("SESSION_COOKIE_SECURE"):
            raise RuntimeError(
                "Production startup refused: set COOKIE_SECURE=1 only after HTTPS is correctly configured."
            )
    elif not secret_key:
        if app.config.get("TESTING") or environment == "development":
            app.config["SECRET_KEY"] = "local-development-only-change-me"
        else:
            app.logger.warning("SECRET_KEY is unset; set a stable random SECRET_KEY before deployment.")
            app.config["SECRET_KEY"] = os.urandom(32)

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = "يرجى تسجيل الدخول للمتابعة."
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.context_processor
    def inject_csrf_token():
        def generate_csrf_token():
            token = session.get("_csrf_token")
            if token is None:
                token = secrets.token_urlsafe(32)
                session["_csrf_token"] = token
            return token
        return {"csrf_token": generate_csrf_token}

    @app.before_request
    def protect_csrf():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf_token")
            submitted = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
            if not expected or not submitted or not secrets.compare_digest(expected, submitted):
                abort(400, description="Missing or invalid CSRF token")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'self'; form-action 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; upgrade-insecure-requests" if app.config.get("FORCE_HTTPS_CSP")
            else "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'self'; form-action 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'"
        )
        return response

    def role_required(*roles):
        def decorator(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if current_user.role not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            allowed, retry_after = _consume_rate_limit(
                ("register", request.remote_addr or "unknown"),
                int(app.config["REGISTER_RATE_LIMIT"]),
                int(app.config["REGISTER_RATE_WINDOW"]),
            )
            if not allowed:
                response = render_template("register.html")
                return response, 429, {"Retry-After": str(retry_after)}
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            valid_input = (
                1 <= len(name) <= 120
                and len(email) <= 255
                and EMAIL_RE.fullmatch(email) is not None
                and 10 <= len(password) <= 1024
            )
            if not valid_input:
                flash("تحقق من الاسم والبريد الإلكتروني، واجعل كلمة المرور بين 10 و1024 حرفًا.", "error")
                return render_template("register.html"), 400
            if User.query.filter_by(email=email).first():
                flash("تعذر إنشاء الحساب بهذه البيانات.", "error")
                return render_template("register.html"), 400
            user = User(name=name, email=email, role="employee")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            session.pop("_csrf_token", None)
            login_user(user)
            flash("تم إنشاء الحساب. أنشئ شركتك وأضف فريقك من لوحة التحكم عند تجهيز هذه الميزة.", "success")
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            allowed, retry_after = _consume_rate_limit(
                ("login", request.remote_addr or "unknown"),
                int(app.config["LOGIN_RATE_LIMIT"]),
                int(app.config["LOGIN_RATE_WINDOW"]),
            )
            if not allowed:
                response = render_template("login.html")
                return response, 429, {"Retry-After": str(retry_after)}
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first() if len(email) <= 255 else None
            if user and len(password) <= 1024 and user.check_password(password):
                session.pop("_csrf_token", None)
                login_user(user)
                return redirect(url_for("dashboard"))
            flash("البريد الإلكتروني أو كلمة المرور غير صحيحة.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        session.pop("_csrf_token", None)
        flash("تم تسجيل الخروج.", "success")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        # No admin-wide data view exists: all users are scoped to their company,
        # or to tasks they created/are assigned when not yet attached to a company.
        tasks_query = Task.query
        if current_user.company_id is not None:
            tasks_query = tasks_query.filter_by(company_id=current_user.company_id)
        else:
            tasks_query = tasks_query.filter(
                (Task.creator_id == current_user.id) | (Task.assignee_id == current_user.id)
            )
        tasks = tasks_query.order_by(Task.created_at.desc()).limit(10).all()
        return render_template(
            "dashboard.html",
            tasks=tasks,
            total_tasks=tasks_query.count(),
            done_tasks=tasks_query.filter_by(status="done").count(),
            pending_tasks=tasks_query.filter(Task.status != "done").count(),
            User=User,
            Company=Company,
            Task=Task,
            WorkSchedule=WorkSchedule,
            Attachment=Attachment,
        )

    @app.route("/health")
    def health():
        return {"status": "ok", "app": "yawmiyat"}

    if app.config.get("AUTO_CREATE_DB") is True:
        with app.app_context():
            db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    if os.environ.get("AUTO_CREATE_DB") == "1":
        with app.app_context():
            db.create_all()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
