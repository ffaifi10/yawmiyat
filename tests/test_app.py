import re

import pytest
import app as app_module
from app import create_app, db, User, Company, Task


CSRF_RE = re.compile(r'name="_csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture()
def app(tmp_path):
    test_database = tmp_path / "test.db"
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{test_database}",
        "AUTO_CREATE_DB": True,
        "LOGIN_RATE_LIMIT": 5,
        "REGISTER_RATE_LIMIT": 5,
    })
    assert application.config["SQLALCHEMY_DATABASE_URI"] == f"sqlite:///{test_database}"
    assert str(tmp_path) in application.config["SQLALCHEMY_DATABASE_URI"]
    with app_module._RATE_LIMIT_LOCK:
        app_module._RATE_LIMIT_BUCKETS.clear()
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = CSRF_RE.search(response.get_data(as_text=True))
    assert match, f"No CSRF token found in {path}"
    return match.group(1)


def register(client, email="test@example.com", password="a-strong-test-password", name="Test User"):
    token = csrf_token(client, "/register")
    return client.post("/register", data={
        "_csrf_token": token, "name": name, "email": email, "password": password,
    })


def logout_client(client):
    token = csrf_token(client, "/dashboard")
    return client.post("/logout", data={"_csrf_token": token})


def test_home_and_health(client):
    assert client.get("/").status_code == 200
    assert "يوميات".encode() in client.get("/").data
    assert client.get("/health").json["status"] == "ok"


def test_auth_pages_render(client):
    assert client.get("/register").status_code == 200
    assert client.get("/login").status_code == 200


def test_registration_hashes_password_and_never_accepts_admin_role(client, app):
    response = register(client)
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(email="test@example.com").one()
        assert user.password_hash != "a-strong-test-password"
        assert user.check_password("a-strong-test-password")
        assert user.role == "employee"


def test_registration_rejects_invalid_input(client):
    token = csrf_token(client, "/register")
    response = client.post("/register", data={
        "_csrf_token": token, "name": "Test User", "email": "not-an-email", "password": "short",
        "role": "admin",
    })
    assert response.status_code == 400


def test_registration_rejects_missing_csrf_token(client):
    assert client.post("/register", data={
        "name": "Test User", "email": "test@example.com", "password": "a-strong-test-password",
    }).status_code == 400


def test_login_rejects_wrong_password_and_accepts_correct_password(client):
    assert register(client).status_code == 302
    assert logout_client(client).status_code == 302
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token, "email": "test@example.com", "password": "wrong-password",
    })
    assert response.status_code == 200
    assert "غير صحيحة".encode() in response.data
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token, "email": "TEST@example.com", "password": "a-strong-test-password",
    })
    assert response.status_code == 302


def test_logout_requires_post_and_csrf(client):
    assert register(client).status_code == 302
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    response = logout_client(client)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_security_headers_and_cookie_settings(app, client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.login_manager.session_protection == "strong"


def test_csrf_token_rotates_after_login_and_logout(client):
    assert register(client).status_code == 302
    after_register = csrf_token(client, "/dashboard")
    assert logout_client(client).status_code == 302
    after_logout = csrf_token(client, "/login")
    assert after_logout != after_register
    token = csrf_token(client, "/login")
    assert client.post("/login", data={
        "_csrf_token": token, "email": "test@example.com", "password": "a-strong-test-password",
    }).status_code == 302
    after_login = csrf_token(client, "/dashboard")
    assert after_login != token


def test_login_rate_limit_blocks_attempts(client, app):
    app.config["LOGIN_RATE_LIMIT"] = 2
    for _ in range(2):
        token = csrf_token(client, "/login")
        assert client.post("/login", data={
            "_csrf_token": token, "email": "nobody@example.com", "password": "wrong",
        }).status_code == 200
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token, "email": "nobody@example.com", "password": "wrong",
    })
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_registration_rate_limit_blocks_attempts(client, app):
    app.config["REGISTER_RATE_LIMIT"] = 2
    for email in ("one@example.com", "two@example.com"):
        token = csrf_token(client, "/register")
        response = client.post("/register", data={
            "_csrf_token": token, "name": "Test User", "email": email,
            "password": "a-strong-test-password",
        })
        assert response.status_code == 302
        logout_client(client)
    token = csrf_token(client, "/register")
    response = client.post("/register", data={
        "_csrf_token": token, "name": "Third User", "email": "three@example.com",
        "password": "a-strong-test-password",
    })
    assert response.status_code == 429


def test_production_requires_strong_stable_secret_and_secure_cookie(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app({"APP_ENV": "production", "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        create_app({
            "APP_ENV": "production", "SECRET_KEY": "x" * 40,
            "SESSION_COOKIE_SECURE": False, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        })
    app = create_app({
        "TESTING": True, "APP_ENV": "production", "SECRET_KEY": "x" * 40,
        "SESSION_COOKIE_SECURE": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    assert app.config["TESTING"] is True


def test_dashboard_scopes_tasks_to_company_or_user(client, app):
    # Create two companies, one company user, one outsider, and isolated tasks.
    with app.app_context():
        company_a = Company(name="Company A")
        company_b = Company(name="Company B")
        db.session.add_all([company_a, company_b])
        db.session.flush()
        user_a = User(name="User A", email="a@example.com", role="employee", company_id=company_a.id)
        user_b = User(name="User B", email="b@example.com", role="employee", company_id=company_b.id)
        user_a.set_password("a-strong-test-password")
        user_b.set_password("a-strong-test-password")
        db.session.add_all([user_a, user_b])
        db.session.flush()
        db.session.add_all([
            Task(title="A private task", creator_id=user_a.id, company_id=company_a.id),
            Task(title="B private task", creator_id=user_b.id, company_id=company_b.id),
        ])
        db.session.commit()
        user_a_email = user_a.email
    # Clear the registration session and authenticate as user A using the real route.
    client.get("/logout")  # GET is rejected; authentication remains until the test client is cleared.
    client = app.test_client()
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token, "email": user_a_email, "password": "a-strong-test-password",
    })
    assert response.status_code == 302
    page = client.get("/dashboard").get_data(as_text=True)
    assert "A private task" in page
    assert "B private task" not in page


def test_rate_limit_window_expires():
    key = ("unit-test", "isolated")
    with app_module._RATE_LIMIT_LOCK:
        app_module._RATE_LIMIT_BUCKETS.pop(key, None)
    assert app_module._consume_rate_limit(key, 1, 10, now=100)[0] is True
    assert app_module._consume_rate_limit(key, 1, 10, now=105)[0] is False
    assert app_module._consume_rate_limit(key, 1, 10, now=111)[0] is True
    with app_module._RATE_LIMIT_LOCK:
        app_module._RATE_LIMIT_BUCKETS.pop(key, None)
