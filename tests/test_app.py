import re

import pytest
from app import create_app, db, User


CSRF_RE = re.compile(r'name="_csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture()
def app(tmp_path):
    test_database = tmp_path / "test.db"
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{test_database}",
        "AUTO_CREATE_DB": True,
    })
    assert app.config["SQLALCHEMY_DATABASE_URI"] == f"sqlite:///{test_database}"
    assert str(tmp_path) in app.config["SQLALCHEMY_DATABASE_URI"]
    with app.app_context():
        db.create_all()
        yield app
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


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "يوميات".encode() in response.data


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_auth_pages_render(client):
    assert client.get("/register").status_code == 200
    assert client.get("/login").status_code == 200


def test_registration_hashes_password_and_logs_in(client, app):
    token = csrf_token(client, "/register")
    response = client.post("/register", data={
        "_csrf_token": token,
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        user = User.query.filter_by(email="test@example.com").one()
        assert user.password_hash != "a-strong-test-password"
        assert user.check_password("a-strong-test-password")
        assert user.role == "employee"
    assert "لوحة التحكم".encode() in response.data or "أهلًا".encode() in response.data


def test_registration_rejects_invalid_email_and_short_password(client):
    token = csrf_token(client, "/register")
    response = client.post("/register", data={
        "_csrf_token": token,
        "name": "Test User",
        "email": "not-an-email",
        "password": "short",
    })
    assert response.status_code == 400


def test_registration_rejects_missing_csrf_token(client):
    response = client.post("/register", data={
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    })
    assert response.status_code == 400


def test_login_rejects_wrong_password(client):
    token = csrf_token(client, "/register")
    client.post("/register", data={
        "_csrf_token": token,
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    })
    logout_token = csrf_token(client, "/dashboard")
    client.post("/logout", data={"_csrf_token": logout_token})
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token,
        "email": "test@example.com",
        "password": "wrong-password",
    })
    assert response.status_code == 200
    assert "غير صحيحة".encode() in response.data


def test_login_success(client):
    token = csrf_token(client, "/register")
    client.post("/register", data={
        "_csrf_token": token,
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    })
    logout_token = csrf_token(client, "/dashboard")
    client.post("/logout", data={"_csrf_token": logout_token})
    token = csrf_token(client, "/login")
    response = client.post("/login", data={
        "_csrf_token": token,
        "email": "TEST@example.com",
        "password": "a-strong-test-password",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "أهلًا".encode() in response.data


def test_logout_requires_post_and_csrf(client):
    token = csrf_token(client, "/register")
    client.post("/register", data={
        "_csrf_token": token,
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    })
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    token = csrf_token(client, "/dashboard")
    response = client.post("/logout", data={"_csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert "تسجيل الخروج".encode() not in response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_security_headers_and_session_cookie_settings(app, client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.login_manager.session_protection == "strong"
