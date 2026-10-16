import pytest
from app import create_app, db, User


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "AUTO_CREATE_DB": True,
    })
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "يوميات".encode() in response.data


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_registration_hashes_password_and_logs_in(client, app):
    response = client.post("/register", data={
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    }, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        user = User.query.filter_by(email="test@example.com").one()
        assert user.password_hash != "a-strong-test-password"
        assert user.check_password("a-strong-test-password")
    assert "لوحة التحكم".encode() in response.data or "أهلًا".encode() in response.data


def test_login_rejects_wrong_password(client):
    client.post("/register", data={
        "name": "Test User",
        "email": "test@example.com",
        "password": "a-strong-test-password",
    })
    client.post("/logout")
    response = client.post("/login", data={
        "email": "test@example.com",
        "password": "wrong-password",
    })
    assert response.status_code == 200
    assert "غير صحيحة".encode() in response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
