import logging
from datetime import datetime, timedelta, timezone
from app.core.config import get_settings
from app.models import PasswordResetToken, RefreshToken, Role
from tests.conftest import make_user

PW = "Str0ngPassw0rd!"
NEWPW = "An0therStr0ngPass!"


def get_token(client, caplog, email="e@x.com"):
    get_settings().APP_ENV = "development"
    with caplog.at_level(logging.WARNING, logger="digiquest.mailer"):
        r = client.post("/api/v1/auth/password-reset/request", json={"email": email})
    get_settings().APP_ENV = "production"
    assert r.status_code == 202
    for rec in caplog.records:
        if "reset token" in rec.getMessage():
            return rec.getMessage().rsplit(": ", 1)[1]
    return None


def test_request_does_not_reveal_account_existence(client, db, caplog):
    make_user(db, "e@x.com")
    a = client.post("/api/v1/auth/password-reset/request", json={"email": "e@x.com"})
    b = client.post("/api/v1/auth/password-reset/request", json={"email": "no@x.com"})
    assert a.status_code == b.status_code == 202 and a.json() == b.json()


def test_token_not_logged_in_production(client, db, caplog):
    make_user(db, "e@x.com")
    with caplog.at_level(logging.WARNING):
        client.post("/api/v1/auth/password-reset/request", json={"email": "e@x.com"})
    raw_hashes = [t.token_hash for t in db.query(PasswordResetToken)]
    assert raw_hashes and not any(h in caplog.text for h in raw_hashes)
    assert "token for" not in caplog.text


def test_reset_flow_single_use_and_logs_out_everywhere(client, db, caplog):
    make_user(db, "e@x.com")
    client.post("/api/v1/auth/login", json={"email": "e@x.com", "password": PW})
    tok = get_token(client, caplog)
    assert tok
    r = client.post("/api/v1/auth/password-reset/confirm", json={"token": tok, "new_password": NEWPW})
    assert r.status_code == 204
    assert all(t.revoked_at for t in db.query(RefreshToken))
    assert client.post("/api/v1/auth/login", json={"email": "e@x.com", "password": PW}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "e@x.com", "password": NEWPW}).status_code == 200
    again = client.post("/api/v1/auth/password-reset/confirm", json={"token": tok, "new_password": NEWPW})
    assert again.status_code == 400  # single use


def test_expired_and_weak_and_bogus_tokens(client, db, caplog):
    make_user(db, "e@x.com")
    tok = get_token(client, caplog)
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": tok, "new_password": "weak"}).status_code == 422
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": "x" * 40, "new_password": NEWPW}).status_code == 400
    t = db.query(PasswordResetToken).first()
    t.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": tok, "new_password": NEWPW}).status_code == 400


def test_new_request_invalidates_previous_token(client, db, caplog):
    make_user(db, "e@x.com")
    first = get_token(client, caplog)
    caplog.clear()
    second = get_token(client, caplog)
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": first, "new_password": NEWPW}).status_code == 400
    assert client.post("/api/v1/auth/password-reset/confirm",
                       json={"token": second, "new_password": NEWPW}).status_code == 204


def test_departments_admin_only_create_and_assign(client, db):
    make_user(db, "adm@x.com", Role.admin)
    make_user(db, "e@x.com")
    tok = lambda e: {"Authorization": "Bearer " + client.post(
        "/api/v1/auth/login", json={"email": e, "password": PW}).json()["access_token"]}
    assert client.post("/api/v1/departments", json={"name": "Eng"}, headers=tok("e@x.com")).status_code == 403
    r = client.post("/api/v1/departments", json={"name": "Eng"}, headers=tok("adm@x.com"))
    assert r.status_code == 201
    assert client.post("/api/v1/departments", json={"name": "Eng"}, headers=tok("adm@x.com")).status_code == 409
    assert len(client.get("/api/v1/departments", headers=tok("e@x.com")).json()) == 1
