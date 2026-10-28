import jwt
import pytest
from fastapi import HTTPException
from app.api.deps import ensure_self_or_admin
from app.core.security import hash_password, verify_password
from app.models import RefreshToken, Role, User
from tests.conftest import make_user

PW = "Str0ngPassw0rd!"


def login(client, email="e@x.com", pw=PW):
    return client.post("/api/v1/auth/login", json={"email": email, "password": pw})


def test_argon2id_hash():
    h = hash_password(PW)
    assert h.startswith("$argon2id$") and verify_password(PW, h) and not verify_password("bad", h)


def test_login_success_sets_httponly_cookie(client, db):
    make_user(db, "e@x.com")
    r = login(client)
    assert r.status_code == 200 and r.json()["access_token"]
    assert "httponly" in r.headers["set-cookie"].lower()


def test_login_failure_is_generic(client, db):
    make_user(db, "e@x.com")
    a, b = login(client, pw="wrong"), login(client, email="nobody@x.com")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_lockout_after_repeated_failures(client, db):
    make_user(db, "e@x.com")
    for _ in range(5):
        login(client, pw="wrong")
    assert login(client).status_code == 401  # correct password still locked out


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_tampered_token_rejected(client, db):
    make_user(db, "e@x.com")
    tok = login(client).json()["access_token"]
    bad = jwt.encode({"sub": "x", "type": "access"}, "y" * 48, algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 200


def test_refresh_rotates_and_reuse_revokes_family(client, db):
    make_user(db, "e@x.com")
    login(client)
    old = client.cookies.get("refresh_token")
    assert client.post("/api/v1/auth/refresh").status_code == 200
    new = client.cookies.get("refresh_token")
    assert new != old
    client.cookies.set("refresh_token", old, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401  # reuse detected
    client.cookies.set("refresh_token", new, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401  # family revoked
    assert all(t.revoked_at for t in db.query(RefreshToken))


def test_logout_revokes_session(client, db):
    make_user(db, "e@x.com")
    login(client)
    tok = client.cookies.get("refresh_token")
    assert client.post("/api/v1/auth/logout").status_code == 204
    client.cookies.set("refresh_token", tok, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_deactivated_user_loses_access(client, db):
    u = make_user(db, "e@x.com")
    tok = login(client).json()["access_token"]
    u.is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_self_access_guard():
    emp, adm = User(id="1", role=Role.employee), User(id="2", role=Role.admin)
    ensure_self_or_admin(emp, "1")
    ensure_self_or_admin(adm, "1")
    with pytest.raises(HTTPException):
        ensure_self_or_admin(emp, "2")
