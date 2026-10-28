from app.models import AuditLog, Role
from app.core.limiter import limiter
from tests.conftest import make_user

PW = "Str0ngPassw0rd!"
NEW = {"employee_code": "E100", "full_name": "New Person", "email": "new@x.com", "password": PW}


def hdr(client, email):
    limiter.reset()
    t = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}


def test_employee_cannot_list_or_create(client, db):
    make_user(db, "e@x.com")
    h = hdr(client, "e@x.com")
    assert client.get("/api/v1/employees", headers=h).status_code == 403
    assert client.post("/api/v1/employees", json=NEW, headers=h).status_code == 403


def test_employee_data_isolation(client, db):
    a, b = make_user(db, "a@x.com"), make_user(db, "b@x.com")
    h = hdr(client, "a@x.com")
    assert client.get(f"/api/v1/employees/{a.id}", headers=h).status_code == 200
    assert client.get(f"/api/v1/employees/{b.id}", headers=h).status_code == 404


def test_admin_create_list_search_and_audit(client, db):
    make_user(db, "adm@x.com", Role.admin)
    h = hdr(client, "adm@x.com")
    r = client.post("/api/v1/employees", json=NEW, headers=h)
    assert r.status_code == 201 and "password" not in r.json()
    assert client.post("/api/v1/employees", json=NEW, headers=h).status_code == 409
    res = client.get("/api/v1/employees?search=New", headers=h).json()
    assert res["total"] == 1 and res["items"][0]["email"] == "new@x.com"
    assert db.query(AuditLog).filter_by(action="employee.create").count() == 1


def test_weak_password_rejected(client, db):
    make_user(db, "adm@x.com", Role.admin)
    h = hdr(client, "adm@x.com")
    assert client.post("/api/v1/employees", json={**NEW, "password": "short"}, headers=h).status_code == 422


def test_admin_cannot_create_admin_but_super_admin_can(client, db):
    make_user(db, "adm@x.com", Role.admin)
    make_user(db, "sup@x.com", Role.super_admin)
    body = {**NEW, "role": "admin"}
    assert client.post("/api/v1/employees", json=body, headers=hdr(client, "adm@x.com")).status_code == 403
    assert client.post("/api/v1/employees", json=body, headers=hdr(client, "sup@x.com")).status_code == 201


def test_deactivation_revokes_access_and_blocks_self_deactivate(client, db):
    adm = make_user(db, "adm@x.com", Role.admin)
    emp = make_user(db, "e@x.com")
    ha, he = hdr(client, "adm@x.com"), hdr(client, "e@x.com")
    assert client.patch(f"/api/v1/employees/{adm.id}", json={"is_active": False}, headers=ha).status_code == 400
    assert client.patch(f"/api/v1/employees/{emp.id}", json={"is_active": False}, headers=ha).status_code == 200
    assert client.get("/api/v1/auth/me", headers=he).status_code == 401


def test_login_rate_limited(client, db):
    limiter.reset()
    codes = [client.post("/api/v1/auth/login", json={"email": "z@x.com", "password": "x"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429
    limiter.reset()
