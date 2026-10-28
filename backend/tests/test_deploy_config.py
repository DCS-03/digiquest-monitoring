import os
import pytest
from sqlalchemy import select
from app.core.config import Settings
from app.models import Role, User
from app.create_admin import main as create_admin_main


@pytest.mark.parametrize("src,expected", [
    ("postgres://u:p@h:5432/d", "postgresql+psycopg://u:p@h:5432/d"),
    ("postgresql://u:p@h/d", "postgresql+psycopg://u:p@h/d"),
    ("postgresql+psycopg://u:p@h/d", "postgresql+psycopg://u:p@h/d"),
    ("sqlite:///./dev.db", "sqlite:///./dev.db"),
])
def test_database_url_normalised(src, expected):
    assert Settings(DATABASE_URL=src, SECRET_KEY="k" * 40).DATABASE_URL == expected


def test_create_admin_env_bootstrap_is_idempotent(db, monkeypatch):
    import app.create_admin as ca
    monkeypatch.setattr(ca, "SessionLocal", lambda: __import__("tests.conftest", fromlist=["x"]).TestSession())
    monkeypatch.setenv("ADMIN_EMAIL", "Boss@x.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "Str0ngPassw0rd!")
    monkeypatch.setattr("sys.argv", ["create_admin", "--skip-if-exists"])
    ca.main()
    ca.main()  # second run must not fail or duplicate
    admins = db.scalars(select(User).where(User.role == Role.super_admin)).all()
    assert len(admins) == 1 and admins[0].email == "boss@x.com"
