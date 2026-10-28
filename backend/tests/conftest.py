import os
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ["COOKIE_SECURE"] = "false"
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import Role, User

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestSession = sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def db():
    Base.metadata.create_all(engine)
    s = TestSession()
    yield s
    s.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    app.dependency_overrides.clear()


def make_user(db, email, role=Role.employee, pw="Str0ngPassw0rd!"):
    u = User(email=email, full_name=email.split("@")[0], role=role, password_hash=hash_password(pw))
    db.add(u)
    db.commit()
    return u


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    from app.core.limiter import limiter
    limiter.reset()
    yield
    limiter.reset()
