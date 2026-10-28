import hashlib
import secrets
from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from app.core.config import get_settings

# argon2-cffi defaults to Argon2id. Parameters follow OWASP guidance (m>=19MiB, t>=2).
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
ALGO = "HS256"


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def validate_password_strength(pw: str) -> None:
    if len(pw) < 12:
        raise ValueError("Password must be at least 12 characters")
    if pw.lower() == pw or pw.upper() == pw or not any(c.isdigit() for c in pw):
        raise ValueError("Password needs upper and lower case letters and a digit")


def create_access_token(user_id: str, role: str) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": user_id, "role": role, "type": "access", "iat": now,
               "exp": now + timedelta(minutes=s.ACCESS_TOKEN_EXPIRE_MINUTES)}
    return jwt.encode(payload, s.SECRET_KEY, algorithm=ALGO)


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(token, get_settings().SECRET_KEY, algorithms=[ALGO])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(48)
    return raw, hash_token(raw)
