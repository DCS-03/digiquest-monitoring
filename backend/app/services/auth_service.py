from datetime import datetime, timedelta, timezone
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.core import security
from app.core.config import get_settings
from app.models import AuditLog, RefreshToken, User, new_id

MAX_FAILED = 5
LOCK_MINUTES = 15
# Verified against when the email is unknown, so timing doesn't reveal valid accounts.
_DUMMY_HASH = security.hash_password("dummy-Password-123")


class AuthError(Exception):
    pass


def audit(db: Session, action: str, actor_id=None, target_type=None, target_id=None, ip=None, detail=None):
    db.add(AuditLog(actor_id=actor_id, action=action, target_type=target_type,
                    target_id=target_id, ip_address=ip, detail=detail))


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def authenticate(db: Session, email: str, password: str, ip: str | None) -> User:
    now = datetime.now(timezone.utc)
    user = db.scalar(select(User).where(User.email == email.lower()))
    if not user:
        security.verify_password(password, _DUMMY_HASH)
        audit(db, "auth.login_failed", ip=ip, detail={"reason": "unknown_user"})
        db.commit()
        raise AuthError("Invalid credentials")
    locked = bool(user.locked_until and _aware(user.locked_until) > now)
    ok = security.verify_password(password, user.password_hash)
    if locked or not user.is_active or not ok:
        if not locked:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
        audit(db, "auth.login_failed", actor_id=user.id, ip=ip)
        db.commit()
        raise AuthError("Invalid credentials")  # identical for every failure cause
    user.failed_logins = 0
    user.locked_until = None
    audit(db, "auth.login", actor_id=user.id, ip=ip)
    return user


def issue_refresh(db: Session, user: User, family_id: str | None = None) -> str:
    raw, hashed = security.new_refresh_token()
    exp = datetime.now(timezone.utc) + timedelta(days=get_settings().REFRESH_TOKEN_EXPIRE_DAYS)
    db.add(RefreshToken(user_id=user.id, family_id=family_id or new_id(), token_hash=hashed, expires_at=exp))
    return raw


def _revoke_family(db: Session, family_id: str):
    db.execute(update(RefreshToken).where(RefreshToken.family_id == family_id,
                                          RefreshToken.revoked_at.is_(None))
               .values(revoked_at=datetime.now(timezone.utc)))


def rotate_refresh(db: Session, raw: str, ip: str | None) -> tuple[User, str]:
    rt = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == security.hash_token(raw)))
    if not rt:
        raise AuthError("Invalid session")
    if rt.revoked_at is not None:  # reuse of a rotated token: assume theft, kill the family
        _revoke_family(db, rt.family_id)
        audit(db, "auth.refresh_reuse_detected", actor_id=rt.user_id, ip=ip)
        db.commit()
        raise AuthError("Invalid session")
    if _aware(rt.expires_at) < datetime.now(timezone.utc) or not rt.user.is_active:
        raise AuthError("Session expired")
    rt.revoked_at = datetime.now(timezone.utc)
    return rt.user, issue_refresh(db, rt.user, rt.family_id)


def revoke_session(db: Session, raw: str):
    rt = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == security.hash_token(raw)))
    if rt:
        _revoke_family(db, rt.family_id)
        audit(db, "auth.logout", actor_id=rt.user_id)
