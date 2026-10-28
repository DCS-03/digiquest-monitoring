import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.core.security import hash_password, hash_token, validate_password_strength
from app.models import PasswordResetToken, RefreshToken, User
from app.services.auth_service import AuthError, audit
from app.services.mailer import send_password_reset

TTL_MINUTES = 60


def request_reset(db: Session, email: str, ip: str | None) -> None:
    """Never reveals whether the email exists."""
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user and user.is_active:
        raw = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        db.execute(update(PasswordResetToken).where(PasswordResetToken.user_id == user.id,
                                                    PasswordResetToken.used_at.is_(None)).values(used_at=now))
        db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(raw),
                                  expires_at=now + timedelta(minutes=TTL_MINUTES)))
        audit(db, "auth.password_reset_requested", actor_id=user.id, ip=ip)
        db.commit()
        send_password_reset(user.email, raw)
    else:
        db.commit()


def confirm_reset(db: Session, raw: str, new_password: str, ip: str | None) -> None:
    validate_password_strength(new_password)
    t = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw)))
    now = datetime.now(timezone.utc)
    exp = t.expires_at if t and t.expires_at.tzinfo else (t.expires_at.replace(tzinfo=timezone.utc) if t else None)
    if not t or t.used_at is not None or exp < now:
        raise AuthError("Invalid or expired token")
    user = db.get(User, t.user_id)
    if not user or not user.is_active:
        raise AuthError("Invalid or expired token")
    user.password_hash = hash_password(new_password)
    user.failed_logins, user.locked_until = 0, None
    t.used_at = now
    # A password reset signs the user out everywhere.
    db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id,
                                          RefreshToken.revoked_at.is_(None)).values(revoked_at=now))
    audit(db, "auth.password_reset_completed", actor_id=user.id, ip=ip)
    db.commit()
