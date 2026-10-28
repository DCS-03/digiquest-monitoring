import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.security import decode_access_token
from app.database import get_db
from app.models import Role, User

bearer = HTTPBearer(auto_error=False)


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    unauth = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated",
                           headers={"WWW-Authenticate": "Bearer"})
    if not cred:
        raise unauth
    try:
        payload = decode_access_token(cred.credentials)
    except jwt.PyJWTError:
        raise unauth
    user = db.get(User, payload["sub"])
    if not user or not user.is_active:  # role always comes from the DB, not the token
        raise unauth
    return user


def require_roles(*roles: Role):
    def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return checker


require_admin = require_roles(Role.admin, Role.super_admin)


def ensure_self_or_admin(user: User, employee_id: str) -> None:
    """Employees may only access their own records (404 avoids confirming others exist)."""
    if user.role == Role.employee and user.id != employee_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
