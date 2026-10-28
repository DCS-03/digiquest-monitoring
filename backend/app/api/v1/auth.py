from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from app.api.deps import current_user
from app.core.limiter import limiter
from app.core.config import get_settings
from app.core.security import create_access_token
from app.database import get_db
from app.models import User
from app.schemas.auth import LoginRequest, ResetConfirm, ResetRequest, TokenResponse, UserOut
from app.services import password_reset as pr
from app.services import auth_service as svc

router = APIRouter(prefix="/auth", tags=["auth"])
COOKIE = "refresh_token"
COOKIE_PATH = "/api/v1/auth"


def _set_cookie(resp: Response, raw: str):
    s = get_settings()
    resp.set_cookie(COOKIE, raw, httponly=True, secure=s.COOKIE_SECURE, samesite="strict",
                    max_age=s.REFRESH_TOKEN_EXPIRE_DAYS * 86400, path=COOKIE_PATH)


def _ip(req: Request):
    return req.client.host if req.client else None


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest, response: Response, db: Session = Depends(get_db)):
    try:
        user = svc.authenticate(db, body.email, body.password, _ip(request))
    except svc.AuthError:
        raise HTTPException(401, "Invalid credentials")
    _set_cookie(response, svc.issue_refresh(db, user))
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id, user.role.value), user=user)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db),
            refresh_token: str | None = Cookie(default=None)):
    if not refresh_token:
        raise HTTPException(401, "Not authenticated")
    try:
        user, new_raw = svc.rotate_refresh(db, refresh_token, _ip(request))
    except svc.AuthError:
        response.delete_cookie(COOKIE, path=COOKIE_PATH)
        raise HTTPException(401, "Session invalid or expired")
    _set_cookie(response, new_raw)
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id, user.role.value), user=user)


@router.post("/logout", status_code=204)
def logout(response: Response, db: Session = Depends(get_db),
           refresh_token: str | None = Cookie(default=None)):
    if refresh_token:
        svc.revoke_session(db, refresh_token)
        db.commit()
    response.delete_cookie(COOKIE, path=COOKIE_PATH)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/password-reset/request", status_code=202)
@limiter.limit("5/minute")
def reset_request(request: Request, body: ResetRequest, db: Session = Depends(get_db)):
    pr.request_reset(db, body.email, _ip(request))
    return {"detail": "If the account exists, a reset link has been sent."}


@router.post("/password-reset/confirm", status_code=204)
@limiter.limit("10/minute")
def reset_confirm(request: Request, body: ResetConfirm, db: Session = Depends(get_db)):
    try:
        pr.confirm_reset(db, body.token, body.new_password, _ip(request))
    except ValueError as e:  # weak password
        raise HTTPException(422, str(e))
    except svc.AuthError:
        raise HTTPException(400, "Invalid or expired token")
