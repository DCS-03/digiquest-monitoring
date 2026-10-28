from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from app.api.deps import current_user, ensure_self_or_admin, require_admin
from app.core.security import hash_password
from app.database import get_db
from app.models import RefreshToken, Role, User
from app.schemas.employee import EmployeeCreate, EmployeeOut, EmployeePage, EmployeeUpdate
from app.services.auth_service import audit
from datetime import datetime, timezone
from sqlalchemy import update

router = APIRouter(prefix="/employees", tags=["employees"])


def _ip(req: Request):
    return req.client.host if req.client else None


@router.get("", response_model=EmployeePage)
def list_employees(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                   search: str | None = Query(None, max_length=100),
                   department_id: str | None = None, is_active: bool | None = None,
                   db: Session = Depends(get_db), _: User = Depends(require_admin)):
    q = select(User)
    if search:
        like = f"%{search}%"
        q = q.where(or_(User.full_name.ilike(like), User.email.ilike(like), User.employee_code.ilike(like)))
    if department_id:
        q = q.where(User.department_id == department_id)
    if is_active is not None:
        q = q.where(User.is_active == is_active)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    items = db.scalars(q.order_by(User.full_name).offset((page - 1) * page_size).limit(page_size)).all()
    return EmployeePage(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=EmployeeOut, status_code=201)
def create_employee(body: EmployeeCreate, request: Request, db: Session = Depends(get_db),
                    actor: User = Depends(require_admin)):
    # Only a super admin can create admin-level accounts.
    if body.role != Role.employee and actor.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can create admin accounts")
    if db.scalar(select(User).where(or_(User.email == body.email.lower(),
                                        User.employee_code == body.employee_code))):
        raise HTTPException(409, "Email or employee ID already exists")
    data = body.model_dump(exclude={"password", "email"})
    u = User(**data, email=body.email.lower(), password_hash=hash_password(body.password))
    db.add(u)
    db.flush()
    audit(db, "employee.create", actor.id, "user", u.id, _ip(request))
    db.commit()
    return u


@router.get("/{employee_id}", response_model=EmployeeOut)
def get_employee(employee_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ensure_self_or_admin(user, employee_id)
    u = db.get(User, employee_id)
    if not u:
        raise HTTPException(404, "Not found")
    return u


@router.patch("/{employee_id}", response_model=EmployeeOut)
def update_employee(employee_id: str, body: EmployeeUpdate, request: Request,
                    db: Session = Depends(get_db), actor: User = Depends(require_admin)):
    u = db.get(User, employee_id)
    if not u:
        raise HTTPException(404, "Not found")
    changes = body.model_dump(exclude_unset=True)
    if changes.get("is_active") is False and u.id == actor.id:
        raise HTTPException(400, "You cannot deactivate your own account")
    if u.role != Role.employee and actor.role != Role.super_admin:
        raise HTTPException(403, "Only a super admin can modify admin accounts")
    for k, v in changes.items():
        setattr(u, k, v)
    if changes.get("is_active") is False:  # deactivation kills all sessions immediately
        db.execute(update(RefreshToken).where(RefreshToken.user_id == u.id, RefreshToken.revoked_at.is_(None))
                   .values(revoked_at=datetime.now(timezone.utc)))
    audit(db, "employee.update", actor.id, "user", u.id, _ip(request), {"fields": list(changes)})
    db.commit()
    return u
