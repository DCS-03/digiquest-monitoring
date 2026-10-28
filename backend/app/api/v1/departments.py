from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.api.deps import current_user, require_admin
from app.database import get_db
from app.models import Department, User
from app.services.auth_service import audit

router = APIRouter(prefix="/departments", tags=["departments"])


class DeptIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class DeptOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    name: str


@router.get("", response_model=list[DeptOut])
def list_departments(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return db.scalars(select(Department).order_by(Department.name)).all()


@router.post("", response_model=DeptOut, status_code=201)
def create_department(body: DeptIn, request: Request, db: Session = Depends(get_db),
                      actor: User = Depends(require_admin)):
    name = body.name.strip()
    if db.scalar(select(Department).where(Department.name == name)):
        raise HTTPException(409, "Department already exists")
    d = Department(name=name)
    db.add(d)
    db.flush()
    audit(db, "department.create", actor.id, "department", d.id,
          request.client.host if request.client else None)
    db.commit()
    return d
