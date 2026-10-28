from datetime import date
from pydantic import BaseModel, EmailStr, Field, field_validator
from app.core.security import validate_password_strength
from app.models import Role


class EmployeeCreate(BaseModel):
    employee_code: str = Field(min_length=1, max_length=40)
    full_name: str = Field(min_length=1, max_length=160)
    email: EmailStr
    password: str
    role: Role = Role.employee
    department_id: str | None = None
    designation: str | None = Field(default=None, max_length=120)
    joining_date: date | None = None

    @field_validator("password")
    @classmethod
    def strong(cls, v):
        validate_password_strength(v)
        return v


class EmployeeUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=160)
    department_id: str | None = None
    designation: str | None = Field(default=None, max_length=120)
    joining_date: date | None = None
    is_active: bool | None = None


class EmployeeOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    employee_code: str | None
    full_name: str
    email: str
    role: Role
    department_id: str | None
    designation: str | None
    joining_date: date | None
    is_active: bool


class EmployeePage(BaseModel):
    items: list[EmployeeOut]
    total: int
    page: int
    page_size: int
