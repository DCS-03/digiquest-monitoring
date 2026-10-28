"""Safe bootstrap: python -m app.create_admin --email a@b.com --name "Name"
Password comes from a hidden prompt (or ADMIN_PASSWORD env var); never hardcoded."""
import argparse
import getpass
import os
import sys
from sqlalchemy import select
from app.core.security import hash_password, validate_password_strength
from app.database import SessionLocal
from app.models import Role, User
from app.services.auth_service import audit


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--email", default=os.environ.get("ADMIN_EMAIL"))
    p.add_argument("--name", default=os.environ.get("ADMIN_NAME", "Administrator"))
    p.add_argument("--skip-if-exists", action="store_true", help="exit 0 quietly if a super admin exists")
    a = p.parse_args()
    if not a.email:
        sys.exit("--email or ADMIN_EMAIL is required")
    pw = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Password: ")
    try:
        validate_password_strength(pw)
    except ValueError as e:
        sys.exit(str(e))
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.role == Role.super_admin)):
            if a.skip_if_exists:
                print("Super admin already exists; skipping.")
                return
            sys.exit("A super admin already exists; refusing to create another.")
        u = User(email=a.email.lower(), full_name=a.name, role=Role.super_admin,
                 password_hash=hash_password(pw))
        db.add(u)
        db.flush()
        audit(db, "admin.bootstrap", actor_id=u.id)
        db.commit()
    print("Super admin created.")


if __name__ == "__main__":
    main()
