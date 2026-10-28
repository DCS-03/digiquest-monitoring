# DigiQuest Employee Monitoring & Productivity System

Transparent, policy-controlled monitoring of company-authorized devices. No covert capture,
no keylogging, no credential collection.

## Status (honest checklist)

| Area | State |
|---|---|
| Backend auth (Argon2id, JWT access + rotating refresh cookie, lockout, rate limits) | Done, 23 pytest tests passing (SQLite) |
| Password reset (single-use, 60 min, revokes all sessions) | Done, tested. **Email transport not wired**: set `APP_ENV=development` to see the token in logs |
| Employee + department management API, audit logs | Done, tested |
| Alembic migrations 0001, 0002 | Verified on SQLite only; not yet run on PostgreSQL |
| Frontend (Next.js JS + Tailwind): login, Axios client | Written, **not yet built or run** |
| Docker Compose | Written, **not yet run** |
| Devices, activity, agent, screenshots, reports, WebSockets | Not started (Phases 2-5) |

## Run the backend

**Windows (PowerShell)** - run line by line (older PowerShell does not support `&&`):

    cd backend
    python -m venv .venv
    .\.venv\Scripts\pip install -r requirements.txt
    .\.venv\Scripts\python -m pytest -q          # tests need no .env
    copy .env.example .env                          # then edit DATABASE_URL and SECRET_KEY
    .\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(64))"   # use as SECRET_KEY
    .\.venv\Scripts\alembic upgrade head
    .\.venv\Scripts\python -m app.create_admin --email you@company.com --name "Your Name"
    .\.venv\Scripts\uvicorn app.main:app --reload

If scripts are blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. If `python` is not found, use `py`.

**Linux / macOS:**

    cd backend
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python -m pytest -q
    cp .env.example .env
    .venv/bin/alembic upgrade head
    .venv/bin/python -m app.create_admin --email you@company.com --name "Your Name"
    .venv/bin/uvicorn app.main:app --reload

Running the server needs PostgreSQL (see `DATABASE_URL`). API docs: http://localhost:8000/docs

## Run the frontend

    cd frontend
    copy .env.example .env.local     (Linux/macOS: cp)
    npm install
    npm run dev

## Selected versions

Ranges are pinned in `backend/requirements.txt` and `frontend/package.json`
(FastAPI >=0.115, SQLAlchemy 2.0, Pydantic 2, Next.js 15, React 19, Tailwind 4).
Lock files will be generated on first install.

## Security notes

- Access tokens: 15 min, held in memory only. Refresh token: httpOnly, SameSite=Strict cookie, hashed in DB, rotated on use; reuse revokes the whole session family.
- Roles are read from the database on every request, so deactivation applies immediately.
- Set `COOKIE_SECURE=true` (default) behind HTTPS; only use `false` for local http.
- Employees receive 404 (not 403) for other employees' records.
