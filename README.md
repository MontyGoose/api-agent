# FastAPI Web Service Starter (Opinionated)

This starter gives you a **production-leaning FastAPI** stack with **Uvicorn**, **Typer CLI**,
**JWT auth hooks**, **ruff + mypy**, **pytest**, **pydantic-settings**, and a clean, modular API layout.

It assumes you're comfortable with engineering concepts but not necessarily a Python expert.

---

## Why this stack

- **FastAPI + Uvicorn**: async-first, excellent performance, OpenAPI by default.
- **`src/` layout**: prevents import foot-guns and keeps packaging clean.
- **Typer CLI**: first-class command-line tasks (`runserver`, `gen-secret`).
- **pydantic-settings**: 12‑factor configuration via env vars and `.env`.
- **structlog**: JSON logs that play nicely with containers/observability tooling.
- **pytest + httpx**: fast async tests with simple ergonomics.
- **ruff + mypy + pre-commit**: opinionated linting, formatting, typing, and hooks.

---

## Prereqs

- Python **3.11+** (3.12 is great)
- One of:
  - **uv** (`curl -LsSf https://astral.sh/uv/install.sh | sh`) — recommended
  - or **pipx** / **venv + pip**
- (Optional) **direnv** to auto-load `.env`

---

## 1) Bootstrap

```bash
# Clone or unzip this template
unzip fastapi-starter.zip && cd fastapi-starter

# Create and activate venv (choose one)

# Preferred: uv (creates .venv and installs)
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Alternative: venv + pip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## 2) Project structure (src layout)

```
fastapi-starter/
├─ src/
│  └─ app/
│     ├─ main.py                 # app factory + wiring
│     ├─ cli.py                  # Typer CLI
│     ├─ core/
│     │  ├─ config.py            # Settings via pydantic-settings
│     │  ├─ logging.py           # structlog config
│     │  └─ security.py          # JWT helpers
│     ├─ api/
│     │  ├─ deps.py              # DI, auth, role-checks
│     │  └─ routes/
│     │     ├─ health.py         # /healthz
│     │     └─ v1/
│     │        ├─ auth.py        # /api/v1/auth/token
│     │        ├─ hello.py       # /api/v1/hello
│     │        └─ items.py       # example resource
│     └─ models/
│        └─ schemas.py           # Pydantic models
├─ tests/
│  ├─ conftest.py
│  └─ test_health.py
├─ .env.example
├─ .gitignore
├─ .pre-commit-config.yaml
├─ Dockerfile
├─ Makefile
├─ pyproject.toml
└─ README.md
```

---

## 3) Environment variables

Copy `.env.example` to `.env` (never commit secrets):

```bash
cp .env.example .env
```

Key vars:

- `ENV` — `local`|`dev`|`prod`
- `DEBUG` — `true|false`
- `SECRET_KEY` — for JWT (use `app cli gen-secret`)
- `ALLOWED_ORIGINS` — comma-separated CORS origins
- `ACCESS_TOKEN_EXPIRE_MINUTES` — JWT expiry

---

## 4) Run the app

**With Typer CLI (preferred):**

```bash
python -m app.cli runserver --host 0.0.0.0 --port 8000
```

**Direct Uvicorn:**

```bash
uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --reload
```

OpenAPI docs:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 5) Testing, linting, typing

```bash
# run tests
pytest

# lint + format (ruff does both)
ruff check .
ruff format .

# type-check
mypy src
```

Pre-commit (recommended):

```bash
pre-commit install
pre-commit run --all-files
```

---

## 6) Security (JWT & role-based authorization)

- Token endpoint: `POST /api/v1/auth/token` (demo: accepts any username, returns a JWT with roles).
- Guard endpoints with dependencies in `api/deps.py`:
  - `get_current_user`
  - `require_roles("admin")`

Replace the demo token-issuing logic with your identity provider or user store.
Use asymmetric keys (RS256) in production.

---

## 7) Adding a new API namespace

- Create a new router under `src/app/api/routes/v1/<your_ns>.py`
- Tag it and include it in `app/main.py` via `include_router`.
- Versioning: keep under `/api/v1/…`; new breaking versions go to `/api/v2`.

---

## 8) Observability & ops

- **Healthcheck**: `GET /healthz`
- **JSON logs** via structlog; can be scraped by your log stack
- Add **metrics** (Prometheus or OpenTelemetry) when you’re ready
- **Docker**: production image uses `uvicorn` served by `gunicorn` workers

---

## 9) Makefile snippets

```bash
make dev     # runserver with reload
make test    # pytest + coverage (extend as needed)
make lint    # ruff check
make format  # ruff format
```

---

## 10) Industry best practices

- 12‑factor config; no secrets in code. Use `.env` only for local.
- `.gitignore` tuned for Python, venvs, caches, IDEs. (Inspired by toptal gitignore generator.)
- Keep handlers small; push logic to `services/` (add the folder when needed).
- Prefer **pydantic** models at the edges and type hints everywhere.
- Strict CI: ruff, mypy, pytest on PRs.

---

Happy shipping!
