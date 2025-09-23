# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

COPY pyproject.toml README.md ./
COPY src ./src

RUN /root/.local/bin/uv venv && . .venv/bin/activate && /root/.local/bin/uv pip install -e ".[dev]"

EXPOSE 8000

RUN useradd -m appuser
USER appuser

CMD [".venv/bin/gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8000", "app.main:create_app", "--log-level", "info", "--timeout", "60"]
