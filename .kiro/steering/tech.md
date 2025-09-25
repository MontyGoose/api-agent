# Technology Stack

## Core Framework
- **FastAPI** (>=0.110.0) - Modern async web framework with automatic OpenAPI generation
- **Uvicorn** with standard extras - ASGI server for production
- **Python 3.11+** (3.12 recommended) - Modern Python with latest performance improvements

## Key Libraries
- **Pydantic** (>=2.6.0) - Data validation and settings management
- **pydantic-settings** - 12-factor configuration via environment variables
- **structlog** - Structured JSON logging for observability
- **Typer** - CLI interface for development tasks
- **PyJWT** - JWT token handling for authentication
- **python-multipart** - Form data handling

## Development Tools
- **pytest** + **pytest-asyncio** - Async testing framework
- **httpx** - HTTP client for testing APIs
- **ruff** - Fast Python linter and formatter (replaces black, isort, flake8)
- **mypy** - Static type checking
- **pre-commit** - Git hooks for code quality

## Build System
- **setuptools** - Standard Python packaging
- **uv** (recommended) or **pip** - Package management
- **Docker** - Containerization with multi-stage builds

## Common Commands

### Development
```bash
# Start development server with reload
make dev
# or
python -m app.cli runserver --reload

# Run tests
make test
# or
pytest

# Lint and format code
make lint format
# or
ruff check . && ruff format .

# Type checking
make type
# or
mypy src
```

### CLI Tools
```bash
# Generate JWT secret
python -m app.cli gen-secret

# Run server with custom options
python -m app.cli runserver --host 0.0.0.0 --port 8000
```

### Docker
```bash
# Build image
docker build -t fastapi-starter .

# Run container
docker run -p 8000:8000 fastapi-starter
```

## Code Quality Standards
- **Line length**: 100 characters (ruff configured)
- **Type hints**: Required for all function definitions (mypy enforced)
- **Import sorting**: Automatic via ruff
- **Quote style**: Double quotes preferred
- **Async/await**: Use async patterns throughout
- **Error handling**: Structured exceptions with proper HTTP status codes