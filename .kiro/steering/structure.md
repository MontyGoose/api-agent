# Project Structure

## Layout Philosophy
This project uses the **src layout** to prevent import issues and maintain clean packaging. All application code lives under `src/app/` with a clear separation of concerns.

## Directory Structure

```
fastapi-starter/
├── src/app/                    # Main application package
│   ├── main.py                 # FastAPI app factory and router wiring
│   ├── cli.py                  # Typer CLI commands
│   ├── core/                   # Core application logic
│   │   ├── config.py           # Settings via pydantic-settings
│   │   ├── logging.py          # structlog configuration
│   │   └── security.py         # JWT helpers and auth utilities
│   ├── api/                    # API layer
│   │   ├── deps.py             # Dependency injection, auth, role checks
│   │   └── routes/             # Route handlers organized by feature
│   │       ├── health.py       # Health check endpoint (/healthz)
│   │       └── v1/             # API version 1
│   │           ├── auth.py     # Authentication endpoints
│   │           ├── hello.py    # Example endpoints
│   │           └── items.py    # Resource CRUD examples
│   └── models/                 # Data models
│       └── schemas.py          # Pydantic models for request/response
├── tests/                      # Test suite
│   ├── conftest.py             # Pytest configuration and fixtures
│   └── test_*.py               # Test modules matching source structure
├── .env.example                # Environment variable template
├── .gitignore                  # Git ignore rules
├── .pre-commit-config.yaml     # Pre-commit hooks configuration
├── Dockerfile                  # Container build instructions
├── Makefile                    # Development shortcuts
├── pyproject.toml              # Project metadata and tool configuration
└── README.md                   # Project documentation
```

## Architectural Patterns

### Application Factory Pattern
- `main.py` contains `create_app()` factory function
- Lifespan events handle startup/shutdown logic
- Middleware and routers configured in factory

### Dependency Injection
- `api/deps.py` contains reusable dependencies
- Authentication and authorization via FastAPI dependencies
- Use `Annotated` types for dependency documentation

### Router Organization
- Health checks at root level (`/healthz`)
- API routes versioned under `/api/v1/`
- Group related endpoints in separate router files
- Tag routers for OpenAPI organization

### Configuration Management
- All settings in `core/config.py` using pydantic-settings
- Environment-based configuration with `.env` support
- Cached settings instance via `@lru_cache`

### Model Organization
- Request/response models in `models/schemas.py`
- Use Pydantic models for all API boundaries
- Separate internal models from API schemas when needed

## Naming Conventions

### Files and Modules
- Snake_case for Python files and modules
- Descriptive names that indicate purpose
- Test files prefixed with `test_`

### API Endpoints
- RESTful resource naming (`/items`, `/users`)
- Kebab-case for multi-word resources
- Version prefix for all API routes (`/api/v1/`)

### Functions and Variables
- Snake_case for functions and variables
- Async functions clearly indicate async nature
- Dependency functions start with `get_` or `require_`

## Adding New Features

### New API Endpoint
1. Create router in `api/routes/v1/feature.py`
2. Define Pydantic models in `models/schemas.py`
3. Add router to `main.py` with appropriate tags
4. Write tests in `tests/test_feature.py`

### New Configuration
1. Add field to `Settings` class in `core/config.py`
2. Update `.env.example` with new variable
3. Document in README.md

### New Dependency
1. Add to `api/deps.py` if reusable
2. Use `Annotated` type hints for clarity
3. Handle errors with appropriate HTTP exceptions