from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import init_logging, get_logger
from app.api.routes.health import router as health_router
from app.api.routes.v1.hello import router as hello_router
from app.api.routes.v1.items import router as items_router
from app.api.routes.v1.auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_logging(debug=settings.DEBUG)
    log = get_logger("startup")
    log.info("app.startup", env=settings.ENV, debug=settings.DEBUG, version=settings.VERSION)
    yield
    log = get_logger("shutdown")
    log.info("app.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_PREFIX}/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS or ["*"] if settings.DEBUG else settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(hello_router)
    app.include_router(items_router)

    return app
