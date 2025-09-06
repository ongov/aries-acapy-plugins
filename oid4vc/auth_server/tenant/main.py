"""Tenant API."""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Path, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from core.logging import get_logger
from core.observability import RequestContextMiddleware, setup_structlog_json
from tenant.config import settings

from .deps import get_db_session
from .routers.grants import router as grants_router
from .routers.introspect import router as introspect_router
from .routers.token import router as token_router
from .routers.well_known import router as well_known_router

logger = get_logger(__name__)

root_path = settings.APP_ROOT_PATH


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hooks."""
    setup_structlog_json()
    yield


app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    openapi_url=f"{root_path}{settings.OPENAPI_URL}",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    root_path=root_path,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
)
app.add_middleware(RequestContextMiddleware)

app.include_router(well_known_router)
app.include_router(token_router)
app.include_router(grants_router)
app.include_router(introspect_router)


@app.get("/tenants/{uid}/healthz")
async def health_check(
    uid: str = Path(...), sess: AsyncSession = Depends(get_db_session)
):
    """Simple health check."""
    return {"ok": True}


@app.exception_handler(Exception)
async def log_unhandled_exception(request: Request, exc: Exception):
    """Log unhandled exceptions with request context."""
    logger.exception(
        "unhandled_exception",
        method=request.method,
        path=request.url.path,
        path_params=dict(request.path_params),
    )
    return ORJSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error"},
    )
