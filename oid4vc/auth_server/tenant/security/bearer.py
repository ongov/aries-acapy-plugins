"""Bearer auth helper for issuer-facing tenant endpoints (grants, introspect)."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from tenant.config import settings


security = HTTPBearer(auto_error=False)


def require_bearer(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> bool:
    """Validate Bearer token against ISSUER_AUTH_TOKEN."""
    token = credentials.credentials if credentials else ""
    expected = settings.ISSUER_AUTH_TOKEN or ""
    if not token or token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True
