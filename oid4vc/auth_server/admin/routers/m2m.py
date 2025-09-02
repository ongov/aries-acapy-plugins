"""API for tenant M2M helpers: DB info, JWKS, JWT signing."""

from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.security.bearer import require_m2m_bearer
from admin.schemas.m2m import (
    JwtSignRequest,
    JwtSignResponse,
    TenantDbResponse,
    TenantJwksResponse,
)
from admin.services.m2m_service import get_tenant_db, get_tenant_jwks
from admin.services.signing_service import sign_tenant_jwt

router = APIRouter(prefix="/tenants/{uid}", dependencies=[Depends(require_m2m_bearer)])


@router.get("/db", response_model=TenantDbResponse)
async def get_db(
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Return tenant DB connect URL and schema."""
    return await get_tenant_db(db, uid)


@router.get("/jwks", response_model=TenantJwksResponse)
async def get_jwks(
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Return public JWKS for the tenant."""
    return await get_tenant_jwks(db, uid)


@router.post("/jwts", response_model=JwtSignResponse, response_model_exclude_none=True)
async def sign_jwt(
    body: JwtSignRequest,
    uid: str = Path(...),
    db: AsyncSession = Depends(get_db_session),
):
    """Sign a JWT for the tenant."""
    return await sign_tenant_jwt(db, uid, body)
