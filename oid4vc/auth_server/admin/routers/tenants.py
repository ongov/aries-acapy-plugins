"""Admin API for tenant management."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.schemas.tenant import KeyGenIn, KeyStatusIn, TenantIn, TenantOut
from admin.schemas.client import ClientCreateIn, ClientCreateOut
from admin.security.bearer import require_admin_auth
from admin.services.tenant_service import TenantService

router = APIRouter(dependencies=[Depends(require_admin_auth)])


@router.get("/tenants", response_model=list[TenantOut])
async def list_tenants(db: AsyncSession = Depends(get_db_session)):
    """List tenants via repository."""
    svc = TenantService(db)
    rows = await svc.list()
    return [TenantOut.model_validate(r) for r in rows]


@router.get("/tenants/{uid}", response_model=TenantOut)
async def get_tenant(uid: str, db: AsyncSession = Depends(get_db_session)):
    """Get a specific tenant via repository."""
    svc = TenantService(db)
    row = await svc.get(uid)
    if not row:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    return TenantOut.model_validate(row)


@router.post("/tenants", response_model=TenantOut, status_code=201)
async def create_tenant(body: TenantIn, db: AsyncSession = Depends(get_db_session)):
    """Create a new tenant via repository."""
    svc = TenantService(db)
    row = await svc.create(body)
    return TenantOut.model_validate(row)


@router.patch("/tenants/{uid}")
async def update_tenant(
    uid: str, body: TenantIn, db: AsyncSession = Depends(get_db_session)
):
    """Update a tenant via repository."""
    svc = TenantService(db)
    await svc.update(uid, body)
    return {"status": "updated", "uid": uid}


@router.delete("/tenants/{uid}")
async def delete_tenant(uid: str, db: AsyncSession = Depends(get_db_session)):
    """Delete a tenant via repository."""
    svc = TenantService(db)
    deleted = await svc.delete(uid)
    if deleted == 0:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    return {"status": "deleted", "uid": uid}


@router.post("/tenants/{uid}/keys")
async def generate_tenant_keypair(
    uid: str, body: KeyGenIn, db: AsyncSession = Depends(get_db_session)
):
    """Generate a keypair for a tenant via service."""
    svc = TenantService(db)
    return await svc.generate_keypair(uid, body)


@router.patch("/tenants/{uid}/keys/{kid}/status")
async def update_key_status(
    uid: str,
    kid: str,
    body: KeyStatusIn,
    db: AsyncSession = Depends(get_db_session),
):
    """Update a tenant key status: active | retired | revoked."""
    svc = TenantService(db)
    return await svc.update_key_status(uid, kid, body.status)


@router.post("/tenants/{uid}/clients", response_model=ClientCreateOut)
async def onboard_client(
    uid: str, body: ClientCreateIn, db: AsyncSession = Depends(get_db_session)
):
    """Register a client in the tenant DB."""
    svc = TenantService(db)
    return await svc.onboard_client(uid, body)
