"""Admin API for tenant management."""

import secrets
from datetime import datetime, timezone

from authlib.jose import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from admin.deps import get_db_session
from admin.models import TenantKey
from admin.repositories.tenant_key_repository import TenantKeyRepository
from admin.repositories.tenant_repository import TenantRepository
from admin.schemas.tenant import KeyGenIn, KeyStatusIn, TenantIn, TenantOut
from admin.security.bearer import require_admin_auth
from admin.services.tenant_service import TenantService
from admin.utils.crypto import encrypt_private_pem
from sqlalchemy.exc import IntegrityError

router = APIRouter(dependencies=[Depends(require_admin_auth)])


@router.get("/tenants", response_model=list[TenantOut])
async def list_tenants(db: AsyncSession = Depends(get_db_session)):
    """List tenants via repository."""
    repo = TenantRepository(db)
    rows = await repo.list()
    return [TenantOut.model_validate(r) for r in rows]


@router.get("/tenants/{uid}", response_model=TenantOut)
async def get_tenant(uid: str, db: AsyncSession = Depends(get_db_session)):
    """Get a specific tenant via repository."""
    repo = TenantRepository(db)
    row = await repo.get_by_uid(uid)
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
    repo = TenantRepository(db)
    row = await repo.get_by_uid(uid)
    if not row:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    values = {
        k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None
    }
    _ = await repo.update_values(row.id, values)
    await db.commit()
    return {"status": "updated", "uid": uid}


@router.delete("/tenants/{uid}")
async def delete_tenant(uid: str, db: AsyncSession = Depends(get_db_session)):
    """Delete a tenant via repository."""
    repo = TenantRepository(db)
    row = await repo.get_by_uid(uid)
    if not row:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    deleted = await repo.delete(row.id)
    if deleted == 0:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    await db.commit()
    return {"status": "deleted", "uid": uid}


@router.post("/tenants/{uid}/keys")
async def generate_tenant_keypair(
    uid: str, body: KeyGenIn, db: AsyncSession = Depends(get_db_session)
):
    """Generate a keypair for a tenant via repository."""
    repo = TenantRepository(db)
    t_row = await repo.get_by_uid(uid)
    if not t_row:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    if body.alg != "ES256":
        raise HTTPException(status_code=400, detail="unsupported_alg")

    prv = ec.generate_private_key(ec.SECP256R1())
    private_pem = prv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    private_pem_enc = encrypt_private_pem(private_pem)

    pub = prv.public_key()
    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    public_jwk = jwk.dumps(public_pem, kty="EC", crv="P-256")
    kid = body.kid or secrets.token_hex(8)
    public_jwk["kid"] = kid
    public_jwk["alg"] = body.alg
    public_jwk["use"] = "sig"

    utcnow = datetime.now(timezone.utc)
    not_before = body.not_before or utcnow
    not_after = body.not_after

    key = TenantKey(
        tenant_id=t_row.id,
        kid=kid,
        alg=body.alg,
        public_jwk=public_jwk,
        private_pem_enc=private_pem_enc,
        status=body.status,
        not_before=not_before,
        not_after=not_after,
        created_at=utcnow,
    )

    repo = TenantKeyRepository(db)
    try:
        await repo.add(key)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="key_exists")

    return {
        "uid": uid,
        "kid": kid,
        "alg": body.alg,
        "status": body.status,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat() if not_after else None,
        "public_jwk": public_jwk,
    }


@router.patch("/tenants/{uid}/keys/{kid}/status")
async def update_key_status(
    uid: str,
    kid: str,
    body: KeyStatusIn,
    db: AsyncSession = Depends(get_db_session),
):
    """Update a tenant key status: active | retired | revoked."""
    repo = TenantRepository(db)
    t_row = await repo.get_by_uid(uid)
    if not t_row:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    new_status = body.status.lower()
    if new_status not in {"active", "retired", "revoked"}:
        raise HTTPException(status_code=400, detail="invalid_status")

    # Update status via repository
    repo = TenantKeyRepository(db)
    changed = await repo.update_status(t_row.id, kid, new_status)
    if changed == 0:
        raise HTTPException(status_code=404, detail="key_not_found")
    await db.commit()
    return {"status": new_status, "kid": kid, "uid": uid}
