"""Tenant service."""

import secrets
import uuid
from datetime import datetime, timezone

import psycopg
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from psycopg import sql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from admin.config import settings
from admin.models import Tenant, TenantKey
from admin.repositories.tenant_key_repository import TenantKeyRepository
from admin.repositories.tenant_repository import TenantRepository
from admin.schemas.client import ClientCreateIn, ClientCreateOut
from admin.schemas.tenant import TenantIn
from admin.services.alembic_service import run_tenant_migration
from admin.utils.crypto import encrypt_db_password, encrypt_private_pem
from admin.utils.db_utils import build_sync_url, resolve_tenant_urls, url_to_dsn
from core.consts import CLIENT_AUTH_METHODS, ClientAuthMethod
from core.crypto.crypto import hash_secret_pbkdf2
from core.models import Client
from core.repositories.client_repository import ClientRepository


class TenantService:
    """Tenant orchestration."""

    def __init__(self, session: AsyncSession):
        """Constructor."""
        self.session = session
        self.repo = TenantRepository(session)

    def _provision(
        self, *, db_name: str, db_schema: str, db_user: str, db_password: str
    ) -> None:
        """Create role and database if missing; schema is created by Alembic."""
        dsn = url_to_dsn(settings.DB_URL_SYNC)
        with psycopg.connect(dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (db_user,))
                row = cur.fetchone()
                if row is None:
                    cur.execute(
                        sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                            sql.Identifier(db_user),
                            sql.Literal(db_password),
                        )
                    )
                else:
                    cur.execute(
                        sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                            sql.Identifier(db_user),
                            sql.Literal(db_password),
                        )
                    )
                cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,))
                if cur.fetchone() is None:
                    # Create DB without OWNER and grant needed privileges to tenant role.
                    cur.execute(
                        sql.SQL(
                            "CREATE DATABASE {} " "ENCODING 'UTF8' TEMPLATE template0"
                        ).format(
                            sql.Identifier(db_name),
                        )
                    )
                # Ensure privileges are present even if DB already existed
                cur.execute(
                    sql.SQL("GRANT CONNECT, CREATE ON DATABASE {} TO {};").format(
                        sql.Identifier(db_name),
                        sql.Identifier(db_user),
                    )
                )

    async def create(self, data: TenantIn) -> Tenant:
        """Create a new tenant."""
        if data.uid is None:
            data.uid = str(uuid.uuid4())
        elif await self.repo.exists_by_uid(data.uid):
            raise HTTPException(status_code=409, detail="tenant_exists")

        now = datetime.now(timezone.utc)
        tenant = Tenant(
            uid=data.uid,
            name=data.name,
            active=True if data.active is None else data.active,
            notes=data.notes,
            created_at=now,
            updated_at=now,
        )
        self.session.add(tenant)
        await self.session.flush()  # ensure tenant.id is available

        db_name = f"{settings.TENANT_DB_NAME}{tenant.id}"
        db_schema = settings.TENANT_DB_SCHEMA
        db_user = db_name
        db_password = secrets.token_urlsafe(32)

        try:
            self._provision(
                db_name=db_name,
                db_schema=db_schema,
                db_user=db_user,
                db_password=db_password,
            )
        except Exception as ex:
            await self.session.rollback()
            raise HTTPException(status_code=500, detail=f"provision_failed: {ex}")

        # Run Alembic migrations via shared service
        alembic_url = build_sync_url(db_name, db_user, db_password)
        try:
            run_tenant_migration(
                sync_url=alembic_url,
                schema=db_schema,
                action="upgrade",
                rev="head",
            )
        except Exception as ex:
            await self.session.rollback()
            raise HTTPException(status_code=500, detail=f"migration_failed: {ex}")

        tenant.db_name = db_name
        tenant.db_schema = db_schema
        tenant.db_user = db_user
        tenant.db_pwd_enc = encrypt_db_password(db_password)

        await self.session.commit()
        await self.session.refresh(tenant)
        return tenant

    async def list(self) -> list[Tenant]:
        """List all tenants."""
        rows = await self.repo.list()
        return list(rows)

    async def get(self, uid: str) -> Tenant | None:
        """Get tenant by uid."""
        return await self.repo.get_by_uid(uid)

    async def update(self, uid: str, data: TenantIn) -> int:
        """Update tenant basic fields; returns rows changed."""
        row = await self.repo.get_by_uid(uid)
        if not row:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        values = {
            k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None
        }
        changed = await self.repo.update_values(row.id, values)
        await self.session.commit()
        return changed

    async def delete(self, uid: str) -> int:
        """Delete a tenant; returns rows deleted."""
        row = await self.repo.get_by_uid(uid)
        if not row:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        deleted = await self.repo.delete(row.id)
        await self.session.commit()
        return deleted

    async def generate_keypair(self, uid: str, body) -> dict:
        """Generate and store a tenant signing keypair (ES256)."""
        repo = self.repo
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
        public_jwk = JsonWebKey.import_key(public_pem).as_dict()  # type: ignore
        if public_jwk is None:
            raise HTTPException(status_code=500, detail="Failed to create JWK from PEM")

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

        key_repo = TenantKeyRepository(self.session)
        try:
            await key_repo.add(key)
            await self.session.commit()
        except IntegrityError:
            await self.session.rollback()
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

    async def update_key_status(self, uid: str, kid: str, new_status: str) -> dict:
        """Update a tenant key status: active | retired | revoked."""
        t_row = await self.repo.get_by_uid(uid)
        if not t_row:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        new_status = new_status.lower()
        if new_status not in {"active", "retired", "revoked"}:
            raise HTTPException(status_code=400, detail="invalid_status")
        key_repo = TenantKeyRepository(self.session)
        changed = await key_repo.update_status(t_row.id, kid, new_status)
        if changed == 0:
            raise HTTPException(status_code=404, detail="key_not_found")
        await self.session.commit()
        return {"status": new_status, "kid": kid, "uid": uid}

    async def onboard_client(self, uid: str, data: ClientCreateIn) -> ClientCreateOut:
        """Create a client record in the tenant DB."""
        # Validate tenant exists
        t = await self.repo.get_by_uid(uid)
        if not t:
            raise HTTPException(status_code=404, detail="tenant_not_found")

        # Validate method
        method = (data.method or "").lower()
        if method not in set(CLIENT_AUTH_METHODS):
            raise HTTPException(status_code=400, detail="invalid_method")

        # Defaults per method
        signing_alg = data.signing_alg
        if not signing_alg:
            if method == ClientAuthMethod.PRIVATE_KEY_JWT:
                signing_alg = "ES256"
            elif method == ClientAuthMethod.SHARED_KEY_JWT:
                signing_alg = "HS256"

        # Validate fields by method
        secret_hash: str | None = None
        if method == ClientAuthMethod.PRIVATE_KEY_JWT:
            if not (data.jwks or data.jwks_uri):
                raise HTTPException(status_code=400, detail="jwks_or_uri_required")
        elif method in (
            ClientAuthMethod.SHARED_KEY_JWT,
            ClientAuthMethod.CLIENT_SECRET_BASIC,
        ):
            if not data.client_secret:
                raise HTTPException(status_code=400, detail="client_secret_required")
            if method == ClientAuthMethod.CLIENT_SECRET_BASIC:
                secret_hash = hash_secret_pbkdf2(data.client_secret)
            else:
                secret_hash = data.client_secret

        client_id = data.client_id or uuid.uuid4().hex

        # Connect to tenant DB (asyncpg) and insert via ORM
        async_url, _, schema = resolve_tenant_urls(t)
        engine = create_async_engine(
            async_url,
            pool_pre_ping=True,
            connect_args={"server_settings": {"search_path": schema}},
        )
        sm = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with sm() as tsession:  # AsyncSession to tenant DB
                # Uniqueness check
                trepo = ClientRepository(tsession)
                if await trepo.get_by_client_id(client_id):
                    raise HTTPException(status_code=409, detail="client_exists")
                c = Client(
                    client_id=client_id,
                    client_auth_method=method,
                    client_auth_signing_alg=signing_alg,
                    client_secret=secret_hash,
                    jwks=data.jwks,
                    jwks_uri=data.jwks_uri,
                )
                tsession.add(c)
                await tsession.commit()
        except HTTPException:
            raise
        except Exception as ex:
            raise HTTPException(status_code=500, detail=f"onboard_failed: {ex}")
        finally:
            await engine.dispose()

        return ClientCreateOut(
            client_id=client_id,
            method=method,
            signing_alg=signing_alg,
            jwks_uri=data.jwks_uri,
            has_jwks=bool(data.jwks),
            secret_returned=bool(data.client_secret),
        )
