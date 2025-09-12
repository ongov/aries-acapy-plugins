"""Tenant service."""

import secrets
import uuid
from datetime import datetime, timezone

import psycopg
from fastapi import HTTPException
from psycopg import sql
from sqlalchemy.ext.asyncio import AsyncSession

from admin.config import settings
from admin.models import Tenant
from admin.repositories.tenant_repository import TenantRepository
from admin.schemas.tenant import TenantIn
from admin.services.alembic_service import run_tenant_migration
from admin.utils.crypto import encrypt_db_password
from admin.utils.db_utils import build_sync_url, url_to_dsn


class TenantService:
    """Tenant orchestration."""

    def __init__(self, session: AsyncSession):
        """Constructor."""
        self.session = session
        self.repo = TenantRepository(session)

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
                    cur.execute(
                        sql.SQL(
                            "CREATE DATABASE {} OWNER {} "
                            "ENCODING 'UTF8' TEMPLATE template0"
                        ).format(
                            sql.Identifier(db_name),
                            sql.Identifier(db_user),
                        )
                    )
