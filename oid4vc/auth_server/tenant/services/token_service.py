"""Issue/rotate tokens via remote signer, using tenant DB only."""

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from tenant.config import settings
from tenant.repositories.access_token_repository import AccessTokenRepository
from tenant.repositories.grant_repository import GrantRepository
from tenant.repositories.refresh_token_repository import RefreshTokenRepository
from tenant.services.signing_service import remote_sign_jwt
from tenant.utils.security import (
    compute_access_exp,
    compute_refresh_exp,
    hash_token,
    new_refresh_token,
    utcnow,
)


class TokenService:
    """Issue/rotate tokens via remote signer, using tenant DB only."""

    @staticmethod
    async def issue_by_pre_auth_code(
        db: AsyncSession,
        uid: str,
        code: str,
        realm: str,
        user_pin: str | None = None,
    ):
        """Issue access+refresh from a pre-auth code."""
        grant_repo = GrantRepository(db)
        access_repo = AccessTokenRepository(db)
        refresh_repo = RefreshTokenRepository(db)

        issuer = f"{settings.ISSUER_BASE_URL}/tenants/{uid}"
        now = utcnow()

        pac = await grant_repo.get_by_code(code)
        if pac is None or pac.used or pac.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_request"
            )
        if pac.user_pin_required and (not user_pin or user_pin != (pac.user_pin or "")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_request"
            )
        await grant_repo.mark_used(pac)

        if not pac.subject or not pac.subject.uid:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="subject_uid_missing",
            )
        access_exp = compute_access_exp(now)
        claims = {
            "iss": issuer,
            "sub": pac.subject.uid,
            "realm": realm,
            "iat": int(now.timestamp()),
            "exp": int(access_exp.timestamp()),
        }
        if pac.authorization_details:
            claims["authorization_details"] = pac.authorization_details

        sign_res = await remote_sign_jwt(
            uid=uid,
            claims=claims,
        )

        token_meta = {"iss": issuer, "realm": realm}
        if pac.authorization_details:
            token_meta["authorization_details"] = pac.authorization_details
        access_token = await access_repo.create(
            subject_id=pac.subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
        )

        refresh_token = new_refresh_token()
        _ = await refresh_repo.create(
            subject_id=pac.subject_id,
            access_token_id=access_token.id,
            token_hash=hash_token(refresh_token),
            issued_at=now,
            expires_at=compute_refresh_exp(now),
            token_metadata={"realm": realm},
        )
        await db.commit()
        return access_token, refresh_token

    @staticmethod
    async def rotate_by_refresh_token(
        db: AsyncSession,
        uid: str,
        refresh_token_value: str,
        realm: str,
    ):
        """Rotate tokens using a refresh token."""
        access_repo = AccessTokenRepository(db)
        refresh_repo = RefreshTokenRepository(db)

        issuer = f"{settings.ISSUER_BASE_URL}/tenants/{uid}"
        now = utcnow()
        access_exp = compute_access_exp(now)

        token_hash = hash_token(refresh_token_value)
        res = await refresh_repo.consume_valid(token_hash=token_hash, now=now)
        if not res:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token"
            )
        subject_id, access_token_id = res

        prev_access = await access_repo.get_by_id(access_token_id)
        if not prev_access or not prev_access.subject or not prev_access.subject.uid:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="subject_uid_missing",
            )
        prev_meta = prev_access.token_metadata or {}
        prev_authz = (
            prev_meta.get("authorization_details")
            if isinstance(prev_meta, dict)
            else None
        )
        claims = {
            "iss": issuer,
            "sub": prev_access.subject.uid,
            "realm": realm,
            "iat": int(now.timestamp()),
            "exp": int(access_exp.timestamp()),
        }
        if prev_authz:
            claims["authorization_details"] = prev_authz

        sign_res = await remote_sign_jwt(
            uid=uid,
            claims=claims,
        )

        token_meta = {"iss": issuer, "realm": realm}
        if prev_authz:
            token_meta["authorization_details"] = prev_authz
        new_access_token = await access_repo.create(
            subject_id=subject_id,
            token=sign_res["jwt"],
            issued_at=now,
            expires_at=access_exp,
            token_metadata=token_meta,
        )

        refresh_token = new_refresh_token()
        _ = await refresh_repo.create(
            subject_id=subject_id,
            access_token_id=new_access_token.id,
            token_hash=hash_token(refresh_token),
            issued_at=now,
            expires_at=compute_refresh_exp(now),
            token_metadata={"realm": realm},
        )
        await db.commit()
        return new_access_token, refresh_token
