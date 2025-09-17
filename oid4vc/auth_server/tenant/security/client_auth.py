"""Client authentication for issuer APIs."""

import json
from typing import Any

import httpx
from authlib.jose import JsonWebKey, jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession

from core.consts import CLIENT_AUTH_METHODS
from core.consts import ClientAuthMethod as CLIENT_AUTH_METHOD
from core.crypto import verify_secret_pbkdf2
from core.models import Client as AuthClient
from tenant.deps import get_db_session
from tenant.repositories.client_repository import ClientRepository

bearer_security = HTTPBearer(auto_error=False)
basic_security = HTTPBasic(auto_error=False)


async def _load_jwks(client) -> dict | None:
    if isinstance(client.jwks, dict):
        return client.jwks
    if client.jwks and isinstance(client.jwks, str):
        try:
            return json.loads(client.jwks)
        except Exception:
            return None
    if client.jwks_uri:
        try:
            async with httpx.AsyncClient(timeout=5.0) as h:
                r = await h.get(client.jwks_uri)
                r.raise_for_status()
                data = r.json()
                return data if isinstance(data, dict) else None
        except Exception:
            return None
    return None


def _audiences_for(request: Request) -> list[str]:
    # Full URL without query
    url = str(request.url)
    base = url.split("?", 1)[0]
    return [base]


async def client_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_security),
    basic_creds: HTTPBasicCredentials | None = Security(basic_security),
    db: AsyncSession = Depends(get_db_session),
) -> AuthClient:
    """Authenticate client and return the persisted Client model."""
    client_id: str | None = None
    token: str | None = None
    unverified_obj: Any | None = None

    scheme = credentials.scheme.lower() if credentials and credentials.scheme else ""
    cred = credentials.credentials if credentials else ""

    if scheme == "bearer" and cred:
        token = cred
        scheme = "bearer"
        try:
            unverified_obj = jwt.decode(token, key="")
            claims: dict[str, Any] = unverified_obj or {}
            client_id = claims.get("iss") or claims.get("sub")
        except Exception:
            # shared_bearer uses JWT format as well; reject non-JWT bearer
            raise HTTPException(status_code=401, detail="invalid_client_assertion")
    elif basic_creds and basic_creds.username is not None:
        # Basic auth
        scheme = "basic"
        client_id = basic_creds.username
        token = basic_creds.password or ""
    else:
        # Unsupported auth
        client_id = None

    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer, Basic"},
        )

    repo = ClientRepository(db)
    client = await repo.get_by_client_id(str(client_id))
    if client is None:
        raise HTTPException(status_code=401, detail="invalid_client")

    allowed = (client.client_auth_method or "").lower()
    if allowed not in set(CLIENT_AUTH_METHODS):
        raise HTTPException(status_code=401, detail="unauthorized_client")

    # Enforce scheme/method
    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC and scheme != "basic":
        raise HTTPException(status_code=401, detail="unauthorized_client")
    if (
        allowed in {CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT, CLIENT_AUTH_METHOD.SHARED_BEARER}
        and scheme != "bearer"
    ):
        raise HTTPException(status_code=401, detail="unauthorized_client")

    if allowed == CLIENT_AUTH_METHOD.PRIVATE_KEY_JWT:
        jwks = await _load_jwks(client)
        if not isinstance(jwks, dict) or not jwks.get("keys"):
            raise HTTPException(status_code=401, detail="invalid_client_keys")
        keys = JsonWebKey.import_key_set(jwks)
        try:
            decoded = jwt.decode(token, keys)  # type: ignore[arg-type]
            decoded.validate(now=None, leeway=30)
            for claim in ("iss", "sub", "aud", "exp", "iat"):
                if claim not in decoded:
                    raise HTTPException(status_code=401, detail=f"missing_{claim}")
            aud = decoded.get("aud")
            expected_aud = _audiences_for(request)
            if isinstance(aud, str):
                aud = [aud]
            if not aud or not any(a in expected_aud for a in aud):
                raise HTTPException(status_code=401, detail="invalid_audience")
        except Exception:
            raise HTTPException(status_code=401, detail="invalid_client_assertion")
        if client.client_auth_signing_alg:
            try:
                header = jwt.get_unverified_header(token)  # type: ignore[arg-type]
                if header.get("alg") != client.client_auth_signing_alg:
                    raise HTTPException(status_code=401, detail="invalid_alg")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=401, detail="invalid_client_assertion")
        request.state.client_id = str(client.client_id)
        return client

    if allowed == CLIENT_AUTH_METHOD.SHARED_BEARER:
        # HS* JWT with client secret
        secret = client.client_secret or ""
        if not secret:
            raise HTTPException(status_code=401, detail="unauthorized_client")
        try:
            decoded = jwt.decode(token, secret)  # type: ignore[arg-type]
            decoded.validate(now=None, leeway=30)
            for claim in ("iss", "sub", "aud", "exp", "iat"):
                if claim not in decoded:
                    raise HTTPException(status_code=401, detail=f"missing_{claim}")
            aud = decoded.get("aud")
            expected_aud = _audiences_for(request)
            if isinstance(aud, str):
                aud = [aud]
            if not aud or not any(a in expected_aud for a in aud):
                raise HTTPException(status_code=401, detail="invalid_audience")
        except Exception:
            raise HTTPException(status_code=401, detail="invalid_client_assertion")
        # Optional alg check
        if client.client_auth_signing_alg:
            try:
                header = jwt.get_unverified_header(token)  # type: ignore[arg-type]
                if header.get("alg") != client.client_auth_signing_alg:
                    raise HTTPException(status_code=401, detail="invalid_alg")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=401, detail="invalid_client_assertion")
        # Ensure iss == sub == client_id
        claims = decoded if isinstance(decoded, dict) else {}
        iss = claims.get("iss")
        sub = claims.get("sub")
        if not iss or not sub or str(iss) != str(sub) or str(iss) != str(client_id):
            raise HTTPException(status_code=401, detail="invalid_client")
        request.state.client_id = str(client.client_id)
        return client

    if allowed == CLIENT_AUTH_METHOD.CLIENT_SECRET_BASIC:
        secret_hash = client.client_secret
        if secret_hash and token:
            if verify_secret_pbkdf2(token, secret_hash):
                request.state.client_id = str(client.client_id)
                return client
            raise HTTPException(status_code=401, detail="invalid_client")
        raise HTTPException(status_code=401, detail="unauthorized_client")

    # Fallback deny
    raise HTTPException(status_code=401, detail="unauthorized_client")
