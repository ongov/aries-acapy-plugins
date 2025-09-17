"""Schemas for client onboarding to tenant DB."""

from typing import Any

from pydantic import BaseModel, Field


class ClientCreateIn(BaseModel):
    """Client onboarding payload."""

    client_id: str | None = Field(default=None)
    method: str = Field(
        description="Auth method: private_key_jwt | client_secret_basic | shared_bearer"
    )
    signing_alg: str | None = Field(default=None, description="e.g., ES256 or HS256")
    jwks: dict[str, Any] | None = Field(default=None)
    jwks_uri: str | None = Field(default=None)
    client_secret: str | None = Field(
        default=None, description="Only for shared_bearer/client_secret_basic"
    )


class ClientCreateOut(BaseModel):
    """Client onboarding response."""

    client_id: str
    method: str
    signing_alg: str | None = None
    jwks_uri: str | None = None
    has_jwks: bool = False
    secret_returned: bool = False
