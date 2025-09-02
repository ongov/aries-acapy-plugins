"""Schemas for grants."""

from pydantic import BaseModel, Field


class PreAuthGrantIn(BaseModel):
    """Input for creating a pre-authorized code."""

    subject_id: str | None = None
    subject_metadata: dict | None = Field(
        default=None,
        description="Saved to subject.metadata when creating a subject",
        examples=[
            {"given_name": "Test", "family_name": "User", "email": "test@example.com"}
        ],
    )
    user_pin_required: bool = False
    user_pin: str | None = None
    authorization_details: dict | None = Field(
        default=None,
        description="Saved to pre_auth_code.authorization_details",
        examples=[
            {
                "type": "openid_credential",
                "format": "sd-jwt_vc",
                "credential_definition": {
                    "type": ["VerifiableCredential", "EmployeeCredential"],
                    "claims": {
                        "given_name": {"mandatory": True},
                        "family_name": {"mandatory": True},
                        "email": {"mandatory": False},
                    },
                },
                "locations": ["https://issuer.example.com/credentials"],
                "encryption": {"alg": "ECDH-ES", "enc": "A256GCM"},
            }
        ],
    )
    ttl_seconds: int | None = Field(
        default=None,
        description="TTL in seconds; falls back to server default",
        examples=[600],
    )


class PreAuthGrantOut(BaseModel):
    """Output for creating a pre-authorized code."""

    pre_authorized_code: str
    user_pin_required: bool
    user_pin: str | None = None
    subject_id: str
