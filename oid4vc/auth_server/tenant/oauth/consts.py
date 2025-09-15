"""OAuth2/OIDC constants."""


class OAuth2Flow:
    """OAuth2 grant types."""

    PRE_AUTH_CODE = "pre_auth_code"
    REFRESH_TOKEN = "refresh_token"


class OAuth2GrantType:
    """OAuth2 grant types."""

    PRE_AUTH_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    REFRESH_TOKEN = "refresh_token"


class ClientAuthMethod:
    """OAuth2 client authentication methods."""

    PRIVATE_KEY_JWT = "private_key_jwt"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    SHARED_BEARER = "shared_bearer"


CLIENT_AUTH_METHODS: tuple[str, ...] = (
    ClientAuthMethod.PRIVATE_KEY_JWT,
    ClientAuthMethod.CLIENT_SECRET_BASIC,
    ClientAuthMethod.SHARED_BEARER,
)
