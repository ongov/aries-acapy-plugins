"""Application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env.tenant", env_prefix="TENANT_", extra="ignore"
    )

    APP_ROOT_PATH: str = ""
    ISSUER_BASE_URL: str

    ACCESS_TOKEN_TTL: int = 900
    REFRESH_TOKEN_TTL: int = 604800
    PRE_AUTH_CODE_TTL: int = 600
    TOKEN_BYTES: int = 48

    DB_DRIVER_ASYNC: str = "postgresql+asyncpg"
    DB_DRIVER_SYNC: str = "postgresql+psycopg"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432

    TRUST_NETWORKS: list[str] = []

    ISSUER_AUTH_TOKEN: str

    ADMIN_M2M_BASE_URL: str
    ADMIN_M2M_AUTH_TOKEN: str
    CONTEXT_CACHE_TTL: int = 900

    KEY_ENC_SECRETS: dict[str, str] = {}
    KEY_ENC_VERSION: int = 1

    # CORS settings
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "OPTIONS"]
    CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type"]
    CORS_ALLOW_CREDENTIALS: bool = False


settings = Settings()
