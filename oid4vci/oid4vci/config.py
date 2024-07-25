"""Retrieve configuration values."""

import json
from dataclasses import dataclass
from os import getenv

from aries_cloudagent.config.base import BaseSettings
from aries_cloudagent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for OID4VCI server; use either "
            f"oid4vci.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for OID4VCI Plugin."""

    host: str
    port: int
    endpoint: str
    cred_handler: dict

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""
        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or getenv("OID4VCI_HOST")
        port = int(plugin_settings.get("port") or getenv("OID4VCI_PORT", "0"))
        endpoint = plugin_settings.get("endpoint") or getenv("OID4VCI_ENDPOINT")
        cred_handler = plugin_settings.get("cred_handler") or getenv(
            "OID4VCI_CRED_HANDLER"
        )

        if not host:
            raise ConfigError("host", "OID4VCI_HOST")
        if not port:
            raise ConfigError("port", "OID4VCI_PORT")
        if not endpoint:
            raise ConfigError("endpoint", "OID4VCI_ENDPOINT")
        if not cred_handler:
            raise ConfigError("cred_handler", "OID4VCI_CRED_HANDLER")

        cred_handler = json.loads(cred_handler)

        return cls(host, port, endpoint, cred_handler)
