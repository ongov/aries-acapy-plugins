"""Retrieve configuration values."""

from dataclasses import dataclass
from os import getenv

from acapy_agent.config.base import BaseSettings
from acapy_agent.config.settings import Settings


class ConfigError(ValueError):
    """Base class for configuration errors."""

    def __init__(self, var: str, env: str):
        """Initialize a ConfigError."""
        super().__init__(
            f"Invalid {var} specified for Status List plugin; use either status_list.{var} plugin config value or environment variable {env}"
        )


@dataclass
class Config:
    """Configuration for Bitstring Plugin."""

    base_url: str
    base_dir: str
    path_pattern: str

    @classmethod
    def from_settings(cls, settings: BaseSettings) -> "Config":
        """Retrieve configuration from context."""

        assert isinstance(settings, Settings)
        plugin_settings = settings.for_plugin("status_list")
        base_url = plugin_settings.get("base_url") or getenv("STATUS_LIST_BASE_URL")
        base_dir = plugin_settings.get("base_dir") or getenv("STATUS_LIST_BASE_DIR")
        path_pattern = plugin_settings.get("path_pattern") or getenv(
            "STATUS_LIST_PATH_PATTERN"
        )

        if not base_url:
            raise ConfigError("base_url", "STATUS_LIST_BASE_URL")
        if not base_dir:
            raise ConfigError("base_dir", "STATUS_LIST_BASE_DIR")
        if not path_pattern:
            raise ConfigError("path_pattern", "STATUS_LIST_PATH_PATTERN")

        return cls(base_url, base_dir, path_pattern)
