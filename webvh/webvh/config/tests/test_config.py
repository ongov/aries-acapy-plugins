from unittest import IsolatedAsyncioTestCase

from acapy_agent.utils.testing import create_test_profile

from ..config import get_plugin_config, get_server_url, is_controller, set_config


class TestConfig(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})

    async def test_config(self):
        # With only plugin config value
        self.profile.settings.set_value(
            "plugin_config",
            {
                "did-webvh": {
                    "server_url": "http://id.test-suite.app:6000",
                    "role": "witness",
                }
            },
        )
        config = await get_plugin_config(self.profile)
        assert config["server_url"] == "http://id.test-suite.app:6000"
        assert config["role"] == "witness"
        assert not await is_controller(self.profile)
        assert await get_server_url(self.profile) == "http://id.test-suite.app:6000"

        # With a new set storage record
        await set_config(
            self.profile,
            {
                "server_url": "http://id.test-suite.app:8080",
                "role": "controller",
                "witness_invitation": "http://id.test-suite.app:3000?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJlMzI5OGIyNS1mZjRlLTRhZmItOTI2Yi03ZDcyZmVlMjQ1ODgiLCAibGFiZWwiOiAid2VidmgtZW5kb3JzZXIiLCAiaGFuZHNoYWtlX3Byb3RvY29scyI6IFsiaHR0cHM6Ly9kaWRjb21tLm9yZy9kaWRleGNoYW5nZS8xLjAiXSwgInNlcnZpY2VzIjogW3siaWQiOiAiI2lubGluZSIsICJ0eXBlIjogImRpZC1jb21tdW5pY2F0aW9uIiwgInJlY2lwaWVudEtleXMiOiBbImRpZDprZXk6ejZNa3FDQ1pxNURSdkdMcDV5akhlZlZTa2JhN0tYWlQ1Nld2SlJacEQ2Z3RvRzU0I3o2TWtxQ0NacTVEUnZHTHA1eWpIZWZWU2tiYTdLWFpUNTZXdkpSWnBENmd0b0c1NCJdLCAic2VydmljZUVuZHBvaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9XX0",
            },
        )
        config = await get_plugin_config(self.profile)
        assert config["server_url"] == "http://id.test-suite.app:8080"
        assert config["role"] == "controller"
        assert config.get("witness_invitation")
        assert await is_controller(self.profile)
        assert await get_server_url(self.profile) == "http://id.test-suite.app:8080"

        # Update the config storage record
        await set_config(
            self.profile,
            {
                "server_url": "http://id.test-suite.app:9090",
                "role": "witness",
            },
        )
        config = await get_plugin_config(self.profile)
        assert config["server_url"] == "http://id.test-suite.app:9090"
        assert config["role"] == "witness"
        assert not config.get("witness_invitation")
        assert not await is_controller(self.profile)
        assert await get_server_url(self.profile) == "http://id.test-suite.app:9090"
