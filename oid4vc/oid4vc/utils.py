"""Utility functions for OID4VCI plugin."""

from acapy_agent.core.profile import Profile


def get_tenant_subpath(profile: Profile, tenant_prefix: str = "/tenants") -> str:
    """Get the tenant path for the current wallet, if any."""
    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    # wallet_id = "2bbc7c59-d119-47be-a017-af475a3262e5"
    tenant_subpath = f"{tenant_prefix}/{wallet_id}" if wallet_id else ""
    return tenant_subpath
