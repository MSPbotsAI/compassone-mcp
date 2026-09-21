from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_BASE_URL = "https://api.blackpointcyber.com"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Transport
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_http_port: int = 8080
    mcp_http_host: str = "0.0.0.0"

    # Auth mode:
    # "gateway" — production/SOP-compliant: API token from an HTTP header per
    #             request (no global state)
    # "env"     — local dev only: a single shared API token from an env var (not SOP-compliant)
    auth_mode: Literal["env", "gateway"] = "gateway"

    # CompassOne credential (only required in env mode)
    compassone_api_token: str | None = None

    # HTTP header name used to pass the API token in gateway mode.
    #
    # Deliberately X-Blackpoint-API-Token, not X-CompassOne-*: this is the name
    # already declared in the platform's vendor registry for the `blackpoint`
    # vendor, and existing tenant authorizations store the credential under it.
    # Renaming it here would silently invalidate every provisioned credential.
    compassone_api_token_header: str = "X-Blackpoint-API-Token"

    # Vendor API base URL. Not a credential field — CompassOne is a single
    # multi-tenant SaaS endpoint; tenancy is expressed per call via the
    # x-tenant-id header, never by a per-customer base URL.
    compassone_base_url: str = DEFAULT_BASE_URL

    @property
    def has_credentials(self) -> bool:
        """Returns True if the server can serve API calls.

        Gateway mode always returns True — each request carries its own credential.
        Env mode requires COMPASSONE_API_TOKEN to be set.
        """
        if self.auth_mode == "gateway":
            return True
        return self.compassone_api_token is not None


def get_settings() -> Settings:
    return Settings()
