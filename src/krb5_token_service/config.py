from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (BROKER_JWKS_URL, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # Route handlers receive Settings via ``Depends``. FastAPI builds a request
    # model from the callable's signature, and the pydantic-settings
    # ``BaseSettings.__init__`` exposes private (``_cli_parse_args`` ...)
    # parameters that FastAPI cannot turn into fields. Overriding ``__init__``
    # with a plain ``**data`` signature keeps env loading intact while giving
    # FastAPI a clean signature to introspect.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # Where the broker publishes the JWKS for its AF Broker Identity Token
    # signing keys (maniaclab/af-mcp-platform#162). The default points at a
    # broker running locally; production deployments must set BROKER_JWKS_URL
    # explicitly (see the Helm chart).
    broker_jwks_url: str = "http://localhost:8080/.well-known/jwks.json"

    # Required `iss` claim on inbound AF Broker Identity Tokens.
    broker_issuer: str = "https://mcp.af.uchicago.edu"

    # Required `aud` claim — this service's own identity in the protocol.
    expected_audience: str = "krb5-token-service"

    # Path to (or bare name of, resolved via PATH) the kinit binary.
    # Configurable so tests can substitute a fake executable and non-standard
    # installs can point elsewhere.
    kinit_bin: str = "kinit"

    # Path to the krb5.conf this service ships (baked into the image; see the
    # Containerfile and etc/krb5.conf). Exported to the kinit child as
    # KRB5_CONFIG — never relies on a system-wide /etc/krb5.conf.
    krb5_config: str = "/app/etc/krb5.conf"

    # Kerberos realm appended to a bare username (CERN.CH per the shipped
    # krb5.conf's default_realm). A username already containing "@" is used
    # as-is — see minting.validate_username.
    default_realm: str = "CERN.CH"

    # Defaults applied when the mint request omits lifetime/renewable_lifetime.
    # Mirror the shipped krb5.conf's ticket_lifetime/renew_lifetime so a
    # request that omits both gets exactly what the KDC would grant anyway.
    default_lifetime: str = "24h"
    default_renewable_lifetime: str = "7d"

    # Pod-local root under which each mint gets a private working dir holding
    # the ccache (created with tempfile.TemporaryDirectory, mode 0700). Lives
    # on the pod's tmpfs /tmp; nothing here touches shared storage.
    ccache_tmp_root: str = "/tmp/krb5cc"

    # Wall-clock bound on the kinit subprocess. A KDC that never responds (or
    # a hung network call) must not hang the request forever; a timeout is
    # treated as an infra failure (502), not a bad password.
    kinit_timeout_seconds: int = Field(default=30, gt=0)

    # Per-username failed-authentication limiter. Unlike voms-token-service
    # (whose local openssl "bad decrypt" failure has no external consequence),
    # a wrong CERN password is a real AS-REQ that counts against CERN's own
    # account-lockout policy — so this service refuses to even invoke kinit
    # once a username has failed too many times within the window. See
    # ratelimit.py and the Helm chart's replicaCount: 1 (this limiter is
    # in-process and per-replica).
    failed_auth_max_attempts: int = Field(default=3, gt=0)
    failed_auth_window_seconds: int = Field(default=900, gt=0)
    failed_auth_lockout_seconds: int = Field(default=900, gt=0)

    # How long a fetched JWKS is served from the in-process cache before a
    # refresh is attempted. A failed refresh serves the stale entry instead of
    # taking token verification down with it (see identity.py).
    jwks_cache_ttl_seconds: int = 300

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()
