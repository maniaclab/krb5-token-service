"""AF Broker Identity Token verification (maniaclab/af-mcp-platform#162).

The inbound credential is a short-lived RS256 JWT minted by the af-mcp-broker
asserting *identity only*: ``iss``/``sub``/``aud``/``exp``/``iat``/``jti``.
The CERN username/password this service mints a ticket for come from the
mint request body, not from the token — the token's only job is proving the
call genuinely came from the broker.

The JWKS cache mirrors af-mcp-platform's identity.py (and
voms-token-service's own identity.py): TTL-bounded, refreshes are
single-flight per URI, and a failed refresh serves the stale entry so a
broker blip does not take ticket issuance down with it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx
import jwt
import structlog
from fastapi import HTTPException, status

if TYPE_CHECKING:
    from krb5_token_service.config import Settings

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# JWKS cache — one entry per JWKS URL, refreshed after the configured TTL.
# ---------------------------------------------------------------------------


@dataclass
class _JwksEntry:
    keys: list[dict[str, Any]]
    fetched_at: float


_jwks_cache: dict[str, _JwksEntry] = {}
# Single-flight: dedupe concurrent refreshes of the same URL. Locks are
# per-event-loop because asyncio.Lock binds to the loop that first uses it
# (tests run many short-lived loops in one process).
_jwks_locks: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}

_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client  # noqa: PLW0603 — module-level singleton, one pool per process
    if _http_client is None:
        _http_client = httpx.AsyncClient()
    return _http_client


def _get_jwks_lock(url: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    entry = _jwks_locks.get(url)
    if entry is None or entry[0] is not loop:
        entry = (loop, asyncio.Lock())
        _jwks_locks[url] = entry
    return entry[1]


async def _fetch_jwks(jwks_url: str) -> list[dict[str, Any]]:
    """Fetch JWKS from the broker, bypassing the TTL cache.

    Raises HTTPException(502) when the broker is unreachable so callers
    higher up the stack can surface a useful error rather than a raw 500.
    """
    try:
        resp = await _get_http_client().get(jwks_url, timeout=10.0)
        resp.raise_for_status()
        return cast("list[dict[str, Any]]", resp.json()["keys"])
    except Exception as exc:
        logger.exception("jwks_fetch_failed", url=jwks_url, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach JWKS endpoint: {jwks_url}",
        ) from exc


async def get_jwks(settings: Settings) -> list[dict[str, Any]]:
    """Return JWKS keys, using a TTL-bounded in-process cache.

    Concurrent refreshes of the same URL are deduplicated, and a refresh
    failure falls back to the stale entry so a broker blip does not take
    token verification down with it.
    """
    url = settings.broker_jwks_url
    ttl = settings.jwks_cache_ttl_seconds
    entry = _jwks_cache.get(url)
    now = time.monotonic()

    if entry is not None and (now - entry.fetched_at) <= ttl:
        return entry.keys

    async with _get_jwks_lock(url):
        # Another request may have refreshed while we waited on the lock.
        entry = _jwks_cache.get(url)
        now = time.monotonic()
        if entry is not None and (now - entry.fetched_at) <= ttl:
            return entry.keys

        try:
            keys = await _fetch_jwks(url)
        except HTTPException:
            if entry is not None:
                logger.warning("jwks_refresh_failed_serving_stale", url=url)
                return entry.keys
            raise
        _jwks_cache[url] = _JwksEntry(keys=keys, fetched_at=now)
        logger.debug("jwks_cache_refreshed", url=url, key_count=len(keys))
        return keys


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


async def verify_broker_token(token: str, settings: Settings) -> dict[str, Any]:
    """Validate an AF Broker Identity Token and return its claims.

    Enforces RS256 signature against the broker's JWKS, ``iss`` ==
    ``broker_issuer``, ``aud`` == ``expected_audience``, and presence of
    ``exp``/``iat``/``sub`` (with expiry verified). Raises HTTPException(401)
    on any validation failure — deliberately without leaking which check
    failed — and lets the JWKS fetch's 502 propagate unchanged.
    """
    keys = await get_jwks(settings)

    error: Exception | str | None = None
    try:
        # Select the signing key by the token's `kid`. A JWKS may carry more
        # than one key; trying keys in list order and treating a signature
        # mismatch as fatal fails whenever the wrong key sorts first.
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key_data = _select_jwk(keys, kid)
        if key_data is None:
            error = f"no JWKS key matches token kid={kid!r}"
        else:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            return jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]  # JWKS only has public keys
                algorithms=["RS256"],
                audience=settings.expected_audience,
                issuer=settings.broker_issuer,
                options={
                    "verify_exp": True,
                    "require": ["exp", "iat", "sub"],
                },
            )
    except jwt.InvalidTokenError as exc:
        error = exc
    except (ValueError, KeyError) as exc:
        error = exc

    logger.warning(
        "jwt_validation_failed",
        error=str(error) if error else "no matching key",
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _select_jwk(keys: list[dict[str, Any]], kid: str | None) -> dict[str, Any] | None:
    """Return the JWK matching ``kid``.

    When the token carries no ``kid`` and the JWKS publishes exactly one key,
    fall back to that key so single-key issuers keep working.
    """
    if kid is not None:
        for key_data in keys:
            if key_data.get("kid") == kid:
                return key_data
        return None
    return keys[0] if len(keys) == 1 else None


def peek_sub(token: str) -> str:
    """Decode the subject claim without signature verification, for audit/log use only."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return cast("str", payload.get("sub", "<unknown>"))
    except Exception:  # noqa: BLE001  # log-only helper; never raises
        return "<unparseable>"
