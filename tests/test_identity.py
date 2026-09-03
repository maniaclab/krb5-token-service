"""Unit tests for AF Broker Identity Token verification and the JWKS cache."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest
from fastapi import HTTPException

from krb5_token_service import identity

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography.hazmat.primitives.asymmetric import rsa

    from krb5_token_service.config import Settings
    from tests.conftest import JwksFetchStub


@pytest.mark.usefixtures("stub_jwks_fetch")
class TestVerifyBrokerToken:
    async def test_valid_token_returns_claims(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(sub="af-user-subject")
        claims = await identity.verify_broker_token(token, settings)
        assert claims["sub"] == "af-user-subject"
        assert claims["jti"]

    async def test_expired_token_is_401(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(expires_in=-60)
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    async def test_wrong_audience_is_401(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(audience="some-other-service")
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    async def test_wrong_issuer_is_401(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(issuer="https://evil.example")
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    async def test_wrong_signing_key_is_401(
        self,
        make_token: Callable[..., str],
        settings: Settings,
        other_rsa_private_key: rsa.RSAPrivateKey,
    ) -> None:
        # Same kid as the published key, but signed by a key the JWKS does
        # not contain — signature verification must fail.
        token = make_token(key=other_rsa_private_key)
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    async def test_unknown_kid_is_401(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(kid="no-such-key")
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    @pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
    async def test_missing_required_claim_is_401(
        self, make_token: Callable[..., str], settings: Settings, claim: str
    ) -> None:
        token = make_token(omit=(claim,))
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(token, settings)
        assert excinfo.value.status_code == 401

    async def test_garbage_token_is_401(self, settings: Settings) -> None:
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token("not-a-jwt", settings)
        assert excinfo.value.status_code == 401

    async def test_no_kid_falls_back_to_single_jwks_key(
        self, make_token: Callable[..., str], settings: Settings
    ) -> None:
        token = make_token(kid=None)
        claims = await identity.verify_broker_token(token, settings)
        assert claims["sub"] == "af-user-subject"


class TestJwksCache:
    async def test_second_verification_within_ttl_uses_cache(
        self,
        make_token: Callable[..., str],
        settings: Settings,
        stub_jwks_fetch: JwksFetchStub,
    ) -> None:
        await identity.verify_broker_token(make_token(), settings)
        await identity.verify_broker_token(make_token(), settings)
        assert stub_jwks_fetch.calls == 1

    async def test_stale_keys_served_when_refresh_fails(
        self,
        make_token: Callable[..., str],
        settings: Settings,
        stub_jwks_fetch: JwksFetchStub,
    ) -> None:
        await identity.verify_broker_token(make_token(), settings)
        # Age the cache entry past the TTL, then make the next fetch fail —
        # verification must fall back to the stale keys rather than erroring.
        entry = identity._jwks_cache[settings.broker_jwks_url]
        entry.fetched_at = time.monotonic() - settings.jwks_cache_ttl_seconds - 1
        stub_jwks_fetch.fail = True
        claims = await identity.verify_broker_token(make_token(), settings)
        assert claims["sub"] == "af-user-subject"
        assert stub_jwks_fetch.calls == 2

    async def test_fetch_failure_with_empty_cache_is_502(
        self,
        make_token: Callable[..., str],
        settings: Settings,
        stub_jwks_fetch: JwksFetchStub,
    ) -> None:
        stub_jwks_fetch.fail = True
        with pytest.raises(HTTPException) as excinfo:
            await identity.verify_broker_token(make_token(), settings)
        assert excinfo.value.status_code == 502

    async def test_concurrent_refreshes_are_single_flight(
        self, settings: Settings, stub_jwks_fetch: JwksFetchStub
    ) -> None:
        stub_jwks_fetch.delay = 0.05
        results = await asyncio.gather(*(identity.get_jwks(settings) for _ in range(5)))
        assert stub_jwks_fetch.calls == 1
        assert all(keys == stub_jwks_fetch.keys for keys in results)
