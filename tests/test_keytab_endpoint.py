"""Integration tests for POST /v1/keytab through the ASGI stack.

The cern-get-keytab the app invokes is a real Python script on disk (see
conftest's fake_cern_get_keytab) — nothing is mocked at the Python level.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

import pytest
from structlog.testing import capture_logs

from tests.conftest import FAKE_CORRECT_PASSWORD

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

    from krb5_token_service.config import Settings


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"username": "gstark", "password": FAKE_CORRECT_PASSWORD}
    payload.update(overrides)
    return payload


def _audit_events(cap_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in cap_logs if entry.get("event") == "audit"]


@pytest.mark.usefixtures("fake_cern_get_keytab")
class TestHappyPath:
    async def test_returns_keytab_and_principal(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_keytab_bytes: bytes,
    ) -> None:
        resp = await client.post(
            "/v1/keytab", headers=_auth(make_token()), json=_body()
        )
        assert resp.status_code == 200
        body = resp.json()
        assert base64.b64decode(body["keytab_b64"]) == fake_keytab_bytes
        assert body["principal"] == "gstark@CERN.CH"

    async def test_audit_line_carries_required_fields(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/keytab",
                headers={**_auth(make_token()), "X-Request-ID": "req-7"},
                json=_body(),
            )
        assert resp.status_code == 200
        (audit,) = _audit_events(cap_logs)
        assert audit["subject"] == "af-user-subject"
        assert audit["username"] == "gstark"
        assert audit["principal"] == "gstark@CERN.CH"
        assert audit["outcome"] == "issued"
        assert audit["request_id"] == "req-7"

    async def test_no_log_line_ever_contains_the_password_or_keytab(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/keytab", headers=_auth(make_token()), json=_body()
            )
        assert resp.status_code == 200
        logged = repr(cap_logs)
        assert FAKE_CORRECT_PASSWORD not in logged
        assert resp.json()["keytab_b64"] not in logged


class TestAuthenticationFailures:
    async def test_missing_authorization_header_is_401(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.post("/v1/keytab", json=_body())
        assert resp.status_code == 401


class TestRequestValidation:
    async def test_invalid_username_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/keytab",
            headers=_auth(make_token()),
            json=_body(username="../etc/passwd"),
        )
        assert resp.status_code == 422


@pytest.mark.usefixtures("fake_cern_get_keytab")
class TestBadPassword:
    async def test_wrong_password_is_400(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/keytab",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "bad password"


class TestSharesRateLimiterWithMint:
    @pytest.mark.usefixtures("fake_cern_get_keytab")
    async def test_locked_out_after_max_failed_attempts(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
    ) -> None:
        for _ in range(settings.failed_auth_max_attempts):
            resp = await client.post(
                "/v1/keytab",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )
            assert resp.status_code == 400

        resp = await client.post(
            "/v1/keytab",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 429

    async def test_keytab_failures_lock_out_mint_too(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
        fake_cern_get_keytab: object,
    ) -> None:
        del fake_cern_get_keytab  # installs the fake binary as a side effect
        for _ in range(settings.failed_auth_max_attempts):
            await client.post(
                "/v1/keytab",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )

        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 429
