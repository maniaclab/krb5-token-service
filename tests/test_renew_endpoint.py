"""Integration tests for POST /v1/renew through the ASGI stack.

The kinit -R the app invokes is a real executable shell script on PATH (see
conftest) — nothing is mocked at the Python level.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

import pytest
from structlog.testing import capture_logs

from tests.conftest import _install_fake_bin

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import httpx

    from krb5_token_service.config import Settings


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _audit_events(cap_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in cap_logs if entry.get("event") == "audit"]


@pytest.mark.usefixtures("fake_kinit_renew")
class TestHappyPath:
    async def test_returns_the_renewed_ccache(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_ccache_bytes: bytes,
        fake_renewed_ccache_bytes: bytes,
    ) -> None:
        resp = await client.post(
            "/v1/renew",
            headers=_auth(make_token()),
            json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert base64.b64decode(body["ccache_b64"]) == fake_renewed_ccache_bytes
        assert body["principal"] == "gstark@CERN.CH"

    async def test_audit_line_carries_required_fields_but_no_username(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_ccache_bytes: bytes,
    ) -> None:
        # /v1/renew's request body carries no username at all — the
        # principal only becomes known after parsing the renewed ccache.
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/renew",
                headers={**_auth(make_token()), "X-Request-ID": "req-99"},
                json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
            )
        assert resp.status_code == 200
        (audit,) = _audit_events(cap_logs)
        assert audit["subject"] == "af-user-subject"
        assert audit["principal"] == "gstark@CERN.CH"
        assert audit["outcome"] == "issued"
        assert audit["request_id"] == "req-99"

    async def test_no_log_line_ever_contains_the_ccache(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_ccache_bytes: bytes,
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/renew",
                headers=_auth(make_token()),
                json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
            )
        assert resp.status_code == 200
        logged = repr(cap_logs)
        assert resp.json()["ccache_b64"] not in logged


class TestAuthenticationFailures:
    async def test_missing_authorization_header_is_401(
        self, client: httpx.AsyncClient, fake_ccache_bytes: bytes
    ) -> None:
        resp = await client.post(
            "/v1/renew",
            json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
        )
        assert resp.status_code == 401

    async def test_expired_token_is_401(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_ccache_bytes: bytes,
    ) -> None:
        resp = await client.post(
            "/v1/renew",
            headers=_auth(make_token(expires_in=-60)),
            json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
        )
        assert resp.status_code == 401


class TestRequestValidation:
    async def test_invalid_base64_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/renew",
            headers=_auth(make_token()),
            json={"ccache_b64": "not-valid-base64!!"},
        )
        assert resp.status_code == 422

    async def test_garbage_ccache_is_422_and_never_reaches_kinit(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        bin_dir = tmp_path / "no-kinit-here"
        bin_dir.mkdir()
        monkeypatch.setenv("PATH", str(bin_dir))
        resp = await client.post(
            "/v1/renew",
            headers=_auth(make_token()),
            json={"ccache_b64": base64.b64encode(b"not-a-real-ccache").decode()},
        )
        assert resp.status_code == 422


@pytest.mark.usefixtures("ticket_expired_kinit")
class TestTicketExpired:
    async def test_expired_ticket_is_400(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_ccache_bytes: bytes,
    ) -> None:
        resp = await client.post(
            "/v1/renew",
            headers=_auth(make_token()),
            json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
        )
        assert resp.status_code == 400


class TestNeverTouchesTheRateLimiter:
    async def test_repeated_expired_renewals_never_429(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
        fake_ccache_bytes: bytes,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _install_fake_bin(
            tmp_path,
            monkeypatch,
            'echo "kinit: Ticket expired while renewing credentials" >&2\nexit 1',
        )
        for _ in range(settings.failed_auth_max_attempts + 2):
            resp = await client.post(
                "/v1/renew",
                headers=_auth(make_token()),
                json={"ccache_b64": base64.b64encode(fake_ccache_bytes).decode()},
            )
        assert resp.status_code == 400  # never 429 -- no credential involved
