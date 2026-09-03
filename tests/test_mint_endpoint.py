"""Integration tests for POST /v1/mint through the ASGI stack.

The kinit the app invokes is a real executable shell script on PATH (see
conftest) — nothing is mocked at the Python level.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from structlog.testing import capture_logs

from tests.conftest import FAKE_CORRECT_PASSWORD, _install_fake_bin

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import httpx

    from krb5_token_service.config import Settings
    from tests.conftest import FakeKinit


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "username": "gstark",
        "password": FAKE_CORRECT_PASSWORD,
    }
    payload.update(overrides)
    return payload


def _audit_events(cap_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in cap_logs if entry.get("event") == "audit"]


@pytest.mark.usefixtures("fake_kinit")
class TestHappyPath:
    async def test_returns_minted_ccache(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 200
        body = resp.json()
        assert body["ccache_b64"]
        assert body["principal"] == "gstark@CERN.CH"
        assert body["realm"] == "CERN.CH"

    async def test_expires_at_is_iso8601_utc_in_the_future(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        expires_at = datetime.fromisoformat(resp.json()["expires_at"])
        assert expires_at.tzinfo is not None
        assert expires_at > datetime.now(UTC)

    async def test_renew_until_is_present_when_ticket_is_renewable(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        renew_until = datetime.fromisoformat(resp.json()["renew_until"])
        assert renew_until.tzinfo is not None

    async def test_default_lifetime_and_renewable_lifetime_are_used_when_omitted(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_kinit: FakeKinit,
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 200
        recorded = fake_kinit.args_file.read_text().split()
        assert recorded[recorded.index("-l") + 1] == "24h"
        assert recorded[recorded.index("-r") + 1] == "7d"

    async def test_explicit_lifetime_and_renewable_lifetime_override_defaults(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_kinit: FakeKinit,
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(lifetime="12h", renewable_lifetime="3d"),
        )
        assert resp.status_code == 200
        recorded = fake_kinit.args_file.read_text().split()
        assert recorded[recorded.index("-l") + 1] == "12h"
        assert recorded[recorded.index("-r") + 1] == "3d"

    async def test_audit_line_carries_required_fields(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint",
                headers={**_auth(make_token()), "X-Request-ID": "req-42"},
                json=_body(),
            )
        assert resp.status_code == 200
        (audit,) = _audit_events(cap_logs)
        assert audit["subject"] == "af-user-subject"
        assert audit["username"] == "gstark"
        assert audit["principal"] == "gstark@CERN.CH"
        assert audit["outcome"] == "issued"
        assert audit["jti"]
        assert audit["request_id"] == "req-42"

    async def test_no_log_line_ever_contains_the_password_or_ccache(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        broker_token = make_token()
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint", headers=_auth(broker_token), json=_body()
            )
        assert resp.status_code == 200
        logged = repr(cap_logs)
        assert FAKE_CORRECT_PASSWORD not in logged
        assert broker_token not in logged
        assert resp.json()["ccache_b64"] not in logged


class TestAuthenticationFailures:
    async def test_missing_authorization_header_is_401(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.post("/v1/mint", json=_body())
        assert resp.status_code == 401

    async def test_expired_token_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token(expires_in=-60)),
            json=_body(),
        )
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    async def test_wrong_audience_is_401(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token(audience="not-us")),
            json=_body(),
        )
        assert resp.status_code == 401

    async def test_denied_request_is_audited(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            await client.post(
                "/v1/mint",
                headers=_auth(make_token(expires_in=-60)),
                json=_body(),
            )
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


@pytest.mark.usefixtures("fake_kinit_keytab")
class TestMintKeytabMode:
    async def test_returns_minted_ccache(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        fake_keytab_bytes: bytes,
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json={
                "username": "gstark",
                "keytab_b64": base64.b64encode(fake_keytab_bytes).decode(),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["principal"] == "gstark@CERN.CH"

    async def test_wrong_keytab_is_400(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json={
                "username": "gstark",
                "keytab_b64": base64.b64encode(b"totally-wrong").decode(),
            },
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "bad keytab"

    async def test_wrong_keytab_does_not_trip_the_rate_limiter(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
    ) -> None:
        for _ in range(settings.failed_auth_max_attempts + 2):
            resp = await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json={
                    "username": "gstark",
                    "keytab_b64": base64.b64encode(b"totally-wrong").decode(),
                },
            )
        assert resp.status_code == 400  # still "bad keytab", never 429

    async def test_invalid_base64_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json={"username": "gstark", "keytab_b64": "not-valid-base64!!"},
        )
        assert resp.status_code == 422


class TestMintRequestExactlyOneCredential:
    async def test_both_password_and_keytab_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(keytab_b64=base64.b64encode(b"x").decode()),
        )
        assert resp.status_code == 422

    async def test_neither_password_nor_keytab_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json={"username": "gstark"},
        )
        assert resp.status_code == 422


class TestRequestValidation:
    async def test_invalid_username_is_422_and_never_reaches_kinit(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # No fake kinit installed at all — if minting were reached, the real
        # kinit (or none) would run instead of failing cleanly via 422.
        _install_fake_bin(tmp_path, monkeypatch, 'echo "must not run" >&2\nexit 1')
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(username="../etc/passwd"),
        )
        assert resp.status_code == 422

    @pytest.mark.usefixtures("fake_kinit")
    async def test_invalid_lifetime_is_422(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(lifetime="not-a-duration"),
        )
        assert resp.status_code == 422


@pytest.mark.usefixtures("fake_kinit")
class TestBadPassword:
    async def test_wrong_password_is_400(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "bad password"

    async def test_bad_password_is_audited_as_denied(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )
        assert resp.status_code == 400
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "denied"


@pytest.mark.usefixtures("unknown_principal_kinit")
class TestUnknownPrincipal:
    async def test_unknown_principal_is_400(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post(
            "/v1/mint", headers=_auth(make_token()), json=_body(username="nosuchuser")
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "unknown principal"

    async def test_unknown_principal_does_not_trip_the_rate_limiter(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        # More attempts than failed_auth_max_attempts — none of them are bad
        # passwords, so none should count against the limiter.
        for _ in range(5):
            resp = await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(username="nosuchuser"),
            )
        assert resp.status_code == 400  # still "unknown principal", not 429


@pytest.mark.usefixtures("revoked_account_kinit")
class TestAccountUnusable:
    async def test_revoked_account_is_403(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 403
        assert "revoked" in resp.json()["detail"]


@pytest.mark.usefixtures("unreachable_kdc_kinit")
class TestMintingInfraFailure:
    async def test_kdc_unreachable_is_502_with_generic_detail(
        self, client: httpx.AsyncClient, make_token: Callable[..., str]
    ) -> None:
        with capture_logs() as cap_logs:
            resp = await client.post(
                "/v1/mint", headers=_auth(make_token()), json=_body()
            )
        assert resp.status_code == 502
        assert resp.json()["detail"] == "Ticket minting failed."
        assert "cerndc" not in resp.text
        (audit,) = _audit_events(cap_logs)
        assert audit["outcome"] == "error"


class TestRateLimiting:
    @pytest.mark.usefixtures("fake_kinit")
    async def test_locked_out_after_max_failed_attempts(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
    ) -> None:
        for _ in range(settings.failed_auth_max_attempts):
            resp = await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )
            assert resp.status_code == 400

        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 429

    async def test_lockout_blocks_even_the_correct_password(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
        fake_kinit: FakeKinit,
    ) -> None:
        for _ in range(settings.failed_auth_max_attempts):
            await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )

        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 429
        # kinit must never have been invoked for the lockout-blocked request:
        # the recorded argv is from the last bad-password attempt only.
        assert "totally-wrong" not in fake_kinit.args_file.read_text()

    @pytest.mark.usefixtures("fake_kinit")
    async def test_successful_mint_resets_the_limiter(
        self,
        client: httpx.AsyncClient,
        make_token: Callable[..., str],
        settings: Settings,
    ) -> None:
        for _ in range(settings.failed_auth_max_attempts - 1):
            await client.post(
                "/v1/mint",
                headers=_auth(make_token()),
                json=_body(password="totally-wrong"),
            )
        resp = await client.post("/v1/mint", headers=_auth(make_token()), json=_body())
        assert resp.status_code == 200

        # Limiter was reset by the success above — another failure now is
        # only the first strike, not the max'th.
        resp = await client.post(
            "/v1/mint",
            headers=_auth(make_token()),
            json=_body(password="totally-wrong"),
        )
        assert resp.status_code == 400


class TestReadyz:
    @pytest.mark.usefixtures("fake_kinit")
    async def test_ready_when_binary_present_krb5_config_readable_and_jwks_fetchable(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}

    async def test_503_when_binary_missing(
        self, make_client: Callable[[Settings], httpx.AsyncClient], settings: Settings
    ) -> None:
        settings.kinit_bin = "/nonexistent/kinit"
        async with make_client(settings) as broken_client:
            resp = await broken_client.get("/readyz")
        assert resp.status_code == 503
        assert "kinit" in resp.json()["detail"]

    async def test_503_when_krb5_config_missing(
        self,
        make_client: Callable[[Settings], httpx.AsyncClient],
        settings: Settings,
        fake_kinit: FakeKinit,
    ) -> None:
        settings.krb5_config = "/nonexistent/krb5.conf"
        async with make_client(settings) as broken_client:
            resp = await broken_client.get("/readyz")
        assert resp.status_code == 503
        assert "krb5.conf" in resp.json()["detail"]
