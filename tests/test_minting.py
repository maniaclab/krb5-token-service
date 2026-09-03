"""Integration tests for Kerberos ticket minting via a real (fake) kinit subprocess.

No Python-level mocking here: the binary under test is an executable shell
script on PATH, exactly how the real kinit is invoked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from structlog.testing import capture_logs

from krb5_token_service.minting import (
    AccountUnusableError,
    BadPasswordError,
    InvalidLifetimeError,
    InvalidUsernameError,
    MintingError,
    UnknownPrincipalError,
    mint_ticket,
    validate_lifetime,
    validate_username,
)
from tests.conftest import FAKE_CORRECT_PASSWORD

if TYPE_CHECKING:
    from pathlib import Path

    from krb5_token_service.config import Settings
    from tests.conftest import FakeKinit


def _password(text: str = FAKE_CORRECT_PASSWORD) -> bytearray:
    return bytearray(text.encode())


class TestValidateUsername:
    @pytest.mark.parametrize(
        "username", ["gstark", "a", "user_name", "user-name", "A1"]
    )
    def test_accepts_safe_tokens(self, username: str) -> None:
        validate_username(username)  # must not raise

    @pytest.mark.parametrize(
        "username",
        [
            "",
            "user@CERN.CH",
            "user@EVIL.COM",
            "../etc/passwd",
            "user name",
            "1abc",
            "-abc",
            "user/root",
        ],
    )
    def test_rejects_unsafe_values(self, username: str) -> None:
        with pytest.raises(InvalidUsernameError):
            validate_username(username)


class TestValidateLifetime:
    @pytest.mark.parametrize(
        "value", ["3600", "24h", "7d", "5:30", "36:00", "8h30s", "1d12h30m"]
    )
    def test_accepts_real_krb5_time_durations(self, value: str) -> None:
        validate_lifetime(value)  # must not raise

    @pytest.mark.parametrize("value", ["", "abc", "1w", "10 minutes", "-5", "5:3"])
    def test_rejects_unsafe_or_malformed_values(self, value: str) -> None:
        with pytest.raises(InvalidLifetimeError):
            validate_lifetime(value)


@pytest.mark.usefixtures("fake_kinit")
class TestMintTicketSuccess:
    async def test_returns_ccache_and_confirmed_fields(
        self, settings: Settings, fake_ccache_bytes: bytes
    ) -> None:
        minted = await mint_ticket("gstark", _password(), "24h", "7d", settings)
        assert minted.ccache == fake_ccache_bytes
        assert minted.principal == "gstark@CERN.CH"
        assert minted.realm == "CERN.CH"

    async def test_expires_at_and_renew_until_are_timezone_aware(
        self, settings: Settings
    ) -> None:
        minted = await mint_ticket("gstark", _password(), "24h", "7d", settings)
        assert minted.expires_at.tzinfo is not None
        assert minted.expires_at > datetime.now(UTC)
        assert minted.renew_until is not None
        assert minted.renew_until.tzinfo is not None

    async def test_invoked_with_expected_flags_and_principal(
        self, settings: Settings, fake_kinit: FakeKinit
    ) -> None:
        await mint_ticket("gstark", _password(), "24h", "7d", settings)
        recorded = fake_kinit.args_file.read_text().split()
        assert recorded[recorded.index("-l") + 1] == "24h"
        assert recorded[recorded.index("-r") + 1] == "7d"
        assert recorded[-1] == "gstark@CERN.CH"

    async def test_ccache_path_is_under_configured_tmp_root(
        self, settings: Settings, fake_kinit: FakeKinit
    ) -> None:
        await mint_ticket("gstark", _password(), "24h", "7d", settings)
        recorded = fake_kinit.args_file.read_text().split()
        cache_arg = recorded[recorded.index("-c") + 1]
        assert cache_arg.startswith(f"FILE:{settings.ccache_tmp_root}")

    async def test_password_buffer_is_zeroed_after_return(
        self, settings: Settings
    ) -> None:
        buf = _password()
        await mint_ticket("gstark", buf, "24h", "7d", settings)
        assert buf == bytearray(len(buf))

    async def test_no_log_line_ever_contains_the_password(
        self, settings: Settings
    ) -> None:
        with capture_logs() as cap_logs:
            await mint_ticket("gstark", _password(), "24h", "7d", settings)
        assert FAKE_CORRECT_PASSWORD not in repr(cap_logs)


class TestMintTicketBadPassword:
    @pytest.mark.usefixtures("fake_kinit")
    async def test_wrong_password_raises_bad_password_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(BadPasswordError):
            await mint_ticket(
                "gstark", _password("totally-wrong"), "24h", "7d", settings
            )

    @pytest.mark.usefixtures("fake_kinit")
    async def test_password_buffer_is_zeroed_even_on_failure(
        self, settings: Settings
    ) -> None:
        buf = _password("totally-wrong")
        with pytest.raises(BadPasswordError):
            await mint_ticket("gstark", buf, "24h", "7d", settings)
        assert buf == bytearray(len(buf))


class TestMintTicketClassifiedFailures:
    @pytest.mark.usefixtures("unknown_principal_kinit")
    async def test_unknown_principal_raises_unknown_principal_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(UnknownPrincipalError):
            await mint_ticket("nosuchuser", _password(), "24h", "7d", settings)

    @pytest.mark.usefixtures("revoked_account_kinit")
    async def test_revoked_account_raises_account_unusable_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(AccountUnusableError, match="revoked"):
            await mint_ticket("gstark", _password(), "24h", "7d", settings)

    @pytest.mark.usefixtures("expired_password_kinit")
    async def test_expired_password_raises_account_unusable_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(AccountUnusableError, match="expired"):
            await mint_ticket("gstark", _password(), "24h", "7d", settings)

    @pytest.mark.usefixtures("unreachable_kdc_kinit")
    async def test_unreachable_kdc_raises_generic_minting_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(MintingError):
            await mint_ticket("gstark", _password(), "24h", "7d", settings)

    @pytest.mark.usefixtures("unreachable_kdc_kinit")
    async def test_generic_minting_error_never_leaks_kdc_hostname(
        self, settings: Settings
    ) -> None:
        with pytest.raises(MintingError) as excinfo:
            await mint_ticket("gstark", _password(), "24h", "7d", settings)
        assert "cerndc" not in str(excinfo.value)


class TestMintTicketInfraFailures:
    async def test_missing_binary_raises_minting_error(
        self, settings: Settings
    ) -> None:
        settings.kinit_bin = "/nonexistent/kinit"
        with pytest.raises(MintingError):
            await mint_ticket("gstark", _password(), "24h", "7d", settings)

    async def test_timeout_raises_minting_error(
        self,
        settings: Settings,
        hanging_kinit: Path,
    ) -> None:
        settings.kinit_timeout_seconds = 1
        with pytest.raises(MintingError, match="timed out"):
            await mint_ticket("gstark", _password(), "24h", "7d", settings)
