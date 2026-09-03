"""Integration tests for Kerberos ticket minting via a real (fake) kinit subprocess.

No Python-level mocking here: the binary under test is an executable shell
script on PATH, exactly how the real kinit is invoked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from structlog.testing import capture_logs

from krb5_token_service.ccache import CcacheParseError
from krb5_token_service.minting import (
    AccountUnusableError,
    BadKeytabError,
    BadPasswordError,
    InvalidLifetimeError,
    InvalidUsernameError,
    MintingError,
    TicketExpiredError,
    UnknownPrincipalError,
    mint_keytab,
    mint_ticket,
    renew_ticket,
    validate_lifetime,
    validate_username,
)
from tests.conftest import FAKE_CORRECT_PASSWORD

if TYPE_CHECKING:
    from pathlib import Path

    from krb5_token_service.config import Settings
    from tests.conftest import FakeCernGetKeytab, FakeKinit


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


@pytest.mark.usefixtures("fake_kinit_keytab")
class TestMintTicketKeytabSuccess:
    async def test_returns_ccache_and_confirmed_fields(
        self, settings: Settings, fake_ccache_bytes: bytes, fake_keytab_bytes: bytes
    ) -> None:
        minted = await mint_ticket(
            "gstark", None, "24h", "7d", settings, keytab=bytearray(fake_keytab_bytes)
        )
        assert minted.ccache == fake_ccache_bytes
        assert minted.principal == "gstark@CERN.CH"

    async def test_invoked_with_dash_k_dash_t_and_no_stdin_password(
        self, settings: Settings, fake_keytab_bytes: bytes, fake_kinit_keytab: FakeKinit
    ) -> None:
        await mint_ticket(
            "gstark", None, "24h", "7d", settings, keytab=bytearray(fake_keytab_bytes)
        )
        recorded = fake_kinit_keytab.args_file.read_text().split()
        assert "-k" in recorded
        assert recorded[recorded.index("-t") + 1].endswith("keytab")
        assert recorded[-1] == "gstark@CERN.CH"

    async def test_keytab_buffer_is_zeroed_after_return(
        self, settings: Settings, fake_keytab_bytes: bytes
    ) -> None:
        buf = bytearray(fake_keytab_bytes)
        await mint_ticket("gstark", None, "24h", "7d", settings, keytab=buf)
        assert buf == bytearray(len(buf))


class TestMintTicketBadKeytab:
    @pytest.mark.usefixtures("fake_kinit_keytab")
    async def test_wrong_keytab_raises_bad_keytab_error(
        self, settings: Settings
    ) -> None:
        # BadKeytabError, not BadPasswordError, is what keeps app.py from
        # ever counting this against the password rate limiter.
        with pytest.raises(BadKeytabError):
            await mint_ticket(
                "gstark",
                None,
                "24h",
                "7d",
                settings,
                keytab=bytearray(b"totally-wrong"),
            )


@pytest.mark.usefixtures("fake_kinit_renew")
class TestRenewTicketSuccess:
    async def test_returns_the_renewed_ccache_not_the_input(
        self,
        settings: Settings,
        fake_ccache_bytes: bytes,
        fake_renewed_ccache_bytes: bytes,
    ) -> None:
        minted = await renew_ticket(fake_ccache_bytes, settings)
        assert minted.ccache == fake_renewed_ccache_bytes
        assert minted.ccache != fake_ccache_bytes

    async def test_invoked_with_dash_r(
        self, settings: Settings, fake_ccache_bytes: bytes, fake_kinit_renew: FakeKinit
    ) -> None:
        await renew_ticket(fake_ccache_bytes, settings)
        recorded = fake_kinit_renew.args_file.read_text().split()
        assert "-R" in recorded


class TestRenewTicketFailures:
    async def test_expired_ticket_raises_ticket_expired_error(
        self, settings: Settings, fake_ccache_bytes: bytes, ticket_expired_kinit: Path
    ) -> None:
        del ticket_expired_kinit  # installs the fake binary as a side effect
        with pytest.raises(TicketExpiredError):
            await renew_ticket(fake_ccache_bytes, settings)

    async def test_garbage_ccache_raises_ccache_parse_error_before_invoking_kinit(
        self, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No fake kinit installed at all: if renew_ticket reached the
        # subprocess call, the real (or absent) kinit would run instead of
        # failing cleanly via CcacheParseError.
        bin_dir = tmp_path / "no-kinit-here"
        bin_dir.mkdir()
        monkeypatch.setenv("PATH", str(bin_dir))
        with pytest.raises(CcacheParseError):
            await renew_ticket(b"not-a-real-ccache", settings)


@pytest.mark.usefixtures("fake_cern_get_keytab")
class TestMintKeytabSuccess:
    async def test_returns_keytab_bytes(
        self, settings: Settings, fake_keytab_bytes: bytes
    ) -> None:
        keytab_bytes = await mint_keytab("gstark", _password(), settings)
        assert keytab_bytes == fake_keytab_bytes

    async def test_invoked_with_expected_flags(
        self, settings: Settings, fake_cern_get_keytab: FakeCernGetKeytab
    ) -> None:
        await mint_keytab("gstark", _password(), settings)
        recorded = fake_cern_get_keytab.args_file.read_text().split()
        assert "-u" in recorded
        assert "-v" in recorded
        assert recorded[recorded.index("-l") + 1] == "gstark"
        assert "--keytab" in recorded

    async def test_password_buffer_is_zeroed_after_return(
        self, settings: Settings
    ) -> None:
        buf = _password()
        await mint_keytab("gstark", buf, settings)
        assert buf == bytearray(len(buf))

    async def test_no_log_line_ever_contains_the_password(
        self, settings: Settings
    ) -> None:
        with capture_logs() as cap_logs:
            await mint_keytab("gstark", _password(), settings)
        assert FAKE_CORRECT_PASSWORD not in repr(cap_logs)


class TestMintKeytabBadPassword:
    @pytest.mark.usefixtures("fake_cern_get_keytab")
    async def test_wrong_password_raises_bad_password_error(
        self, settings: Settings
    ) -> None:
        with pytest.raises(BadPasswordError):
            await mint_keytab("gstark", _password("totally-wrong"), settings)

    @pytest.mark.usefixtures("fake_cern_get_keytab")
    async def test_password_buffer_is_zeroed_even_on_failure(
        self, settings: Settings
    ) -> None:
        buf = _password("totally-wrong")
        with pytest.raises(BadPasswordError):
            await mint_keytab("gstark", buf, settings)
        assert buf == bytearray(len(buf))
