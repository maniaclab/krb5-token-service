"""Unit tests for Settings (env-driven configuration)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from krb5_token_service.config import Settings, get_settings

if TYPE_CHECKING:
    import pytest


class TestDefaults:
    def test_expected_audience_defaults_to_service_name(self) -> None:
        assert Settings(_env_file=None).expected_audience == "krb5-token-service"

    def test_kinit_bin_default(self) -> None:
        assert Settings(_env_file=None).kinit_bin == "kinit"

    def test_krb5_config_default(self) -> None:
        assert Settings(_env_file=None).krb5_config == "/app/etc/krb5.conf"

    def test_default_realm_default(self) -> None:
        assert Settings(_env_file=None).default_realm == "CERN.CH"

    def test_default_lifetime_default(self) -> None:
        assert Settings(_env_file=None).default_lifetime == "24h"

    def test_default_renewable_lifetime_default(self) -> None:
        assert Settings(_env_file=None).default_renewable_lifetime == "7d"

    def test_kinit_timeout_default(self) -> None:
        assert Settings(_env_file=None).kinit_timeout_seconds == 30

    def test_failed_auth_defaults(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.failed_auth_max_attempts == 3
        assert settings.failed_auth_window_seconds == 900
        assert settings.failed_auth_lockout_seconds == 900

    def test_jwks_cache_ttl_default(self) -> None:
        assert Settings(_env_file=None).jwks_cache_ttl_seconds == 300


class TestEnvOverrides:
    def test_env_vars_override_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BROKER_JWKS_URL", "https://broker.example/jwks")
        monkeypatch.setenv("BROKER_ISSUER", "https://broker.example")
        monkeypatch.setenv("EXPECTED_AUDIENCE", "other-audience")
        monkeypatch.setenv("KINIT_BIN", "/opt/krb5/bin/kinit")
        monkeypatch.setenv("KRB5_CONFIG", "/opt/krb5/krb5.conf")
        monkeypatch.setenv("DEFAULT_REALM", "EXAMPLE.COM")
        monkeypatch.setenv("DEFAULT_LIFETIME", "12h")
        monkeypatch.setenv("DEFAULT_RENEWABLE_LIFETIME", "3d")
        monkeypatch.setenv("KINIT_TIMEOUT_SECONDS", "10")
        monkeypatch.setenv("FAILED_AUTH_MAX_ATTEMPTS", "5")

        settings = Settings(_env_file=None)
        assert settings.broker_jwks_url == "https://broker.example/jwks"
        assert settings.broker_issuer == "https://broker.example"
        assert settings.expected_audience == "other-audience"
        assert settings.kinit_bin == "/opt/krb5/bin/kinit"
        assert settings.krb5_config == "/opt/krb5/krb5.conf"
        assert settings.default_realm == "EXAMPLE.COM"
        assert settings.default_lifetime == "12h"
        assert settings.default_renewable_lifetime == "3d"
        assert settings.kinit_timeout_seconds == 10
        assert settings.failed_auth_max_attempts == 5


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
