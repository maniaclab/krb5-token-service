"""Unit tests for structlog JSON logging configuration."""

from __future__ import annotations

import json

import pytest
import structlog

from krb5_token_service.logging import configure_logging


@pytest.fixture(autouse=True)
def _reset_structlog() -> None:
    structlog.reset_defaults()


def test_emits_json_lines_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    structlog.get_logger("test").info("something_happened", answer=42)
    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["event"] == "something_happened"
    assert payload["answer"] == 42
    assert payload["level"] == "info"


def test_sensitive_values_are_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    # Defense in depth: even if a code path mistakenly passes a password or
    # token to a logger, the emitted line must not contain it.
    configure_logging("INFO")
    structlog.get_logger("test").info(
        "oops",
        token="super-secret",
        authorization="Bearer xyz",
        password="my-cern-password",
        ccache="binary-ccache-bytes-repr",
    )
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert "super-secret" not in line
    assert "Bearer xyz" not in line
    assert "my-cern-password" not in line
    assert "binary-ccache-bytes-repr" not in line
    payload = json.loads(line)
    assert payload["token"] == "[REDACTED]"
    assert payload["authorization"] == "[REDACTED]"
    assert payload["password"] == "[REDACTED]"
    assert payload["ccache"] == "[REDACTED]"
