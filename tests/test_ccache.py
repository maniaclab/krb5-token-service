"""Unit tests for FILE-ccache parsing (ccache.py).

Exercises the real pykrb5-backed parser against genuine ccache byte strings
built by tests/ccache_fixtures.py — the same wire format kinit itself
writes.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

from krb5_token_service.ccache import CcacheParseError, read_ccache
from tests.ccache_fixtures import build_ccache

if TYPE_CHECKING:
    from pathlib import Path


class TestReadCcache:
    def test_parses_principal_realm_and_times(self, tmp_path: Path) -> None:
        now = int(time.time())
        path = tmp_path / "ccache"
        path.write_bytes(
            build_ccache(
                username="gstark",
                realm="CERN.CH",
                authtime=now,
                endtime=now + 86400,
                renew_till=now + 604800,
            )
        )
        info = read_ccache(path)
        assert info.principal == "gstark@CERN.CH"
        assert info.realm == "CERN.CH"
        assert int(info.expires_at.timestamp()) == now + 86400
        assert info.renew_until is not None
        assert int(info.renew_until.timestamp()) == now + 604800

    def test_expires_at_and_renew_until_are_timezone_aware_utc(
        self, tmp_path: Path
    ) -> None:
        now = int(time.time())
        path = tmp_path / "ccache"
        path.write_bytes(
            build_ccache(
                username="gstark",
                realm="CERN.CH",
                authtime=now,
                endtime=now + 3600,
                renew_till=now + 3600,
            )
        )
        info = read_ccache(path)
        assert info.expires_at.tzinfo is not None
        assert info.renew_until is not None
        assert info.renew_until.tzinfo is not None

    def test_zero_renew_till_is_none(self, tmp_path: Path) -> None:
        # A non-renewable ticket (no -r requested / KDC denied renewal)
        # carries renew_till == 0 in the ccache — must surface as None, not
        # as an epoch timestamp.
        now = int(time.time())
        path = tmp_path / "ccache"
        path.write_bytes(
            build_ccache(
                username="gstark",
                realm="CERN.CH",
                authtime=now,
                endtime=now + 3600,
                renew_till=0,
            )
        )
        info = read_ccache(path)
        assert info.renew_until is None

    def test_config_entry_is_skipped_not_mistaken_for_the_tgt(
        self, tmp_path: Path
    ) -> None:
        # build_ccache always writes an X-CACHECONF: config entry (all-zero
        # times) ahead of the real TGT — if read_ccache picked it up instead
        # of skipping it, expires_at would be the Unix epoch.
        now = int(time.time())
        path = tmp_path / "ccache"
        path.write_bytes(
            build_ccache(
                username="gstark",
                realm="CERN.CH",
                authtime=now,
                endtime=now + 3600,
            )
        )
        info = read_ccache(path)
        assert info.expires_at.timestamp() > 0

    def test_no_tgt_credential_raises_ccache_parse_error(self, tmp_path: Path) -> None:
        now = int(time.time())
        path = tmp_path / "ccache"
        path.write_bytes(
            build_ccache(
                username="gstark",
                realm="CERN.CH",
                authtime=now,
                endtime=now + 3600,
                include_tgt=False,
            )
        )
        with pytest.raises(CcacheParseError):
            read_ccache(path)
