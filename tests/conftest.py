"""Shared fixtures: RSA keypair, stubbed JWKS fetch, a broker-token factory,
and fake ``kinit`` executables covering every classified failure mode plus
success.

The JWKS is never fetched over the network in tests — ``stub_jwks_fetch``
replaces ``identity._fetch_jwks`` (the single network boundary) with an
in-process stub serving keys generated here. Each fake ``kinit`` writes a
genuine FILE-ccache v4 byte string (tests/ccache_fixtures.py) on success, so
minting.py's downstream ccache.py parsing exercises the real wire format,
not a hand-rolled fake.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from krb5_token_service import identity
from krb5_token_service.app import create_app
from krb5_token_service.config import Settings
from tests.ccache_fixtures import build_ccache

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path

TEST_KID = "test-signing-key"

# The password the fake kinit scripts treat as "correct". Any other stdin
# content is treated as a bad password, mirroring real kinit's "Password
# incorrect while getting initial credentials" failure.
FAKE_CORRECT_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(scope="session")
def rsa_private_key() -> rsa.RSAPrivateKey:
    # 2048 bits keeps per-session generation fast while staying a realistic
    # RS256 key size.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_private_key() -> rsa.RSAPrivateKey:
    """A second keypair NOT in the served JWKS — for wrong-signature tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_private_key: rsa.RSAPrivateKey) -> list[dict[str, Any]]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    jwk.update({"kid": TEST_KID, "alg": "RS256", "use": "sig"})
    return [jwk]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    krb5_config = tmp_path / "krb5.conf"
    krb5_config.write_text("[libdefaults]\n  default_realm = CERN.CH\n")
    return Settings(
        _env_file=None,
        broker_jwks_url="https://broker.test/jwks",
        broker_issuer="https://broker.test",
        krb5_config=str(krb5_config),
        ccache_tmp_root=str(tmp_path / "krb5cc"),
        # Short window/lockout so the rate-limit tests don't need to sleep
        # for the production defaults (15 minutes each).
        failed_auth_max_attempts=3,
        failed_auth_window_seconds=900,
        failed_auth_lockout_seconds=900,
    )


class JwksFetchStub:
    """Callable standing in for ``identity._fetch_jwks``.

    Counts calls, can be told to fail (mimicking the real fetch's 502), and
    can delay to expose single-flight behavior.
    """

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.calls = 0
        self.fail = False
        self.delay = 0.0

    async def __call__(self, jwks_url: str) -> list[dict[str, Any]]:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise HTTPException(
                status_code=502,
                detail=f"Unable to reach JWKS endpoint: {jwks_url}",
            )
        return self.keys


@pytest.fixture
def stub_jwks_fetch(
    jwks: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> JwksFetchStub:
    identity._jwks_cache.clear()
    stub = JwksFetchStub(jwks)
    monkeypatch.setattr(identity, "_fetch_jwks", stub)
    return stub


@pytest.fixture
def make_token(
    rsa_private_key: rsa.RSAPrivateKey, settings: Settings
) -> Callable[..., str]:
    """Factory for AF Broker Identity Tokens with controllable claims."""

    def _make(
        *,
        sub: str = "af-user-subject",
        issuer: str | None = None,
        audience: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = TEST_KID,
        expires_in: int = 300,
        omit: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer or settings.broker_issuer,
            "sub": sub,
            "aud": audience or settings.expected_audience,
            "exp": now + expires_in,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        if extra:
            claims.update(extra)
        for claim in omit:
            claims.pop(claim, None)
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            claims, key or rsa_private_key, algorithm="RS256", headers=headers
        )

    return _make


@pytest.fixture
def fake_ccache_bytes() -> bytes:
    """A genuine FILE-ccache v4 byte string standing in for a kinit mint.

    Built by tests/ccache_fixtures.py — the same wire format
    src/krb5_token_service/ccache.py parses in production, so this exercises
    real MIT ccache binary parsing, not a hand-rolled fake.
    """
    now = int(time.time())
    return build_ccache(
        username="gstark",
        realm="CERN.CH",
        authtime=now,
        endtime=now + 86400,
        renew_till=now + 604800,
    )


@pytest.fixture
def fake_renewed_ccache_bytes() -> bytes:
    """A second, distinguishable ccache standing in for kinit -R's output.

    A different endtime than fake_ccache_bytes, so a test can prove the
    response reflects a fresh post-renewal read rather than just echoing
    back the pre-call input.
    """
    now = int(time.time())
    return build_ccache(
        username="gstark",
        realm="CERN.CH",
        authtime=now,
        endtime=now + 172800,
        renew_till=now + 604800,
    )


@pytest.fixture
def fake_keytab_bytes() -> bytes:
    """Arbitrary bytes standing in for a real keytab file's contents.

    minting.py never parses keytab bytes itself (unlike a ccache) — it just
    writes them to a tmpfs file and hands the path to kinit -kt — so these
    don't need to be a real MIT keytab, only a fixed, comparable blob the
    fake kinit script below can match against.
    """
    return b"\x05\x02fake-keytab-fixture-not-a-real-keytab-file"


def _install_fake_bin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> Path:
    """Write an executable ``kinit`` shell script into a tmpdir and prepend that tmpdir to PATH."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "kinit"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return script


class FakeKinit(NamedTuple):
    path: Path
    args_file: Path


# Shared shell fragment: record argv, parse it looking for the value
# following -c (FILE:<path>), then read the password from kinit's real
# stdin contract and compare it to FAKE_CORRECT_PASSWORD. On success, copies
# the pre-built fake ccache to that path; on mismatch, fails exactly the way
# a real kinit fails on a wrong password (verified against krb5/krb5's
# kinit.c — see minting.py's _BAD_PASSWORD_MARKERS docstring).
_FAKE_BIN_DISPATCH = f"""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
out="${{out#FILE:}}"
IFS= read -r password
if [ "$password" = "{FAKE_CORRECT_PASSWORD}" ]; then
  cp "$FAKE_CCACHE_PATH" "$out"
  exit 0
else
  echo "kinit: Password incorrect while getting initial credentials" >&2
  exit 1
fi
"""


@pytest.fixture
def fake_kinit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_ccache_bytes: bytes,
) -> FakeKinit:
    """A fake kinit on PATH: records its argv, writes a real ccache to -c's FILE: path on the correct password."""
    ccache_source = tmp_path / "fake_source.ccache"
    ccache_source.write_bytes(fake_ccache_bytes)
    monkeypatch.setenv("FAKE_CCACHE_PATH", str(ccache_source))
    args_file = tmp_path / "kinit_args.txt"
    script = _install_fake_bin(
        tmp_path,
        monkeypatch,
        f'echo "$@" > "{args_file}"\n{_FAKE_BIN_DISPATCH}',
    )
    return FakeKinit(path=script, args_file=args_file)


# Shell fragment for -kt (keytab) mode: parse argv for -c (ccache out path)
# and -t (keytab path); "succeed" only when the keytab file's content
# byte-for-byte matches the fixture path FAKE_KEYTAB_PATH points at. Never
# reads stdin — kinit -kt sends none (see minting.mint_ticket).
_FAKE_BIN_KEYTAB_DISPATCH = """
out=""
keytab=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) out="$2"; shift 2 ;;
    -t) keytab="$2"; shift 2 ;;
    *) shift ;;
  esac
done
out="${out#FILE:}"
if cmp -s "$keytab" "$FAKE_KEYTAB_PATH"; then
  cp "$FAKE_CCACHE_PATH" "$out"
  exit 0
else
  echo "kinit: Preauthentication failed while getting initial credentials" >&2
  exit 1
fi
"""


@pytest.fixture
def fake_kinit_keytab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_ccache_bytes: bytes,
    fake_keytab_bytes: bytes,
) -> FakeKinit:
    """A fake kinit -kt on PATH: records argv, succeeds only for a byte-exact keytab match."""
    ccache_source = tmp_path / "fake_source.ccache"
    ccache_source.write_bytes(fake_ccache_bytes)
    monkeypatch.setenv("FAKE_CCACHE_PATH", str(ccache_source))
    keytab_source = tmp_path / "fake_source.keytab"
    keytab_source.write_bytes(fake_keytab_bytes)
    monkeypatch.setenv("FAKE_KEYTAB_PATH", str(keytab_source))
    args_file = tmp_path / "kinit_keytab_args.txt"
    script = _install_fake_bin(
        tmp_path,
        monkeypatch,
        f'echo "$@" > "{args_file}"\n{_FAKE_BIN_KEYTAB_DISPATCH}',
    )
    return FakeKinit(path=script, args_file=args_file)


# Shell fragment for -R (renew) mode: parse argv for -c only. The ccache
# already at that path is what renew_ticket itself wrote before invoking
# kinit -- "succeed" by overwriting it with a distinguishable renewed
# fixture, so a test can prove the response reflects a fresh post-call read.
_FAKE_BIN_RENEW_DISPATCH = """
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
out="${out#FILE:}"
cp "$FAKE_RENEWED_CCACHE_PATH" "$out"
exit 0
"""


@pytest.fixture
def fake_kinit_renew(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_renewed_ccache_bytes: bytes,
) -> FakeKinit:
    """A fake kinit -R on PATH: always succeeds, overwriting the ccache with a renewed fixture."""
    renewed_source = tmp_path / "fake_renewed.ccache"
    renewed_source.write_bytes(fake_renewed_ccache_bytes)
    monkeypatch.setenv("FAKE_RENEWED_CCACHE_PATH", str(renewed_source))
    args_file = tmp_path / "kinit_renew_args.txt"
    script = _install_fake_bin(
        tmp_path,
        monkeypatch,
        f'echo "$@" > "{args_file}"\n{_FAKE_BIN_RENEW_DISPATCH}',
    )
    return FakeKinit(path=script, args_file=args_file)


@pytest.fixture
def ticket_expired_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit -R that always fails as a real kinit does past renew_until."""
    return _install_fake_bin(
        tmp_path,
        monkeypatch,
        _stderr_only_script("kinit: Ticket expired while renewing credentials"),
    )


def _stderr_only_script(message: str) -> str:
    return f'echo "{message}" >&2\nexit 1\n'


@pytest.fixture
def unknown_principal_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit that always fails as a real KDC does for an unknown principal."""
    return _install_fake_bin(
        tmp_path,
        monkeypatch,
        _stderr_only_script(
            "kinit: Client not found in Kerberos database while getting "
            "initial credentials"
        ),
    )


@pytest.fixture
def revoked_account_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit that always fails as a real KDC does for a revoked account."""
    return _install_fake_bin(
        tmp_path,
        monkeypatch,
        _stderr_only_script(
            "kinit: Client's credentials have been revoked while getting "
            "initial credentials"
        ),
    )


@pytest.fixture
def expired_password_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit that always fails as a real KDC does for an expired password."""
    return _install_fake_bin(
        tmp_path,
        monkeypatch,
        _stderr_only_script(
            "kinit: Password has expired while getting initial credentials"
        ),
    )


@pytest.fixture
def unreachable_kdc_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit that always fails as a real kinit does when no KDC answers."""
    return _install_fake_bin(
        tmp_path,
        monkeypatch,
        _stderr_only_script(
            "kinit: Cannot contact any KDC for requested realm 'CERN.CH' "
            "while getting initial credentials"
        ),
    )


@pytest.fixture
def hanging_kinit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake kinit that never returns — for timeout tests."""
    return _install_fake_bin(tmp_path, monkeypatch, "sleep 100")


class FakeCernGetKeytab(NamedTuple):
    path: Path
    args_file: Path


# A fake cern-get-keytab as a plain Python script (invoked as
# `sys.executable <script> ...`, matching mint_keytab's real invocation — no
# shebang or exec bit needed). Records argv, reads the password from stdin
# (the patched real script's non-interactive input path — see
# etc/cern-get-keytab.patch), and on a match copies the fixture keytab to
# the --keytab path; on mismatch, prints the real msktutil/krb5 error text
# etc/cern-get-keytab.patch's fourth hunk makes reach stderr (see
# minting.py's _classify_cern_get_keytab_stderr docstring).
_FAKE_CERN_GET_KEYTAB_SCRIPT = f"""
import os
import shutil
import sys

argv = sys.argv[1:]
with open(os.environ["FAKE_CGK_ARGS_FILE"], "w") as f:
    f.write(" ".join(argv))

keytab_path = None
for i, arg in enumerate(argv):
    if arg == "--keytab":
        keytab_path = argv[i + 1]

password = sys.stdin.readline().rstrip("\\n")
if password == "{FAKE_CORRECT_PASSWORD}":
    shutil.copy(os.environ["FAKE_KEYTAB_PATH"], keytab_path)
    sys.exit(0)
else:
    print(
        "Error: krb5_get_init_creds_password failed: Preauthentication failed",
        file=sys.stderr,
    )
    sys.exit(1)
"""


@pytest.fixture
def fake_cern_get_keytab(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_keytab_bytes: bytes,
    settings: Settings,
) -> FakeCernGetKeytab:
    """A fake cern-get-keytab: points settings.cern_get_keytab_bin at a script under this fixture's control."""
    keytab_source = tmp_path / "fake_bootstrap_source.keytab"
    keytab_source.write_bytes(fake_keytab_bytes)
    monkeypatch.setenv("FAKE_KEYTAB_PATH", str(keytab_source))
    args_file = tmp_path / "cern_get_keytab_args.txt"
    monkeypatch.setenv("FAKE_CGK_ARGS_FILE", str(args_file))
    script_path = tmp_path / "fake-cern-get-keytab.py"
    script_path.write_text(_FAKE_CERN_GET_KEYTAB_SCRIPT)
    settings.cern_get_keytab_bin = str(script_path)
    return FakeCernGetKeytab(path=script_path, args_file=args_file)


@pytest.fixture
def make_client(
    stub_jwks_fetch: JwksFetchStub,
) -> Callable[[Settings], httpx.AsyncClient]:
    """Factory building an ASGI test client around a fresh app for *settings*."""

    def _make(settings: Settings) -> httpx.AsyncClient:
        app = create_app(settings)
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )

    return _make


@pytest.fixture
async def client(
    make_client: Callable[[Settings], httpx.AsyncClient], settings: Settings
) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(settings) as test_client:
        yield test_client
