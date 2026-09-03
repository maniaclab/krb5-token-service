"""Kerberos ticket minting via the ``kinit`` CLI.

The user's CERN password is the only secret this service receives that it
does not itself own. It is transmitted to kinit over the subprocess's stdin
— never on argv, never logged — and the buffer holding it is zeroed in
place immediately after use, mirroring voms-token-service's minting.py
discipline for the Globus passphrase.

Unlike voms-proxy-init, kinit needs no on-disk user credential to mint
against: the password is the entire credential. There is therefore no homes
mount, no impersonation, and no privileged capability requirement here — the
service runs as a single unprivileged uid for its whole lifetime, and the
minted ccache is staged in a private 0700 directory on the pod's own tmpfs
that this process itself owns outright.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from krb5_token_service.ccache import read_ccache

if TYPE_CHECKING:
    from datetime import datetime

    from krb5_token_service.config import Settings

logger = structlog.get_logger(__name__)


class InvalidUsernameError(Exception):
    """Raised when the request's username isn't a single safe token.

    A bare username is required — never ``user@REALM`` — so a request can
    never smuggle a realm other than ``settings.default_realm`` into the
    principal kinit authenticates as.
    """


class InvalidLifetimeError(Exception):
    """Raised when a lifetime/renewable_lifetime value isn't a krb5 time duration.

    See MIT's "Time duration" format: ``h:m[:s]``, ``NdNhNmNs``, or a bare
    integer count of seconds.
    """


class MintingError(Exception):
    """Raised when kinit fails for a reason other than the password/account.

    The message is deliberately generic: kinit's stderr can reference KDC
    hostnames and is logged server-side only, never returned to the client.
    """


class BadPasswordError(Exception):
    """Raised when kinit fails because the CERN password was wrong.

    Distinct from every other failure here because it is the one outcome
    that must count against ratelimit.RateLimiter — see app.py.
    """


class UnknownPrincipalError(Exception):
    """Raised when the KDC has no such principal in this realm.

    Not counted against the rate limiter: this is a request-shape problem
    (an unknown username), not a guessing attempt against a real account.
    """


class AccountUnusableError(Exception):
    """Raised when the KDC refuses a structurally valid, correctly-authenticated request.

    Covers a revoked or already-expired CERN account — retrying (with any
    password) cannot help, and the message is a fixed, user-actionable
    string, never kinit's stderr.
    """


@dataclass(frozen=True)
class MintedTicket:
    ccache: bytes
    principal: str
    realm: str
    expires_at: datetime
    renew_until: datetime | None


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite *buf* in place with NUL bytes.

    Unlike rebinding an immutable ``bytes`` object, mutating a ``bytearray``
    genuinely clears the underlying buffer, so a secret held in one is
    erased once this returns.
    """
    for i in range(len(buf)):
        buf[i] = 0


# CERN usernames are a single alphanumeric token. Requiring this (rather
# than accepting anything that isn't a shell metacharacter) rules out an
# embedded "@REALM" entirely — the realm always comes from
# settings.default_realm, never from the request.
_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def validate_username(username: str) -> None:
    if not _USERNAME_RE.fullmatch(username):
        raise InvalidUsernameError(username)


# MIT krb5's "Time duration" format (doc/basic/date_format.rst): h:m[:s],
# NdNhNmNs (any subset of that order), or a bare count of seconds. The
# NdNhNmNs form technically also allows space-separated components
# ("10d 0h 0m 0s"); deliberately not accepted here to keep the grammar this
# service validates unambiguous — the defaults ("24h", "7d") and any
# single-component override never need them.
_LIFETIME_RE = re.compile(
    r"^\d+$"  # plain seconds
    r"|^\d{1,3}:\d{2}(?::\d{2})?$"  # h:m[:s]
    r"|^(?:\d+d)?(?:\d+h)?(?:\d+m)?(?:\d+s)?$"  # NdNhNmNs subset
)


def validate_lifetime(value: str) -> None:
    if not value or not _LIFETIME_RE.fullmatch(value):
        raise InvalidLifetimeError(value)


# Real kinit/KDC stderr text (verified against krb5/krb5's kinit.c and
# error_tables/krb5_err.et — see this repo's design doc). kinit special-cases
# a password-prompted KRB5KDC_ERR_PREAUTH_FAILED (or a decrypt failure) as
# "Password incorrect while <doing>"; every other error falls through to
# com_err's "<message> while <doing>" — so these are prefix/substring
# markers, not full-line matches, matched case-sensitively against kinit's
# real output (unlike voms-proxy-init's markers, which lowercase-compare
# against openssl's own lowercase text).
_BAD_PASSWORD_MARKERS: tuple[str, ...] = ("Password incorrect",)
_UNKNOWN_PRINCIPAL_MARKERS: tuple[str, ...] = ("not found in Kerberos database",)
_REVOKED_MARKERS: tuple[str, ...] = ("credentials have been revoked",)
_PASSWORD_EXPIRED_MARKERS: tuple[str, ...] = ("Password has expired",)

_ACCOUNT_REVOKED_DETAIL = (
    "This CERN account's credentials have been revoked. Contact CERN account support."
)
_PASSWORD_EXPIRED_DETAIL = (
    "This CERN account's password has expired and must be changed before a "
    "ticket can be minted."
)


def _classify_stderr(stderr: str) -> Exception | None:
    """Map real kinit/KDC stderr to one of this module's typed exceptions.

    Returns None when no known marker matches, so the caller falls back to a
    generic MintingError.
    """
    if any(marker in stderr for marker in _BAD_PASSWORD_MARKERS):
        return BadPasswordError("bad password")
    if any(marker in stderr for marker in _UNKNOWN_PRINCIPAL_MARKERS):
        return UnknownPrincipalError("unknown principal")
    if any(marker in stderr for marker in _REVOKED_MARKERS):
        return AccountUnusableError(_ACCOUNT_REVOKED_DETAIL)
    if any(marker in stderr for marker in _PASSWORD_EXPIRED_MARKERS):
        return AccountUnusableError(_PASSWORD_EXPIRED_DETAIL)
    return None


async def mint_ticket(
    username: str,
    password: bytearray,
    lifetime: str,
    renewable_lifetime: str,
    settings: Settings,
) -> MintedTicket:
    """Mint a Kerberos ticket for *username* by shelling out to kinit.

    Runs::

        kinit -c FILE:<ccache> -l <lifetime> -r <renewable_lifetime> \\
            <username>@<default_realm>

    feeding *password* on stdin, exactly as a human typing it at kinit's own
    prompt would (see prompter.c: MIT's prompter explicitly supports a
    non-tty stdin). Takes ownership of *password* and zeros it (and the
    stdin buffer built from it) before returning, on every path — success,
    bad password, or infra failure.

    The subprocess call is synchronous (``subprocess.run``, offloaded to a
    thread via ``run_in_executor``) rather than ``asyncio.create_subprocess_exec``,
    mirroring voms-token-service's minting.py — the timeout is enforced by
    the stdlib's own process-group kill on expiry, not by cancelling an
    asyncio subprocess transport mid-flight.
    """
    principal = f"{username}@{settings.default_realm}"
    child_env = {**os.environ, "KRB5_CONFIG": settings.krb5_config}

    tmp_root = Path(settings.ccache_tmp_root)
    tmp_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    stdin_payload = bytearray(password)
    stdin_payload.extend(b"\n")
    try:
        with tempfile.TemporaryDirectory(dir=tmp_root) as tmpdir:
            ccache_path = Path(tmpdir) / "ccache"
            argv = [
                settings.kinit_bin,
                "-c",
                f"FILE:{ccache_path}",
                "-l",
                lifetime,
                "-r",
                renewable_lifetime,
                principal,
            ]

            try:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        argv,
                        input=bytes(stdin_payload),
                        capture_output=True,
                        check=False,
                        timeout=settings.kinit_timeout_seconds,
                        env=child_env,
                    ),
                )
            except OSError as exc:
                logger.exception(
                    "kinit_spawn_failed",
                    binary=settings.kinit_bin,
                    error=str(exc),
                )
                raise MintingError("failed to invoke kinit") from exc
            except subprocess.TimeoutExpired as exc:
                logger.exception(
                    "kinit_timed_out",
                    username=username,
                    timeout=settings.kinit_timeout_seconds,
                )
                raise MintingError("kinit timed out") from exc

            if result.returncode != 0:
                stderr_text = result.stderr.decode(errors="replace").strip()
                classified = _classify_stderr(stderr_text)
                if classified is not None:
                    if not isinstance(classified, BadPasswordError):
                        # Bad password is the expected, non-exceptional
                        # outcome of a mistyped password; everything else is
                        # logged with stderr for operator diagnosis.
                        logger.warning(
                            "kinit_failed",
                            returncode=result.returncode,
                            stderr=stderr_text,
                            username=username,
                            classified=type(classified).__name__,
                        )
                    raise classified
                logger.error(
                    "kinit_failed",
                    returncode=result.returncode,
                    stderr=stderr_text,
                    username=username,
                )
                raise MintingError(f"kinit exited {result.returncode}")

            try:
                ccache_bytes = ccache_path.read_bytes()
            except OSError as exc:
                logger.exception("kinit_no_output", username=username)
                raise MintingError("kinit produced no ccache file") from exc
            if not ccache_bytes:
                logger.error("kinit_empty_output", username=username)
                raise MintingError("kinit produced an empty ccache file")

            info = read_ccache(ccache_path)
    finally:
        _zero_bytearray(stdin_payload)
        _zero_bytearray(password)

    return MintedTicket(
        ccache=ccache_bytes,
        principal=info.principal,
        realm=info.realm,
        expires_at=info.expires_at,
        renew_until=info.renew_until,
    )
