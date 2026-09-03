"""Kerberos ticket minting via the ``kinit`` CLI, plus renewal and keytab bootstrap.

The user's CERN password (or, for keytab minting, the keytab bytes) is the
only secret this service receives that it does not itself own. It is
transmitted to the child process over stdin — never on argv, never logged —
and the buffer holding it is zeroed in place immediately after use, mirroring
voms-token-service's minting.py discipline for the Globus passphrase.

Unlike voms-proxy-init, kinit needs no on-disk user credential to mint
against: the password (or keytab) is the entire credential. There is
therefore no homes mount, no impersonation, and no privileged capability
requirement here — the service runs as a single unprivileged uid for its
whole lifetime, and the minted ccache is staged in a private 0700 directory
on the pod's own tmpfs that this process itself owns outright.

Three minting paths share this module:

- ``mint_ticket`` — a fresh ticket via password (stdin) or keytab (``-kt``).
- ``renew_ticket`` — ``kinit -R`` on a ccache this service minted earlier.
  No secret at all: the caller's proof of possession is the ccache itself.
- ``mint_keytab`` — bootstraps a new keytab from a password via CERN's own
  ``cern-get-keytab`` (see etc/cern-get-keytab.patch for the two fixes this
  service depends on: a real shell-injection bug in the vendored script, and
  a stdin-based non-interactive password input it didn't otherwise have).
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from krb5_token_service.ccache import CcacheParseError, read_ccache

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
    """Raised when kinit fails for a reason other than the password/account/keytab.

    The message is deliberately generic: kinit's stderr can reference KDC
    hostnames and is logged server-side only, never returned to the client.
    """


class BadPasswordError(Exception):
    """Raised when kinit (or cern-get-keytab) fails because the CERN password was wrong.

    Distinct from every other failure here because it is the one outcome
    that must count against ratelimit.RateLimiter — see app.py. Shared
    between /v1/mint's password path and /v1/keytab: both send the password
    to CERN's real Active Directory/KDC backend for verification (see
    _classify_cern_get_keytab_stderr's docstring for what cern-get-keytab's
    msktutil backend actually does, verified against a real run), so both
    risk the same CERN account-lockout counter.
    """


class BadKeytabError(Exception):
    """Raised when kinit -kt fails because the supplied keytab doesn't match the account.

    Distinct from BadPasswordError: no password was involved, so a stale or
    wrong keytab must never count against the password-guessing rate
    limiter.
    """


class UnknownPrincipalError(Exception):
    """Raised when the KDC has no such principal in this realm.

    Not counted against the rate limiter: this is a request-shape problem
    (an unknown username), not a guessing attempt against a real account.
    """


class AccountUnusableError(Exception):
    """Raised when the KDC refuses a structurally valid, correctly-authenticated request.

    Covers a revoked or already-expired CERN account — retrying (with any
    password or keytab) cannot help, and the message is a fixed,
    user-actionable string, never kinit's stderr.
    """


class TicketExpiredError(Exception):
    """Raised when kinit -R fails because the ticket is past its renew_until.

    Not a bug the caller can retry around — they must mint a fresh ticket
    (password or keytab) instead.
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
# error_tables/krb5_err.et). kinit special-cases a password-prompted
# KRB5KDC_ERR_PREAUTH_FAILED (or a decrypt failure) as "Password incorrect
# while <doing>"; every other error falls through to com_err's "<message>
# while <doing>" — so these are prefix/substring markers, not full-line
# matches, matched case-sensitively against kinit's real output (unlike
# voms-proxy-init's markers, which lowercase-compare against openssl's own
# lowercase text).
_BAD_PASSWORD_MARKERS: tuple[str, ...] = ("Password incorrect",)
_UNKNOWN_PRINCIPAL_MARKERS: tuple[str, ...] = ("not found in Kerberos database",)
_REVOKED_MARKERS: tuple[str, ...] = ("credentials have been revoked",)
_PASSWORD_EXPIRED_MARKERS: tuple[str, ...] = ("Password has expired",)

# kinit -kt (keytab auth) and cern-get-keytab's own msktutil-mediated
# password check never set kinit.c's `pwprompt` flag (that flag is only set
# inside the interactive password-prompt callback, kinit_prompter — verified
# against kinit.c) so neither gets the friendly "Password incorrect"
# rewording a wrong *password* gets in the normal password-auth path above.
# Both instead surface the raw com_err-formatted message, which for a bad
# key is one of these two.
_BAD_KEY_MARKERS: tuple[str, ...] = (
    "Preauthentication failed",
    "Decrypt integrity check failed",
)

_TICKET_EXPIRED_MARKERS: tuple[str, ...] = ("Ticket expired",)

# msktutil's own top-level failure summary (see
# _classify_cern_get_keytab_stderr's docstring for how this was verified
# against CERN's real backend) — the only cern-get-keytab failure text that
# actually reaches stderr.
_NO_CREDENTIALS_MARKERS: tuple[str, ...] = (
    "Could not find any credentials to authenticate with",
)

_ACCOUNT_REVOKED_DETAIL = (
    "This CERN account's credentials have been revoked. Contact CERN account support."
)
_PASSWORD_EXPIRED_DETAIL = (
    "This CERN account's password has expired and must be changed before a "
    "ticket can be minted."
)


def _classify_password_stderr(stderr: str) -> Exception | None:
    """Map kinit's password-auth stderr to one of this module's typed exceptions."""
    if any(marker in stderr for marker in _BAD_PASSWORD_MARKERS):
        return BadPasswordError("bad password")
    if any(marker in stderr for marker in _UNKNOWN_PRINCIPAL_MARKERS):
        return UnknownPrincipalError("unknown principal")
    if any(marker in stderr for marker in _REVOKED_MARKERS):
        return AccountUnusableError(_ACCOUNT_REVOKED_DETAIL)
    if any(marker in stderr for marker in _PASSWORD_EXPIRED_MARKERS):
        return AccountUnusableError(_PASSWORD_EXPIRED_DETAIL)
    return None


def _classify_keytab_stderr(stderr: str) -> Exception | None:
    """Map kinit -kt's stderr to one of this module's typed exceptions."""
    if any(marker in stderr for marker in _BAD_KEY_MARKERS):
        return BadKeytabError("bad keytab")
    if any(marker in stderr for marker in _UNKNOWN_PRINCIPAL_MARKERS):
        return UnknownPrincipalError("unknown principal")
    if any(marker in stderr for marker in _REVOKED_MARKERS):
        return AccountUnusableError(_ACCOUNT_REVOKED_DETAIL)
    return None


def _classify_renew_stderr(stderr: str) -> Exception | None:
    """Map kinit -R's stderr to one of this module's typed exceptions."""
    if any(marker in stderr for marker in _TICKET_EXPIRED_MARKERS):
        return TicketExpiredError("ticket no longer renewable")
    return None


def _classify_cern_get_keytab_stderr(stderr: str) -> Exception | None:
    """Map cern-get-keytab's stderr to one of this module's typed exceptions.

    Verified against a real (deliberately wrong) password run against
    CERN's real Active Directory backend, not assumed from source alone:
    msktutil's --use-service-account credential-acquisition machinery tries
    several internal strategies (see msktkrb5.cpp's try_machine_password /
    try_machine_supplied_password / try_user_creds), and each one's own
    "Preauthentication failed"-style error lands on cern-get-keytab's
    STDOUT (verbose progress output it already prints unconditionally) —
    not stderr. Only msktutil's own top-level summary, "Could not find any
    credentials to authenticate with...", reaches stderr, and only because
    of etc/cern-get-keytab.patch's fourth hunk (without it this was
    silently discarded on every failure). That summary does not distinguish
    a wrong password from a genuinely unknown account the way kinit's own
    errors do — there is deliberately no UnknownPrincipalError branch here;
    both outcomes count against the rate limiter, a known, disclosed
    trade-off rather than a guess at internal msktutil behavior this
    service can't actually observe from its own output.
    """
    if any(
        marker in stderr for marker in (*_BAD_KEY_MARKERS, *_NO_CREDENTIALS_MARKERS)
    ):
        return BadPasswordError("bad password")
    return None


async def _run_subprocess(
    argv: list[str],
    *,
    stdin: bytes | None,
    timeout_seconds: float,
    binary: str,
    context: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run *argv* off the event loop, translating spawn/timeout failures to MintingError.

    Shared by every kinit invocation (mint/renew) and the cern-get-keytab
    invocation — the timeout is enforced by the stdlib's own process kill on
    expiry, not by cancelling an asyncio subprocess transport mid-flight
    (mirroring voms-token-service's minting.py).
    """
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                argv,
                input=stdin,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
                env=env,
            ),
        )
    except OSError as exc:
        logger.exception("subprocess_spawn_failed", binary=binary, error=str(exc))
        raise MintingError(f"failed to invoke {binary}") from exc
    except subprocess.TimeoutExpired as exc:
        logger.exception(
            "subprocess_timed_out",
            binary=binary,
            context=context,
            timeout=timeout_seconds,
        )
        raise MintingError(f"{binary} timed out") from exc


async def mint_ticket(
    username: str,
    password: bytearray | None,
    lifetime: str,
    renewable_lifetime: str,
    settings: Settings,
    *,
    keytab: bytearray | None = None,
) -> MintedTicket:
    """Mint a Kerberos ticket for *username* by shelling out to kinit.

    Exactly one of *password* or *keytab* must be given (enforced by
    app.py's request validation, not re-checked here). Password mode runs::

        kinit -c FILE:<ccache> -l <lifetime> -r <renewable_lifetime> \\
            <username>@<default_realm>

    feeding *password* on stdin, exactly as a human typing it at kinit's own
    prompt would (see prompter.c: MIT's prompter explicitly supports a
    non-tty stdin). Keytab mode instead writes *keytab* to a private tmpfs
    file and adds ``-k -t <path>`` — no stdin needed at all. Takes ownership
    of whichever of *password*/*keytab* was given and zeros it (and, for
    password mode, the stdin buffer built from it) before returning, on
    every path — success, bad credential, or infra failure.
    """
    if (password is None) == (keytab is None):
        raise ValueError("mint_ticket requires exactly one of password or keytab")

    principal = f"{username}@{settings.default_realm}"
    child_env = {**os.environ, "KRB5_CONFIG": settings.krb5_config}

    tmp_root = Path(settings.ccache_tmp_root)
    tmp_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    stdin_payload: bytearray | None = None
    if password is not None:
        stdin_payload = bytearray(password)
        stdin_payload.extend(b"\n")
    try:
        with tempfile.TemporaryDirectory(dir=tmp_root) as tmpdir:
            ccache_path = Path(tmpdir) / "ccache"
            argv = [settings.kinit_bin, "-c", f"FILE:{ccache_path}"]
            if keytab is not None:
                keytab_path = Path(tmpdir) / "keytab"
                keytab_path.write_bytes(bytes(keytab))
                keytab_path.chmod(0o600)
                argv += ["-k", "-t", str(keytab_path)]
            argv += ["-l", lifetime, "-r", renewable_lifetime, principal]

            result = await _run_subprocess(
                argv,
                stdin=bytes(stdin_payload) if stdin_payload is not None else None,
                timeout_seconds=settings.kinit_timeout_seconds,
                binary=settings.kinit_bin,
                context=username,
                env=child_env,
            )

            if result.returncode != 0:
                stderr_text = result.stderr.decode(errors="replace").strip()
                classify = (
                    _classify_keytab_stderr
                    if keytab is not None
                    else _classify_password_stderr
                )
                classified = classify(stderr_text)
                if classified is not None:
                    if not isinstance(classified, (BadPasswordError, BadKeytabError)):
                        # Bad password/keytab is the expected, non-exceptional
                        # outcome of a mistyped credential; everything else is
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
        if stdin_payload is not None:
            _zero_bytearray(stdin_payload)
        if password is not None:
            _zero_bytearray(password)
        if keytab is not None:
            _zero_bytearray(keytab)

    return MintedTicket(
        ccache=ccache_bytes,
        principal=info.principal,
        realm=info.realm,
        expires_at=info.expires_at,
        renew_until=info.renew_until,
    )


async def renew_ticket(ccache: bytes, settings: Settings) -> MintedTicket:
    """Renew a ccache this service minted earlier by shelling out to ``kinit -R``.

    No secret is involved at all — the caller's proof of possession is the
    ccache itself, so this bypasses ratelimit.RateLimiter entirely (see
    app.py). *ccache* is written to a private tmpfs file and parsed with
    ccache.read_ccache BEFORE kinit is ever invoked: a caller-supplied blob
    that isn't a real ccache is a 422 the caller can fix, not a kinit
    failure to classify. Capped at the ticket's own renew_until — past that,
    kinit -R fails with TicketExpiredError and the caller must mint a fresh
    ticket instead (password or keytab).
    """
    child_env = {**os.environ, "KRB5_CONFIG": settings.krb5_config}

    tmp_root = Path(settings.ccache_tmp_root)
    tmp_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=tmp_root) as tmpdir:
        ccache_path = Path(tmpdir) / "ccache"
        ccache_path.write_bytes(ccache)
        ccache_path.chmod(0o600)

        # Raises ccache.CcacheParseError (caught by app.py as a 422) for a
        # blob that isn't a real ccache, before kinit is ever invoked.
        read_ccache(ccache_path)

        argv = [settings.kinit_bin, "-R", "-c", f"FILE:{ccache_path}"]
        result = await _run_subprocess(
            argv,
            stdin=None,
            timeout_seconds=settings.kinit_timeout_seconds,
            binary=settings.kinit_bin,
            context="renew",
            env=child_env,
        )

        if result.returncode != 0:
            stderr_text = result.stderr.decode(errors="replace").strip()
            classified = _classify_renew_stderr(stderr_text)
            if classified is not None:
                raise classified
            logger.error(
                "kinit_renew_failed", returncode=result.returncode, stderr=stderr_text
            )
            raise MintingError(f"kinit -R exited {result.returncode}")

        renewed_bytes = ccache_path.read_bytes()
        if not renewed_bytes:
            logger.error("kinit_renew_empty_output")
            raise MintingError("kinit -R produced an empty ccache file")

        info = read_ccache(ccache_path)

    return MintedTicket(
        ccache=renewed_bytes,
        principal=info.principal,
        realm=info.realm,
        expires_at=info.expires_at,
        renew_until=info.renew_until,
    )


async def mint_keytab(username: str, password: bytearray, settings: Settings) -> bytes:
    """Bootstrap a fresh keytab for *username* via CERN's own ``cern-get-keytab``.

    Runs the patched vendored script (see etc/cern-get-keytab.patch) under
    this process's own Python interpreter (``sys.executable`` — the pixi
    env's python, which is what has requests/pyyaml, the script's own
    dependencies, importable; the script's ``#!/usr/bin/python3`` shebang is
    never relied on)::

        <python> <cern_get_keytab_bin> -u -v -l <username> \\
            --keytab <tmpfile>

    feeding *password* on stdin (the patch adds this input path; without it,
    the only non-interactive option is ``-p <password>`` on argv). Returns
    the raw keytab bytes for the caller to hand off to its own credential
    store — this service never persists them. Takes ownership of *password*
    and zeros it before returning, on every path.
    """
    child_env = {**os.environ, "KRB5_CONFIG": settings.krb5_config}

    tmp_root = Path(settings.ccache_tmp_root)
    tmp_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    stdin_payload = bytearray(password)
    stdin_payload.extend(b"\n")
    try:
        with tempfile.TemporaryDirectory(dir=tmp_root) as tmpdir:
            keytab_path = Path(tmpdir) / "keytab"
            argv = [
                sys.executable,
                settings.cern_get_keytab_bin,
                "-u",
                "-v",
                "-l",
                username,
                "--keytab",
                str(keytab_path),
            ]

            result = await _run_subprocess(
                argv,
                stdin=bytes(stdin_payload),
                timeout_seconds=settings.cern_get_keytab_timeout_seconds,
                binary=settings.cern_get_keytab_bin,
                context=username,
                env=child_env,
            )

            if result.returncode != 0:
                stderr_text = result.stderr.decode(errors="replace").strip()
                classified = _classify_cern_get_keytab_stderr(stderr_text)
                if classified is not None:
                    if not isinstance(classified, BadPasswordError):
                        logger.warning(
                            "cern_get_keytab_failed",
                            returncode=result.returncode,
                            stderr=stderr_text,
                            username=username,
                            classified=type(classified).__name__,
                        )
                    raise classified
                logger.error(
                    "cern_get_keytab_failed",
                    returncode=result.returncode,
                    stderr=stderr_text,
                    username=username,
                )
                raise MintingError(f"cern-get-keytab exited {result.returncode}")

            try:
                keytab_bytes = keytab_path.read_bytes()
            except OSError as exc:
                logger.exception("cern_get_keytab_no_output", username=username)
                raise MintingError("cern-get-keytab produced no keytab file") from exc
            if not keytab_bytes:
                logger.error("cern_get_keytab_empty_output", username=username)
                raise MintingError("cern-get-keytab produced an empty keytab file")
    finally:
        _zero_bytearray(stdin_payload)
        _zero_bytearray(password)

    return keytab_bytes


__all__ = [
    "AccountUnusableError",
    "BadKeytabError",
    "BadPasswordError",
    "CcacheParseError",
    "InvalidLifetimeError",
    "InvalidUsernameError",
    "MintedTicket",
    "MintingError",
    "TicketExpiredError",
    "UnknownPrincipalError",
    "mint_keytab",
    "mint_ticket",
    "renew_ticket",
    "validate_lifetime",
    "validate_username",
]
