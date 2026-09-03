"""FastAPI application: minting endpoints plus health probes.

Authorization model: none beyond identity, by design. The af-mcp-broker has
already authenticated and authorized the user before minting the AF Broker
Identity Token this service verifies; a valid token proves the call
genuinely came from the broker. The CERN username/password (or keytab) to
mint a ticket for come from the request body — this service derives no
authorization from token claims. Do not add capability logic here based on
token claims.
"""

from __future__ import annotations

import base64
import binascii
import os
import shutil
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, SecretStr, model_validator

from krb5_token_service.ccache import CcacheParseError
from krb5_token_service.config import Settings, get_settings
from krb5_token_service.identity import get_jwks, peek_sub, verify_broker_token
from krb5_token_service.logging import configure_logging
from krb5_token_service.minting import (
    AccountUnusableError,
    BadKeytabError,
    BadPasswordError,
    InvalidLifetimeError,
    InvalidUsernameError,
    MintedTicket,
    MintingError,
    TicketExpiredError,
    UnknownPrincipalError,
    mint_keytab,
    mint_ticket,
    renew_ticket,
    validate_lifetime,
    validate_username,
)
from krb5_token_service.ratelimit import RateLimitedError, RateLimiter

logger = structlog.get_logger(__name__)

# ``auto_error=False`` so a missing header is audited before the 401 is raised.
_bearer_scheme = HTTPBearer(auto_error=False)

router = APIRouter()


class MintRequest(BaseModel):
    username: str
    password: SecretStr | None = None
    keytab_b64: str | None = None
    lifetime: str | None = None
    renewable_lifetime: str | None = None

    @model_validator(mode="after")
    def _exactly_one_credential(self) -> MintRequest:
        if (self.password is None) == (self.keytab_b64 is None):
            raise ValueError("exactly one of password or keytab_b64 is required")
        return self


class MintResponse(BaseModel):
    ccache_b64: str
    principal: str
    realm: str
    expires_at: str  # ISO8601 UTC
    renew_until: str | None = None  # ISO8601 UTC, None when not renewable


class RenewRequest(BaseModel):
    ccache_b64: str


class KeytabRequest(BaseModel):
    username: str
    password: SecretStr


class KeytabResponse(BaseModel):
    keytab_b64: str
    principal: str


def _audit(
    *,
    subject: str | None,
    username: str | None,
    principal: str | None,
    jti: str | None,
    outcome: str,  # "issued" | "denied" | "error"
    request_id: str,
) -> None:
    """One structlog JSON audit line per request.

    NEVER include the password, keytab, or the minted ccache here — only the
    username and the confirmed principal. See also
    logging.SensitiveValueRedactProcessor for the backstop.
    """
    logger.info(
        "audit",
        subject=subject,
        username=username,
        principal=principal,
        jti=jti,
        outcome=outcome,
        request_id=request_id,
    )


def _mint_response(minted: MintedTicket) -> MintResponse:
    return MintResponse(
        ccache_b64=base64.b64encode(minted.ccache).decode(),
        principal=minted.principal,
        realm=minted.realm,
        expires_at=minted.expires_at.isoformat(),
        renew_until=minted.renew_until.isoformat() if minted.renew_until else None,
    )


@router.post("/v1/mint", response_model=MintResponse)
async def mint(
    request: Request,
    body: MintRequest,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> MintResponse:
    settings: Settings = request.app.state.settings
    rate_limiter: RateLimiter = request.app.state.rate_limiter
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    if credentials is None:
        _audit(
            subject=None,
            username=None,
            principal=None,
            jti=None,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await verify_broker_token(credentials.credentials, settings)
    except HTTPException as exc:
        # 401 (invalid token) is a denial; anything else (e.g. the JWKS
        # fetch's 502) is a platform error, not the caller's fault.
        outcome = (
            "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
        )
        _audit(
            subject=peek_sub(credentials.credentials),
            username=body.username,
            principal=None,
            jti=None,
            outcome=outcome,
            request_id=request_id,
        )
        raise

    subject: str = claims["sub"]
    jti: str | None = claims.get("jti")

    try:
        validate_username(body.username)
    except InvalidUsernameError:
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid username",
        ) from None

    lifetime = body.lifetime or settings.default_lifetime
    renewable_lifetime = body.renewable_lifetime or settings.default_renewable_lifetime
    try:
        validate_lifetime(lifetime)
        validate_lifetime(renewable_lifetime)
    except InvalidLifetimeError:
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid lifetime",
        ) from None

    # Only the password path risks CERN's account-lockout counter (see
    # minting.BadPasswordError) — a keytab request skips the limiter
    # entirely, matching how /v1/renew (no credential at all) also skips it.
    if body.password is not None:
        try:
            rate_limiter.check(body.username)
        except RateLimitedError as exc:
            # kinit is never invoked on this path — the KDC never sees a
            # blocked attempt.
            _audit(
                subject=subject,
                username=body.username,
                principal=None,
                jti=jti,
                outcome="denied",
                request_id=request_id,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(exc),
            ) from None

    # Copy the credential into a mutable buffer at the earliest point
    # possible; mint_ticket takes ownership of it and zeros it (success or
    # failure) before returning. Only the pydantic SecretStr/str original is
    # out of reach of that discipline.
    password_buf: bytearray | None = None
    keytab_buf: bytearray | None = None
    if body.password is not None:
        password_buf = bytearray(body.password.get_secret_value().encode())
    else:
        assert body.keytab_b64 is not None
        try:
            keytab_buf = bytearray(base64.b64decode(body.keytab_b64, validate=True))
        except (binascii.Error, ValueError):
            _audit(
                subject=subject,
                username=body.username,
                principal=None,
                jti=jti,
                outcome="denied",
                request_id=request_id,
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="invalid keytab_b64",
            ) from None

    try:
        minted = await mint_ticket(
            body.username,
            password_buf,
            lifetime,
            renewable_lifetime,
            settings,
            keytab=keytab_buf,
        )
    except BadPasswordError:
        rate_limiter.record_failure(body.username)
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad password",
        ) from None
    except BadKeytabError:
        # Not counted against the limiter: no password was involved.
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad keytab",
        ) from None
    except UnknownPrincipalError:
        # Not counted against the limiter: a wrong username isn't a
        # guessing attempt against a real account.
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown principal",
        ) from None
    except AccountUnusableError as exc:
        # User-actionable (contact CERN support / change password), not a
        # retry-later infra failure and not counted against the limiter —
        # the account is already locked or expired regardless of credential.
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from None
    except MintingError as exc:
        # Generic detail only — kinit's stderr was logged server-side by
        # minting.py and must never reach the client.
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="error",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Ticket minting failed.",
        ) from exc

    if body.password is not None:
        rate_limiter.reset(body.username)
    _audit(
        subject=subject,
        username=body.username,
        principal=minted.principal,
        jti=jti,
        outcome="issued",
        request_id=request_id,
    )
    return _mint_response(minted)


@router.post("/v1/renew", response_model=MintResponse)
async def renew(
    request: Request,
    body: RenewRequest,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> MintResponse:
    """Renew a ccache this service minted earlier, via ``kinit -R``.

    No credential is involved at all — the caller's proof of possession is
    the ccache itself — so this never touches the failed-auth rate limiter.
    Capped at the ticket's own renew_until; past that, mint a fresh ticket
    via /v1/mint instead.
    """
    settings: Settings = request.app.state.settings
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    if credentials is None:
        _audit(
            subject=None,
            username=None,
            principal=None,
            jti=None,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await verify_broker_token(credentials.credentials, settings)
    except HTTPException as exc:
        outcome = (
            "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
        )
        _audit(
            subject=peek_sub(credentials.credentials),
            username=None,
            principal=None,
            jti=None,
            outcome=outcome,
            request_id=request_id,
        )
        raise

    subject: str = claims["sub"]
    jti: str | None = claims.get("jti")

    try:
        ccache_bytes = base64.b64decode(body.ccache_b64, validate=True)
    except (binascii.Error, ValueError):
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid ccache_b64",
        ) from None

    try:
        minted = await renew_ticket(ccache_bytes, settings)
    except CcacheParseError:
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid ccache",
        ) from None
    except TicketExpiredError as exc:
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from None
    except MintingError as exc:
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="error",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Ticket renewal failed.",
        ) from exc

    _audit(
        subject=subject,
        username=None,
        principal=minted.principal,
        jti=jti,
        outcome="issued",
        request_id=request_id,
    )
    return _mint_response(minted)


@router.post("/v1/keytab", response_model=KeytabResponse)
async def keytab(
    request: Request,
    body: KeytabRequest,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
) -> KeytabResponse:
    """Bootstrap a fresh keytab for the caller's CERN account via cern-get-keytab.

    Shares the failed-auth rate limiter with /v1/mint's password path: this
    endpoint's password check is a real AS-REQ against the same CERN account
    (see minting.BadPasswordError), so both risk the same CERN-side lockout
    counter. The returned keytab is never persisted by this service — the
    caller is responsible for storing it (e.g. in the broker's own vault)
    for future /v1/mint keytab-mode calls.
    """
    settings: Settings = request.app.state.settings
    rate_limiter: RateLimiter = request.app.state.rate_limiter
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    if credentials is None:
        _audit(
            subject=None,
            username=None,
            principal=None,
            jti=None,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await verify_broker_token(credentials.credentials, settings)
    except HTTPException as exc:
        outcome = (
            "denied" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "error"
        )
        _audit(
            subject=peek_sub(credentials.credentials),
            username=body.username,
            principal=None,
            jti=None,
            outcome=outcome,
            request_id=request_id,
        )
        raise

    subject: str = claims["sub"]
    jti: str | None = claims.get("jti")

    try:
        validate_username(body.username)
    except InvalidUsernameError:
        _audit(
            subject=subject,
            username=None,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="invalid username",
        ) from None

    try:
        rate_limiter.check(body.username)
    except RateLimitedError as exc:
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from None

    password_buf = bytearray(body.password.get_secret_value().encode())
    try:
        keytab_bytes = await mint_keytab(body.username, password_buf, settings)
    except BadPasswordError:
        rate_limiter.record_failure(body.username)
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="denied",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bad password",
        ) from None
    except MintingError as exc:
        # cern-get-keytab's msktutil backend doesn't distinguish an unknown
        # account from a wrong password in its own stderr the way kinit
        # does (see minting._classify_cern_get_keytab_stderr) — both are
        # BadPasswordError above, so there is deliberately no separate
        # UnknownPrincipalError branch here.
        _audit(
            subject=subject,
            username=body.username,
            principal=None,
            jti=jti,
            outcome="error",
            request_id=request_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Keytab generation failed.",
        ) from exc

    rate_limiter.reset(body.username)
    principal = f"{body.username}@{settings.default_realm}"
    _audit(
        subject=subject,
        username=body.username,
        principal=principal,
        jti=jti,
        outcome="issued",
        request_id=request_id,
    )
    return KeytabResponse(
        keytab_b64=base64.b64encode(keytab_bytes).decode(),
        principal=principal,
    )


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> dict[str, str]:
    """Ready only when kinit is executable, KRB5_CONFIG is readable, and the
    broker JWKS is fetchable. Deliberately does NOT check KDC reachability —
    a CERN-side outage must not flap this pod's readiness. Deliberately does
    NOT check cern-get-keytab either: /v1/keytab is a bootstrap convenience,
    not the service's core purpose, and its own CERN-side dependency (LDAP,
    not just the KDC) must not flap readiness either.
    """
    settings: Settings = request.app.state.settings
    problems: list[str] = []
    if shutil.which(settings.kinit_bin) is None:
        problems.append(
            f"kinit binary not found or not executable: {settings.kinit_bin}"
        )
    if not os.access(settings.krb5_config, os.R_OK):
        problems.append(f"krb5.conf not readable: {settings.krb5_config}")
    try:
        await get_jwks(settings)
    except HTTPException:
        problems.append(f"broker JWKS endpoint unreachable: {settings.broker_jwks_url}")
    if problems:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="; ".join(problems),
        )
    return {"status": "ready"}


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; tests pass explicit Settings, production uses env."""
    if settings is None:
        settings = get_settings()
    configure_logging(settings.log_level)
    application = FastAPI(
        title="krb5-token-service",
        description="Kerberos ticket minting for the AF MCP platform",
        version="0.2.0",
    )
    application.state.settings = settings
    application.state.rate_limiter = RateLimiter(
        max_attempts=settings.failed_auth_max_attempts,
        window_seconds=settings.failed_auth_window_seconds,
        lockout_seconds=settings.failed_auth_lockout_seconds,
    )
    application.include_router(router)
    return application


app = create_app()
