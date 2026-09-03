"""Per-username failed-authentication limiter.

Unlike voms-token-service (whose "bad passphrase" failure is a local openssl
check against the user's own key file, with no consequence outside this
pod), a wrong CERN password is a real AS-REQ against CERN's KDC and counts
against CERN's own account-lockout policy. This service refuses to even
invoke kinit once a username has failed too many times within a sliding
window — a blocked attempt never reaches the KDC, so it cannot itself
contribute to a lockout.

This is in-process, per-replica state (see the Helm chart's
``replicaCount: 1``): scaling this deployment up would silently multiply the
effective attempt budget against the same CERN account, since each replica
tracks failures independently.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class RateLimitedError(Exception):
    """Raised when *username* has too many recent failed authentication attempts.

    kinit is never invoked on this path.
    """

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"too many failed authentication attempts; retry after "
            f"{retry_after_seconds:.0f}s"
        )


@dataclass
class _UsernameState:
    failure_times: list[float] = field(default_factory=list)
    locked_until: float | None = None


class RateLimiter:
    """Sliding-window failed-attempt limiter, keyed by username.

    ``check`` must be called (and allowed to raise) before every kinit
    invocation. ``record_failure`` is called only after a confirmed
    bad-password response from kinit — never for a failure that isn't the
    caller's fault (KDC unreachable, timeout), which must not count against
    them. ``reset`` clears state on a successful mint.
    """

    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: float,
        lockout_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._clock = clock
        self._state: dict[str, _UsernameState] = {}

    def check(self, username: str) -> None:
        state = self._state.get(username)
        if state is None or state.locked_until is None:
            return
        now = self._clock()
        if now < state.locked_until:
            raise RateLimitedError(state.locked_until - now)
        # Lockout expired: start clean rather than resurrecting failure
        # timestamps from before the lockout.
        state.locked_until = None
        state.failure_times.clear()

    def record_failure(self, username: str) -> None:
        now = self._clock()
        state = self._state.setdefault(username, _UsernameState())
        state.failure_times = [
            t for t in state.failure_times if now - t < self._window_seconds
        ]
        state.failure_times.append(now)
        if len(state.failure_times) >= self._max_attempts:
            state.locked_until = now + self._lockout_seconds

    def reset(self, username: str) -> None:
        self._state.pop(username, None)
