"""Unit tests for the per-username failed-authentication limiter."""

from __future__ import annotations

import pytest

from krb5_token_service.ratelimit import RateLimitedError, RateLimiter


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _limiter(
    clock: _FakeClock,
    *,
    max_attempts: int = 3,
    window: float = 900,
    lockout: float = 900,
) -> RateLimiter:
    return RateLimiter(
        max_attempts=max_attempts,
        window_seconds=window,
        lockout_seconds=lockout,
        clock=clock,
    )


class TestRateLimiter:
    def test_check_passes_for_unknown_username(self) -> None:
        limiter = _limiter(_FakeClock())
        limiter.check("gstark")  # must not raise

    def test_check_passes_below_max_attempts(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3)
        limiter.record_failure("gstark")
        limiter.record_failure("gstark")
        limiter.check("gstark")  # 2 failures, still under 3 — must not raise

    def test_locks_out_after_max_attempts(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3)
        for _ in range(3):
            limiter.record_failure("gstark")
        with pytest.raises(RateLimitedError):
            limiter.check("gstark")

    def test_lockout_is_scoped_to_the_failing_username(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3)
        for _ in range(3):
            limiter.record_failure("gstark")
        limiter.check("alice")  # different username — must not raise

    def test_lockout_expires_after_lockout_seconds(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3, lockout=60)
        for _ in range(3):
            limiter.record_failure("gstark")
        with pytest.raises(RateLimitedError):
            limiter.check("gstark")
        clock.advance(61)
        limiter.check("gstark")  # lockout expired — must not raise

    def test_failures_outside_window_do_not_accumulate(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3, window=900)
        limiter.record_failure("gstark")
        clock.advance(901)  # first failure ages out of the window
        limiter.record_failure("gstark")
        limiter.record_failure("gstark")
        limiter.check("gstark")  # only 2 failures within the window — must not raise

    def test_retry_after_seconds_reflects_remaining_lockout(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=1, lockout=100)
        limiter.record_failure("gstark")
        clock.advance(40)
        with pytest.raises(RateLimitedError) as excinfo:
            limiter.check("gstark")
        assert excinfo.value.retry_after_seconds == pytest.approx(60, abs=1)

    def test_reset_clears_failure_history(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=3)
        limiter.record_failure("gstark")
        limiter.record_failure("gstark")
        limiter.reset("gstark")
        limiter.record_failure("gstark")
        limiter.check("gstark")  # only 1 failure since reset — must not raise

    def test_reset_after_lockout_allows_immediate_retry(self) -> None:
        clock = _FakeClock()
        limiter = _limiter(clock, max_attempts=1, lockout=900)
        limiter.record_failure("gstark")
        with pytest.raises(RateLimitedError):
            limiter.check("gstark")
        limiter.reset("gstark")
        limiter.check("gstark")  # must not raise
