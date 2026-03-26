"""Tests for the rate limiter."""

from __future__ import annotations

from theaios.guardrails.rate_limit import RateLimiter
from theaios.guardrails.types import RateLimitConfig


class TestRateLimiter:
    def test_within_limits(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=5, window=60)
        for _ in range(5):
            assert limiter.check("key1", config)
            limiter.record("key1", config)

    def test_exceeds_limit(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=3, window=60)
        for _ in range(3):
            limiter.record("key1", config)
        assert not limiter.check("key1", config)

    def test_different_keys_independent(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=2, window=60)
        limiter.record("key1", config)
        limiter.record("key1", config)
        assert not limiter.check("key1", config)
        assert limiter.check("key2", config)  # key2 is fresh

    def test_check_and_record(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=2, window=60)
        assert limiter.check_and_record("k", config)
        assert limiter.check_and_record("k", config)
        assert not limiter.check_and_record("k", config)

    def test_reset_key(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=1, window=60)
        limiter.record("k", config)
        assert not limiter.check("k", config)
        limiter.reset("k")
        assert limiter.check("k", config)

    def test_reset_all(self) -> None:
        limiter = RateLimiter()
        config = RateLimitConfig(max=1, window=60)
        limiter.record("k1", config)
        limiter.record("k2", config)
        limiter.reset()
        assert limiter.check("k1", config)
        assert limiter.check("k2", config)
