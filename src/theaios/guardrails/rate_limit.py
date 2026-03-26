"""In-memory sliding window rate limiter."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from theaios.guardrails.types import RateLimitConfig


class RateLimiter:
    """Sliding window rate limiter using in-memory deques.

    Tracks timestamps of events per key and checks whether the count
    within the window exceeds the maximum.
    """

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, config: RateLimitConfig) -> bool:
        """Return True if the key is within rate limits, False if exceeded."""
        now = time.monotonic()
        window = self._windows[key]

        # Remove expired entries
        cutoff = now - config.window
        while window and window[0] < cutoff:
            window.popleft()

        return len(window) < config.max

    def record(self, key: str, config: RateLimitConfig) -> None:
        """Record a usage event for the given key."""
        now = time.monotonic()
        window = self._windows[key]

        # Clean up expired entries
        cutoff = now - config.window
        while window and window[0] < cutoff:
            window.popleft()

        window.append(now)

    def check_and_record(self, key: str, config: RateLimitConfig) -> bool:
        """Check rate limit and record if within limits.

        Returns True if within limits (and records), False if exceeded.
        """
        if not self.check(key, config):
            return False
        self.record(key, config)
        return True

    def reset(self, key: str | None = None) -> None:
        """Reset rate limit state for a key, or all keys if None."""
        if key is None:
            self._windows.clear()
        elif key in self._windows:
            del self._windows[key]
