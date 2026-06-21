"""
utils/rate_limiter.py - Token-bucket rate limiting
"""

import asyncio
import time


class RateLimiter:
    """Token-bucket rate limiter for controlling request rates."""

    def __init__(self, rate: int, burst: int = None):
        """
        Args:
            rate: Max requests per second
            burst: Max burst size (defaults to rate)
        """
        self.rate = rate
        self.burst = burst or rate
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self.burst,
                self._tokens + elapsed * self.rate
            )
            self._last_refill = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *args):
        pass
