"""
utils/proxy.py - Proxy rotation and management
"""

import asyncio
import logging
import random
from typing import List, Optional

logger = logging.getLogger(__name__)


class ProxyRotator:
    """Round-robin and random proxy rotation with health tracking."""

    def __init__(self, proxies: List[str]):
        self.proxies = proxies
        self._index = 0
        self._failed: set = set()
        self._lock = asyncio.Lock()

    async def get_proxy(self, strategy: str = "round_robin") -> Optional[str]:
        """Get next available proxy."""
        if not self.proxies:
            return None

        available = [p for p in self.proxies if p not in self._failed]
        if not available:
            # Reset failures and try again
            self._failed.clear()
            available = self.proxies

        async with self._lock:
            if strategy == "random":
                return random.choice(available)
            else:
                proxy = available[self._index % len(available)]
                self._index += 1
                return proxy

    async def mark_failed(self, proxy: str) -> None:
        """Mark a proxy as failed."""
        self._failed.add(proxy)
        logger.debug(f"Proxy marked as failed: {proxy} ({len(self._failed)}/{len(self.proxies)} failed)")

    @property
    def healthy_count(self) -> int:
        return len(self.proxies) - len(self._failed)
