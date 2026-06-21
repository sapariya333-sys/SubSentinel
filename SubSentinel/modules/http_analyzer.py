"""
modules/http_analyzer.py - HTTP/HTTPS response analysis
"""

import asyncio
import logging
import re
import ssl
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from core.config import ScanConfig
from core.models import HTTPData

logger = logging.getLogger(__name__)


class HTTPAnalyzer:
    """Async HTTP/HTTPS analysis with retry support."""

    TITLE_PATTERN = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE | re.DOTALL)

    def __init__(self, config: ScanConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        """Build httpx client with configured options."""
        proxies = None
        if self.config.proxy:
            proxies = {"http://": self.config.proxy, "https://": self.config.proxy}

        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        return httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.config.timeout),
            verify=False,  # We handle SSL analysis separately
            follow_redirects=True,
            max_redirects=5,
            proxies=proxies,
        )

    async def analyze(self, hostname: str) -> Optional[HTTPData]:
        """Analyze HTTP/HTTPS responses for a hostname."""
        # Try HTTPS first, then HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            result = await self._fetch(url)
            if result:
                return result

        return None

    async def _fetch(self, url: str, retry: int = 0) -> Optional[HTTPData]:
        """Fetch URL with retry support."""
        http_data = HTTPData(url=url)

        if self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

        try:
            async with self._build_client() as client:
                start = time.monotonic()
                response = await client.get(url)
                elapsed = (time.monotonic() - start) * 1000

                http_data.status_code = response.status_code
                http_data.headers = dict(response.headers)
                http_data.final_url = str(response.url)
                http_data.server = response.headers.get("server", "")
                http_data.content_type = response.headers.get("content-type", "")
                http_data.response_time_ms = elapsed
                http_data.is_https = url.startswith("https")

                # Get redirect chain
                for redirect in response.history:
                    http_data.redirect_chain.append(str(redirect.url))

                # Get body (limit size)
                try:
                    body_bytes = response.content[:500_000]  # 500KB max
                    http_data.body = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    http_data.body = ""

                # Extract title
                if http_data.body:
                    title_match = self.TITLE_PATTERN.search(http_data.body)
                    if title_match:
                        http_data.title = " ".join(title_match.group(1).split()).strip()

                # SSL info if HTTPS
                if url.startswith("https"):
                    http_data.ssl_valid = True  # httpx would raise if invalid

                return http_data

        except httpx.ConnectTimeout:
            http_data.error = "Connection timeout"
        except httpx.ConnectError as e:
            http_data.error = f"Connection error: {e}"
        except httpx.TooManyRedirects:
            http_data.error = "Too many redirects"
        except ssl.SSLError as e:
            http_data.ssl_error = str(e)
            http_data.ssl_valid = False
            # Try without verifying cert
            return await self._fetch_insecure(url, http_data)
        except Exception as e:
            http_data.error = str(e)

        # Retry logic
        if retry < self.config.retries and not http_data.status_code:
            await asyncio.sleep(0.5 * (retry + 1))
            return await self._fetch(url, retry + 1)

        # Return even error responses - error content is useful for fingerprinting
        if http_data.error and not http_data.status_code:
            return None

        return http_data

    async def _fetch_insecure(self, url: str, base_data: HTTPData) -> Optional[HTTPData]:
        """Fetch with SSL verification disabled."""
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=True,
                headers={"User-Agent": self.config.user_agent}
            ) as client:
                response = await client.get(url)
                base_data.status_code = response.status_code
                base_data.headers = dict(response.headers)
                try:
                    base_data.body = response.content[:500_000].decode("utf-8", errors="replace")
                except Exception:
                    pass
                return base_data
        except Exception:
            return base_data if base_data.status_code else None
