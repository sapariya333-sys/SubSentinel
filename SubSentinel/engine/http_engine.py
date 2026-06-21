"""
engine/http_engine.py - Enterprise HTTP analysis engine with TLS fingerprinting,
CDN detection, WAF detection, JS redirect analysis, content hashing, and entropy scoring.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import re
import ssl
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from core.models import HTTPData, TLSInfo

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Patterns
# ──────────────────────────────────────────────────────────────

TITLE_RE        = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
JS_REDIRECT_RE  = re.compile(
    r'(?:window\.location\s*(?:=|\.(?:href|replace|assign)\s*\())\s*["\']([^"\']+)',
    re.I
)
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^;]*;\s*url=([^"\'>\s]+)',
    re.I
)

CDN_HEADERS: Dict[str, str] = {
    "cf-ray":                "Cloudflare",
    "x-amz-cf-id":          "AWS CloudFront",
    "x-served-by":          "Fastly",
    "x-fastly-request-id":  "Fastly",
    "x-cache":              "Generic CDN",
    "x-akamai-transformed": "Akamai",
    "server-timing":        "Generic CDN",
    "x-azure-ref":          "Azure CDN",
    "x-ms-ref":             "Azure CDN",
}

WAF_INDICATORS: Dict[str, str] = {
    "x-sucuri-id":          "Sucuri",
    "x-firewall-protection":"Generic WAF",
    "__cfduid":             "Cloudflare WAF",
    "x-datadome-cid":       "DataDome",
    "x-edgeconnect-midmile":"Akamai",
    "set-cookie:incap_ses":  "Imperva Incapsula",
}

ERROR_PAGE_PATTERNS: Dict[str, str] = {
    r'no such app':                        "heroku_no_such_app",
    r'nosuchbucket':                       "s3_no_such_bucket",
    r"there isn't a github pages site":    "github_pages_missing",
    r'does not exist in our system':       "hubspot_missing",
    r'project not found':                  "surge_missing",
    r'site not found':                     "firebase_missing",
    r'this page is coming soon':           "generic_coming_soon",
    r'application error':                  "generic_app_error",
    r'service unavailable':                "generic_503",
    r'the specified bucket does not exist':"s3_no_such_bucket",
    r'404 web site not found':             "azure_missing",
    r'fastly error.*unknown domain':       "fastly_unconfigured",
    r'help center closed':                 "zendesk_closed",
    r'whatever you were looking for.*doesn': "tumblr_missing",
}

# User-agent pool for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class HTTPEngine:
    """
    Enterprise HTTP analysis engine.

    Features:
    - HTTPS + HTTP with automatic fallback
    - TLS certificate analysis (CN, SAN, expiry, mismatch)
    - CDN and WAF fingerprinting
    - JS redirect and meta-refresh detection
    - Content hashing + Shannon entropy scoring
    - Browser-like request headers with rotation
    - Configurable retry with exponential backoff
    - Proxy support
    """

    MAX_BODY_BYTES = 512_000  # 512 KB

    def __init__(
        self,
        timeout:    int   = 12,
        retries:    int   = 3,
        proxy:      Optional[str] = None,
        user_agent: Optional[str] = None,
        delay:      float = 0.0,
        rotate_ua:  bool  = True,
    ):
        self._timeout   = timeout
        self._retries   = retries
        self._proxy     = proxy
        self._user_agent = user_agent
        self._delay     = delay
        self._rotate_ua = rotate_ua
        self._ua_index  = 0

    def _next_ua(self) -> str:
        if self._user_agent:
            return self._user_agent
        ua = USER_AGENTS[self._ua_index % len(USER_AGENTS)]
        if self._rotate_ua:
            self._ua_index += 1
        return ua

    def _build_headers(self) -> Dict[str, str]:
        return {
            "User-Agent":      self._next_ua(),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT":             "1",
            "Connection":      "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def _build_client(self, verify: bool = False) -> httpx.AsyncClient:
        proxies = None
        if self._proxy:
            proxies = {"http://": self._proxy, "https://": self._proxy}
        return httpx.AsyncClient(
            headers=self._build_headers(),
            timeout=httpx.Timeout(self._timeout),
            verify=verify,
            follow_redirects=True,
            max_redirects=8,
            http2=True,
            proxies=proxies,
        )

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    async def analyze(self, hostname: str) -> Optional[HTTPData]:
        """Try HTTPS then HTTP; return richer result."""
        if self._delay > 0:
            await asyncio.sleep(self._delay)

        for scheme in ("https", "http"):
            result = await self._fetch_with_retry(f"{scheme}://{hostname}")
            if result and result.status_code is not None:
                return result

        return None

    # ──────────────────────────────────────────
    # Fetch with retry/backoff
    # ──────────────────────────────────────────

    async def _fetch_with_retry(self, url: str) -> Optional[HTTPData]:
        last_result: Optional[HTTPData] = None
        for attempt in range(self._retries + 1):
            try:
                result = await self._fetch(url)
                if result and result.status_code:
                    return result
                last_result = result
            except Exception as e:
                logger.debug(f"HTTP fetch attempt {attempt+1} failed: {url} — {e}")
                if attempt < self._retries:
                    await asyncio.sleep(min(2 ** attempt * 0.5, 4.0))
        return last_result

    async def _fetch(self, url: str) -> Optional[HTTPData]:
        data = HTTPData(url=url, is_https=url.startswith("https"))
        is_https = data.is_https

        try:
            async with self._build_client(verify=is_https) as client:
                t0 = time.monotonic()
                response = await client.get(url)
                data.response_time_ms = (time.monotonic() - t0) * 1000
                data.status_code  = response.status_code
                data.headers      = {k.lower(): v for k, v in response.headers.items()}
                data.final_url    = str(response.url)
                data.server       = data.headers.get("server", "")
                data.content_type = data.headers.get("content-type", "")
                data.http_version = "2" if response.http_version == "HTTP/2" else "1.1"

                data.redirect_chain = [str(r.url) for r in response.history]

                # Body
                raw = response.content[:self.MAX_BODY_BYTES]
                data.body        = raw.decode("utf-8", errors="replace")
                data.body_length = len(raw)
                data.body_hash   = hashlib.sha256(raw).hexdigest()

                # Title
                m = TITLE_RE.search(data.body)
                data.title = " ".join(m.group(1).split()).strip() if m else None

                # TLS (only HTTPS)
                if is_https:
                    data.tls_info = await self._analyze_tls(url, data.headers)

                # Advanced analysis
                self._analyze_cdn(data)
                self._analyze_waf(data)
                self._analyze_redirects(data)
                self._analyze_content(data)

        except httpx.ConnectTimeout:
            data.error = "connect_timeout"
        except httpx.ReadTimeout:
            data.error = "read_timeout"
        except httpx.ConnectError as e:
            data.error = f"connect_error: {e}"
        except ssl.SSLError as e:
            # SSL error — retry without verify
            if is_https:
                return await self._fetch_ssl_fallback(url)
            data.error = f"ssl_error: {e}"
        except Exception as e:
            data.error = str(e)

        return data if data.status_code else None

    async def _fetch_ssl_fallback(self, url: str) -> Optional[HTTPData]:
        """Retry with SSL verification disabled — captures cert errors."""
        data = HTTPData(url=url, is_https=True)
        try:
            async with self._build_client(verify=False) as client:
                t0 = time.monotonic()
                response = await client.get(url)
                data.response_time_ms = (time.monotonic() - t0) * 1000
                data.status_code  = response.status_code
                data.headers      = {k.lower(): v for k, v in response.headers.items()}
                data.final_url    = str(response.url)
                raw = response.content[:self.MAX_BODY_BYTES]
                data.body         = raw.decode("utf-8", errors="replace")
                data.body_length  = len(raw)
                data.body_hash    = hashlib.sha256(raw).hexdigest()
                m = TITLE_RE.search(data.body)
                data.title        = " ".join(m.group(1).split()).strip() if m else None
                data.tls_info     = TLSInfo(is_valid=False, error="ssl_verification_failed")
                self._analyze_cdn(data)
                self._analyze_waf(data)
                self._analyze_redirects(data)
                self._analyze_content(data)
        except Exception as e:
            data.error = str(e)
        return data if data.status_code else None

    # ──────────────────────────────────────────
    # TLS Analysis
    # ──────────────────────────────────────────

    async def _analyze_tls(self, url: str, headers: Dict[str, str]) -> TLSInfo:
        """Extract TLS certificate metadata."""
        info = TLSInfo(is_valid=True)
        hostname = urlparse(url).hostname or ""
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _get_cert():
                import socket
                conn = ctx.wrap_socket(
                    socket.create_connection((hostname, 443), timeout=5),
                    server_hostname=hostname
                )
                cert = conn.getpeercert()
                conn.close()
                return cert

            cert = await asyncio.wait_for(
                loop.run_in_executor(None, _get_cert), timeout=8
            )
            if cert:
                info.subject = str(cert.get("subject", ""))
                info.issuer  = str(cert.get("issuer", ""))
                info.common_name = dict(x[0] for x in cert.get("subject", [])).get("commonName")
                info.not_before  = cert.get("notBefore")
                info.not_after   = cert.get("notAfter")

                # SAN
                san = cert.get("subjectAltName", [])
                info.san_list = [v for t, v in san if t == "DNS"]

                # CN mismatch check
                if info.common_name:
                    cn = info.common_name.lstrip("*.")
                    if not hostname.endswith(cn):
                        info.cn_mismatch = True

                info.wildcard_cert = any("*." in s for s in info.san_list)
                info.self_signed   = info.issuer == info.subject

        except ssl.SSLCertVerificationError as e:
            info.is_valid = False
            info.error = str(e)
            if "expired" in str(e).lower():
                info.is_expired = True
        except Exception as e:
            info.is_valid = False
            info.error = str(e)

        return info

    # ──────────────────────────────────────────
    # Content Analysis
    # ──────────────────────────────────────────

    def _analyze_cdn(self, data: HTTPData) -> None:
        for header, cdn in CDN_HEADERS.items():
            if header in data.headers:
                data.cdn_provider = cdn
                break

    def _analyze_waf(self, data: HTTPData) -> None:
        all_headers = " ".join(data.headers.keys()).lower()
        for pattern, waf in WAF_INDICATORS.items():
            if ":" in pattern:
                h, v = pattern.split(":", 1)
                if h in data.headers and v.strip() in data.headers[h].lower():
                    data.waf_detected = True
                    data.waf_provider = waf
                    return
            elif pattern in all_headers:
                data.waf_detected = True
                data.waf_provider = waf
                return

    def _analyze_redirects(self, data: HTTPData) -> None:
        if not data.body:
            return
        m = JS_REDIRECT_RE.search(data.body)
        if m:
            data.is_js_redirect = True
            data.js_redirect_target = m.group(1)
        m2 = META_REFRESH_RE.search(data.body)
        if m2:
            data.meta_refresh_url = m2.group(1)

    def _analyze_content(self, data: HTTPData) -> None:
        if not data.body:
            return

        body_lower = data.body.lower()

        # Error page classification
        for pattern, error_type in ERROR_PAGE_PATTERNS.items():
            if re.search(pattern, body_lower):
                data.has_error_page = True
                data.error_page_type = error_type
                break

        # Shannon entropy
        data.content_entropy = self._shannon_entropy(data.body[:4096])

        # Word / link / form counts
        data.word_count = len(data.body.split())
        data.link_count = body_lower.count("<a ")
        data.form_count = body_lower.count("<form")

        # ── Active application signals ────────────────────────
        set_cookie = data.headers.get("set-cookie", "")
        if set_cookie:
            data.has_set_cookie = True
            if re.search(r"(session|sess|auth|token|jwt|csrf|xsrf|remember|logged)", set_cookie, re.I):
                data.has_session_cookie = True
            data.cookie_names = [c.split("=")[0].strip() for c in set_cookie.split(";") if "=" in c]

        if data.headers.get("www-authenticate") or data.headers.get("authorization"):
            data.has_auth_header = True

        if "content-security-policy" in data.headers:
            data.has_csp_header = True

        if re.search(r"<form[^>]*(?:login|signin|sign-in|auth)", body_lower, re.I):
            data.has_login_form = True


    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)
