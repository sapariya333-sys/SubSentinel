"""
validation/claimability.py - Provider-specific claimability verification.
SAFE — never performs destructive actions. Read-only API/HTTP checks only.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp
import httpx

from core.models import ClaimabilityResult, DNSData, FingerprintMatch, VerificationStage

logger = logging.getLogger(__name__)

TIMEOUT = 12


class ClaimabilityValidator:
    """
    Route verification to provider-specific checkers.
    Returns ClaimabilityResult with confidence 0.0–1.0.
    """

    _REGISTRY = {}  # populated by @register

    def __init__(self, timeout: int = TIMEOUT):
        self._timeout = timeout

    async def validate(
        self,
        subdomain: str,
        fingerprint: FingerprintMatch,
        dns_data: DNSData,
    ) -> ClaimabilityResult:
        checker = self._REGISTRY.get(fingerprint.service)
        if checker:
            try:
                return await asyncio.wait_for(
                    checker(self, subdomain, dns_data),
                    timeout=self._timeout
                )
            except asyncio.TimeoutError:
                return ClaimabilityResult(
                    is_claimable=False,
                    verification_method="timeout",
                    evidence="Verification timed out",
                    error="timeout",
                )
            except Exception as e:
                logger.debug(f"Claimability check error [{fingerprint.service}]: {e}")
                return ClaimabilityResult(
                    is_claimable=False,
                    verification_method="error",
                    evidence=str(e),
                    error=str(e),
                )
        return await self._generic(subdomain, fingerprint, dns_data)

    # ──────────────────────────────────────────
    # Decorator-based registry
    # ──────────────────────────────────────────

    @classmethod
    def register(cls, *services):
        def decorator(fn):
            for svc in services:
                cls._REGISTRY[svc] = fn
            return fn
        return decorator

    # ──────────────────────────────────────────
    # GitHub Pages
    # ──────────────────────────────────────────

    @register.__func__("GitHub Pages")
    async def _github(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if "github.io" not in cname:
                continue
            # Extract username: username.github.io
            parts = cname.rstrip(".").split(".")
            if len(parts) < 3:
                continue
            username = parts[0]

            async with aiohttp.ClientSession() as s:
                # Check user exists
                async with s.get(
                    f"https://api.github.com/users/{username}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 404:
                        return ClaimabilityResult(
                            is_claimable=True,
                            verification_method="github_api",
                            evidence=f"GitHub user '{username}' does not exist — username available",
                            confidence=0.95,
                            details={"username": username, "user_exists": False},
                            verification_stage=VerificationStage.API_VERIFIED,
                            safe_poc=f"# 1. Register github.com/{username}\n"
                                     f"# 2. Create repo {username}.github.io\n"
                                     f"# 3. Push index.html\n"
                                     f"# 4. Enable GitHub Pages"
                        )
                    elif r.status == 200:
                        # User exists — check if repo exists
                        async with s.get(
                            f"https://api.github.com/repos/{username}/{username}.github.io",
                            headers={"Accept": "application/vnd.github.v3+json"},
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as rr:
                            if rr.status == 404:
                                return ClaimabilityResult(
                                    is_claimable=True,
                                    verification_method="github_api",
                                    evidence=f"GitHub user '{username}' exists but .github.io repo is missing",
                                    confidence=0.80,
                                    details={"username": username, "user_exists": True, "repo_exists": False},
                                    verification_stage=VerificationStage.API_VERIFIED,
                                )
                            return ClaimabilityResult(
                                is_claimable=False,
                                verification_method="github_api",
                                evidence=f"GitHub Pages repo {username}.github.io exists",
                                confidence=0.95,
                            )

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="github_api",
            evidence="Could not extract GitHub username from CNAME chain",
        )

    # ──────────────────────────────────────────
    # Heroku
    # ──────────────────────────────────────────

    @register.__func__("Heroku")
    async def _heroku(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if "herokudns.com" not in cname and "herokuapp.com" not in cname:
                continue
            app_name = cname.split(".herokudns.com")[0].split(".herokuapp.com")[0].rstrip(".")
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{app_name}.herokuapp.com")
                if r.status_code == 404 and "no such app" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence=f"Heroku app '{app_name}' does not exist (No such app)",
                        confidence=0.90,
                        details={"app_name": app_name},
                        verification_stage=VerificationStage.API_VERIFIED,
                        safe_poc=f"heroku create {app_name} --region us\n"
                                 f"heroku domains:add {subdomain} -a {app_name}",
                    )
                return ClaimabilityResult(
                    is_claimable=False,
                    verification_method="http_check",
                    evidence=f"Heroku app '{app_name}' responds (status {r.status_code})",
                    confidence=0.85,
                )
        return ClaimabilityResult(is_claimable=False, verification_method="heroku", evidence="App name not parseable")

    # ──────────────────────────────────────────
    # AWS S3
    # ──────────────────────────────────────────

    @register.__func__("AWS S3")
    async def _s3(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        bucket = subdomain
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            for url in [
                f"https://s3.amazonaws.com/{bucket}",
                f"https://{bucket}.s3.amazonaws.com",
            ]:
                try:
                    r = await c.get(url)
                    txt = r.text.lower()
                    if "nosuchbucket" in txt or "the specified bucket does not exist" in txt:
                        return ClaimabilityResult(
                            is_claimable=True,
                            verification_method="s3_api",
                            evidence=f"S3 bucket '{bucket}' does not exist (NoSuchBucket)",
                            confidence=0.95,
                            details={"bucket": bucket, "checked_url": url},
                            verification_stage=VerificationStage.API_VERIFIED,
                            safe_poc=f"aws s3api create-bucket --bucket {bucket} --region us-east-1\n"
                                     f"aws s3 website s3://{bucket}/ --index-document index.html",
                        )
                    if r.status_code == 403:
                        return ClaimabilityResult(
                            is_claimable=False,
                            verification_method="s3_api",
                            evidence=f"S3 bucket '{bucket}' exists but is private (403)",
                            confidence=0.90,
                        )
                except Exception:
                    continue
        return ClaimabilityResult(is_claimable=False, verification_method="s3_api", evidence="Inconclusive")

    # ──────────────────────────────────────────
    # Azure
    # ──────────────────────────────────────────

    @register.__func__("Azure")
    async def _azure(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if ".azurewebsites.net" in cname:
                app = cname.split(".azurewebsites.net")[0].rstrip(".")
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    r = await c.get(f"https://{app}.azurewebsites.net")
                    if r.status_code == 404 and ("web site not found" in r.text.lower() or "web app" in r.text.lower()):
                        return ClaimabilityResult(
                            is_claimable=True,
                            verification_method="azure_http",
                            evidence=f"Azure Web App '{app}' not found",
                            confidence=0.80,
                            verification_stage=VerificationStage.API_VERIFIED,
                        )
        return ClaimabilityResult(is_claimable=False, verification_method="azure_http", evidence="Could not verify")

    # ──────────────────────────────────────────
    # Generic HTTP fallback
    # ──────────────────────────────────────────

    async def _generic(
        self,
        subdomain: str,
        fingerprint: FingerprintMatch,
        dns_data: DNSData,
    ) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if r.status_code in (404, 410) and fingerprint.fingerprint:
                    if fingerprint.fingerprint.lower() in r.text.lower():
                        return ClaimabilityResult(
                            is_claimable=True,
                            verification_method="generic_http",
                            evidence=f"Fingerprint confirmed in {r.status_code} response",
                            confidence=0.60,
                        )
        except Exception:
            pass
        return ClaimabilityResult(
            is_claimable=False,
            verification_method="generic_http",
            evidence="No generic confirmation available",
            confidence=0.0,
        )


# Register methods that used the decorator pattern
ClaimabilityValidator._REGISTRY["GitHub Pages"] = ClaimabilityValidator._github
ClaimabilityValidator._REGISTRY["Heroku"]       = ClaimabilityValidator._heroku
ClaimabilityValidator._REGISTRY["AWS S3"]       = ClaimabilityValidator._s3
ClaimabilityValidator._REGISTRY["Azure"]        = ClaimabilityValidator._azure
