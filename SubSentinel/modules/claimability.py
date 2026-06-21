"""
modules/claimability.py - Verify whether a resource is actually unclaimed
Critical for reducing false positives.
"""

import asyncio
import logging
import re
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import aiohttp
import httpx

from core.config import ScanConfig
from core.models import FingerprintMatch, DNSData, ClaimabilityResult

logger = logging.getLogger(__name__)


class ClaimabilityChecker:
    """Verify if a takeover target is actually claimable (not already claimed)."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def check(
        self,
        subdomain: str,
        fingerprint: FingerprintMatch,
        dns_data: DNSData
    ) -> ClaimabilityResult:
        """Route to appropriate claimability checker."""
        service = fingerprint.service

        checkers = {
            "GitHub Pages": self._check_github_pages,
            "Heroku": self._check_heroku,
            "AWS S3": self._check_s3,
            "Netlify": self._check_netlify,
            "Azure": self._check_azure,
            "Vercel": self._check_vercel,
            "Surge.sh": self._check_surge,
            "Firebase": self._check_firebase,
            "Render": self._check_render,
            "Railway": self._check_railway,
        }

        checker = checkers.get(service)
        if checker:
            try:
                return await asyncio.wait_for(
                    checker(subdomain, dns_data),
                    timeout=15
                )
            except asyncio.TimeoutError:
                return ClaimabilityResult(
                    is_claimable=False,
                    verification_method="timeout",
                    evidence="Verification timed out - unable to confirm claimability",
                    error="Timeout"
                )
            except Exception as e:
                logger.debug(f"Claimability check error for {subdomain}: {e}")
                return ClaimabilityResult(
                    is_claimable=False,
                    verification_method="error",
                    evidence=str(e),
                    error=str(e)
                )

        # Generic check
        return await self._generic_check(subdomain, fingerprint, dns_data)

    async def _check_github_pages(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check if GitHub Pages site is unclaimed."""
        # Extract GitHub username from CNAME
        # Format: username.github.io
        for cname in dns_data.cname_chain:
            if "github.io" in cname:
                username = cname.split(".github.io")[0]
                # Check if GitHub user/org exists
                api_url = f"https://api.github.com/users/{username}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            api_url,
                            headers={"Accept": "application/vnd.github.v3+json"},
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            if resp.status == 404:
                                return ClaimabilityResult(
                                    is_claimable=True,
                                    verification_method="github_api",
                                    evidence=f"GitHub user/org '{username}' does not exist",
                                    details={"username": username, "api_status": 404}
                                )
                            elif resp.status == 200:
                                # User exists - check if repo exists
                                repo_url = f"https://api.github.com/repos/{username}/{username}.github.io"
                                async with session.get(
                                    repo_url,
                                    headers={"Accept": "application/vnd.github.v3+json"},
                                    timeout=aiohttp.ClientTimeout(total=10)
                                ) as repo_resp:
                                    if repo_resp.status == 404:
                                        return ClaimabilityResult(
                                            is_claimable=True,
                                            verification_method="github_api",
                                            evidence=f"GitHub user '{username}' exists but has no github.io repo",
                                            details={"username": username, "user_exists": True, "repo_exists": False}
                                        )
                                    elif repo_resp.status == 200:
                                        return ClaimabilityResult(
                                            is_claimable=False,
                                            verification_method="github_api",
                                            evidence=f"GitHub Pages site exists for '{username}'",
                                            details={"username": username, "repo_exists": True}
                                        )
                except Exception as e:
                    logger.debug(f"GitHub API check failed: {e}")

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="github_api",
            evidence="Could not extract GitHub username from CNAME chain"
        )

    async def _check_heroku(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check if Heroku app is unclaimed."""
        # Extract app name from CNAME: appname.herokudns.com
        for cname in dns_data.cname_chain:
            if "herokudns.com" in cname or "herokuapp.com" in cname:
                app_name = cname.split(".herokudns.com")[0].split(".herokuapp.com")[0]
                # Try to fetch the app directly
                app_url = f"https://{app_name}.herokuapp.com"
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as client:
                        resp = await client.get(app_url)
                        if resp.status_code == 404 and "no such app" in resp.text.lower():
                            return ClaimabilityResult(
                                is_claimable=True,
                                verification_method="http_check",
                                evidence=f"Heroku app '{app_name}' returns 'No such app'",
                                details={"app_name": app_name, "status": 404}
                            )
                        else:
                            return ClaimabilityResult(
                                is_claimable=False,
                                verification_method="http_check",
                                evidence=f"Heroku app '{app_name}' appears to be active (status: {resp.status_code})"
                            )
                except Exception as e:
                    logger.debug(f"Heroku check failed: {e}")

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="heroku_check",
            evidence="Could not extract Heroku app name"
        )

    async def _check_s3(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check if S3 bucket is unclaimed."""
        bucket_name = subdomain  # S3 bucket is usually the subdomain itself

        # Try S3 API (unauthenticated)
        s3_url = f"https://s3.amazonaws.com/{bucket_name}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(s3_url)
                text = resp.text.lower()

                if resp.status_code == 404 and "nosuchbucket" in text:
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="s3_api",
                        evidence=f"S3 bucket '{bucket_name}' does not exist (NoSuchBucket)",
                        details={"bucket": bucket_name, "status": 404}
                    )
                elif resp.status_code == 403:
                    return ClaimabilityResult(
                        is_claimable=False,
                        verification_method="s3_api",
                        evidence=f"S3 bucket '{bucket_name}' exists but is private (403 Forbidden)"
                    )
                elif resp.status_code == 200:
                    return ClaimabilityResult(
                        is_claimable=False,
                        verification_method="s3_api",
                        evidence=f"S3 bucket '{bucket_name}' exists and is public"
                    )
        except Exception as e:
            logger.debug(f"S3 check failed: {e}")

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="s3_check",
            evidence="S3 bucket status could not be determined"
        )

    async def _check_netlify(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Netlify site status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404 and "netlify" in resp.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Netlify site not found (404 with Netlify branding)"
                    )
        except Exception as e:
            logger.debug(f"Netlify check failed: {e}")

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="netlify_check",
            evidence="Could not verify Netlify claimability"
        )

    async def _check_azure(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Azure resource status."""
        for cname in dns_data.cname_chain:
            if ".azurewebsites.net" in cname:
                # Extract app name
                app_name = cname.split(".azurewebsites.net")[0]
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as client:
                        resp = await client.get(f"https://{app_name}.azurewebsites.net")
                        if resp.status_code == 404:
                            return ClaimabilityResult(
                                is_claimable=True,
                                verification_method="azure_check",
                                evidence=f"Azure web app '{app_name}' not found",
                                details={"app_name": app_name}
                            )
                except Exception:
                    pass

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="azure_check",
            evidence="Could not verify Azure claimability"
        )

    async def _check_vercel(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Vercel deployment status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404 and "vercel" in resp.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Vercel deployment not found"
                    )
        except Exception:
            pass

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="vercel_check",
            evidence="Could not verify Vercel claimability"
        )

    async def _check_surge(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Surge.sh project status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404 and "project not found" in resp.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Surge.sh project not found - claimable via `surge` CLI"
                    )
        except Exception:
            pass

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="surge_check",
            evidence="Could not verify Surge.sh claimability"
        )

    async def _check_firebase(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Firebase hosting status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404 and "site not found" in resp.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Firebase hosting site not found"
                    )
        except Exception:
            pass

        return ClaimabilityResult(is_claimable=False, verification_method="firebase_check", evidence="")

    async def _check_render(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Render service status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404:
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Render service not found"
                    )
        except Exception:
            pass
        return ClaimabilityResult(is_claimable=False, verification_method="render_check", evidence="")

    async def _check_railway(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Check Railway service status."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code == 404:
                    return ClaimabilityResult(
                        is_claimable=True,
                        verification_method="http_check",
                        evidence="Railway app not found"
                    )
        except Exception:
            pass
        return ClaimabilityResult(is_claimable=False, verification_method="railway_check", evidence="")

    async def _generic_check(
        self,
        subdomain: str,
        fingerprint: FingerprintMatch,
        dns_data: DNSData
    ) -> ClaimabilityResult:
        """Generic claimability check based on HTTP response."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{subdomain}")
                if resp.status_code in [404, 410]:
                    # Check if fingerprint text appears in body
                    if fingerprint.fingerprint and fingerprint.fingerprint.lower() in resp.text.lower():
                        return ClaimabilityResult(
                            is_claimable=True,
                            verification_method="generic_http",
                            evidence=f"Fingerprint '{fingerprint.fingerprint}' found in 404 response",
                        )
        except Exception:
            pass

        return ClaimabilityResult(
            is_claimable=False,
            verification_method="generic_check",
            evidence="Could not verify claimability"
        )
