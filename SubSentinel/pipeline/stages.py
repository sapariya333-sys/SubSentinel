"""
pipeline/stages.py - Deterministic 3-stage verification pipeline.

THE CORE RULE (fixes the Heroku false-positive problem):
  Provider CNAME match ≠ vulnerable
  Backend endpoint error ≠ custom domain unclaimed
  Body fingerprint ≠ proof

Only Stage 3 (Hard Validation) can produce CONFIRMED.

STAGE 1 — Provider Detection
  Detect which provider the CNAME points to.
  Output: provider_detected (never vulnerable)

STAGE 2 — Soft Validation
  Probe the CUSTOM DOMAIN (not the raw backend).
  Look for active application signals that prove it is LIVE:
    - session cookies
    - auth redirects
    - login forms
    - real content (high entropy, many words)
    - WAF protection
    - valid TLS for the custom hostname
  If ANY live indicator found → abort. It is NOT vulnerable.
  Output: suspected OR aborted

STAGE 3 — Hard Validation
  Provider-specific deterministic checks:
  - Probe custom domain with correct Host header
  - Compare custom domain vs raw backend response
  - Check provider API where available
  Only confirm if CUSTOM DOMAIN ITSELF shows unclaimed state.
  Output: confirmed OR inconclusive
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from core.models import (
    ClaimabilityResult, ConfidenceResult, ConfidenceDimensions,
    DNSData, DanglingType, Finding, FingerprintMatch, FingerprintSignal,
    HardValidationResult, HTTPData, Signal, SoftValidationResult,
    VerificationStage, ValidationVerdict,
)
from engine.confidence_engine import (
    ConfidenceEngine, PARKED_PATTERNS, GENERIC_PAGE_PATTERNS, WILDCARD_BODY_PATTERNS
)
from engine.dns_engine import DNSEngine
from engine.http_engine import HTTPEngine
from providers.base import ProviderMatch
from providers.registry import all_providers, get_provider

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Patterns: signals that a LIVE application is present
# ─────────────────────────────────────────────────────────────

# Cookies that strongly indicate an active session
SESSION_COOKIE_NAMES = re.compile(
    r'(session|sess|auth|token|jwt|csrf|xsrf|__secure|remember|logged)',
    re.I
)

# Auth-related redirect patterns
AUTH_REDIRECT_PATTERNS = re.compile(
    r'(login|signin|sign-in|authenticate|oauth|sso|saml|auth\.|/auth)',
    re.I
)

# Content patterns that indicate real application (not error pages)
LIVE_APP_PATTERNS = re.compile(
    r'(<nav|<header|<footer|<main|navbar|sidebar|dashboard|'
    r'application/json|api/v\d|Authorization:|Bearer\s+[A-Za-z0-9])',
    re.I
)

# CSP header presence indicates intentional security headers — live app
CSP_HEADER = "content-security-policy"

# Unclaimed state patterns — must appear on CUSTOM DOMAIN to matter
UNCLAIMED_ON_CUSTOM_DOMAIN = {
    "heroku":    re.compile(r'no\s+such\s+app|herokucdn\.com/error-pages/no-such-app', re.I),
    "github":    re.compile(r"there isn't a github pages site here", re.I),
    "netlify":   re.compile(r'not\s+found\s+-\s+request\s+id:', re.I),
    "vercel":    re.compile(r'deployment.*does\s+not\s+exist', re.I),
    "s3":        re.compile(r'<code>nosuchbucket</code>|nosuchbucket', re.I),
    "azure":     re.compile(r'404\s+web\s+site\s+not\s+found', re.I),
    "fastly":    re.compile(r'fastly\s+error.*unknown\s+domain', re.I),
    "surge":     re.compile(r'project\s+not\s+found', re.I),
    "pantheon":  re.compile(r'404\s+error\s+unknown\s+site', re.I),
    "shopify":   re.compile(r'sorry.*shop.*unavailable', re.I),
}


@dataclass
class PipelineContext:
    """Full mutable state carried through all 3 stages."""
    subdomain: str

    # Stage outputs
    dns_data:       Optional[DNSData]         = None
    http_data:      Optional[HTTPData]        = None
    provider_match: Optional[ProviderMatch]   = None
    soft_result:    Optional[SoftValidationResult] = None
    hard_result:    Optional[HardValidationResult] = None
    confidence:     Optional[ConfidenceResult] = None
    screenshot_path: Optional[str]            = None

    # Flow control
    aborted:      bool  = False
    abort_reason: str   = ""
    stage:        int   = 0
    duration_ms:  float = 0.0

    # Reasoning chain (human-readable)
    reasoning: List[str] = field(default_factory=list)


class DetectionPipeline:
    """
    3-stage deterministic pipeline.

    Stage 1 — Provider Detection (never marks vulnerable)
    Stage 2 — Soft Validation   (live-app detection, abort if live)
    Stage 3 — Hard Validation   (provider-specific, confirms unclaimed)
    """

    def __init__(
        self,
        dns_engine:     DNSEngine,
        http_engine:    HTTPEngine,
        confidence_eng: ConfidenceEngine,
        min_confidence: int  = 30,
        screenshot_fn        = None,
        evidence_fn          = None,
        timeout:        int  = 12,
    ):
        self.dns            = dns_engine
        self.http           = http_engine
        self.conf           = confidence_eng
        self.min_confidence = min_confidence
        self._screenshot    = screenshot_fn
        self._evidence      = evidence_fn
        self._timeout       = timeout
        self._providers     = all_providers()

    # ─────────────────────────────────────────────────────────
    # Entry point
    # ─────────────────────────────────────────────────────────

    async def run(self, subdomain: str) -> Optional[Finding]:
        ctx = PipelineContext(subdomain=subdomain)
        t0  = time.monotonic()

        stages = [
            self._s0_dns_and_wildcard,
            self._s1_provider_detection,
            self._s2_soft_validation,
            self._s3_hard_validation,
            self._s4_confidence_and_evidence,
        ]

        for stage_fn in stages:
            await stage_fn(ctx)
            if ctx.aborted:
                logger.debug(f"[{subdomain}] ABORT stage={ctx.stage}: {ctx.abort_reason}")
                return None

        ctx.duration_ms = (time.monotonic() - t0) * 1000

        if not ctx.confidence or ctx.confidence.score < self.min_confidence:
            return None

        return self._build_finding(ctx)

    # ─────────────────────────────────────────────────────────
    # S0: DNS resolution + wildcard filter
    # ─────────────────────────────────────────────────────────

    async def _s0_dns_and_wildcard(self, ctx: PipelineContext) -> None:
        ctx.stage = 0
        dns = await self.dns.analyze(ctx.subdomain)
        if not dns:
            ctx.aborted = True
            ctx.abort_reason = "DNS analysis failed"
            return

        # No CNAME and resolves cleanly → not a takeover candidate
        if dns.resolves and not dns.has_cname and not dns.is_dangling:
            ctx.aborted = True
            ctx.abort_reason = "Resolves without CNAME — not a candidate"
            return

        if dns.is_wildcard:
            ctx.aborted = True
            ctx.abort_reason = "Wildcard DNS"
            return

        ctx.dns_data = dns
        ctx.reasoning.append(f"DNS: cname_chain={dns.cname_chain}, dangling={dns.is_dangling}")

    # ─────────────────────────────────────────────────────────
    # S1: Provider Detection — NEVER marks vulnerable
    # ─────────────────────────────────────────────────────────

    async def _s1_provider_detection(self, ctx: PipelineContext) -> None:
        ctx.stage = 1
        dns = ctx.dns_data
        if not dns:
            ctx.aborted = True
            ctx.abort_reason = "No DNS data"
            return

        # HTTP probe for body matching
        if dns.has_cname or dns.is_dangling or dns.resolves:
            ctx.http_data = await self.http.analyze(ctx.subdomain)

        # Try all providers
        best: Optional[ProviderMatch] = None
        for provider in self._providers:
            match = provider.fingerprint(dns, ctx.http_data)
            if match and (best is None or match.confidence > best.confidence):
                best = match

        if best is None and not dns.is_dangling:
            ctx.aborted = True
            ctx.abort_reason = "No provider match and no dangling CNAME"
            return

        ctx.provider_match = best
        if best:
            ctx.reasoning.append(
                f"Provider detected: {best.service} "
                f"(fp_confidence={best.confidence:.2f}, "
                f"signals={[s.method.value for s in best.signals]})"
            )
        else:
            ctx.reasoning.append("No provider matched — dangling CNAME only")

    # ─────────────────────────────────────────────────────────
    # S2: Soft Validation — detect live applications
    # This stage's job is to KILL false positives by proving the
    # custom domain itself is serving a live application.
    # ─────────────────────────────────────────────────────────

    async def _s2_soft_validation(self, ctx: PipelineContext) -> None:
        ctx.stage = 2
        sv = SoftValidationResult()
        http = ctx.http_data

        if not http:
            sv.verdict = ValidationVerdict.INCONCLUSIVE
            ctx.soft_result = sv
            return

        # ── Check body for parked/generic pages ───────────────
        body = http.body or ""
        if PARKED_PATTERNS.search(body):
            ctx.aborted = True
            ctx.abort_reason = "Parked domain"
            return
        if GENERIC_PAGE_PATTERNS.search(body):
            ctx.aborted = True
            ctx.abort_reason = "Generic server default page"
            return
        if WILDCARD_BODY_PATTERNS.search(body):
            ctx.aborted = True
            ctx.abort_reason = "cPanel/Plesk catch-all"
            return

        # ── Detect LIVE APPLICATION signals ───────────────────
        live_indicators: List[str] = []

        # 1. Session / auth cookies set by the CUSTOM DOMAIN
        set_cookie = http.headers.get("set-cookie", "")
        if set_cookie:
            sv.has_session_cookies = True
            cookie_names = [c.split("=")[0].strip() for c in set_cookie.split(";") if "=" in c]
            if SESSION_COOKIE_NAMES.search(set_cookie):
                live_indicators.append(
                    f"Session/auth cookie set on custom domain: {set_cookie[:100]}"
                )

        # 2. Auth redirect — final URL points to a login page
        final = http.final_url or ""
        if AUTH_REDIRECT_PATTERNS.search(final):
            sv.has_auth_redirects = True
            live_indicators.append(f"Auth redirect detected: {final}")

        # 3. Redirect chain leads to completely different domain (live app)
        if http.redirect_chain:
            for url in http.redirect_chain:
                if AUTH_REDIRECT_PATTERNS.search(url):
                    live_indicators.append(f"Redirect to auth: {url}")
                    sv.has_auth_redirects = True
                    break

        # 4. CSP header present on custom domain
        if CSP_HEADER in http.headers:
            sv.has_waf = True
            live_indicators.append("Content-Security-Policy header present")

        # 5. High-entropy body with substantial content = real app
        if http.content_entropy > 4.5 and http.word_count > 200:
            sv.has_active_content = True
            live_indicators.append(
                f"Rich content: entropy={http.content_entropy:.2f}, "
                f"words={http.word_count}"
            )

        # 6. Login form present
        if http.has_login_form or (body and re.search(r'<form[^>]+(?:login|signin|auth)', body, re.I)):
            sv.has_login_form = True
            live_indicators.append("Login form detected on custom domain")

        # 7. WAF/security headers blocking (means someone configured this)
        if http.status_code == 403 and http.waf_detected:
            live_indicators.append(f"WAF returning 403: {http.waf_provider}")

        # 8. TLS certificate valid FOR this custom hostname
        if http.tls_info and http.tls_info.is_valid and not http.tls_info.cn_mismatch:
            sv.tls_valid_for_custom_domain = True
            # Valid TLS alone is not proof of live — but combined with other signals it matters

        sv.live_indicators = live_indicators
        sv.body_entropy    = http.content_entropy
        sv.response_word_count = http.word_count
        sv.evidence        = live_indicators[:]

        # ── Decision ──────────────────────────────────────────
        # ANY of these definitively proves the custom domain is live
        definitive_live = (
            sv.has_session_cookies
            or sv.has_auth_redirects
            or sv.has_login_form
            or (sv.has_active_content and sv.tls_valid_for_custom_domain)
        )

        if definitive_live:
            sv.is_definitively_live = True
            sv.verdict = ValidationVerdict.LIVE
            ctx.soft_result = sv
            ctx.aborted = True
            ctx.abort_reason = (
                f"Custom domain is definitively LIVE — not vulnerable. "
                f"Indicators: {', '.join(live_indicators[:3])}"
            )
            logger.info(
                f"[{ctx.subdomain}] FALSE POSITIVE KILLED: active app detected. "
                f"{live_indicators}"
            )
            return

        sv.verdict = ValidationVerdict.INCONCLUSIVE
        ctx.soft_result = sv
        if live_indicators:
            ctx.reasoning.append(f"Soft validation: suspicious signals but not definitive: {live_indicators}")
        else:
            ctx.reasoning.append("Soft validation: no live-app signals found — proceeding to hard validation")

    # ─────────────────────────────────────────────────────────
    # S3: Hard Validation — deterministic, provider-specific
    # This is the ONLY place CONFIRMED can be produced.
    # ─────────────────────────────────────────────────────────

    async def _s3_hard_validation(self, ctx: PipelineContext) -> None:
        ctx.stage = 3
        pm  = ctx.provider_match
        dns = ctx.dns_data

        if not pm or not dns:
            # Dangling CNAME with no provider match — still report as suspected
            ctx.hard_result = HardValidationResult(
                verdict=ValidationVerdict.INCONCLUSIVE,
                evidence=["No provider match — dangling CNAME only"],
                confidence=0.3,
            )
            return

        provider = get_provider(pm.service)
        if not provider:
            ctx.hard_result = HardValidationResult(
                verdict=ValidationVerdict.INCONCLUSIVE,
                evidence=[f"No hard validator for provider: {pm.service}"],
                confidence=0.2,
            )
            return

        try:
            result = await asyncio.wait_for(
                self._run_hard_validator(provider, ctx),
                timeout=20,
            )
            ctx.hard_result = result
            if result.is_confirmed_vulnerable:
                ctx.reasoning.append(
                    f"HARD VALIDATION CONFIRMED: {pm.service} — "
                    f"custom domain shows unclaimed state. Evidence: {result.evidence}"
                )
            else:
                ctx.reasoning.append(
                    f"Hard validation inconclusive/live: {result.verdict.value} — "
                    f"{result.evidence}"
                )
        except asyncio.TimeoutError:
            ctx.hard_result = HardValidationResult(
                verdict=ValidationVerdict.INCONCLUSIVE,
                evidence=["Hard validation timed out"],
                confidence=0.1,
            )
        except Exception as e:
            logger.debug(f"Hard validation error [{ctx.subdomain}]: {e}")
            ctx.hard_result = HardValidationResult(
                verdict=ValidationVerdict.ERROR,
                evidence=[str(e)],
                confidence=0.0,
            )

    async def _run_hard_validator(
        self, provider, ctx: PipelineContext
    ) -> HardValidationResult:
        """
        The actual hard validation logic.
        Key principle: validate THE CUSTOM DOMAIN, not the raw backend.
        """
        subdomain = ctx.subdomain
        dns       = ctx.dns_data
        http      = ctx.http_data
        service   = ctx.provider_match.service.lower() if ctx.provider_match else ""

        evidence: List[str] = []
        details:  Dict[str, Any] = {}

        # ── Step 1: Probe the custom domain with correct Host header ──
        # This ensures we're evaluating what a browser would see
        custom_domain_body = ""
        custom_domain_status = 0
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=self._timeout,
                follow_redirects=True, max_redirects=5,
            ) as client:
                resp = await client.get(
                    f"https://{subdomain}",
                    headers={
                        "Host":       subdomain,
                        "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
                    },
                )
                custom_domain_status = resp.status_code
                custom_domain_body   = resp.text[:20000]
                evidence.append(f"Custom domain probe: HTTP {custom_domain_status}")
        except Exception as e:
            evidence.append(f"Custom domain probe failed: {e}")

        # ── Step 2: Check if the custom domain itself shows unclaimed state ──
        # This is THE critical check. The raw backend may show errors,
        # but if the custom domain shows a live app, it is NOT vulnerable.
        unclaimed_on_custom = False

        for provider_key, pattern in UNCLAIMED_ON_CUSTOM_DOMAIN.items():
            if provider_key in service and custom_domain_body:
                if pattern.search(custom_domain_body):
                    unclaimed_on_custom = True
                    evidence.append(
                        f"CONFIRMED: custom domain '{subdomain}' shows "
                        f"'{provider_key}' unclaimed error page"
                    )
                    details["unclaimed_pattern"] = provider_key
                    break

        if not unclaimed_on_custom and custom_domain_status in (200, 301, 302, 303, 307):
            # Custom domain returned a live response → NOT vulnerable
            evidence.append(
                f"Custom domain returned HTTP {custom_domain_status} — appears live"
            )
            return HardValidationResult(
                verdict=ValidationVerdict.LIVE,
                is_confirmed_vulnerable=False,
                custom_domain_shows_unclaimed=False,
                evidence=evidence,
                confidence=0.85,
            )

        # ── Step 3: Provider-specific API/endpoint checks ──────────────
        provider_confirmed = False
        safe_poc: Optional[str] = None

        if "heroku" in service:
            provider_confirmed, poc = await self._validate_heroku(subdomain, dns, evidence)
            safe_poc = poc

        elif "github" in service:
            provider_confirmed, poc = await self._validate_github(dns, evidence)
            safe_poc = poc

        elif "s3" in service or "aws" in service.lower():
            provider_confirmed, poc = await self._validate_s3(subdomain, evidence)
            safe_poc = poc

        elif "netlify" in service:
            provider_confirmed = unclaimed_on_custom
            safe_poc = f"netlify sites:create && netlify domains:add {subdomain}"

        elif "vercel" in service:
            provider_confirmed = unclaimed_on_custom
            safe_poc = f"vercel --name my-project && vercel domains add {subdomain}"

        elif "azure" in service:
            provider_confirmed, poc = await self._validate_azure(dns, evidence)
            safe_poc = poc

        elif "surge" in service:
            provider_confirmed = unclaimed_on_custom
            safe_poc = f"echo '<h1>PoC</h1>' > index.html && surge --domain {subdomain}"

        else:
            provider_confirmed = unclaimed_on_custom

        is_confirmed = provider_confirmed and unclaimed_on_custom

        return HardValidationResult(
            verdict=(ValidationVerdict.UNCLAIMED if is_confirmed
                     else ValidationVerdict.INCONCLUSIVE),
            is_confirmed_vulnerable=is_confirmed,
            custom_domain_shows_unclaimed=unclaimed_on_custom,
            raw_endpoint_shows_unclaimed=bool(
                ctx.http_data and ctx.http_data.has_error_page
            ),
            ownership_verifiable=provider_confirmed,
            safe_poc=safe_poc,
            evidence=evidence,
            details=details,
            confidence=0.95 if is_confirmed else 0.4,
        )

    # ── Provider-specific validators ──────────────────────────

    async def _validate_heroku(
        self, subdomain: str, dns: DNSData, evidence: List[str]
    ):
        """
        Heroku hard validation.
        CRITICAL FIX: We must check the CUSTOM DOMAIN, NOT just herokudns.com.
        A working custom domain may CNAME to herokudns.com but still be live.
        """
        import aiohttp as _aiohttp

        for cname in dns.cname_chain:
            for suffix in (".herokudns.com", ".herokuapp.com"):
                if suffix not in cname:
                    continue
                app_name = cname.split(suffix)[0].rstrip(".")

                # Check the raw Heroku app endpoint
                raw_url = f"https://{app_name}.herokuapp.com"
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as c:
                        r = await c.get(raw_url, follow_redirects=True)
                        raw_is_unclaimed = (
                            r.status_code == 404
                            and "no such app" in r.text.lower()
                        )
                        if raw_is_unclaimed:
                            evidence.append(
                                f"Heroku raw endpoint '{raw_url}' confirms: No such app"
                            )
                        else:
                            evidence.append(
                                f"Heroku raw endpoint '{raw_url}' returned HTTP {r.status_code} "
                                f"— app may be active"
                            )
                        # NOTE: raw_is_unclaimed alone is NOT enough.
                        # Must also confirm custom domain shows unclaimed state.
                        poc = (
                            f"heroku create {app_name} --region us\n"
                            f"heroku domains:add {subdomain} -a {app_name}"
                        )
                        return raw_is_unclaimed, poc
                except Exception as e:
                    evidence.append(f"Heroku raw endpoint check failed: {e}")

        return False, None

    async def _validate_github(self, dns: DNSData, evidence: List[str]):
        import aiohttp as _aiohttp
        _T = _aiohttp.ClientTimeout(total=10)

        for cname in dns.cname_chain:
            if "github.io" not in cname:
                continue
            parts = cname.rstrip(".").split(".")
            if len(parts) < 3:
                continue
            username = parts[0]
            try:
                async with _aiohttp.ClientSession() as s:
                    async with s.get(
                        f"https://api.github.com/users/{username}",
                        headers={"Accept": "application/vnd.github.v3+json"},
                        timeout=_T,
                    ) as r:
                        if r.status == 404:
                            evidence.append(f"GitHub API: user '{username}' does not exist")
                            poc = (
                                f"# 1. Register github.com/{username}\n"
                                f"# 2. Create repo {username}.github.io\n"
                                f"# 3. Push index.html\n"
                                f"# 4. Enable GitHub Pages"
                            )
                            return True, poc
                        elif r.status == 200:
                            async with s.get(
                                f"https://api.github.com/repos/{username}/{username}.github.io",
                                headers={"Accept": "application/vnd.github.v3+json"},
                                timeout=_T,
                            ) as rr:
                                if rr.status == 404:
                                    evidence.append(
                                        f"GitHub API: user '{username}' exists but "
                                        f".github.io repo is missing"
                                    )
                                    return True, f"# Create repo {username}.github.io"
                                evidence.append(
                                    f"GitHub API: repo {username}.github.io exists"
                                )
                                return False, None
            except Exception as e:
                evidence.append(f"GitHub API check failed: {e}")

        return False, None

    async def _validate_s3(self, subdomain: str, evidence: List[str]):
        bucket = subdomain
        for url in [f"https://s3.amazonaws.com/{bucket}",
                    f"https://{bucket}.s3.amazonaws.com"]:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    r = await c.get(url)
                    t = r.text.lower()
                    if "nosuchbucket" in t or "bucket does not exist" in t:
                        evidence.append(f"S3 API: bucket '{bucket}' does not exist")
                        poc = (
                            f"aws s3api create-bucket --bucket {bucket} --region us-east-1\n"
                            f"aws s3 website s3://{bucket}/ --index-document index.html"
                        )
                        return True, poc
                    if r.status_code == 403:
                        evidence.append(f"S3: bucket '{bucket}' exists but private (403)")
                        return False, None
            except Exception as e:
                evidence.append(f"S3 check failed: {e}")
        return False, None

    async def _validate_azure(self, dns: DNSData, evidence: List[str]):
        for cname in dns.cname_chain:
            if ".azurewebsites.net" not in cname:
                continue
            app = cname.split(".azurewebsites.net")[0].rstrip(".")
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    r = await c.get(f"https://{app}.azurewebsites.net")
                    body = r.text.lower()
                    if r.status_code == 404 and ("web site not found" in body or "app not found" in body):
                        evidence.append(f"Azure: web app '{app}' not found")
                        return True, f"# Create Azure App Service with name: {app}"
                    evidence.append(f"Azure app '{app}' returned HTTP {r.status_code}")
            except Exception as e:
                evidence.append(f"Azure check failed: {e}")
        return False, None

    # ─────────────────────────────────────────────────────────
    # S4: Confidence scoring and evidence collection
    # ─────────────────────────────────────────────────────────

    async def _s4_confidence_and_evidence(self, ctx: PipelineContext) -> None:
        ctx.stage = 4

        # Convert to FingerprintMatch for confidence engine
        fp: Optional[FingerprintMatch] = None
        if ctx.provider_match:
            fp = FingerprintMatch(
                service=ctx.provider_match.service,
                signals=ctx.provider_match.signals,
                cname_pattern=ctx.provider_match.cname_matched,
                fingerprint=ctx.provider_match.body_matched,
                matched_on=(
                    "multi"  if ctx.provider_match.cname_matched and ctx.provider_match.body_matched
                    else "cname"
                ),
                confidence_boost=int(ctx.provider_match.exploitability * 15),
                match_score=ctx.provider_match.confidence,
            )

        # Build legacy ClaimabilityResult from HardValidationResult
        claim: Optional[ClaimabilityResult] = None
        if ctx.hard_result:
            claim = ClaimabilityResult(
                is_claimable=ctx.hard_result.is_confirmed_vulnerable,
                verification_method="hard_validation",
                evidence="\n".join(ctx.hard_result.evidence),
                confidence=ctx.hard_result.confidence,
                verification_stage=(
                    VerificationStage.CONFIRMED
                    if ctx.hard_result.is_confirmed_vulnerable
                    else VerificationStage.FINGERPRINTED
                ),
                safe_poc=ctx.hard_result.safe_poc,
            )

        ctx.confidence = self.conf.score(
            dns_data=ctx.dns_data,
            http_data=ctx.http_data,
            fingerprint=fp,
            claimability=claim,
            soft_result=ctx.soft_result,
            hard_result=ctx.hard_result,
        )

        # Screenshot for actionable findings
        if self._screenshot and ctx.confidence and ctx.confidence.score >= 40:
            try:
                ctx.screenshot_path = await self._screenshot(ctx.subdomain)
            except Exception as e:
                logger.debug(f"Screenshot error: {e}")

        # Evidence files
        if self._evidence:
            try:
                await self._evidence(
                    subdomain=ctx.subdomain,
                    dns_data=ctx.dns_data,
                    http_data=ctx.http_data,
                    fingerprint=fp,
                    screenshot_path=ctx.screenshot_path,
                )
            except Exception as e:
                logger.debug(f"Evidence error: {e}")

    # ─────────────────────────────────────────────────────────
    # Build Finding
    # ─────────────────────────────────────────────────────────

    def _build_finding(self, ctx: PipelineContext) -> Finding:
        dns = ctx.dns_data
        http = ctx.http_data
        pm  = ctx.provider_match
        hv  = ctx.hard_result

        stage = VerificationStage.DNS_ONLY
        if hv and hv.is_confirmed_vulnerable:
            stage = VerificationStage.CONFIRMED
        elif hv and hv.verdict != ValidationVerdict.NOT_CHECKED:
            stage = VerificationStage.API_VERIFIED
        elif ctx.soft_result:
            stage = VerificationStage.SUSPECTED
        elif pm:
            stage = VerificationStage.FINGERPRINTED

        return Finding(
            subdomain=ctx.subdomain,
            provider=pm.service if pm else "Unknown",
            confidence=ctx.confidence,
            timestamp=datetime.utcnow(),
            cname=dns.primary_cname if dns else None,
            cname_chain=dns.cname_chain if dns else [],
            dns_data=dns,
            dangling_type=dns.dangling_type if dns else DanglingType.UNKNOWN,
            http_status=http.status_code if http else None,
            http_title=http.title if http else None,
            headers=http.headers if http else {},
            http_data=http,
            tls_info=http.tls_info if http else None,
            fingerprint_matched=pm.body_matched if pm else None,
            match_signals=pm.signals if pm else [],
            soft_validation=ctx.soft_result,
            hard_validation=hv,
            verification_stage=stage,
            screenshot_path=ctx.screenshot_path,
        )
