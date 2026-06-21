"""
providers/registry.py - All provider modules with full validation logic.
15 providers: GitHub Pages, Azure, Heroku, Shopify, Fastly, Zendesk,
CloudFront, Netlify, Vercel, Pantheon, Tumblr, Bitbucket, Surge, Acquia, Cargo.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Type

import aiohttp
import httpx

from core.models import ClaimabilityResult, DNSData, VerificationStage
from providers.base import ProviderBase, ProviderMatch

logger = logging.getLogger(__name__)
_T = aiohttp.ClientTimeout(total=10)


# ─────────────────────────────────────────────────────────────
# 1. GitHub Pages
# ─────────────────────────────────────────────────────────────

class GitHubPagesProvider(ProviderBase):
    NAME       = "GitHub Pages"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://docs.github.com/en/pages"
    CNAME_PATTERNS    = ["github.io"]
    BODY_FINGERPRINTS = [
        "There isn't a GitHub Pages site here.",
        "For root URLs (like http://example.com/) you must provide an index.html file",
    ]
    VULNERABLE_STATUS_CODES = [404]
    FALSE_POSITIVE_STRINGS  = ["github.com/404", "Page not found · GitHub"]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if "github.io" not in cname:
                continue
            parts = cname.rstrip(".").split(".")
            if len(parts) < 3:
                continue
            username = parts[0]
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        f"https://api.github.com/users/{username}",
                        headers={"Accept": "application/vnd.github.v3+json"},
                        timeout=_T,
                    ) as r:
                        if r.status == 404:
                            return ClaimabilityResult(
                                is_claimable=True,
                                verification_method="github_api",
                                evidence=f"GitHub user '{username}' does not exist — namespace available",
                                confidence=0.97,
                                details={"username": username, "user_exists": False},
                                verification_stage=VerificationStage.API_VERIFIED,
                                safe_poc=(
                                    f"1. Register github.com/{username}\n"
                                    f"2. Create repo: {username}.github.io\n"
                                    f"3. Push index.html\n"
                                    f"4. Enable GitHub Pages in repo settings"
                                ),
                            )
                        elif r.status == 200:
                            async with s.get(
                                f"https://api.github.com/repos/{username}/{username}.github.io",
                                headers={"Accept": "application/vnd.github.v3+json"},
                                timeout=_T,
                            ) as rr:
                                if rr.status == 404:
                                    return ClaimabilityResult(
                                        is_claimable=True,
                                        verification_method="github_api",
                                        evidence=f"User '{username}' exists but .github.io repo missing",
                                        confidence=0.82,
                                        details={"username": username, "repo_exists": False},
                                        verification_stage=VerificationStage.API_VERIFIED,
                                    )
                                return ClaimabilityResult(
                                    is_claimable=False,
                                    verification_method="github_api",
                                    evidence=f"Repo {username}.github.io exists — not claimable",
                                    confidence=0.98,
                                )
            except Exception as e:
                logger.debug(f"GitHub validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="github_api",
                                  evidence="Username not parseable from CNAME chain")

    def poc(self, subdomain: str, dns_data: DNSData) -> str:
        for cname in dns_data.cname_chain:
            if "github.io" in cname:
                u = cname.rstrip(".").split(".")[0]
                return (f"# GitHub Pages Takeover PoC\n"
                        f"# 1. Register: https://github.com/join  (use username: {u})\n"
                        f"# 2. Create repo: {u}.github.io\n"
                        f"# 3. git clone + push index.html\n"
                        f"# 4. Enable Pages: Settings → Pages → Source: main")
        return super().poc(subdomain, dns_data)


# ─────────────────────────────────────────────────────────────
# 2. Heroku
# ─────────────────────────────────────────────────────────────

class HerokuProvider(ProviderBase):
    NAME       = "Heroku"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://devcenter.heroku.com/articles/custom-domains"
    CNAME_PATTERNS    = [".herokudns.com", ".herokuapp.com"]
    BODY_FINGERPRINTS = ["No such app", "herokucdn.com/error-pages/no-such-app.html"]
    BODY_REGEX        = [r"no\s+such\s+app", r"heroku.*not\s+found"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            for suffix in (".herokudns.com", ".herokuapp.com"):
                if suffix in cname:
                    app = cname.split(suffix)[0].rstrip(".")
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=10) as c:
                            r = await c.get(f"https://{app}.herokuapp.com")
                            if r.status_code == 404 and "no such app" in r.text.lower():
                                return ClaimabilityResult(
                                    is_claimable=True,
                                    verification_method="http_check",
                                    evidence=f"Heroku app '{app}' returns 'No such app'",
                                    confidence=0.93,
                                    details={"app_name": app},
                                    verification_stage=VerificationStage.API_VERIFIED,
                                    safe_poc=(f"heroku create {app} --region us\n"
                                              f"heroku domains:add {subdomain} -a {app}"),
                                )
                            return ClaimabilityResult(
                                is_claimable=False, verification_method="http_check",
                                evidence=f"App '{app}' is active (HTTP {r.status_code})",
                                confidence=0.90,
                            )
                    except Exception as e:
                        logger.debug(f"Heroku validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="heroku",
                                  evidence="App name not parseable")


# ─────────────────────────────────────────────────────────────
# 3. AWS S3
# ─────────────────────────────────────────────────────────────

class AWSS3Provider(ProviderBase):
    NAME       = "AWS S3"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html"
    CNAME_PATTERNS    = [".s3.amazonaws.com", ".s3-website", "s3-website-", ".s3.us-", ".s3.eu-", ".s3.ap-"]
    BODY_FINGERPRINTS = ["NoSuchBucket", "The specified bucket does not exist", "<Code>NoSuchBucket</Code>"]
    BODY_REGEX        = [r"<Code>NoSuchBucket</Code>", r"NoSuchBucket"]
    VULNERABLE_STATUS_CODES = [403, 404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        bucket = subdomain
        for url in [f"https://s3.amazonaws.com/{bucket}", f"https://{bucket}.s3.amazonaws.com"]:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    r = await c.get(url)
                    t = r.text.lower()
                    if "nosuchbucket" in t or "bucket does not exist" in t:
                        return ClaimabilityResult(
                            is_claimable=True, verification_method="s3_api",
                            evidence=f"S3 bucket '{bucket}' does not exist (NoSuchBucket)",
                            confidence=0.97,
                            details={"bucket": bucket},
                            verification_stage=VerificationStage.API_VERIFIED,
                            safe_poc=(f"aws s3api create-bucket --bucket {bucket} --region us-east-1\n"
                                      f"aws s3 website s3://{bucket}/ --index-document index.html"),
                        )
                    if r.status_code == 403:
                        return ClaimabilityResult(
                            is_claimable=False, verification_method="s3_api",
                            evidence=f"Bucket '{bucket}' exists but private (403)", confidence=0.93,
                        )
            except Exception:
                continue
        return ClaimabilityResult(is_claimable=False, verification_method="s3_api", evidence="Inconclusive")


# ─────────────────────────────────────────────────────────────
# 4. Azure
# ─────────────────────────────────────────────────────────────

class AzureProvider(ProviderBase):
    NAME       = "Azure"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://docs.microsoft.com/en-us/azure/app-service/manage-custom-dns-buy-domain"
    CNAME_PATTERNS    = [".azurewebsites.net", ".blob.core.windows.net", ".cloudapp.azure.com",
                         ".cloudapp.net", ".trafficmanager.net", ".azureedge.net", ".azurefd.net"]
    BODY_FINGERPRINTS = ["404 Web Site not found", "Microsoft Azure Web App - Error 404",
                         "Web App not found", "App not found"]
    BODY_REGEX        = [r"404\s+web\s+site\s+not\s+found", r"microsoft\s+azure.*error\s+404"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if ".azurewebsites.net" in cname:
                app = cname.split(".azurewebsites.net")[0].rstrip(".")
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as c:
                        r = await c.get(f"https://{app}.azurewebsites.net")
                        body = r.text.lower()
                        if r.status_code == 404 and ("web site not found" in body or "app not found" in body):
                            return ClaimabilityResult(
                                is_claimable=True, verification_method="azure_http",
                                evidence=f"Azure Web App '{app}' not found",
                                confidence=0.82, details={"app_name": app},
                                verification_stage=VerificationStage.API_VERIFIED,
                            )
                except Exception as e:
                    logger.debug(f"Azure validate: {e}")
            elif ".blob.core.windows.net" in cname:
                parts = cname.split(".blob.core.windows.net")[0].split(".")
                if len(parts) >= 2:
                    account, container = parts[-2], parts[-1]
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="azure_blob",
                        evidence=f"Azure Blob container dangling: {account}/{container}",
                        confidence=0.72,
                    )
        return ClaimabilityResult(is_claimable=False, verification_method="azure_http",
                                  evidence="Could not verify Azure resource status")


# ─────────────────────────────────────────────────────────────
# 5. Netlify
# ─────────────────────────────────────────────────────────────

class NetlifyProvider(ProviderBase):
    NAME       = "Netlify"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://docs.netlify.com/domains-https/custom-domains/"
    CNAME_PATTERNS    = [".netlify.app", ".netlify.com"]
    BODY_FINGERPRINTS = ["Not found - Request ID:", "netlify"]
    BODY_REGEX        = [r"not\s+found\s+-\s+request\s+id:", r"netlify.*404"]
    HEADER_PATTERNS   = [{"name": "x-nf-request-id", "value": ""}]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if r.status_code == 404 and "not found - request id" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="netlify_http",
                        evidence="Netlify 404 with Request ID — site not configured",
                        confidence=0.88, verification_stage=VerificationStage.API_VERIFIED,
                        safe_poc="netlify sites:create && netlify domains:add " + subdomain,
                    )
        except Exception as e:
            logger.debug(f"Netlify validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="netlify_http",
                                  evidence="Netlify site appears active")


# ─────────────────────────────────────────────────────────────
# 6. Vercel
# ─────────────────────────────────────────────────────────────

class VercelProvider(ProviderBase):
    NAME       = "Vercel"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://vercel.com/docs/custom-domains"
    CNAME_PATTERNS    = [".vercel.app", ".vercel.com", ".now.sh"]
    BODY_FINGERPRINTS = ["The deployment you are trying to access does not exist",
                         "This Deployment doesn't exist"]
    BODY_REGEX        = [r"deployment.*does\s+not\s+exist", r"vercel.*404"]
    HEADER_PATTERNS   = [{"name": "x-vercel-id", "value": ""}]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if r.status_code == 404 and "deployment" in r.text.lower() and "not exist" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="vercel_http",
                        evidence="Vercel deployment not found",
                        confidence=0.87, verification_stage=VerificationStage.API_VERIFIED,
                        safe_poc=f"vercel --name my-project\nvercel domains add {subdomain}",
                    )
        except Exception as e:
            logger.debug(f"Vercel validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="vercel_http",
                                  evidence="Vercel deployment appears active")


# ─────────────────────────────────────────────────────────────
# 7. Shopify
# ─────────────────────────────────────────────────────────────

class ShopifyProvider(ProviderBase):
    NAME       = "Shopify"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://help.shopify.com/en/manual/domains"
    CNAME_PATTERNS    = [".myshopify.com", "shops.myshopify.com"]
    BODY_FINGERPRINTS = ["Sorry, this shop is currently unavailable.", "Only one step left!"]
    BODY_REGEX        = [r"shop.*unavailable", r"shopify.*404"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if r.status_code == 404 and ("unavailable" in r.text.lower() or "one step left" in r.text.lower()):
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="shopify_http",
                        evidence="Shopify store is unavailable — domain can be claimed",
                        confidence=0.83, verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"Shopify validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="shopify_http",
                                  evidence="Shopify store appears active")


# ─────────────────────────────────────────────────────────────
# 8. Fastly
# ─────────────────────────────────────────────────────────────

class FastlyProvider(ProviderBase):
    NAME       = "Fastly"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://developer.fastly.com/reference/api/"
    CNAME_PATTERNS    = [".fastly.net", ".fastlylb.net", ".fastly.com"]
    BODY_FINGERPRINTS = ["Fastly error: unknown domain", "Please check that this domain has been added"]
    BODY_REGEX        = [r"fastly\s+error.*unknown\s+domain", r"fastly.*not\s+configured"]
    HEADER_PATTERNS   = [{"name": "x-served-by", "value": "cache-"}, {"name": "x-fastly-request-id", "value": ""}]
    VULNERABLE_STATUS_CODES = [404]
    FALSE_POSITIVE_STRINGS  = ["Via: 1.1 varnish"]  # Active Fastly traffic

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if "fastly error" in r.text.lower() and "unknown domain" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="fastly_http",
                        evidence="Fastly returns 'unknown domain' error — service unconfigured",
                        confidence=0.91, verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"Fastly validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="fastly_http",
                                  evidence="Fastly service appears configured")


# ─────────────────────────────────────────────────────────────
# 9. Zendesk
# ─────────────────────────────────────────────────────────────

class ZendeskProvider(ProviderBase):
    NAME       = "Zendesk"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://support.zendesk.com/hc/en-us/articles/203664356"
    CNAME_PATTERNS    = [".zendesk.com"]
    BODY_FINGERPRINTS = ["Help Center Closed", "Oops, this help center no longer exists"]
    BODY_REGEX        = [r"help\s+center.*closed", r"zendesk.*no\s+longer\s+exists"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                body = r.text.lower()
                if "help center closed" in body or "no longer exists" in body:
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="zendesk_http",
                        evidence="Zendesk Help Center is closed — subdomain available",
                        confidence=0.84, verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"Zendesk validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="zendesk_http",
                                  evidence="Zendesk instance appears active")


# ─────────────────────────────────────────────────────────────
# 10. CloudFront
# ─────────────────────────────────────────────────────────────

class CloudFrontProvider(ProviderBase):
    NAME       = "AWS CloudFront"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html"
    CNAME_PATTERNS    = [".cloudfront.net"]
    BODY_FINGERPRINTS = ["Bad request.", "ERROR: The request could not be satisfied"]
    BODY_REGEX        = [r"bad\s+request.*cloudfront", r"request\s+could\s+not\s+be\s+satisfied"]
    HEADER_PATTERNS   = [{"name": "x-cache", "value": "error from cloudfront"},
                         {"name": "x-amz-cf-id", "value": ""}]
    VULNERABLE_STATUS_CODES = [403, 404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
                body = r.text.lower()
                # CloudFront CNAME misconfiguration shows specific patterns
                if ("bad request" in body or "could not be satisfied" in body) and \
                   ("cloudfront" in body or "x-amz-cf-id" in headers_lower):
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="cloudfront_http",
                        evidence="CloudFront distribution misconfigured — CNAME may be reclaimable",
                        confidence=0.72,
                        verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"CloudFront validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="cloudfront_http",
                                  evidence="CloudFront distribution appears active")


# ─────────────────────────────────────────────────────────────
# 11. Pantheon
# ─────────────────────────────────────────────────────────────

class PantheonProvider(ProviderBase):
    NAME       = "Pantheon"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://pantheon.io/docs/custom-domains"
    CNAME_PATTERNS    = [".pantheonsite.io", ".pantheon.io", ".getpantheon.com"]
    BODY_FINGERPRINTS = ["404 error unknown site!", "The gods are wise, but do not know of the site which you seek."]
    BODY_REGEX        = [r"404.*unknown\s+site", r"pantheon.*not\s+found"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if "unknown site" in r.text.lower() or "gods are wise" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="pantheon_http",
                        evidence="Pantheon site not found — domain available to claim",
                        confidence=0.88, verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"Pantheon validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="pantheon_http",
                                  evidence="Pantheon site appears active")


# ─────────────────────────────────────────────────────────────
# 12. Tumblr
# ─────────────────────────────────────────────────────────────

class TumblrProvider(ProviderBase):
    NAME       = "Tumblr"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://help.tumblr.com/hc/en-us/articles/231256048"
    CNAME_PATTERNS    = [".tumblr.com", "domains.tumblr.com"]
    BODY_FINGERPRINTS = ["Whatever you were looking for doesn't currently exist at this address.",
                         "There's nothing here."]
    BODY_REGEX        = [r"doesn't\s+currently\s+exist\s+at\s+this\s+address", r"tumblr.*nothing\s+here"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if "doesn't currently exist" in r.text.lower() or "nothing here" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="tumblr_http",
                        evidence="Tumblr custom domain not configured — claimable",
                        confidence=0.80, verification_stage=VerificationStage.API_VERIFIED,
                    )
        except Exception as e:
            logger.debug(f"Tumblr validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="tumblr_http",
                                  evidence="Tumblr blog appears active")


# ─────────────────────────────────────────────────────────────
# 13. Surge.sh
# ─────────────────────────────────────────────────────────────

class SurgeProvider(ProviderBase):
    NAME       = "Surge.sh"
    DIFFICULTY = "easy"
    DOCS_URL   = "https://surge.sh/help/adding-a-custom-domain"
    CNAME_PATTERNS    = [".surge.sh"]
    BODY_FINGERPRINTS = ["project not found", "doesn't appear to be a Surge project"]
    BODY_REGEX        = [r"project\s+not\s+found", r"surge.*not\s+found"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if "project not found" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="surge_http",
                        evidence="Surge.sh project not found — claimable with `surge` CLI",
                        confidence=0.92, verification_stage=VerificationStage.API_VERIFIED,
                        safe_poc=f"echo '<h1>Claimed</h1>' > index.html && surge --domain {subdomain}",
                    )
        except Exception as e:
            logger.debug(f"Surge validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="surge_http",
                                  evidence="Surge project appears active")


# ─────────────────────────────────────────────────────────────
# 14. Bitbucket
# ─────────────────────────────────────────────────────────────

class BitbucketProvider(ProviderBase):
    NAME       = "Bitbucket"
    DIFFICULTY = "medium"
    DOCS_URL   = "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/"
    CNAME_PATTERNS    = [".bitbucket.io"]
    BODY_FINGERPRINTS = ["Repository not found", "The page you have requested does not exist"]
    BODY_REGEX        = [r"repository\s+not\s+found", r"bitbucket.*page.*not.*exist"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        for cname in dns_data.cname_chain:
            if "bitbucket.io" not in cname:
                continue
            parts = cname.rstrip(".").split(".")
            if len(parts) < 3:
                continue
            username = parts[0]
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        f"https://api.bitbucket.org/2.0/users/{username}",
                        timeout=_T,
                    ) as r:
                        if r.status == 404:
                            return ClaimabilityResult(
                                is_claimable=True, verification_method="bitbucket_api",
                                evidence=f"Bitbucket user '{username}' does not exist",
                                confidence=0.88, verification_stage=VerificationStage.API_VERIFIED,
                            )
            except Exception as e:
                logger.debug(f"Bitbucket validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="bitbucket_api",
                                  evidence="Bitbucket user/repo appears active")


# ─────────────────────────────────────────────────────────────
# 15. Acquia
# ─────────────────────────────────────────────────────────────

class AcquiaProvider(ProviderBase):
    NAME       = "Acquia"
    DIFFICULTY = "hard"
    DOCS_URL   = "https://docs.acquia.com/cloud-platform/manage/domains/"
    CNAME_PATTERNS    = [".acquia-sites.com", ".acquia.io", ".acquiasites.com"]
    BODY_FINGERPRINTS = ["Web Site Not Found", "The site you are looking for could not be found"]
    BODY_REGEX        = [r"acquia.*not\s+found", r"site.*could\s+not\s+be\s+found"]
    VULNERABLE_STATUS_CODES = [404]

    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(f"https://{subdomain}")
                if "web site not found" in r.text.lower() or "could not be found" in r.text.lower():
                    return ClaimabilityResult(
                        is_claimable=True, verification_method="acquia_http",
                        evidence="Acquia site not found — domain may be reclaimable",
                        confidence=0.70,
                    )
        except Exception as e:
            logger.debug(f"Acquia validate: {e}")
        return ClaimabilityResult(is_claimable=False, verification_method="acquia_http",
                                  evidence="Acquia site appears active")


# ─────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────

ALL_PROVIDERS: List[ProviderBase] = [
    GitHubPagesProvider(),
    HerokuProvider(),
    AWSS3Provider(),
    AzureProvider(),
    NetlifyProvider(),
    VercelProvider(),
    ShopifyProvider(),
    FastlyProvider(),
    ZendeskProvider(),
    CloudFrontProvider(),
    PantheonProvider(),
    TumblrProvider(),
    SurgeProvider(),
    BitbucketProvider(),
    AcquiaProvider(),
]

PROVIDER_MAP: Dict[str, ProviderBase] = {p.NAME: p for p in ALL_PROVIDERS}


def get_provider(name: str) -> Optional[ProviderBase]:
    return PROVIDER_MAP.get(name)


def all_providers() -> List[ProviderBase]:
    return ALL_PROVIDERS
