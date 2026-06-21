"""
tests/test_core.py - Core unit tests for SubSentinel
Run with: pytest tests/ -v
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# --- Model tests ---

def test_dns_data_primary_cname():
    from core.models import DNSData
    d = DNSData(hostname="dev.example.com")
    d.cname_chain = ["dev.example.com.herokudns.com", "something.herokudns.com"]
    d.has_cname = True
    d.primary_cname = d.cname_chain[-1]
    assert d.primary_cname == "something.herokudns.com"
    assert d.final_cname == "something.herokudns.com"


def test_confidence_result_label():
    from core.models import ConfidenceResult
    assert ConfidenceResult(score=90, severity="critical").label == "CRITICAL"
    assert ConfidenceResult(score=70, severity="high").label == "HIGH"
    assert ConfidenceResult(score=50, severity="medium").label == "MEDIUM"
    assert ConfidenceResult(score=25, severity="low").label == "LOW"
    assert ConfidenceResult(score=5, severity="info").label == "INFO"


def test_finding_severity():
    from core.models import Finding, ConfidenceResult
    f = Finding(
        subdomain="dev.example.com",
        provider="Heroku",
        confidence=ConfidenceResult(score=90, severity="critical"),
        timestamp=datetime.utcnow()
    )
    assert f.is_critical is True
    assert f.severity == "critical"


def test_finding_to_dict():
    from core.models import Finding, ConfidenceResult
    f = Finding(
        subdomain="dev.example.com",
        provider="GitHub Pages",
        confidence=ConfidenceResult(score=85, severity="critical", reasons=["Test reason"]),
        timestamp=datetime.utcnow(),
        cname="user.github.io",
        cname_chain=["user.github.io"],
        http_status=404,
    )
    d = f.to_dict()
    assert d["subdomain"] == "dev.example.com"
    assert d["provider"] == "GitHub Pages"
    assert d["confidence"] == 85
    assert d["severity"] == "CRITICAL"
    assert "remediation" in d
    assert "references" in d


# --- Confidence scorer tests ---

def test_confidence_wildcard_ignored():
    from modules.confidence import ConfidenceScorer
    from core.models import DNSData
    scorer = ConfidenceScorer()
    dns = DNSData(hostname="x.example.com", is_wildcard=True)
    result = scorer.score(dns_data=dns, http_data=None, fingerprint=None, claimability=None)
    assert result.score == 0
    assert "Wildcard" in result.deductions[0]


def test_confidence_full_critical():
    from modules.confidence import ConfidenceScorer
    from core.models import DNSData, HTTPData, FingerprintMatch, ClaimabilityResult
    scorer = ConfidenceScorer()

    dns = DNSData(
        hostname="dev.example.com",
        has_cname=True,
        is_nxdomain=True,
        is_dangling=True,
        cname_chain=["dev.herokudns.com"],
        primary_cname="dev.herokudns.com"
    )
    http = HTTPData(url="https://dev.example.com", status_code=404, body="No such app", title="Error")
    fp = FingerprintMatch(
        service="Heroku",
        cname_pattern=".herokudns.com",
        fingerprint="No such app",
        confidence_boost=25
    )
    claim = ClaimabilityResult(is_claimable=True, evidence="App does not exist")

    result = scorer.score(dns, http, fp, claim)
    assert result.score >= 85
    assert result.severity == "critical"


def test_confidence_parked_domain_deduction():
    from modules.confidence import ConfidenceScorer
    from core.models import DNSData, HTTPData, FingerprintMatch
    scorer = ConfidenceScorer()

    dns = DNSData(hostname="dev.example.com", has_cname=True, cname_chain=["x.netlify.app"])
    http = HTTPData(url="https://dev.example.com", status_code=404,
                    body="This domain is for sale - sedoparking.com", title="Parked")
    fp = FingerprintMatch(service="Netlify", cname_pattern=".netlify.app", confidence_boost=20)

    result = scorer.score(dns, http, fp, None)
    assert any("parked" in d.lower() for d in result.deductions)


# --- DNS Analyzer tests ---

@pytest.mark.asyncio
async def test_dns_cname_chain_loop_protection():
    """CNAME chain should not loop infinitely."""
    from modules.dns_analyzer import DNSAnalyzer
    from core.config import ScanConfig
    config = ScanConfig()
    analyzer = DNSAnalyzer(config)

    # Patch resolver to simulate a loop
    call_count = 0
    async def mock_resolve(name, rdtype):
        nonlocal call_count
        call_count += 1
        if call_count > 20:
            raise Exception("Too many calls - loop not protected")
        mock = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.target = MagicMock()
        mock_rdata.target.__str__ = lambda self: "a.example.com."
        mock.__iter__ = lambda self: iter([mock_rdata])
        return mock

    with patch.object(analyzer.resolver, 'resolve', side_effect=mock_resolve):
        chain = await analyzer._resolve_cname("a.example.com")
        assert len(chain) <= 10  # max_depth enforced


# --- Fingerprinter tests ---

@pytest.mark.asyncio
async def test_fingerprinter_heroku_cname_match():
    from modules.fingerprinter import ServiceFingerprinter
    from core.models import DNSData, HTTPData, Subdomain
    from core.config import ScanConfig
    config = ScanConfig()
    fp = ServiceFingerprinter(config)
    await fp._ensure_loaded()

    dns = DNSData(
        hostname="dev.example.com",
        has_cname=True,
        is_dangling=True,
        is_nxdomain=True,
        cname_chain=["dev-app.herokudns.com"],
        primary_cname="dev-app.herokudns.com"
    )
    http = HTTPData(url="https://dev.example.com", status_code=404, body="No such app")
    sub = Subdomain(hostname="dev.example.com")

    result = await fp.fingerprint(sub, dns, http)
    assert result is not None
    assert result.service == "Heroku"


@pytest.mark.asyncio
async def test_fingerprinter_no_match_clean_site():
    from modules.fingerprinter import ServiceFingerprinter
    from core.models import DNSData, HTTPData, Subdomain
    from core.config import ScanConfig
    config = ScanConfig()
    fp = ServiceFingerprinter(config)
    await fp._ensure_loaded()

    dns = DNSData(hostname="www.example.com", a_records=["1.2.3.4"], resolves=True)
    http = HTTPData(url="https://www.example.com", status_code=200, body="Welcome to our site!")
    sub = Subdomain(hostname="www.example.com")

    result = await fp.fingerprint(sub, dns, http)
    assert result is None  # Clean site, no match


# --- Enumerator tests ---

@pytest.mark.asyncio
async def test_enumerator_deduplication():
    from modules.enumerator import SubdomainEnumerator
    from core.config import ScanConfig
    config = ScanConfig(use_crtsh=False, use_subfinder=False, use_amass=False, use_chaos=False)
    enum = SubdomainEnumerator(config)

    dupes = {"dev.example.com", "dev.example.com", "staging.example.com"}
    validated = enum._validate_subdomains(dupes, "example.com")
    assert len(validated) == 2
    assert "dev.example.com" in validated
    assert "staging.example.com" in validated


def test_enumerator_rejects_invalid():
    from modules.enumerator import SubdomainEnumerator
    from core.config import ScanConfig
    config = ScanConfig()
    enum = SubdomainEnumerator(config)

    invalid = {
        "*.example.com",          # wildcard
        "not-a-subdomain",        # no parent
        "other.com",              # wrong domain
        "a" * 300 + ".example.com",  # too long
    }
    validated = enum._validate_subdomains(invalid, "example.com")
    assert len(validated) == 0


# --- Rate limiter tests ---

@pytest.mark.asyncio
async def test_rate_limiter_allows_burst():
    from utils.rate_limiter import RateLimiter
    import time
    rl = RateLimiter(rate=100, burst=5)
    start = time.monotonic()
    for _ in range(5):
        await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 1.0  # Burst of 5 should be near-instant


@pytest.mark.asyncio
async def test_rate_limiter_throttles():
    from utils.rate_limiter import RateLimiter
    import time
    rl = RateLimiter(rate=5, burst=1)  # 5 req/sec, burst of 1
    start = time.monotonic()
    for _ in range(3):
        await rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.3  # 3 requests at 5/sec = at least 0.4s


# --- Proxy rotator tests ---

@pytest.mark.asyncio
async def test_proxy_rotator_round_robin():
    from utils.proxy import ProxyRotator
    proxies = ["http://p1:8080", "http://p2:8080", "http://p3:8080"]
    rotator = ProxyRotator(proxies)
    results = [await rotator.get_proxy() for _ in range(6)]
    # Should cycle through proxies
    assert results[0] == results[3]
    assert results[1] == results[4]


@pytest.mark.asyncio
async def test_proxy_rotator_skips_failed():
    from utils.proxy import ProxyRotator
    proxies = ["http://p1:8080", "http://p2:8080"]
    rotator = ProxyRotator(proxies)
    await rotator.mark_failed("http://p1:8080")
    for _ in range(5):
        p = await rotator.get_proxy()
        assert p == "http://p2:8080"
