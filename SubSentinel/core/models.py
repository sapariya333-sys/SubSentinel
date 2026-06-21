"""
core/models.py - Typed data models for SubSentinel v4.1
Redesigned confidence system: four independent dimensions replace single score.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class DanglingType(str, Enum):
    CNAME_NXDOMAIN     = "cname_nxdomain"
    CNAME_UNREGISTERED = "cname_unregistered"
    ORPHANED_IP        = "orphaned_ip"
    DEAD_NS            = "dead_ns"
    EXPIRED_RESOURCE   = "expired_resource"
    UNCLAIMED_BUCKET   = "unclaimed_bucket"
    UNKNOWN            = "unknown"


class VerificationStage(str, Enum):
    """Ordered pipeline stages — only CONFIRMED means deterministic proof."""
    DNS_ONLY    = "dns_only"        # Stage 1-2 complete
    DNS_HTTP    = "dns_http"        # Stage 3 complete
    SUSPECTED   = "suspected"       # Stage 4-5: soft validation passed
    FINGERPRINTED = "fingerprinted" # Provider detected
    API_VERIFIED  = "api_verified"  # Provider API confirmed resource missing
    CONFIRMED     = "confirmed"     # Deterministic — custom domain itself shows unclaimed state
    # NEVER mark CONFIRMED from body match alone — requires custom domain validation


class ValidationVerdict(str, Enum):
    """Deterministic outcome — only populated after hard validation."""
    NOT_CHECKED   = "not_checked"
    LIVE          = "live"           # Custom domain serves a real application
    UNCLAIMED     = "unclaimed"      # Custom domain itself shows unclaimed error
    INCONCLUSIVE  = "inconclusive"   # Cannot determine
    ERROR         = "error"          # Validation failed


class MatchMethod(str, Enum):
    CNAME_EXACT  = "cname_exact"
    CNAME_REGEX  = "cname_regex"
    BODY_EXACT   = "body_exact"
    BODY_REGEX   = "body_regex"
    BODY_FUZZY   = "body_fuzzy"
    HEADER       = "header"
    STATUS_CODE  = "status_code"
    TLS_CN       = "tls_cn"
    MULTI_SIGNAL = "multi_signal"


# ─────────────────────────────────────────────────────────────
# DNS Models
# ─────────────────────────────────────────────────────────────

@dataclass
class ResolverResult:
    resolver_ip: str
    a_records: List[str]   = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    cname_chain: List[str] = field(default_factory=list)
    is_nxdomain: bool = False
    is_servfail: bool = False
    latency_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class DNSConsistency:
    resolvers_queried: int   = 0
    resolvers_agreed: int    = 0
    consistency_score: float = 0.0
    discrepancies: List[str] = field(default_factory=list)
    authoritative_ns: List[str] = field(default_factory=list)
    propagation_complete: bool = True


@dataclass
class DNSData:
    hostname: str
    a_records: List[str]     = field(default_factory=list)
    aaaa_records: List[str]  = field(default_factory=list)
    cname_chain: List[str]   = field(default_factory=list)
    ns_records: List[str]    = field(default_factory=list)
    mx_records: List[str]    = field(default_factory=list)
    txt_records: List[str]   = field(default_factory=list)
    resolves: bool            = False
    is_nxdomain: bool         = False
    is_servfail: bool         = False
    is_wildcard: bool         = False
    is_dangling: bool         = False
    has_cname: bool           = False
    dnssec_valid: Optional[bool] = None
    primary_cname: Optional[str] = None
    cname_depth: int          = 0
    dangling_type: DanglingType = DanglingType.UNKNOWN
    resolver_results: List[ResolverResult] = field(default_factory=list)
    consistency: Optional[DNSConsistency]  = None
    anomalies: List[str]      = field(default_factory=list)
    ttl_values: Dict[str, int] = field(default_factory=dict)
    resolution_time_ms: float = 0.0
    error: Optional[str]      = None

    @property
    def final_cname(self) -> Optional[str]:
        return self.cname_chain[-1] if self.cname_chain else None

    @property
    def is_suspicious(self) -> bool:
        return self.is_dangling or (self.is_nxdomain and self.has_cname)

    def all_ips(self) -> Set[str]:
        return set(self.a_records + self.aaaa_records)


# ─────────────────────────────────────────────────────────────
# HTTP Models
# ─────────────────────────────────────────────────────────────

@dataclass
class TLSInfo:
    is_valid: bool           = False
    is_expired: bool         = False
    common_name: Optional[str] = None
    san_list: List[str]      = field(default_factory=list)
    issuer: Optional[str]    = None
    subject: Optional[str]   = None
    not_before: Optional[str] = None
    not_after: Optional[str]  = None
    days_until_expiry: Optional[int] = None
    self_signed: bool         = False
    wildcard_cert: bool       = False
    cn_mismatch: bool         = False
    error: Optional[str]      = None


@dataclass
class HTTPData:
    url: str
    status_code: Optional[int]     = None
    title: Optional[str]           = None
    body: Optional[str]            = None
    body_hash: Optional[str]       = None
    body_length: int               = 0
    headers: Dict[str, str]        = field(default_factory=dict)
    redirect_chain: List[str]      = field(default_factory=list)
    final_url: Optional[str]       = None
    is_https: bool                 = False
    tls_info: Optional[TLSInfo]    = None
    server: Optional[str]          = None
    content_type: Optional[str]    = None
    response_time_ms: float        = 0.0
    is_js_redirect: bool           = False
    js_redirect_target: Optional[str] = None
    meta_refresh_url: Optional[str]   = None
    cdn_provider: Optional[str]    = None
    waf_detected: bool             = False
    waf_provider: Optional[str]    = None
    http_version: str              = "1.1"
    has_error_page: bool           = False
    error_page_type: Optional[str] = None
    content_entropy: float         = 0.0
    word_count: int                = 0
    link_count: int                = 0
    form_count: int                = 0
    # NEW: active application signals
    has_session_cookie: bool       = False
    has_auth_header: bool          = False
    has_csp_header: bool           = False
    has_login_form: bool           = False
    has_set_cookie: bool           = False
    cookie_names: List[str]        = field(default_factory=list)
    error: Optional[str]           = None


# ─────────────────────────────────────────────────────────────
# Fingerprint Models
# ─────────────────────────────────────────────────────────────

@dataclass
class FingerprintSignal:
    method: MatchMethod
    pattern: str
    matched_value: str
    weight: float
    description: str = ""


@dataclass
class FingerprintMatch:
    service: str
    signals: List[FingerprintSignal]    = field(default_factory=list)
    cname_pattern: Optional[str]        = None
    fingerprint: Optional[str]          = None
    matched_on: str                     = "cname"
    vulnerable_status_codes: List[int]  = field(default_factory=list)
    takeover_difficulty: str            = "medium"
    documentation_url: Optional[str]    = None
    notes: Optional[str]               = None
    confidence_boost: int              = 0
    false_positive_rules: List[str]    = field(default_factory=list)
    match_score: float                 = 0.0
    match_methods: List[MatchMethod]   = field(default_factory=list)

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def is_high_confidence(self) -> bool:
        return self.match_score >= 0.7 and self.signal_count >= 2


# ─────────────────────────────────────────────────────────────
# Validation Models (NEW — replaces simple ClaimabilityResult)
# ─────────────────────────────────────────────────────────────

@dataclass
class SoftValidationResult:
    """
    Stage 2 (Soft Validation) output.
    Analyzes the CUSTOM DOMAIN response — not the raw provider endpoint.
    """
    verdict: ValidationVerdict         = ValidationVerdict.NOT_CHECKED
    # Active application signals found on the CUSTOM domain
    has_session_cookies: bool          = False
    has_auth_redirects: bool           = False
    has_login_form: bool               = False
    has_active_content: bool           = False
    has_waf: bool                      = False
    cdn_matches_provider: bool         = False
    tls_valid_for_custom_domain: bool  = False
    redirect_to_live_app: bool         = False
    redirect_chain: List[str]          = field(default_factory=list)
    body_entropy: float                = 0.0
    response_word_count: int           = 0
    evidence: List[str]               = field(default_factory=list)
    # If any of these are True, do NOT proceed to hard validation — it's live
    is_definitively_live: bool         = False
    live_indicators: List[str]        = field(default_factory=list)


@dataclass
class HardValidationResult:
    """
    Stage 3 (Hard Validation) output.
    Provider-specific deterministic check.
    ONLY set is_confirmed_vulnerable=True when certain.
    """
    verdict: ValidationVerdict             = ValidationVerdict.NOT_CHECKED
    is_confirmed_vulnerable: bool          = False
    provider_api_checked: bool             = False
    custom_domain_shows_unclaimed: bool    = False  # The key check
    raw_endpoint_shows_unclaimed: bool     = False
    ownership_verifiable: bool             = False
    safe_poc: Optional[str]               = None
    evidence: List[str]                   = field(default_factory=list)
    details: Dict[str, Any]              = field(default_factory=dict)
    confidence: float                     = 0.0   # 0.0–1.0


# Keep backward compat alias
@dataclass
class ClaimabilityResult:
    is_claimable: bool                    = False
    verification_method: str              = ""
    evidence: str                         = ""
    confidence: float                     = 0.0
    details: Dict[str, Any]              = field(default_factory=dict)
    verification_stage: VerificationStage = VerificationStage.DNS_ONLY
    error: Optional[str]                  = None
    safe_poc: Optional[str]              = None


# ─────────────────────────────────────────────────────────────
# Confidence Models (REDESIGNED — 4 dimensions)
# ─────────────────────────────────────────────────────────────

@dataclass
class ConfidenceDimensions:
    """
    Four independent confidence dimensions.
    A finding is only actionable when ALL four are above threshold.

    fingerprint:  How well does the provider match?   (detection quality)
    exposure:     Is the DNS/HTTP state actually wrong? (attack surface)
    claimability: Can the resource actually be claimed? (feasibility)
    exploitability: How easy is it to exploit?          (impact)
    """
    fingerprint: float    = 0.0   # 0.0–1.0
    exposure: float       = 0.0   # 0.0–1.0
    claimability: float   = 0.0   # 0.0–1.0
    exploitability: float = 0.0   # 0.0–1.0

    @property
    def composite(self) -> float:
        """Geometric mean — requires ALL dimensions to be reasonable."""
        import math
        vals = [self.fingerprint, self.exposure, self.claimability, self.exploitability]
        if any(v <= 0 for v in vals):
            return 0.0
        return (self.fingerprint * self.exposure * self.claimability * self.exploitability) ** 0.25

    @property
    def score(self) -> int:
        return int(self.composite * 100)


@dataclass
class Signal:
    name: str
    value: float
    weight: float
    description: str
    category: str

    @property
    def weighted_value(self) -> float:
        return self.value * self.weight


@dataclass
class ConfidenceResult:
    score: int                           = 0
    severity: str                        = "info"
    dimensions: Optional[ConfidenceDimensions] = None
    signals: List[Signal]               = field(default_factory=list)
    reasons: List[str]                  = field(default_factory=list)
    deductions: List[str]               = field(default_factory=list)
    verification_stage: VerificationStage = VerificationStage.DNS_ONLY
    false_positive_risk: str            = "unknown"
    takeover_likelihood: str            = "unknown"

    @property
    def label(self) -> str:
        if self.score >= 85: return "CRITICAL"
        if self.score >= 65: return "HIGH"
        if self.score >= 40: return "MEDIUM"
        if self.score >= 20: return "LOW"
        return "INFO"

    @property
    def is_actionable(self) -> bool:
        return self.score >= 40


# ─────────────────────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    subdomain: str
    timestamp: datetime
    response_text: Optional[str]           = None
    response_headers: Dict[str, str]       = field(default_factory=dict)
    html_title: Optional[str]             = None
    dns_records: Dict[str, Any]           = field(default_factory=dict)
    cname_chain: List[str]               = field(default_factory=list)
    tls_details: Optional[Dict[str, Any]] = None
    screenshot_path: Optional[str]        = None
    dom_snapshot_path: Optional[str]      = None
    har_path: Optional[str]              = None
    raw_proof: Dict[str, Any]            = field(default_factory=dict)
    evidence_dir: Optional[str]          = None
    poc_command: Optional[str]           = None
    reproduction_steps: List[str]        = field(default_factory=list)
    curl_command: Optional[str]          = None
    dig_command: Optional[str]           = None
    # NEW: validation evidence chain
    soft_validation: Optional[SoftValidationResult]  = None
    hard_validation: Optional[HardValidationResult]  = None
    reasoning_chain: List[str]           = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    subdomain: str
    provider: str
    confidence: ConfidenceResult
    timestamp: datetime

    cname: Optional[str]              = None
    cname_chain: List[str]           = field(default_factory=list)
    dns_data: Optional[DNSData]      = None
    dangling_type: DanglingType       = DanglingType.UNKNOWN

    http_status: Optional[int]        = None
    http_title: Optional[str]         = None
    headers: Dict[str, str]          = field(default_factory=dict)
    http_data: Optional[HTTPData]    = None
    tls_info: Optional[TLSInfo]      = None

    fingerprint_matched: Optional[str]          = None
    fingerprint: Optional[FingerprintMatch]      = None
    match_signals: List[FingerprintSignal]       = field(default_factory=list)

    # NEW: separate validation results
    soft_validation: Optional[SoftValidationResult] = None
    hard_validation: Optional[HardValidationResult] = None
    claimability: Optional[ClaimabilityResult]      = None   # legacy compat

    verification_stage: VerificationStage = VerificationStage.DNS_ONLY
    evidence: Optional[Evidence]          = None
    screenshot_path: Optional[str]        = None
    scan_id: Optional[str]               = None
    source: str                          = "unknown"

    @property
    def severity(self) -> str:
        return self.confidence.severity

    @property
    def is_critical(self) -> bool:
        return self.confidence.score >= 85

    @property
    def is_verified(self) -> bool:
        """Only True if hard validation confirmed unclaimed state."""
        return (
            self.verification_stage == VerificationStage.CONFIRMED
            or (self.hard_validation is not None
                and self.hard_validation.is_confirmed_vulnerable)
        )

    def to_dict(self) -> Dict[str, Any]:
        hv = self.hard_validation
        sv = self.soft_validation
        dims = self.confidence.dimensions

        return {
            "subdomain": self.subdomain,
            "provider": self.provider,
            "severity": self.confidence.severity.upper(),
            "confidence": self.confidence.score,
            "confidence_dimensions": {
                "fingerprint":    round(dims.fingerprint, 3)    if dims else None,
                "exposure":       round(dims.exposure, 3)       if dims else None,
                "claimability":   round(dims.claimability, 3)   if dims else None,
                "exploitability": round(dims.exploitability, 3) if dims else None,
            },
            "takeover_likelihood": self.confidence.takeover_likelihood,
            "false_positive_risk": self.confidence.false_positive_risk,
            "verification_stage":  self.verification_stage.value,
            "is_verified":         self.is_verified,
            "cname": self.cname,
            "cname_chain": self.cname_chain,
            "dangling_type": self.dangling_type.value,
            "http_status": self.http_status,
            "http_title": self.http_title,
            "fingerprint_matched": self.fingerprint_matched,
            "soft_validation": {
                "verdict": sv.verdict.value if sv else None,
                "is_live": sv.is_definitively_live if sv else None,
                "live_indicators": sv.live_indicators if sv else [],
                "evidence": sv.evidence if sv else [],
            },
            "hard_validation": {
                "verdict": hv.verdict.value if hv else None,
                "confirmed_vulnerable": hv.is_confirmed_vulnerable if hv else None,
                "custom_domain_unclaimed": hv.custom_domain_shows_unclaimed if hv else None,
                "evidence": hv.evidence if hv else [],
                "safe_poc": hv.safe_poc if hv else None,
            },
            "reasoning_chain": self.confidence.reasons,
            "deductions": self.confidence.deductions,
            "timestamp": self.timestamp.isoformat(),
            "remediation": self._get_remediation(),
        }

    def _get_remediation(self) -> str:
        r = {
            "GitHub Pages": "Remove CNAME or create/reclaim the GitHub Pages repository.",
            "Heroku":        "Remove CNAME or re-create the Heroku application.",
            "AWS S3":        "Remove CNAME or create the S3 bucket with the same name.",
            "Azure":         "Remove CNAME or recreate the Azure App Service resource.",
            "Netlify":       "Remove CNAME or create a Netlify site claiming this domain.",
            "Vercel":        "Remove CNAME or redeploy to Vercel claiming this domain.",
            "Fastly":        "Remove CNAME or reconfigure the Fastly CDN service.",
            "Shopify":       "Remove CNAME or reconnect the Shopify storefront.",
            "Zendesk":       "Remove CNAME or reconfigure the Zendesk Help Center.",
            "AWS CloudFront":"Remove CNAME or reconfigure the CloudFront distribution.",
            "Surge.sh":      "Remove CNAME or reclaim via `surge --domain <subdomain>`.",
        }
        return r.get(self.provider,
                     "Remove the dangling DNS record or recreate the referenced cloud resource.")


@dataclass
class Subdomain:
    hostname: str
    dns_data: Optional[DNSData] = None
    source: str = "unknown"
    discovered_at: Optional[datetime] = None


@dataclass
class ScanResult:
    domain: str
    findings: List[Finding]
    stats: Dict[str, Any]
    start_time: datetime
    end_time: datetime
    scan_id: str = ""

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.confidence.score >= 85]
