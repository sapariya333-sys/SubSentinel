"""
engine/confidence_engine.py - 4-dimensional confidence engine.

Dimensions (geometric mean — ALL must be reasonable):
  fingerprint:    How well was the provider detected?
  exposure:       Is the DNS/HTTP state genuinely anomalous?
  claimability:   Is the resource actually unclaimed? (hard validation)
  exploitability: How easy is it to exploit?

The geometric mean ensures a single weak dimension tanks the score.
This prevents: "strong fingerprint + live application = CRITICAL".
"""

from __future__ import annotations

import re
from typing import List, Optional

from core.models import (
    ClaimabilityResult, ConfidenceDimensions, ConfidenceResult,
    DNSData, FingerprintMatch, HardValidationResult, HTTPData,
    Signal, SoftValidationResult, VerificationStage, ValidationVerdict,
)

# ─────────────────────────────────────────────────────────────
# False-positive pattern libraries (used by pipeline too)
# ─────────────────────────────────────────────────────────────

PARKED_PATTERNS = re.compile(
    r'(sedoparking|parking|domain\s+for\s+sale|buy\s+this\s+domain|'
    r'hugedomains|godaddy\s+parking|afternic|dan\.com|brandbu|'
    r'undeveloped|sedo\.com|namecheap\s+parking|domain\s+is\s+for\s+sale)',
    re.I
)

GENERIC_PAGE_PATTERNS = re.compile(
    r'(welcome\s+to\s+nginx|apache2?\s+ubuntu\s+default|'
    r'it\s+works!|iis windows server|default\s+web\s+site|'
    r'congratulations.*site.*working|test\s+page\s+for\s+the\s+apache|'
    r'placeholder\s+page)',
    re.I
)

WILDCARD_BODY_PATTERNS = re.compile(
    r'(cPanel|Plesk|DirectAdmin|cpanel\.net|CWP\s+Panel)',
    re.I
)


class ConfidenceEngine:
    """
    4-dimensional confidence scoring.

    Key design principles:
    1. Geometric mean — all dimensions must be healthy for a high score
    2. Hard validation result (or its absence) dominates claimability
    3. Live-app detection in soft validation forces score to near-zero
    4. CONFIRMED verdict is the only path to CRITICAL
    """

    def score(
        self,
        dns_data:     Optional[DNSData],
        http_data:    Optional[HTTPData],
        fingerprint:  Optional[FingerprintMatch],
        claimability: Optional[ClaimabilityResult],
        soft_result:  Optional[SoftValidationResult] = None,
        hard_result:  Optional[HardValidationResult] = None,
    ) -> ConfidenceResult:

        reasons:    List[str] = []
        deductions: List[str] = []

        if not dns_data:
            return self._zero("No DNS data")

        if dns_data.is_wildcard:
            return self._zero("Wildcard DNS")

        # If soft validation found a live app, this is a false positive
        if soft_result and soft_result.is_definitively_live:
            return self._zero(
                f"Live app detected: {', '.join(soft_result.live_indicators[:2])}"
            )

        # ── Dimension 1: Fingerprint confidence ───────────────
        fp_conf = self._fingerprint_dim(fingerprint, dns_data, reasons, deductions)

        # ── Dimension 2: Exposure confidence ─────────────────
        exp_conf = self._exposure_dim(dns_data, http_data, reasons, deductions)

        # ── Dimension 3: Claimability confidence ─────────────
        claim_conf = self._claimability_dim(
            claimability, hard_result, reasons, deductions
        )

        # ── Dimension 4: Exploitability ───────────────────────
        exploit_conf = self._exploitability_dim(
            fingerprint, dns_data, hard_result, reasons
        )

        # ── Composite (geometric mean) ─────────────────────────
        dims = ConfidenceDimensions(
            fingerprint=fp_conf,
            exposure=exp_conf,
            claimability=claim_conf,
            exploitability=exploit_conf,
        )
        score = dims.score   # geometric mean × 100

        # ── Severity ──────────────────────────────────────────
        # CRITICAL requires CONFIRMED hard validation — never from fingerprint alone
        is_confirmed = (
            hard_result is not None
            and hard_result.is_confirmed_vulnerable
            and hard_result.custom_domain_shows_unclaimed
        )

        if is_confirmed and score >= 75:
            severity = "critical"
        elif score >= 65:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"
        else:
            severity = "info"

        # ── Takeover likelihood ────────────────────────────────
        if is_confirmed:
            likelihood = "confirmed"
        elif score >= 60 and claim_conf > 0.5:
            likelihood = "likely"
        elif score >= 35:
            likelihood = "possible"
        else:
            likelihood = "unlikely"

        # ── False positive risk ────────────────────────────────
        if is_confirmed:
            fp_risk = "low"
        elif soft_result and soft_result.live_indicators:
            fp_risk = "high"   # We saw live signals but not definitive
        elif hard_result and hard_result.verdict == ValidationVerdict.LIVE:
            fp_risk = "high"
        elif claim_conf < 0.3:
            fp_risk = "high"
        elif score >= 50:
            fp_risk = "medium"
        else:
            fp_risk = "high"

        # ── Verification stage ─────────────────────────────────
        if is_confirmed:
            stage = VerificationStage.CONFIRMED
        elif hard_result and hard_result.verdict != ValidationVerdict.NOT_CHECKED:
            stage = VerificationStage.API_VERIFIED
        elif soft_result:
            stage = VerificationStage.SUSPECTED
        elif fingerprint:
            stage = VerificationStage.FINGERPRINTED
        elif http_data:
            stage = VerificationStage.DNS_HTTP
        else:
            stage = VerificationStage.DNS_ONLY

        return ConfidenceResult(
            score=min(100, max(0, score)),
            severity=severity,
            dimensions=dims,
            signals=[],        # signals now live in reasoning
            reasons=reasons,
            deductions=deductions,
            verification_stage=stage,
            false_positive_risk=fp_risk,
            takeover_likelihood=likelihood,
        )

    # ─────────────────────────────────────────────────────────
    # Dimension calculators
    # ─────────────────────────────────────────────────────────

    def _fingerprint_dim(
        self,
        fp:         Optional[FingerprintMatch],
        dns:        DNSData,
        reasons:    List[str],
        deductions: List[str],
    ) -> float:
        """How well was the provider fingerprinted?"""
        if not fp:
            # Dangling CNAME with no provider match → partial credit
            if dns.is_dangling:
                deductions.append("No provider match — dangling CNAME only")
                return 0.25
            return 0.0

        score = fp.match_score   # 0.0–1.0 from provider base

        if fp.cname_pattern and fp.fingerprint:
            score = min(1.0, score + 0.15)   # bonus for multi-signal
            reasons.append(f"Multi-signal match: CNAME + body ({fp.service})")
        elif fp.cname_pattern:
            reasons.append(f"CNAME matched {fp.service}: {fp.cname_pattern}")
        elif fp.fingerprint:
            reasons.append(f"Body fingerprint matched: '{fp.fingerprint}'")

        return round(min(1.0, score), 3)

    def _exposure_dim(
        self,
        dns:        DNSData,
        http:       Optional[HTTPData],
        reasons:    List[str],
        deductions: List[str],
    ) -> float:
        """Is the DNS/HTTP state genuinely anomalous?"""
        score = 0.0

        if dns.is_dangling and dns.has_cname:
            score += 0.45
            reasons.append(f"Dangling CNAME: {dns.primary_cname}")

        if dns.is_nxdomain and dns.has_cname:
            score += 0.25
            reasons.append("NXDOMAIN with CNAME chain")

        if http:
            if http.status_code == 404:
                score += 0.15
            if http.has_error_page:
                score += 0.10
                reasons.append(f"Error page type: {http.error_page_type}")
            if http.tls_info and http.tls_info.cn_mismatch:
                score += 0.05
                reasons.append("TLS CN mismatch on custom domain")

        # Multi-resolver consistency increases exposure confidence
        if dns.consistency and dns.consistency.consistency_score >= 0.8:
            score += 0.10
            reasons.append(
                f"NXDOMAIN confirmed by {dns.consistency.resolvers_queried} resolvers "
                f"({dns.consistency.consistency_score:.0%} agreement)"
            )

        # Deductions
        if http and http.waf_detected:
            score -= 0.10
            deductions.append(f"WAF detected ({http.waf_provider}) — may be blocking errors")

        if dns.consistency and dns.consistency.consistency_score < 0.5:
            score -= 0.15
            deductions.append("DNS inconsistent across resolvers — may be propagation issue")

        return round(min(1.0, max(0.0, score)), 3)

    def _claimability_dim(
        self,
        claimability: Optional[ClaimabilityResult],
        hard_result:  Optional[HardValidationResult],
        reasons:      List[str],
        deductions:   List[str],
    ) -> float:
        """Is the resource actually unclaimed and takeable?"""

        # Hard validation is the gold standard
        if hard_result:
            if hard_result.is_confirmed_vulnerable and hard_result.custom_domain_shows_unclaimed:
                reasons.append(
                    f"CONFIRMED: custom domain shows unclaimed state "
                    f"(confidence={hard_result.confidence:.0%})"
                )
                return round(min(1.0, hard_result.confidence), 3)

            if hard_result.verdict == ValidationVerdict.LIVE:
                deductions.append("Hard validation: custom domain is LIVE — not claimable")
                return 0.0

            if hard_result.raw_endpoint_shows_unclaimed and not hard_result.custom_domain_shows_unclaimed:
                deductions.append(
                    "Raw provider endpoint shows error but custom domain is live — "
                    "this is a FALSE POSITIVE pattern (e.g. Heroku with active custom domain)"
                )
                return 0.05

            if hard_result.verdict == ValidationVerdict.INCONCLUSIVE:
                return 0.25

        # Legacy claimability fallback
        if claimability:
            if claimability.is_claimable:
                reasons.append(f"Claimability: {claimability.evidence}")
                return round(min(0.7, claimability.confidence), 3)
            if claimability.verification_method not in ("timeout", "error"):
                deductions.append(f"Not claimable: {claimability.evidence}")
                return 0.05

        # No validation performed → low but non-zero
        return 0.15

    def _exploitability_dim(
        self,
        fp:          Optional[FingerprintMatch],
        dns:         DNSData,
        hard_result: Optional[HardValidationResult],
        reasons:     List[str],
    ) -> float:
        """How feasible is actual exploitation?"""
        score = 0.3   # base

        if hard_result and hard_result.is_confirmed_vulnerable:
            score += 0.4
            if hard_result.safe_poc:
                score += 0.1
                reasons.append(f"Safe PoC available: {hard_result.safe_poc[:60]}...")

        if fp:
            if fp.takeover_difficulty == "easy":
                score += 0.2
            elif fp.takeover_difficulty == "hard":
                score -= 0.2

        if dns.is_dangling:
            score += 0.1

        return round(min(1.0, max(0.0, score)), 3)

    # ─────────────────────────────────────────────────────────

    def _zero(self, reason: str) -> ConfidenceResult:
        return ConfidenceResult(
            score=0, severity="info",
            dimensions=ConfidenceDimensions(),
            deductions=[reason],
            takeover_likelihood="unlikely",
            false_positive_risk="high",
        )
