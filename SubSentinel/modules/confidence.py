"""
modules/confidence.py - Confidence scoring with false positive reduction
"""

from typing import Optional
from core.models import DNSData, HTTPData, FingerprintMatch, ClaimabilityResult, ConfidenceResult


class ConfidenceScorer:
    """
    Score confidence of subdomain takeover findings.
    
    Scoring matrix:
    ┌──────────────────────────────────────────────────┐
    │ Condition                          │ Points       │
    ├──────────────────────────────────────────────────┤
    │ Confirmed claimable resource       │ +40          │
    │ Matching body fingerprint          │ +25          │
    │ Matching CNAME pattern             │ +20          │
    │ NXDOMAIN with CNAME                │ +15          │
    │ Dangling CNAME                     │ +10          │
    │ 404 status code                    │ +10          │
    │ Provider-specific confidence boost  │ variable     │
    ├──────────────────────────────────────────────────┤
    │ Wildcard DNS response              │ -100 (ignore)│
    │ No CNAME and no fingerprint        │ -50          │
    │ Parked domain indicators           │ -20          │
    │ Wildcard response content          │ -30          │
    └──────────────────────────────────────────────────┘
    """

    # Parked domain indicators (reduce confidence)
    PARKED_INDICATORS = [
        "parking",
        "parked domain",
        "domain for sale",
        "buy this domain",
        "sedoparking",
        "hugedomains",
        "godaddy parking",
        "dan.com",
        "afternic",
        "brandbu",
    ]

    # Generic catch-all indicators (wildcard-like responses)
    GENERIC_INDICATORS = [
        "welcome to nginx",
        "apache2 ubuntu default page",
        "it works",
        "default web site page",
        "iis windows server",
        "congratulations, the site is working",
    ]

    def score(
        self,
        dns_data: Optional[DNSData],
        http_data: Optional[HTTPData],
        fingerprint: Optional[FingerprintMatch],
        claimability: Optional[ClaimabilityResult]
    ) -> ConfidenceResult:
        """Calculate confidence score."""
        score = 0
        reasons = []
        deductions = []

        if not dns_data:
            return ConfidenceResult(score=0, severity="info", reasons=["No DNS data"], deductions=[])

        # Immediate disqualifiers
        if dns_data.is_wildcard:
            return ConfidenceResult(
                score=0,
                severity="info",
                reasons=[],
                deductions=["Wildcard DNS response - not a takeover candidate"]
            )

        # --- POSITIVE SIGNALS ---

        # Confirmed claimable (highest signal)
        if claimability and claimability.is_claimable:
            score += 40
            reasons.append(f"Confirmed claimable: {claimability.evidence}")

        # Body fingerprint match
        if fingerprint and fingerprint.fingerprint:
            score += 25
            reasons.append(f"Body fingerprint matched: '{fingerprint.fingerprint}'")

        # CNAME pattern match
        if fingerprint and fingerprint.cname_pattern:
            score += 20
            reasons.append(f"CNAME points to {fingerprint.service}: {fingerprint.cname_pattern}")

        # DNS conditions
        if dns_data.is_dangling and dns_data.has_cname:
            score += 15
            reasons.append("Dangling CNAME - target does not resolve")

        if dns_data.is_nxdomain and dns_data.has_cname:
            score += 10
            reasons.append("NXDOMAIN with CNAME chain")

        # HTTP status
        if http_data and http_data.status_code == 404:
            score += 10
            reasons.append("Returns HTTP 404")

        # Provider confidence boost
        if fingerprint and fingerprint.confidence_boost:
            score += fingerprint.confidence_boost
            reasons.append(f"Provider-specific confidence boost (+{fingerprint.confidence_boost})")

        # --- NEGATIVE SIGNALS (deductions) ---

        # Parked domain
        if http_data and http_data.body:
            body_lower = http_data.body.lower()
            for indicator in self.PARKED_INDICATORS:
                if indicator in body_lower:
                    score -= 20
                    deduction = f"Parked domain indicator found: '{indicator}'"
                    deductions.append(deduction)
                    break

            # Generic/default page
            for indicator in self.GENERIC_INDICATORS:
                if indicator in body_lower:
                    score -= 30
                    deductions.append(f"Generic default page detected: '{indicator}'")
                    break

        # No CNAME at all with fingerprint mismatch
        if not dns_data.has_cname and not fingerprint:
            score -= 50
            deductions.append("No CNAME and no fingerprint match")

        # Claimability check failed definitively
        if claimability and not claimability.is_claimable and claimability.verification_method not in ("timeout", "error", "generic_check"):
            score -= 20
            deductions.append(f"Claimability verification failed: {claimability.evidence}")

        # --- BOUNDS ---
        score = max(0, min(100, score))

        # Determine severity
        if score >= 85:
            severity = "critical"
        elif score >= 65:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"
        else:
            severity = "info"

        return ConfidenceResult(
            score=score,
            severity=severity,
            reasons=reasons,
            deductions=deductions
        )
