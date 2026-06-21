"""
providers/base.py - Abstract base for all provider-specific takeover modules.

Every provider inherits ProviderBase and implements:
  - fingerprint()     → does this host belong to me?
  - validate()        → is the resource actually unclaimed?
  - false_positive()  → reasons to discard this match
  - poc()             → safe proof-of-concept steps
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from core.models import (
    ClaimabilityResult, DNSData, FingerprintMatch,
    FingerprintSignal, HTTPData, MatchMethod, VerificationStage,
)


@dataclass
class ProviderMatch:
    """Returned by provider.fingerprint() when a match is found."""
    service: str
    confidence: float           # 0.0–1.0 fingerprint confidence
    exploitability: float       # 0.0–1.0 how easy to claim
    signals: List[FingerprintSignal] = field(default_factory=list)
    cname_matched: Optional[str] = None
    body_matched: Optional[str]  = None
    notes: str = ""


class ProviderBase(ABC):
    """Abstract provider detection module."""

    NAME: str = ""
    DIFFICULTY: str = "medium"     # easy / medium / hard
    DOCS_URL: str = ""

    # ── Subclasses fill these ───────────────────────
    CNAME_PATTERNS:    List[str] = []
    BODY_FINGERPRINTS: List[str] = []
    BODY_REGEX:        List[str] = []
    HEADER_PATTERNS:   List[dict] = []
    FALSE_POSITIVE_STRINGS: List[str] = []
    VULNERABLE_STATUS_CODES: List[int] = [404]

    # ──────────────────────────────────────────
    # Core API
    # ──────────────────────────────────────────

    def fingerprint(self, dns_data: DNSData, http_data: Optional[HTTPData]) -> Optional[ProviderMatch]:
        """Return ProviderMatch if this provider is detected, else None."""
        signals: List[FingerprintSignal] = []

        # CNAME matching
        cname_hit = self._match_cname(dns_data, signals)

        # Body matching
        body_hit = self._match_body(http_data, signals)

        # Header matching
        self._match_headers(http_data, signals)

        if not signals:
            return None

        # Gate: CNAME alone needs DNS anomaly
        has_cname = any(s.method == MatchMethod.CNAME_EXACT for s in signals)
        has_body  = any(s.method in (MatchMethod.BODY_EXACT, MatchMethod.BODY_REGEX) for s in signals)

        if has_cname and not has_body:
            if not (dns_data.is_dangling or dns_data.is_nxdomain):
                return None

        if has_body and not has_cname:
            if not (dns_data.has_cname or dns_data.is_nxdomain):
                return None

        # Multi-signal bonus
        if has_cname and has_body:
            signals.append(FingerprintSignal(
                method=MatchMethod.MULTI_SIGNAL,
                pattern="cname+body",
                matched_value="both",
                weight=0.15,
                description="CNAME + body corroborate each other",
            ))

        # False-positive check
        if self._is_false_positive(dns_data, http_data):
            return None

        confidence    = min(1.0, sum(s.weight for s in signals))
        exploitability = self._exploitability_score(dns_data, http_data)

        return ProviderMatch(
            service=self.NAME,
            confidence=confidence,
            exploitability=exploitability,
            signals=signals,
            cname_matched=cname_hit,
            body_matched=body_hit,
            notes=self.DOCS_URL,
        )

    @abstractmethod
    async def validate(self, subdomain: str, dns_data: DNSData) -> ClaimabilityResult:
        """Provider-specific claimability verification. MUST be non-destructive."""

    def false_positive_reasons(self, dns_data: DNSData, http_data: Optional[HTTPData]) -> List[str]:
        """Return list of reasons this might be a false positive."""
        reasons = []
        if dns_data.is_wildcard:
            reasons.append("Wildcard DNS response")
        if http_data and http_data.waf_detected:
            reasons.append(f"WAF detected: {http_data.waf_provider}")
        if http_data and http_data.cdn_provider:
            reasons.append(f"CDN: {http_data.cdn_provider}")
        return reasons

    def poc(self, subdomain: str, dns_data: DNSData) -> str:
        """Generate safe, non-destructive proof-of-concept steps."""
        return f"# Provider: {self.NAME}\n# Docs: {self.DOCS_URL}\n# See README for claiming steps."

    # ──────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────

    def _match_cname(self, dns_data: DNSData, signals: List[FingerprintSignal]) -> Optional[str]:
        for cname in dns_data.cname_chain:
            for pat in self.CNAME_PATTERNS:
                if pat.lower() in cname.lower():
                    signals.append(FingerprintSignal(
                        method=MatchMethod.CNAME_EXACT,
                        pattern=pat,
                        matched_value=cname,
                        weight=0.35,
                        description=f"CNAME '{cname}' contains '{pat}'",
                    ))
                    return cname
        return None

    def _match_body(self, http_data: Optional[HTTPData], signals: List[FingerprintSignal]) -> Optional[str]:
        if not http_data or not http_data.body:
            return None
        body_lower = http_data.body.lower()

        # Exact strings
        for fp in self.BODY_FINGERPRINTS:
            if fp.lower() in body_lower:
                signals.append(FingerprintSignal(
                    method=MatchMethod.BODY_EXACT,
                    pattern=fp,
                    matched_value=fp,
                    weight=0.40,
                    description=f"Body contains '{fp}'",
                ))
                return fp

        # Regex patterns
        import re
        for pat in self.BODY_REGEX:
            m = re.search(pat, http_data.body, re.I | re.S)
            if m:
                signals.append(FingerprintSignal(
                    method=MatchMethod.BODY_REGEX,
                    pattern=pat,
                    matched_value=m.group(0)[:100],
                    weight=0.35,
                    description=f"Body regex matched: {pat}",
                ))
                return m.group(0)[:100]
        return None

    def _match_headers(self, http_data: Optional[HTTPData], signals: List[FingerprintSignal]) -> None:
        if not http_data:
            return
        for hpat in self.HEADER_PATTERNS:
            name  = hpat.get("name", "").lower()
            value = hpat.get("value", "").lower()
            actual = http_data.headers.get(name, "").lower()
            if actual and (not value or value in actual):
                signals.append(FingerprintSignal(
                    method=MatchMethod.HEADER,
                    pattern=f"{name}:{value}",
                    matched_value=actual,
                    weight=0.20,
                    description=f"Header '{name}' matched",
                ))
                return

    def _is_false_positive(self, dns_data: DNSData, http_data: Optional[HTTPData]) -> bool:
        if dns_data.is_wildcard:
            return True
        body = (http_data.body or "").lower() if http_data else ""
        for fp_str in self.FALSE_POSITIVE_STRINGS:
            if fp_str.lower() in body:
                return True
        return False

    def _exploitability_score(self, dns_data: DNSData, http_data: Optional[HTTPData]) -> float:
        score = 0.5  # base
        if dns_data.is_dangling:      score += 0.2
        if dns_data.is_nxdomain:      score += 0.1
        if http_data and http_data.status_code == 404: score += 0.1
        if self.DIFFICULTY == "easy":   score += 0.1
        if self.DIFFICULTY == "hard":   score -= 0.2
        return min(1.0, max(0.0, score))
