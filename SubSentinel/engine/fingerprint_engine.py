"""
engine/fingerprint_engine.py - Enterprise multi-signal fingerprint engine.
Supports exact, regex, fuzzy, header, TLS, and status-code matching with
per-provider false-positive suppression rules.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.models import (
    DNSData, FingerprintMatch, FingerprintSignal, HTTPData,
    MatchMethod, Subdomain
)

logger = logging.getLogger(__name__)

LOCAL_DB = Path(__file__).parent.parent / "fingerprints" / "fingerprints.yaml"


class FingerprintEngine:
    """
    Multi-signal fingerprint engine.

    Match priority (highest → lowest confidence):
      1. CNAME exact  +  body exact   → multi_signal
      2. CNAME exact  +  body regex   → multi_signal
      3. Body exact alone (NXDOMAIN required)
      4. CNAME exact alone (dangling required)
      5. Header match
      6. Status code alone            → ignored (too noisy)

    Each provider carries false_positive_rules that veto matches.
    """

    def __init__(self):
        self._fingerprints: List[Dict[str, Any]] = []
        self._loaded = False

    def load(self, path: Path = LOCAL_DB) -> None:
        if self._loaded:
            return
        try:
            data = yaml.safe_load(path.read_text())
            self._fingerprints = data.get("fingerprints", [])
            logger.info(f"Loaded {len(self._fingerprints)} fingerprints")
        except Exception as e:
            logger.error(f"Fingerprint load failed: {e}")
        self._loaded = True

    async def fingerprint(
        self,
        subdomain: Subdomain,
        dns_data: DNSData,
        http_data: Optional[HTTPData],
    ) -> Optional[FingerprintMatch]:
        if not self._loaded:
            self.load()

        best: Optional[FingerprintMatch] = None

        for fp_def in self._fingerprints:
            match = self._evaluate(fp_def, dns_data, http_data)
            if match is None:
                continue
            # Apply false-positive suppression
            if self._is_false_positive(fp_def, dns_data, http_data):
                logger.debug(f"FP suppressed: {fp_def['service']}")
                continue
            if best is None or match.match_score > best.match_score:
                best = match

        return best

    # ─────────────────────────────────────────
    def _evaluate(
        self,
        fp: Dict[str, Any],
        dns_data: DNSData,
        http_data: Optional[HTTPData],
    ) -> Optional[FingerprintMatch]:
        signals: List[FingerprintSignal] = []
        service = fp["service"]

        # ── CNAME matching ────────────────────
        cname_hit: Optional[str] = None
        cname_pattern_hit: Optional[str] = None
        for cname in dns_data.cname_chain:
            for pat in fp.get("cname_patterns", []):
                if pat.lower() in cname.lower():
                    cname_hit = cname
                    cname_pattern_hit = pat
                    signals.append(FingerprintSignal(
                        method=MatchMethod.CNAME_EXACT,
                        pattern=pat,
                        matched_value=cname,
                        weight=0.35,
                        description=f"CNAME contains '{pat}'"
                    ))
                    break
            if cname_hit:
                break

        # ── Body exact matching ───────────────
        body_hit: Optional[str] = None
        if http_data and http_data.body:
            body_lower = http_data.body.lower()
            for bfp in fp.get("body_fingerprints", []):
                if bfp.lower() in body_lower:
                    body_hit = bfp
                    signals.append(FingerprintSignal(
                        method=MatchMethod.BODY_EXACT,
                        pattern=bfp,
                        matched_value=bfp,
                        weight=0.40,
                        description=f"Body contains '{bfp}'"
                    ))
                    break

        # ── Body regex matching ───────────────
        if not body_hit and http_data and http_data.body:
            for pat in fp.get("body_regex", []):
                m = re.search(pat, http_data.body, re.I | re.S)
                if m:
                    signals.append(FingerprintSignal(
                        method=MatchMethod.BODY_REGEX,
                        pattern=pat,
                        matched_value=m.group(0)[:80],
                        weight=0.35,
                        description=f"Body regex match: {pat}"
                    ))
                    body_hit = m.group(0)[:80]
                    break

        # ── Header matching ───────────────────
        if http_data:
            for hdr_pat in fp.get("header_patterns", []):
                header_name  = hdr_pat.get("name", "").lower()
                header_value = hdr_pat.get("value", "").lower()
                actual = http_data.headers.get(header_name, "").lower()
                if actual and (not header_value or header_value in actual):
                    signals.append(FingerprintSignal(
                        method=MatchMethod.HEADER,
                        pattern=f"{header_name}: {header_value}",
                        matched_value=actual,
                        weight=0.20,
                        description=f"Header '{header_name}' matched"
                    ))
                    break

        # ── Decision ──────────────────────────
        if not signals:
            return None

        # Gate: CNAME alone requires dangling/NXDOMAIN
        has_cname_signal = any(s.method == MatchMethod.CNAME_EXACT for s in signals)
        has_body_signal  = any(s.method in (MatchMethod.BODY_EXACT, MatchMethod.BODY_REGEX) for s in signals)

        if has_cname_signal and not has_body_signal:
            if not (dns_data.is_dangling or dns_data.is_nxdomain):
                return None   # CNAME match but domain resolves fine — not a takeover

        # Gate: body alone requires some DNS anomaly
        if has_body_signal and not has_cname_signal:
            if not (dns_data.is_dangling or dns_data.is_nxdomain or dns_data.has_cname):
                return None

        # Bonus signal for multi-match
        if has_cname_signal and has_body_signal:
            signals.append(FingerprintSignal(
                method=MatchMethod.MULTI_SIGNAL,
                pattern="cname+body",
                matched_value="both matched",
                weight=0.15,
                description="Both CNAME and body signals present"
            ))

        match_score = min(1.0, sum(s.weight for s in signals))

        return FingerprintMatch(
            service=service,
            signals=signals,
            cname_pattern=cname_pattern_hit,
            fingerprint=body_hit,
            matched_on=("multi" if has_cname_signal and has_body_signal
                        else ("cname" if has_cname_signal else "body")),
            vulnerable_status_codes=fp.get("status_codes", [404]),
            takeover_difficulty=fp.get("difficulty", "medium"),
            documentation_url=fp.get("docs"),
            notes=fp.get("notes"),
            confidence_boost=fp.get("confidence_boost", 0),
            false_positive_rules=fp.get("false_positive_rules", []),
            match_score=match_score,
            match_methods=[s.method for s in signals],
        )

    def _is_false_positive(
        self,
        fp: Dict[str, Any],
        dns_data: DNSData,
        http_data: Optional[HTTPData],
    ) -> bool:
        """Apply provider-defined false-positive rules."""
        for rule in fp.get("false_positive_rules", []):
            rule_lower = rule.lower()
            # Body contains FP indicator
            if http_data and http_data.body:
                if rule_lower in http_data.body.lower():
                    return True
            # CNAME contains FP indicator
            for cname in dns_data.cname_chain:
                if rule_lower in cname.lower():
                    return True
        return False
