"""
ai/detector.py - Future AI/ML-based fingerprint detection module

Architecture designed for future integration of:
- ML-based fingerprint detection
- Anomaly detection on HTTP response patterns
- Fuzzy response matching
- Adaptive fingerprint learning
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from core.models import DNSData, HTTPData, FingerprintMatch

logger = logging.getLogger(__name__)


@dataclass
class AIDetectionResult:
    """Result from AI-based detection."""
    is_suspicious: bool = False
    predicted_service: Optional[str] = None
    anomaly_score: float = 0.0  # 0.0 = normal, 1.0 = highly anomalous
    feature_vector: List[float] = field(default_factory=list)
    explanation: str = ""
    confidence: float = 0.0


class FeatureExtractor:
    """
    Extracts numerical features from HTTP/DNS data for ML models.
    
    Feature vector (36 dimensions):
    [0-3]   HTTP status code one-hot (200, 301, 403, 404)
    [4-8]   Response body length buckets
    [9-13]  Title presence and keywords
    [14-18] Header features (Server, X-Powered-By, etc.)
    [19-23] DNS features (CNAME depth, NXDOMAIN, wildcard)
    [24-28] TLS/SSL features
    [29-35] Known-pattern boolean flags
    """

    KNOWN_ERROR_KEYWORDS = [
        "not found", "no such", "does not exist", "404", "error",
        "unavailable", "no app", "unconfigured", "missing", "deleted"
    ]

    PROVIDER_KEYWORDS = {
        "github": ["github", "gh-pages"],
        "heroku": ["heroku", "herokuapp"],
        "aws": ["amazonaws", "s3", "cloudfront"],
        "azure": ["azure", "windows.net"],
        "netlify": ["netlify"],
        "vercel": ["vercel", "now.sh"],
    }

    def extract(self, dns_data: Optional[DNSData], http_data: Optional[HTTPData]) -> List[float]:
        """Extract feature vector from DNS and HTTP data."""
        features = []

        # HTTP status features
        status = http_data.status_code if http_data else 0
        features.extend([
            1.0 if status == 200 else 0.0,
            1.0 if status in (301, 302) else 0.0,
            1.0 if status == 403 else 0.0,
            1.0 if status == 404 else 0.0,
        ])

        # Body length
        body_len = len(http_data.body or "") if http_data else 0
        features.extend([
            1.0 if body_len == 0 else 0.0,
            1.0 if 0 < body_len < 500 else 0.0,
            1.0 if 500 <= body_len < 5000 else 0.0,
            1.0 if 5000 <= body_len < 50000 else 0.0,
            1.0 if body_len >= 50000 else 0.0,
        ])

        # Title features
        title = (http_data.title or "").lower() if http_data else ""
        features.extend([
            1.0 if title else 0.0,
            1.0 if any(kw in title for kw in self.KNOWN_ERROR_KEYWORDS) else 0.0,
            1.0 if "404" in title else 0.0,
            1.0 if len(title) < 20 else 0.0,
            1.0 if len(title) > 100 else 0.0,
        ])

        # Header features
        headers = {k.lower(): v for k, v in (http_data.headers if http_data else {}).items()}
        features.extend([
            1.0 if "server" in headers else 0.0,
            1.0 if "x-powered-by" in headers else 0.0,
            1.0 if "cf-ray" in headers else 0.0,  # Cloudflare
            1.0 if "x-github-request-id" in headers else 0.0,  # GitHub
            1.0 if "x-heroku-error" in headers else 0.0,  # Heroku
        ])

        # DNS features
        features.extend([
            float(len(dns_data.cname_chain)) / 5.0 if dns_data else 0.0,  # normalized
            1.0 if (dns_data and dns_data.is_nxdomain) else 0.0,
            1.0 if (dns_data and dns_data.is_dangling) else 0.0,
            1.0 if (dns_data and dns_data.is_wildcard) else 0.0,
            1.0 if (dns_data and dns_data.has_cname) else 0.0,
        ])

        # TLS features
        features.extend([
            1.0 if (http_data and http_data.is_https) else 0.0,
            1.0 if (http_data and http_data.ssl_valid) else 0.0,
            1.0 if (http_data and http_data.ssl_error) else 0.0,
            0.0,  # Reserved for cert age
            0.0,  # Reserved for cert chain depth
        ])

        # Body keyword pattern flags
        body = (http_data.body or "").lower() if http_data else ""
        for provider, keywords in self.PROVIDER_KEYWORDS.items():
            features.append(1.0 if any(kw in body for kw in keywords) else 0.0)
        # Pad to 7 provider features
        while len(features) < 36:
            features.append(0.0)

        return features[:36]


class AnomalyDetector:
    """
    Placeholder for ML anomaly detection.
    
    Future implementation will use:
    - Isolation Forest for anomaly scoring
    - Response body embeddings (TF-IDF or sentence transformers)
    - CNAME graph analysis
    - Historical baseline comparison
    """

    def __init__(self):
        self._model = None
        self._fitted = False
        self.feature_extractor = FeatureExtractor()

    def is_available(self) -> bool:
        """Check if ML model is available."""
        try:
            import sklearn  # noqa
            return True
        except ImportError:
            return False

    async def score(
        self,
        dns_data: Optional[DNSData],
        http_data: Optional[HTTPData]
    ) -> AIDetectionResult:
        """Score a subdomain for anomalous takeover patterns."""
        features = self.feature_extractor.extract(dns_data, http_data)

        # Heuristic scoring (pre-ML placeholder)
        anomaly_score = self._heuristic_score(features, dns_data, http_data)

        return AIDetectionResult(
            is_suspicious=anomaly_score > 0.6,
            anomaly_score=anomaly_score,
            feature_vector=features,
            explanation=self._explain(anomaly_score, dns_data, http_data),
            confidence=min(anomaly_score * 0.7, 1.0)  # AI confidence is lower than rule-based
        )

    def _heuristic_score(
        self,
        features: List[float],
        dns_data: Optional[DNSData],
        http_data: Optional[HTTPData]
    ) -> float:
        """Simple heuristic scoring until ML model is trained."""
        score = 0.0

        # NXDOMAIN with CNAME = very suspicious
        if dns_data and dns_data.is_nxdomain and dns_data.has_cname:
            score += 0.4

        # 404 response
        if http_data and http_data.status_code == 404:
            score += 0.2

        # Short response body (often error pages)
        body_len = len(http_data.body or "") if http_data else 0
        if 0 < body_len < 2000:
            score += 0.15

        # No title or very short title
        title = (http_data.title or "") if http_data else ""
        if not title or len(title) < 15:
            score += 0.1

        # Dangling CNAME
        if dns_data and dns_data.is_dangling:
            score += 0.25

        return min(score, 1.0)

    def _explain(
        self,
        score: float,
        dns_data: Optional[DNSData],
        http_data: Optional[HTTPData]
    ) -> str:
        reasons = []
        if dns_data and dns_data.is_nxdomain:
            reasons.append("NXDOMAIN response")
        if dns_data and dns_data.is_dangling:
            reasons.append("Dangling CNAME")
        if http_data and http_data.status_code == 404:
            reasons.append("HTTP 404")
        if not reasons:
            return "No significant anomalies detected"
        return f"Anomaly score {score:.2f}: {', '.join(reasons)}"


class AdaptiveFingerprintLearner:
    """
    Placeholder for adaptive fingerprint learning.
    
    Future implementation:
    - Cluster similar 404/error responses
    - Auto-generate fingerprint candidates
    - Submit to community fingerprint database
    - Track false positive patterns
    """

    def __init__(self):
        self._seen_responses: Dict[str, int] = {}

    def observe(self, service: str, body: str, is_true_positive: bool) -> None:
        """Record observation for learning."""
        key = f"{service}:{hash(body[:200])}"
        self._seen_responses[key] = self._seen_responses.get(key, 0) + (1 if is_true_positive else -1)

    def suggest_fingerprints(self) -> List[Dict[str, Any]]:
        """Suggest new fingerprints based on observations."""
        # Future: cluster responses and extract common patterns
        return []
