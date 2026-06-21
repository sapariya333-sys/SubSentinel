"""
modules/fingerprinter.py - Service fingerprinting against known takeover-prone providers
"""

import logging
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

import yaml
import aiohttp

from core.config import ScanConfig
from core.models import DNSData, HTTPData, Subdomain, FingerprintMatch

logger = logging.getLogger(__name__)

FINGERPRINT_DB_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
LOCAL_DB_PATH = Path(__file__).parent.parent / "fingerprints" / "fingerprints.yaml"


class ServiceFingerprinter:
    """Fingerprint subdomains against known vulnerable SaaS patterns."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._fingerprints: List[Dict[str, Any]] = []
        self._loaded = False

    async def _ensure_loaded(self):
        """Load fingerprint database."""
        if self._loaded:
            return

        if self.config.update_fingerprints:
            await self._update_fingerprints()

        self._load_local_fingerprints()
        self._loaded = True

    def _load_local_fingerprints(self):
        """Load fingerprints from local YAML file."""
        try:
            if LOCAL_DB_PATH.exists():
                data = yaml.safe_load(LOCAL_DB_PATH.read_text())
                self._fingerprints = data.get("fingerprints", [])
                logger.debug(f"Loaded {len(self._fingerprints)} fingerprints from local DB")
        except Exception as e:
            logger.error(f"Failed to load fingerprints: {e}")

    async def _update_fingerprints(self):
        """Download latest fingerprints from remote source."""
        url = self.config.fingerprint_url or FINGERPRINT_DB_URL
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Save to local cache
                        cache_path = Path(__file__).parent.parent / "fingerprints" / "remote_cache.yaml"
                        cache_path.write_text(content)
                        logger.info("Fingerprints updated from remote source")
        except Exception as e:
            logger.warning(f"Failed to update fingerprints: {e}")

    async def fingerprint(
        self,
        subdomain: Subdomain,
        dns_data: DNSData,
        http_data: Optional[HTTPData]
    ) -> Optional[FingerprintMatch]:
        """Match subdomain against fingerprint database."""
        await self._ensure_loaded()

        for fp in self._fingerprints:
            match = self._check_fingerprint(fp, dns_data, http_data)
            if match:
                return match

        return None

    def _check_fingerprint(
        self,
        fp: Dict[str, Any],
        dns_data: DNSData,
        http_data: Optional[HTTPData]
    ) -> Optional[FingerprintMatch]:
        """Check a single fingerprint against DNS and HTTP data."""
        service = fp.get("service", "Unknown")
        matched_on = None

        # --- CNAME matching ---
        cname_patterns = fp.get("cname_patterns", [])
        cname_matched = False

        if cname_patterns and dns_data.cname_chain:
            for cname in dns_data.cname_chain:
                cname_lower = cname.lower()
                for pattern in cname_patterns:
                    if pattern.lower() in cname_lower:
                        cname_matched = True
                        matched_on = "cname"
                        logger.debug(f"CNAME match: {cname} -> {service}")
                        break
                if cname_matched:
                    break

        # --- Body fingerprinting ---
        body_matched = False
        body_pattern_found = None

        if http_data and http_data.body:
            body_lower = http_data.body.lower()
            for body_fp in fp.get("body_fingerprints", []):
                if body_fp.lower() in body_lower:
                    body_matched = True
                    body_pattern_found = body_fp
                    if not matched_on:
                        matched_on = "body"
                    logger.debug(f"Body match: {body_fp!r} -> {service}")
                    break

        # --- Status code matching ---
        status_matched = False
        if http_data and http_data.status_code:
            vulnerable_codes = fp.get("status_codes", [404])
            if http_data.status_code in vulnerable_codes:
                status_matched = True

        # Decision logic - require at least CNAME or body match
        # Both CNAME + body = highest confidence
        if not cname_matched and not body_matched:
            return None

        # Must have body match OR (CNAME match + NXDOMAIN/dangling)
        if cname_matched and not body_matched:
            # CNAME alone - only flag if DNS is dangling
            if not dns_data.is_dangling and not dns_data.is_nxdomain:
                return None

        return FingerprintMatch(
            service=service,
            cname_pattern=self._get_matched_cname_pattern(fp, dns_data),
            fingerprint=body_pattern_found,
            matched_on=matched_on or "cname",
            vulnerable_status_codes=fp.get("status_codes", [404]),
            takeover_difficulty=fp.get("difficulty", "medium"),
            documentation_url=fp.get("docs"),
            notes=fp.get("notes"),
            confidence_boost=fp.get("confidence_boost", 10)
        )

    def _get_matched_cname_pattern(self, fp: Dict[str, Any], dns_data: DNSData) -> Optional[str]:
        """Find which CNAME pattern matched."""
        for pattern in fp.get("cname_patterns", []):
            for cname in dns_data.cname_chain:
                if pattern.lower() in cname.lower():
                    return pattern
        return None
