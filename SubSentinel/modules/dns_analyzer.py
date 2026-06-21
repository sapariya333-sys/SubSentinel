"""
modules/dns_analyzer.py - DNS resolution and dangling CNAME detection
"""

import asyncio
import logging
from typing import Optional, List, Set

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from core.config import ScanConfig
from core.models import DNSData

logger = logging.getLogger(__name__)

# Known wildcard indicators
WILDCARD_INDICATORS = {
    "000.000.000.000",
    "127.0.0.1",
    "0.0.0.0",
}

# NXDOMAIN equivalents some providers return
NXDOMAIN_CNAMES = {
    "ghost.io",
    "herokudns.com",
    "statuspage.io",
    "helpscoutdocs.com",
}


class DNSAnalyzer:
    """Async DNS resolution and analysis."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 8
        # Use reliable resolvers
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        # Cache for wildcard detection
        self._wildcard_cache: dict = {}

    async def analyze(self, hostname: str) -> Optional[DNSData]:
        """Full DNS analysis for a hostname."""
        dns_data = DNSData(hostname=hostname)

        # Parallel resolution
        tasks = [
            self._resolve_a(hostname),
            self._resolve_aaaa(hostname),
            self._resolve_cname(hostname),
            self._resolve_ns(hostname),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        a_records, aaaa_records, cname_chain, ns_records = results

        # Process results
        dns_data.a_records = a_records if isinstance(a_records, list) else []
        dns_data.aaaa_records = aaaa_records if isinstance(aaaa_records, list) else []
        dns_data.cname_chain = cname_chain if isinstance(cname_chain, list) else []
        dns_data.ns_records = ns_records if isinstance(ns_records, list) else []

        # Determine primary CNAME
        if dns_data.cname_chain:
            dns_data.has_cname = True
            dns_data.primary_cname = dns_data.cname_chain[-1]

        # Determine resolution status
        dns_data.resolves = bool(dns_data.a_records or dns_data.aaaa_records)

        # Detect NXDOMAIN
        if not dns_data.resolves and not dns_data.cname_chain:
            dns_data.is_nxdomain = True
            return dns_data  # Nothing to check

        # Detect dangling CNAME
        if dns_data.has_cname and not dns_data.resolves:
            dns_data.is_dangling = True
            dns_data.is_nxdomain = True

        # Detect wildcard
        if dns_data.resolves:
            dns_data.is_wildcard = await self._check_wildcard(hostname)

        return dns_data

    async def _resolve_a(self, hostname: str) -> List[str]:
        """Resolve A records."""
        try:
            answers = await self.resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            return []

    async def _resolve_aaaa(self, hostname: str) -> List[str]:
        """Resolve AAAA records."""
        try:
            answers = await self.resolver.resolve(hostname, "AAAA")
            return [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            return []

    async def _resolve_cname(self, hostname: str) -> List[str]:
        """Resolve full CNAME chain."""
        chain = []
        current = hostname
        visited: Set[str] = set()
        max_depth = 10

        while len(chain) < max_depth:
            if current in visited:
                break
            visited.add(current)

            try:
                answers = await self.resolver.resolve(current, "CNAME")
                for rdata in answers:
                    target = str(rdata.target).rstrip(".")
                    chain.append(target)
                    current = target
                    break
            except dns.resolver.NoAnswer:
                break
            except dns.resolver.NXDOMAIN:
                # CNAME target doesn't exist - dangling!
                if chain:
                    logger.debug(f"Dangling CNAME detected: {hostname} -> {chain}")
                break
            except Exception:
                break

        return chain

    async def _resolve_ns(self, hostname: str) -> List[str]:
        """Resolve NS records."""
        try:
            # Try the hostname itself, then parent domain
            parts = hostname.split(".")
            for i in range(len(parts)):
                domain = ".".join(parts[i:])
                if len(domain.split(".")) < 2:
                    continue
                try:
                    answers = await self.resolver.resolve(domain, "NS")
                    return [str(r).rstrip(".") for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
        except Exception:
            pass
        return []

    async def _check_wildcard(self, hostname: str) -> bool:
        """Check if hostname is in a wildcard DNS zone."""
        # Extract parent domain
        parts = hostname.split(".")
        if len(parts) < 2:
            return False

        parent = ".".join(parts[1:])

        if parent in self._wildcard_cache:
            return self._wildcard_cache[parent]

        # Check with a random subdomain that shouldn't exist
        import random
        import string
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        test_host = f"{random_sub}.{parent}"

        try:
            await self.resolver.resolve(test_host, "A")
            # If this resolves, it's a wildcard
            logger.debug(f"Wildcard DNS detected for *.{parent}")
            self._wildcard_cache[parent] = True
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._wildcard_cache[parent] = False
            return False
        except Exception:
            self._wildcard_cache[parent] = False
            return False
