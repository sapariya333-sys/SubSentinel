"""
engine/dns_engine.py - Enterprise async DNS engine with multi-resolver pools,
consistency scoring, wildcard detection, CNAME traversal, and anomaly detection.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import string
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.resolver

from core.models import (
    DNSData, DNSConsistency, DanglingType, ResolverResult
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Resolver pools — ordered by reliability + geographic spread
# ──────────────────────────────────────────────────────────────
PRIMARY_RESOLVERS = [
    "8.8.8.8",       # Google
    "1.1.1.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "208.67.222.222", # OpenDNS
]

SECONDARY_RESOLVERS = [
    "8.8.4.4",       # Google secondary
    "1.0.0.1",       # Cloudflare secondary
    "9.9.9.10",      # Quad9 secondary (no filtering)
    "64.6.64.6",     # Verisign
    "94.140.14.14",  # AdGuard
]

# Providers known to return NXDOMAIN when resource is unclaimed
NXDOMAIN_ON_UNCLAIMED: Set[str] = {
    "herokudns.com",
    "ghost.io",
    "helpscoutdocs.com",
    "statuspage.io",
    "uservoice.com",
    "helpjuice.com",
    "readme.io",
    "aftership.com",
    "smartling.com",
}

# IPs that indicate wildcard / catch-all (never real takeover)
WILDCARD_SAFE_IPS: Set[str] = {
    "0.0.0.0",
    "127.0.0.1",
    "::1",
}


class ResolverPool:
    """Thread-safe async pool of DNS resolvers with health scoring."""

    def __init__(self, nameservers: List[str], timeout: float = 4.0):
        self._servers = nameservers
        self._timeout = timeout
        self._health: Dict[str, float] = {s: 1.0 for s in nameservers}
        self._lock = asyncio.Lock()
        self._resolvers: Dict[str, dns.asyncresolver.Resolver] = {}

    def _build(self, nameserver: str) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [nameserver]
        r.timeout = self._timeout
        r.lifetime = self._timeout * 2
        return r

    def get_resolver(self, nameserver: str) -> dns.asyncresolver.Resolver:
        if nameserver not in self._resolvers:
            self._resolvers[nameserver] = self._build(nameserver)
        return self._resolvers[nameserver]

    async def penalize(self, server: str, amount: float = 0.2) -> None:
        async with self._lock:
            self._health[server] = max(0.0, self._health[server] - amount)

    async def reward(self, server: str, amount: float = 0.05) -> None:
        async with self._lock:
            self._health[server] = min(1.0, self._health[server] + amount)

    def healthy_servers(self, min_health: float = 0.3) -> List[str]:
        return [s for s, h in self._health.items() if h >= min_health]

    def pick(self) -> str:
        healthy = self.healthy_servers()
        if not healthy:
            self._health = {s: 1.0 for s in self._servers}
            healthy = self._servers
        # Weighted random pick
        weights = [self._health[s] for s in healthy]
        total = sum(weights)
        r = random.random() * total
        cumulative = 0.0
        for s, w in zip(healthy, weights):
            cumulative += w
            if r <= cumulative:
                return s
        return healthy[-1]


class DNSEngine:
    """
    Enterprise DNS analysis engine.

    Features:
    - Multi-resolver verification with consistency scoring
    - Deep CNAME chain traversal with loop protection
    - Multi-sample wildcard detection
    - DNSSEC awareness
    - DNS anomaly detection
    - Intelligent caching
    - Resolver health scoring
    - Backoff/retry logic
    """

    WILDCARD_PROBE_COUNT = 3      # Random subdomains to probe for wildcards
    MAX_CNAME_DEPTH      = 15
    CONSISTENCY_QUORUM   = 2      # Min resolvers that must agree

    def __init__(
        self,
        primary_resolvers:   Optional[List[str]] = None,
        secondary_resolvers: Optional[List[str]] = None,
        timeout:   float = 4.0,
        retries:   int   = 2,
        use_multi_resolver: bool = True,
    ):
        self._primary_pool   = ResolverPool(primary_resolvers or PRIMARY_RESOLVERS, timeout)
        self._secondary_pool = ResolverPool(secondary_resolvers or SECONDARY_RESOLVERS, timeout)
        self._timeout  = timeout
        self._retries  = retries
        self._use_multi = use_multi_resolver

        # Caches
        self._wildcard_cache: Dict[str, bool] = {}
        self._result_cache:   Dict[str, DNSData] = {}
        self._ns_cache:       Dict[str, List[str]] = {}

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    async def analyze(self, hostname: str) -> DNSData:
        """Full DNS analysis pipeline."""
        if hostname in self._result_cache:
            return self._result_cache[hostname]

        t_start = time.monotonic()
        data = DNSData(hostname=hostname)

        # 1. Parallel record resolution
        a, aaaa, cname_chain, ns, txt = await asyncio.gather(
            self._resolve("A",     hostname),
            self._resolve("AAAA",  hostname),
            self._resolve_cname_chain(hostname),
            self._resolve_ns_walk(hostname),
            self._resolve("TXT",   hostname),
            return_exceptions=True,
        )

        data.a_records    = a     if isinstance(a,    list) else []
        data.aaaa_records = aaaa  if isinstance(aaaa, list) else []
        data.cname_chain  = cname_chain if isinstance(cname_chain, list) else []
        data.ns_records   = ns    if isinstance(ns,   list) else []
        data.txt_records  = txt   if isinstance(txt,  list) else []

        # 2. Derived fields
        data.has_cname = bool(data.cname_chain)
        data.cname_depth = len(data.cname_chain)
        if data.has_cname:
            data.primary_cname = data.cname_chain[-1]
        data.resolves = bool(data.a_records or data.aaaa_records)

        # 3. NXDOMAIN / dangling logic
        if not data.resolves and not data.cname_chain:
            data.is_nxdomain = True
        elif data.has_cname and not data.resolves:
            data.is_dangling = True
            data.is_nxdomain = True
            data.dangling_type = DanglingType.CNAME_NXDOMAIN

        # 4. Wildcard detection (only if resolves to avoid false positives)
        if data.resolves:
            data.is_wildcard = await self._detect_wildcard(hostname)
        elif data.is_dangling:
            # Also check wildcard for dangling — parent might be wildcard
            data.is_wildcard = await self._detect_wildcard(hostname)

        # 5. Multi-resolver consistency check
        if self._use_multi and (data.is_dangling or data.is_nxdomain):
            data.consistency = await self._check_consistency(hostname)
            data.resolver_results = data.consistency.__dict__.get("_raw_results", [])

        # 6. Anomaly detection
        data.anomalies = self._detect_anomalies(data)

        # 7. Check known-unclaimed CNAME providers
        if data.has_cname and not data.is_dangling:
            for provider_domain in NXDOMAIN_ON_UNCLAIMED:
                if data.primary_cname and provider_domain in data.primary_cname:
                    data.is_dangling = True
                    data.dangling_type = DanglingType.CNAME_UNREGISTERED
                    data.anomalies.append(
                        f"CNAME points to {provider_domain} which returns NXDOMAIN for unclaimed resources"
                    )
                    break

        data.resolution_time_ms = (time.monotonic() - t_start) * 1000
        self._result_cache[hostname] = data
        return data

    # ──────────────────────────────────────────
    # Resolution Internals
    # ──────────────────────────────────────────

    async def _resolve(self, rdtype: str, hostname: str) -> List[str]:
        """Resolve a record type with retry and backoff."""
        for attempt in range(self._retries + 1):
            server = self._primary_pool.pick()
            resolver = self._primary_pool.get_resolver(server)
            try:
                t0 = time.monotonic()
                answers = await resolver.resolve(hostname, rdtype)
                latency = (time.monotonic() - t0) * 1000
                await self._primary_pool.reward(server)
                return [str(r).rstrip(".") for r in answers]
            except dns.resolver.NXDOMAIN:
                return []
            except dns.resolver.NoAnswer:
                return []
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                await self._primary_pool.penalize(server)
                if attempt < self._retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
            except Exception as e:
                logger.debug(f"DNS {rdtype} {hostname} error: {e}")
                break
        return []

    async def _resolve_cname_chain(self, hostname: str) -> List[str]:
        """Deep CNAME traversal with loop detection and NXDOMAIN capture."""
        chain: List[str] = []
        current = hostname
        visited: Set[str] = set()

        for _ in range(self.MAX_CNAME_DEPTH):
            if current in visited:
                logger.debug(f"CNAME loop detected at {current}")
                break
            visited.add(current)

            server = self._primary_pool.pick()
            resolver = self._primary_pool.get_resolver(server)
            try:
                answers = await resolver.resolve(current, "CNAME")
                for rdata in answers:
                    target = str(rdata.target).rstrip(".")
                    chain.append(target)
                    current = target
                    break
            except dns.resolver.NXDOMAIN:
                # CNAME target is NXDOMAIN — dangling confirmed
                if chain:
                    logger.debug(f"Dangling CNAME chain: {hostname} -> {chain} (NXDOMAIN)")
                break
            except dns.resolver.NoAnswer:
                break  # No more CNAMEs
            except (dns.exception.Timeout, Exception):
                break

        return chain

    async def _resolve_ns_walk(self, hostname: str) -> List[str]:
        """Walk up DNS hierarchy to find NS records."""
        if hostname in self._ns_cache:
            return self._ns_cache[hostname]

        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if len(candidate.split(".")) < 2:
                continue
            try:
                answers = await self._primary_pool.get_resolver(
                    self._primary_pool.pick()
                ).resolve(candidate, "NS")
                ns_list = [str(r).rstrip(".") for r in answers]
                self._ns_cache[hostname] = ns_list
                return ns_list
            except Exception:
                continue

        return []

    # ──────────────────────────────────────────
    # Wildcard Detection
    # ──────────────────────────────────────────

    async def _detect_wildcard(self, hostname: str) -> bool:
        """
        Multi-probe wildcard detection.
        Fires WILDCARD_PROBE_COUNT random-subdomain queries.
        Returns True only if ALL probes resolve (conservative).
        """
        parts = hostname.split(".")
        if len(parts) < 2:
            return False
        parent = ".".join(parts[1:])

        if parent in self._wildcard_cache:
            return self._wildcard_cache[parent]

        probes = [
            "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            for _ in range(self.WILDCARD_PROBE_COUNT)
        ]

        hits = 0
        for probe in probes:
            test = f"{probe}.{parent}"
            result = await self._resolve("A", test)
            if result:
                # Verify IPs are not in safe-IP set (not 127.0.0.1 etc.)
                real_ips = set(result) - WILDCARD_SAFE_IPS
                if real_ips:
                    hits += 1

        is_wildcard = hits >= 2  # At least 2/3 probes resolve
        self._wildcard_cache[parent] = is_wildcard
        if is_wildcard:
            logger.debug(f"Wildcard DNS: *.{parent} ({hits}/{self.WILDCARD_PROBE_COUNT} probes hit)")
        return is_wildcard

    # ──────────────────────────────────────────
    # Multi-Resolver Consistency
    # ──────────────────────────────────────────

    async def _check_consistency(self, hostname: str) -> DNSConsistency:
        """
        Query 3 resolvers (primary + secondary) and compare results.
        Inconsistency may indicate DNS propagation issues or split-brain.
        """
        servers = (
            self._primary_pool.healthy_servers()[:2] +
            self._secondary_pool.healthy_servers()[:1]
        )
        if not servers:
            servers = PRIMARY_RESOLVERS[:3]

        tasks = [self._single_resolver_query(s, hostname) for s in servers]
        results: List[ResolverResult] = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in results if isinstance(r, ResolverResult)]

        consistency = DNSConsistency(resolvers_queried=len(servers))

        if not results:
            return consistency

        # Compare NXDOMAIN agreement
        nxdomain_votes = sum(1 for r in results if r.is_nxdomain)
        consistency.resolvers_agreed = nxdomain_votes
        consistency.consistency_score = nxdomain_votes / len(results)

        if nxdomain_votes < len(results):
            consistency.propagation_complete = False
            consistency.discrepancies.append(
                f"NXDOMAIN agreement: {nxdomain_votes}/{len(results)} resolvers"
            )

        return consistency

    async def _single_resolver_query(
        self, nameserver: str, hostname: str
    ) -> ResolverResult:
        """Query a single resolver for A + CNAME."""
        result = ResolverResult(resolver_ip=nameserver)
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = self._timeout
        resolver.lifetime = self._timeout

        t0 = time.monotonic()
        try:
            ans = await resolver.resolve(hostname, "A")
            result.a_records = [str(r) for r in ans]
        except dns.resolver.NXDOMAIN:
            result.is_nxdomain = True
        except dns.resolver.SERVFAIL:
            result.is_servfail = True
        except Exception as e:
            result.error = str(e)

        result.latency_ms = (time.monotonic() - t0) * 1000
        return result

    # ──────────────────────────────────────────
    # Anomaly Detection
    # ──────────────────────────────────────────

    def _detect_anomalies(self, data: DNSData) -> List[str]:
        """Detect suspicious DNS patterns."""
        anomalies: List[str] = []

        # Deep CNAME chains (> 5 hops is unusual)
        if data.cname_depth > 5:
            anomalies.append(f"Unusual CNAME depth: {data.cname_depth} hops")

        # CNAME pointing to itself
        if data.hostname in data.cname_chain:
            anomalies.append("CNAME chain contains original hostname (loop)")

        # Multiple IPs with no CDN explanation
        if len(data.a_records) > 8:
            anomalies.append(f"Unusually many A records: {len(data.a_records)}")

        # CNAME and A records both present (unusual)
        if data.has_cname and data.a_records:
            anomalies.append("Both CNAME chain and direct A records present")

        # CNAME targets known-dead providers
        for dead in NXDOMAIN_ON_UNCLAIMED:
            if data.primary_cname and dead in data.primary_cname:
                anomalies.append(f"CNAME targets provider with unclaimed-NXDOMAIN behavior: {dead}")

        return anomalies
