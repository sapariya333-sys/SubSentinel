"""
modules/enumerator.py - Massively expanded subdomain enumeration engine.

Sources (30 total, all free/no-key unless noted):
  No API key needed (18):
    crtsh, certspotter, hackertarget, rapiddns, alienvault,
    urlscan, threatcrowd, anubis, dnsdumpster, sitedossier,
    wayback, commoncrawl, digitorus, shrewdeye, merklemap,
    leakix, bufferover, riddler

  Optional API keys (12):
    virustotal, shodan, securitytrails, censys, binaryedge,
    fullhunt, chaos, netlas, zoomeye, bevigil, whoisxml, facebook

  External binaries (optional, massive boost):
    subfinder, amass, assetfinder, findomain, knockpy
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import quote

import aiohttp

from core.config import ScanConfig

logger = logging.getLogger(__name__)

TIMEOUT_DEFAULT = aiohttp.ClientTimeout(total=30)
TIMEOUT_SLOW    = aiohttp.ClientTimeout(total=60)

HOSTNAME_RE = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\b'
)


@dataclass
class SourceResult:
    source: str
    subdomains: Set[str] = field(default_factory=set)
    error: Optional[str] = None
    count: int = 0


class SubdomainEnumerator:
    """
    30-source async subdomain enumerator.
    All sources run concurrently. Results are merged and deduplicated.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None

    # ──────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────

    async def enumerate(self, domain: str) -> List[str]:
        """Run all enabled sources concurrently, merge, deduplicate, validate."""
        all_subs: Set[str] = set()
        source_tasks = self._build_tasks(domain)

        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/2.0)"}
        connector = aiohttp.TCPConnector(limit=50, ssl=False)
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            self._session = session
            results = await asyncio.gather(*[t(domain) for t in source_tasks], return_exceptions=True)

        self._session = None

        source_counts: Dict[str, int] = {}
        for r in results:
            if isinstance(r, SourceResult):
                all_subs.update(r.subdomains)
                source_counts[r.source] = len(r.subdomains)
                if r.error:
                    logger.debug(f"[{r.source}] error: {r.error}")
            elif isinstance(r, Exception):
                logger.debug(f"Source task exception: {r}")

        # External binaries (run separately — they manage their own I/O)
        binary_subs = await self._run_binaries(domain)
        all_subs.update(binary_subs)

        validated = self._validate(all_subs, domain)

        # Summary log
        logger.info(f"Enumeration complete: {len(validated)} unique subdomains")
        for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                logger.debug(f"  {src}: {count}")

        return sorted(validated)

    def _build_tasks(self, domain: str):
        """Build list of source coroutine functions."""
        tasks = [
            # ── Always-on (no key needed) ──────────────────────
            self._crtsh,
            self._certspotter,
            self._hackertarget,
            self._rapiddns,
            self._alienvault,
            self._urlscan,
            self._threatcrowd,
            self._anubis,
            self._sitedossier,
            self._wayback,
            self._commoncrawl,
            self._digitorus,
            self._shrewdeye,
            self._merklemap,
            self._bufferover,
            self._riddler,
            self._leakix,
            self._dnsdumpster,
        ]

        # ── Optional API key sources ───────────────────────────
        k = self.config.api_keys

        if k.get("virustotal"):
            tasks.append(self._virustotal)
        if k.get("shodan"):
            tasks.append(self._shodan)
        if k.get("securitytrails"):
            tasks.append(self._securitytrails)
        if k.get("censys_id") and k.get("censys_secret"):
            tasks.append(self._censys)
        if k.get("binaryedge"):
            tasks.append(self._binaryedge)
        if k.get("fullhunt"):
            tasks.append(self._fullhunt)
        if k.get("chaos"):
            tasks.append(self._chaos)
        if k.get("netlas"):
            tasks.append(self._netlas)
        if k.get("zoomeye"):
            tasks.append(self._zoomeye)
        if k.get("bevigil"):
            tasks.append(self._bevigil)
        if k.get("whoisxml"):
            tasks.append(self._whoisxml)
        if k.get("facebook_app_id") and k.get("facebook_app_secret"):
            tasks.append(self._facebook)

        return tasks

    # ──────────────────────────────────────────────────────────
    # Helper: extract subdomains from text
    # ──────────────────────────────────────────────────────────

    def _extract(self, text: str, domain: str) -> Set[str]:
        found = set()
        for m in HOSTNAME_RE.finditer(text):
            h = m.group(1).lower().rstrip(".")
            if h.endswith(f".{domain}") or h == domain:
                found.add(h)
        return found

    def _ok(self, name: str, subs: Set[str]) -> SourceResult:
        return SourceResult(source=name, subdomains=subs, count=len(subs))

    def _err(self, name: str, e) -> SourceResult:
        return SourceResult(source=name, error=str(e))

    # ──────────────────────────────────────────────────────────
    # Sources — No API Key Required
    # ──────────────────────────────────────────────────────────

    async def _crtsh(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        for q in [f"%.{domain}", f"%.%.{domain}"]:
            try:
                url = f"https://crt.sh/?q={quote(q)}&output=json"
                async with self._session.get(url, timeout=TIMEOUT_SLOW) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        for entry in data:
                            for name in entry.get("name_value", "").split("\n"):
                                name = name.strip().lower().lstrip("*.")
                                if name.endswith(f".{domain}") or name == domain:
                                    subs.add(name)
            except Exception as e:
                return self._err("crtsh", e)
        return self._ok("crtsh", subs)

    async def _certspotter(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for entry in data:
                        for name in entry.get("dns_names", []):
                            name = name.lower().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                subs.add(name)
        except Exception as e:
            return self._err("certspotter", e)
        return self._ok("certspotter", subs)

    async def _hackertarget(self, domain: str) -> SourceResult:
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                text = await r.text()
                subs = self._extract(text, domain)
                return self._ok("hackertarget", subs)
        except Exception as e:
            return self._err("hackertarget", e)

    async def _rapiddns(self, domain: str) -> SourceResult:
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                text = await r.text()
                subs = self._extract(text, domain)
                return self._ok("rapiddns", subs)
        except Exception as e:
            return self._err("rapiddns", e)

    async def _alienvault(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        page = 1
        try:
            while page <= 10:
                url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
                       f"{domain}/passive_dns?limit=500&page={page}")
                async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                    if r.status != 200:
                        break
                    data = await r.json(content_type=None)
                    records = data.get("passive_dns", [])
                    if not records:
                        break
                    for rec in records:
                        h = rec.get("hostname", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
                    if not data.get("has_next"):
                        break
                    page += 1
        except Exception as e:
            return self._err("alienvault", e)
        return self._ok("alienvault", subs)

    async def _urlscan(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        h = page.get("domain", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("urlscan", e)
        return self._ok("urlscan", subs)

    async def _threatcrowd(self, domain: str) -> SourceResult:
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    subs = set()
                    for h in data.get("subdomains", []):
                        h = h.lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
                    return self._ok("threatcrowd", subs)
        except Exception as e:
            return self._err("threatcrowd", e)
        return self._ok("threatcrowd", set())

    async def _anubis(self, domain: str) -> SourceResult:
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    subs = {h.lower() for h in data
                            if isinstance(h, str) and (h.endswith(f".{domain}") or h == domain)}
                    return self._ok("anubis", subs)
        except Exception as e:
            return self._err("anubis", e)
        return self._ok("anubis", set())

    async def _sitedossier(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"http://www.sitedossier.com/parentdomain/{domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                text = await r.text()
                subs = self._extract(text, domain)
        except Exception as e:
            return self._err("sitedossier", e)
        return self._ok("sitedossier", subs)

    async def _wayback(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}"
                   f"&output=text&fl=original&collapse=urlkey&limit=100000")
            async with self._session.get(url, timeout=TIMEOUT_SLOW) as r:
                if r.status == 200:
                    text = await r.text()
                    subs = self._extract(text, domain)
        except Exception as e:
            return self._err("wayback", e)
        return self._ok("wayback", subs)

    async def _commoncrawl(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            # Get latest index
            async with self._session.get(
                "https://index.commoncrawl.org/collinfo.json",
                timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status != 200:
                    return self._ok("commoncrawl", subs)
                indexes = await r.json(content_type=None)

            latest = indexes[0].get("cdx-api", "") if indexes else ""
            if not latest:
                return self._ok("commoncrawl", subs)

            url = f"{latest}?url=*.{domain}&output=json&fl=url&limit=50000&collapse=urlkey"
            async with self._session.get(url, timeout=TIMEOUT_SLOW) as r:
                if r.status == 200:
                    text = await r.text()
                    subs = self._extract(text, domain)
        except Exception as e:
            return self._err("commoncrawl", e)
        return self._ok("commoncrawl", subs)

    async def _digitorus(self, domain: str) -> SourceResult:
        try:
            url = f"https://certificatedetails.com/{domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                text = await r.text()
                subs = self._extract(text, domain)
                return self._ok("digitorus", subs)
        except Exception as e:
            return self._err("digitorus", e)

    async def _shrewdeye(self, domain: str) -> SourceResult:
        try:
            url = f"https://shrewdeye.app/domains/{domain}.json"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    subs = set()
                    for entry in data if isinstance(data, list) else []:
                        h = str(entry).lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
                    return self._ok("shrewdeye", subs)
        except Exception as e:
            return self._err("shrewdeye", e)
        return self._ok("shrewdeye", set())

    async def _merklemap(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://api.merklemap.com/search?query={domain}&page=0"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for entry in data.get("results", []):
                        h = entry.get("domain", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("merklemap", e)
        return self._ok("merklemap", subs)

    async def _bufferover(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://tls.bufferover.run/dns?q=.{domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for item in data.get("FDNS_A", []) + data.get("RDNS", []):
                        parts = item.split(",")
                        for p in parts:
                            p = p.strip().lower()
                            if p.endswith(f".{domain}") or p == domain:
                                subs.add(p)
        except Exception as e:
            return self._err("bufferover", e)
        return self._ok("bufferover", subs)

    async def _riddler(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://riddler.io/search/exportcsv?q=pld:{domain}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    text = await r.text()
                    subs = self._extract(text, domain)
        except Exception as e:
            return self._err("riddler", e)
        return self._ok("riddler", subs)

    async def _leakix(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        try:
            url = f"https://leakix.net/domain/{domain}"
            headers = {"Accept": "application/json"}
            async with self._session.get(url, headers=headers, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for entry in data if isinstance(data, list) else []:
                        h = entry.get("subdomain", "").lower()
                        if h and (h.endswith(f".{domain}") or h == domain):
                            subs.add(h)
        except Exception as e:
            return self._err("leakix", e)
        return self._ok("leakix", subs)

    async def _dnsdumpster(self, domain: str) -> SourceResult:
        """DNSDumpster requires a CSRF token — 2-step request."""
        subs: Set[str] = set()
        try:
            base = "https://dnsdumpster.com/"
            async with self._session.get(base, timeout=TIMEOUT_DEFAULT) as r:
                text = await r.text()
                csrf = re.search(r"csrfmiddlewaretoken.*?value=['\"]([^'\"]+)", text)
                token = csrf.group(1) if csrf else ""
                cookies = r.cookies

            if not token:
                return self._ok("dnsdumpster", subs)

            data = {"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"}
            headers = {"Referer": base}
            async with self._session.post(
                base, data=data, headers=headers,
                cookies=cookies, timeout=TIMEOUT_DEFAULT
            ) as r2:
                if r2.status == 200:
                    text2 = await r2.text()
                    subs = self._extract(text2, domain)
        except Exception as e:
            return self._err("dnsdumpster", e)
        return self._ok("dnsdumpster", subs)

    # ──────────────────────────────────────────────────────────
    # Sources — API Key Required
    # ──────────────────────────────────────────────────────────

    async def _virustotal(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("virustotal", "")
        cursor = ""
        try:
            while True:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
                if cursor:
                    url += f"&cursor={cursor}"
                async with self._session.get(
                    url, headers={"x-apikey": key}, timeout=TIMEOUT_DEFAULT
                ) as r:
                    if r.status != 200:
                        break
                    data = await r.json(content_type=None)
                    for item in data.get("data", []):
                        h = item.get("id", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
                    cursor = data.get("meta", {}).get("cursor", "")
                    if not cursor or len(subs) > 5000:
                        break
        except Exception as e:
            return self._err("virustotal", e)
        return self._ok("virustotal", subs)

    async def _shodan(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("shodan", "")
        try:
            url = f"https://api.shodan.io/dns/domain/{domain}?key={key}"
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for sub in data.get("subdomains", []):
                        h = f"{sub}.{domain}".lower()
                        subs.add(h)
        except Exception as e:
            return self._err("shodan", e)
        return self._ok("shodan", subs)

    async def _securitytrails(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("securitytrails", "")
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
            async with self._session.get(
                url, headers={"APIKEY": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for sub in data.get("subdomains", []):
                        subs.add(f"{sub}.{domain}".lower())
        except Exception as e:
            return self._err("securitytrails", e)
        return self._ok("securitytrails", subs)

    async def _censys(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        uid    = self.config.api_keys.get("censys_id", "")
        secret = self.config.api_keys.get("censys_secret", "")
        token  = base64.b64encode(f"{uid}:{secret}".encode()).decode()
        try:
            url  = "https://search.censys.io/api/v2/certificates/search"
            body = {"q": f"parsed.names: {domain}", "per_page": 100, "fields": ["parsed.names"]}
            async with self._session.post(
                url,
                json=body,
                headers={"Authorization": f"Basic {token}"},
                timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for hit in data.get("result", {}).get("hits", []):
                        for name in hit.get("parsed.names", []):
                            name = name.lower().lstrip("*.")
                            if name.endswith(f".{domain}") or name == domain:
                                subs.add(name)
        except Exception as e:
            return self._err("censys", e)
        return self._ok("censys", subs)

    async def _binaryedge(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("binaryedge", "")
        try:
            url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
            async with self._session.get(
                url, headers={"X-Key": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for h in data.get("events", []):
                        h = h.lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("binaryedge", e)
        return self._ok("binaryedge", subs)

    async def _fullhunt(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("fullhunt", "")
        try:
            url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
            async with self._session.get(
                url, headers={"X-API-KEY": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for h in data.get("hosts", []):
                        h = h.lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("fullhunt", e)
        return self._ok("fullhunt", subs)

    async def _chaos(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("chaos", "")
        try:
            url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
            async with self._session.get(
                url, headers={"Authorization": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for sub in data.get("subdomains", []):
                        subs.add(f"{sub}.{domain}".lower())
        except Exception as e:
            return self._err("chaos", e)
        return self._ok("chaos", subs)

    async def _netlas(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("netlas", "")
        try:
            url = f"https://app.netlas.io/api/domains/?q=domain:*.{domain}&source_type=include&start=0&fields=domain"
            async with self._session.get(
                url, headers={"X-API-Key": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for item in data.get("items", []):
                        h = item.get("data", {}).get("domain", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("netlas", e)
        return self._ok("netlas", subs)

    async def _zoomeye(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("zoomeye", "")
        try:
            url = f"https://api.zoomeye.hk/domain/search?q={domain}&type=1&s=1000&page=1"
            async with self._session.get(
                url, headers={"API-KEY": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for item in data.get("list", []):
                        h = item.get("name", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("zoomeye", e)
        return self._ok("zoomeye", subs)

    async def _bevigil(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("bevigil", "")
        try:
            url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
            async with self._session.get(
                url, headers={"X-Access-Token": key}, timeout=TIMEOUT_DEFAULT
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for h in data.get("subdomains", []):
                        h = h.lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("bevigil", e)
        return self._ok("bevigil", subs)

    async def _whoisxml(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        key = self.config.api_keys.get("whoisxml", "")
        try:
            url = (f"https://subdomains.whoisxmlapi.com/api/v1"
                   f"?apiKey={key}&domainName={domain}&outputFormat=JSON")
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for record in data.get("result", {}).get("records", []):
                        h = record.get("domain", "").lower()
                        if h.endswith(f".{domain}") or h == domain:
                            subs.add(h)
        except Exception as e:
            return self._err("whoisxml", e)
        return self._ok("whoisxml", subs)

    async def _facebook(self, domain: str) -> SourceResult:
        subs: Set[str] = set()
        app_id     = self.config.api_keys.get("facebook_app_id", "")
        app_secret = self.config.api_keys.get("facebook_app_secret", "")
        try:
            # Get access token
            token_url = f"https://graph.facebook.com/oauth/access_token?client_id={app_id}&client_secret={app_secret}&grant_type=client_credentials"
            async with self._session.get(token_url, timeout=TIMEOUT_DEFAULT) as r:
                token_data = await r.json(content_type=None)
                access_token = token_data.get("access_token", "")

            if not access_token:
                return self._ok("facebook", subs)

            url = (f"https://graph.facebook.com/certificates"
                   f"?query={domain}&fields=domains&limit=10000&access_token={access_token}")
            async with self._session.get(url, timeout=TIMEOUT_DEFAULT) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for cert in data.get("data", []):
                        for h in cert.get("domains", []):
                            h = h.lower().lstrip("*.")
                            if h.endswith(f".{domain}") or h == domain:
                                subs.add(h)
        except Exception as e:
            return self._err("facebook", e)
        return self._ok("facebook", subs)

    # ──────────────────────────────────────────────────────────
    # External Binaries
    # ──────────────────────────────────────────────────────────

    async def _run_binaries(self, domain: str) -> Set[str]:
        """Run installed external tools concurrently."""
        tools = []
        if self.config.use_subfinder:
            tools.append(self._bin_subfinder(domain))
        if self.config.use_amass:
            tools.append(self._bin_amass(domain))
        if self.config.use_assetfinder:
            tools.append(self._bin_assetfinder(domain))
        if self.config.use_findomain:
            tools.append(self._bin_findomain(domain))

        if not tools:
            return set()

        results = await asyncio.gather(*tools, return_exceptions=True)
        combined: Set[str] = set()
        for r in results:
            if isinstance(r, set):
                combined.update(r)
        return combined

    async def _bin_subfinder(self, domain: str) -> Set[str]:
        return await self._run_binary(
            ["subfinder", "-d", domain, "-silent", "-all", "-timeout", "30"],
            domain, timeout=120
        )

    async def _bin_amass(self, domain: str) -> Set[str]:
        return await self._run_binary(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "10"],
            domain, timeout=300
        )

    async def _bin_assetfinder(self, domain: str) -> Set[str]:
        return await self._run_binary(
            ["assetfinder", "--subs-only", domain],
            domain, timeout=60
        )

    async def _bin_findomain(self, domain: str) -> Set[str]:
        return await self._run_binary(
            ["findomain", "-t", domain, "-q"],
            domain, timeout=60
        )

    async def _run_binary(self, cmd: List[str], domain: str, timeout: int = 120) -> Set[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            subs = set()
            for line in stdout.decode(errors="replace").splitlines():
                h = line.strip().lower()
                if h.endswith(f".{domain}") or h == domain:
                    subs.add(h)
            logger.debug(f"{cmd[0]} found {len(subs)} subdomains")
            return subs
        except FileNotFoundError:
            logger.debug(f"{cmd[0]} not installed — skipping")
            return set()
        except asyncio.TimeoutError:
            logger.debug(f"{cmd[0]} timed out")
            return set()
        except Exception as e:
            logger.debug(f"{cmd[0]} error: {e}")
            return set()

    # ──────────────────────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────────────────────

    VALID_HOST_RE = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )

    def _validate(self, subdomains: Set[str], domain: str) -> List[str]:
        valid = []
        for h in subdomains:
            h = h.strip().lower().rstrip(".")
            if not h:
                continue
            if not (h.endswith(f".{domain}") or h == domain):
                continue
            if len(h) > 253:
                continue
            if not self.VALID_HOST_RE.match(h):
                continue
            valid.append(h)
        return sorted(set(valid))
