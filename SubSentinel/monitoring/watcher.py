"""
monitoring/watcher.py - Continuous monitoring daemon mode
"""

import asyncio
import logging
from datetime import datetime
from typing import Set, List, Optional

from rich.console import Console

from core.config import ScanConfig
from core.models import Finding

console = Console()
logger = logging.getLogger(__name__)


class MonitoringWatcher:
    """Continuous monitoring daemon for subdomain takeover detection."""

    def __init__(self, scanner, config: ScanConfig):
        self.scanner = scanner
        self.config = config
        self.known_findings: Set[str] = set()
        self.known_subdomains: Set[str] = set()
        self.scan_count = 0

    async def run(self) -> None:
        """Main monitoring loop."""
        domain = self.config.domain or "multiple domains"
        console.print(f"\n[bold cyan]👁  Continuous monitoring:[/bold cyan] [green]{domain}[/green]")
        console.print(f"[dim]Interval: {self.config.watch_interval}s | Ctrl+C to stop[/dim]\n")

        while True:
            try:
                await self._run_scan_cycle()
                self.scan_count += 1
                console.print(
                    f"[dim]✓ Scan #{self.scan_count} complete. "
                    f"Next in {self.config.watch_interval}s[/dim]"
                )
                await asyncio.sleep(self.config.watch_interval)
            except asyncio.CancelledError:
                break
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Monitoring cycle error: {e}")
                await asyncio.sleep(60)

    async def _run_scan_cycle(self) -> None:
        """Execute one monitoring scan cycle."""
        console.print(
            f"\n[bold cyan]⟳ Scan #{self.scan_count + 1}[/bold cyan] "
            f"[dim]{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
        )

        domains = self.scanner._get_target_domains()
        current_findings: List[Finding] = []

        for domain in domains:
            subdomains = await self.scanner._enumerate_subdomains(domain)

            # Detect new subdomains
            new_subs = set(subdomains) - self.known_subdomains
            if new_subs:
                console.print(f"  [yellow]+ {len(new_subs)} new subdomains detected[/yellow]")
            self.known_subdomains.update(subdomains)

            # Analyze each subdomain
            for subdomain in subdomains:
                finding = await self.scanner._analyze_subdomain(subdomain)
                if finding:
                    current_findings.append(finding)

        # Detect NEW vulnerabilities (not seen before)
        for finding in current_findings:
            if finding.subdomain not in self.known_findings:
                self.known_findings.add(finding.subdomain)
                await self._handle_new_finding(finding)

        # Detect RESOLVED vulnerabilities
        current_vulnerable = {f.subdomain for f in current_findings}
        newly_resolved = self.known_findings - current_vulnerable
        for subdomain in newly_resolved:
            self.known_findings.discard(subdomain)
            console.print(f"  [green]✓ Resolved: {subdomain}[/green]")

        # Persist to DB
        for finding in current_findings:
            await self.scanner.db.save_finding(finding)

        # Update master findings list and generate report
        self.scanner.findings.extend(
            f for f in current_findings
            if f.subdomain not in {x.subdomain for x in self.scanner.findings}
        )
        if current_findings:
            await self.scanner.report_generator.generate(
                self.scanner.findings,
                self.scanner.scan_stats
            )

    async def _handle_new_finding(self, finding: Finding) -> None:
        """Handle a newly discovered finding."""
        sev = finding.confidence.severity.upper()
        console.print(
            f"  [bold red]🆕 NEW: {finding.subdomain}[/bold red] "
            f"[{sev}] {finding.provider} ({finding.confidence.score}%)"
        )
        await self.scanner.alert_manager.send_alert(finding)
        self.scanner.findings.append(finding)
