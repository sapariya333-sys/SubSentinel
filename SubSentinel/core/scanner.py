"""
core/scanner.py - Enterprise scan orchestrator.
Wires all v4 components through the 8-stage pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TextColumn, TimeElapsedColumn, MofNCompleteColumn)
from rich.table import Table
from rich.text import Text
from rich.rule import Rule

from alerts.manager import AlertManager
from core.config import ScanConfig
from core.models import Finding, ScanResult
from engine.confidence_engine import ConfidenceEngine
from engine.dns_engine import DNSEngine
from engine.http_engine import HTTPEngine
from modules.enumerator import SubdomainEnumerator
from modules.evidence import EvidenceCollector
from modules.screenshot import ScreenshotEngine
from monitoring.watcher import MonitoringWatcher
from pipeline.stages import DetectionPipeline
from reports.generator import ReportGenerator
from utils.database import Database
from utils.logger import setup_logger

console = Console()
logger  = logging.getLogger(__name__)

SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
}


class SubSentinelScanner:
    """v4 enterprise scan orchestrator."""

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.scan_id  = str(uuid.uuid4())[:8].upper()
        self.logger   = setup_logger("SubSentinel", config.verbose, config.debug)
        self.start_time = datetime.utcnow()

        # Engines
        self.dns_engine  = DNSEngine(timeout=config.timeout, retries=config.retries)
        self.http_engine = HTTPEngine(
            timeout=config.timeout, retries=config.retries,
            proxy=config.proxy, user_agent=config.user_agent,
            delay=config.delay, rotate_ua=True,
        )
        self.confidence_engine = ConfidenceEngine()

        # Support
        self.enumerator    = SubdomainEnumerator(config)
        self.screenshot_eng = ScreenshotEngine(config)
        self.evidence_coll = EvidenceCollector(config)
        self.alert_manager = AlertManager(config)
        self.report_gen    = ReportGenerator(config)
        self.db            = Database(config.db_path)

        # Pipeline
        self.pipeline = DetectionPipeline(
            dns_engine=self.dns_engine,
            http_engine=self.http_engine,
            confidence_eng=self.confidence_engine,
            min_confidence=config.min_confidence,
            screenshot_fn=self.screenshot_eng.capture,
            evidence_fn=self.evidence_coll.collect,
        )

        # Concurrency
        self.semaphore = asyncio.Semaphore(config.threads)

        # Results
        self.findings: List[Finding] = []
        self.stats: Dict[str, int] = {
            "total": 0, "processed": 0, "fingerprinted": 0,
            "vulnerable": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        }

    # ──────────────────────────────────────────────────────────
    # Entry points
    # ──────────────────────────────────────────────────────────

    async def run(self) -> ScanResult:
        await self.db.initialize()

        if self.config.watch_mode:
            watcher = MonitoringWatcher(self, self.config)
            await watcher.run()
        else:
            await self._single_scan()

        return ScanResult(
            domain=self.config.domain or "multiple",
            findings=self.findings,
            stats=self.stats,
            start_time=self.start_time,
            end_time=datetime.utcnow(),
            scan_id=self.scan_id,
        )

    # ──────────────────────────────────────────────────────────
    # Scan flow
    # ──────────────────────────────────────────────────────────

    async def _single_scan(self) -> None:
        for domain in self._get_targets():
            console.print(Rule(f"[bold red]▸ {domain}[/bold red]", style="red"))
            await self._scan_domain(domain)
        await self._finalize()

    def _get_targets(self) -> List[str]:
        targets = []
        if self.config.domain:
            targets.append(self.config.domain)
        if self.config.domain_list:
            p = Path(self.config.domain_list)
            if p.exists():
                targets.extend(
                    l.strip() for l in p.read_text().splitlines()
                    if l.strip() and not l.startswith("#")
                )
        return list(dict.fromkeys(targets))

    async def _scan_domain(self, domain: str) -> None:
        subdomains = await self._enumerate(domain)
        self.stats["total"] += len(subdomains)
        console.print(f"  [dim]↳ {len(subdomains)} subdomains queued[/dim]")

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold red]{task.description}[/bold red]"),
            BarColumn(bar_width=40, style="red", complete_style="bold red"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Scanning", total=len(subdomains))
            coros = [self._process(sub, progress, task) for sub in subdomains]
            await asyncio.gather(*coros, return_exceptions=True)

    async def _enumerate(self, domain: str) -> List[str]:
        if self.config.subdomains_file:
            p = Path(self.config.subdomains_file)
            subs = [l.strip() for l in p.read_text().splitlines() if l.strip()]
            console.print(f"  [green]✓[/green] Loaded {len(subs)} subdomains from file")
            return subs

        console.print(f"  [yellow]⟳[/yellow] Enumerating subdomains (30 sources)...")
        subs = await self.enumerator.enumerate(domain)
        console.print(f"  [green]✓[/green] {len(subs)} unique subdomains discovered")
        return subs

    # ──────────────────────────────────────────────────────────
    # Per-subdomain
    # ──────────────────────────────────────────────────────────

    async def _process(
        self, subdomain: str,
        progress: Optional[Progress] = None,
        task_id = None,
    ) -> Optional[Finding]:
        async with self.semaphore:
            try:
                finding = await self.pipeline.run(subdomain)
                if finding:
                    self.findings.append(finding)
                    self.stats["vulnerable"] += 1
                    sev = finding.confidence.severity
                    self.stats[sev] = self.stats.get(sev, 0) + 1
                    await self.db.save_finding(finding)
                    await self._print_finding(finding)
                    await self.alert_manager.send_alert(finding)
                self.stats["processed"] += 1
                return finding
            except Exception as e:
                logger.debug(f"Process error [{subdomain}]: {e}")
                return None
            finally:
                if progress and task_id is not None:
                    progress.advance(task_id)

    async def _print_finding(self, f: Finding) -> None:
        lbl   = f.confidence.label
        style = SEV_STYLE.get(lbl, "white")
        likelihood = f.confidence.takeover_likelihood
        verified = "✅ CONFIRMED" if f.is_verified else ("🔍 SUSPECTED" if f.soft_validation else "📡 DETECTED")
        dims  = f.confidence.dimensions

        console.print(
            f"  [{style}][{lbl}][/{style}] {verified}  "
            f"[bold]{f.subdomain}[/bold]  "
            f"[cyan]→ {f.provider}[/cyan]"
        )
        if dims:
            console.print(
                f"    [dim]fp={dims.fingerprint:.2f}  "
                f"exp={dims.exposure:.2f}  "
                f"claim={dims.claimability:.2f}  "
                f"exploit={dims.exploitability:.2f}  "
                f"composite={dims.composite:.0%}  "
                f"stage={f.verification_stage.value}[/dim]"
            )
        # Show FP-kill reason if present
        sv = f.soft_validation
        hv = f.hard_validation
        if hv and hv.evidence:
            console.print(f"    [dim]evidence: {hv.evidence[0]}[/dim]")

    async def _finalize(self) -> None:
        await self.report_gen.generate(self.findings, self.stats)
        self._print_summary()

    # ──────────────────────────────────────────────────────────
    # Summary output
    # ──────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        duration = int((datetime.utcnow() - self.start_time).total_seconds())
        console.print()
        console.print(Rule("[bold red]SCAN COMPLETE[/bold red]", style="red"))

        console.print(Panel(
            f"[bold]Scan ID:[/bold]     {self.scan_id}\n"
            f"[bold]Duration:[/bold]    {duration}s\n"
            f"[bold]Subdomains:[/bold]  {self.stats['total']} queued  /  {self.stats['processed']} processed\n"
            f"[bold]Findings:[/bold]    "
            f"[bold red]{self.stats.get('critical',0)} CRITICAL[/bold red]  "
            f"[red]{self.stats.get('high',0)} HIGH[/red]  "
            f"[yellow]{self.stats.get('medium',0)} MEDIUM[/yellow]  "
            f"[blue]{self.stats.get('low',0)} LOW[/blue]",
            title="[bold red]SubSentinel v4[/bold red]",
            border_style="red",
            padding=(0, 2),
        ))

        if not self.findings:
            console.print("\n[green]✓ No takeover vulnerabilities detected.[/green]")
            return

        # Findings table
        t = Table(
            title="[bold red]Takeover Findings[/bold red]",
            border_style="red",
            header_style="bold red",
            show_lines=True,
        )
        t.add_column("Subdomain",   style="cyan",   no_wrap=True)
        t.add_column("Provider",    style="green",  min_width=12)
        t.add_column("Severity",    justify="center", min_width=10)
        t.add_column("Confidence",  justify="right",  min_width=10)
        t.add_column("Likelihood",  justify="center", min_width=12)
        t.add_column("FP Risk",     justify="center", min_width=9)
        t.add_column("Stage",       style="dim",      min_width=14)

        for f in sorted(self.findings, key=lambda x: x.confidence.score, reverse=True):
            lbl   = f.confidence.label
            style = SEV_STYLE.get(lbl, "white")
            clm   = ("✅" if f.claimability and f.claimability.is_claimable
                     else "❓" if not f.claimability else "✗")
            fp_risk = f.confidence.false_positive_risk
            fp_color = {"low": "green", "medium": "yellow", "high": "red"}.get(fp_risk, "dim")
            t.add_row(
                f.subdomain,
                f.provider,
                f"[{style}]{lbl}[/{style}]",
                f"[{style}]{f.confidence.score}%[/{style}]",
                f.confidence.takeover_likelihood,
                f"[{fp_color}]{fp_risk}[/{fp_color}]",
                f.verification_stage.value,
            )
        console.print()
        console.print(t)
