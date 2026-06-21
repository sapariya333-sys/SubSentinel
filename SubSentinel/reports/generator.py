"""
reports/generator.py - Multi-format report generation
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from core.config import ScanConfig
from core.models import Finding

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate reports in multiple formats."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, findings: List[Finding], stats: Dict[str, Any]) -> None:
        """Generate all enabled report formats."""
        if not findings and not self.config.json_output:
            logger.info("No findings to report")
            return

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain_slug = (self.config.domain or "scan").replace(".", "_")

        # Always generate JSON (source of truth)
        json_path = self.output_dir / f"subsentinel_{domain_slug}_{timestamp}.json"
        self._generate_json(findings, stats, json_path)
        logger.info(f"JSON report: {json_path}")

        if self.config.html_output:
            html_path = self.output_dir / f"subsentinel_{domain_slug}_{timestamp}.html"
            self._generate_html(findings, stats, html_path)
            logger.info(f"HTML report: {html_path}")

        if self.config.markdown_output:
            md_path = self.output_dir / f"subsentinel_{domain_slug}_{timestamp}.md"
            self._generate_markdown(findings, stats, md_path)
            logger.info(f"Markdown report: {md_path}")

        if self.config.csv_output:
            csv_path = self.output_dir / f"subsentinel_{domain_slug}_{timestamp}.csv"
            self._generate_csv(findings, csv_path)
            logger.info(f"CSV report: {csv_path}")

        from rich.console import Console
        console = Console()
        console.print(f"\n[bold green]📄 Reports saved to:[/bold green] {self.output_dir}")

    def _generate_json(self, findings: List[Finding], stats: Dict, path: Path) -> None:
        """Generate JSON report."""
        data = {
            "meta": {
                "tool": "SubSentinel",
                "version": "2.0.0",
                "generated": datetime.utcnow().isoformat(),
                "target": self.config.domain or "multiple",
            },
            "stats": stats,
            "findings": [f.to_dict() for f in findings]
        }
        path.write_text(json.dumps(data, indent=2, default=str))

    def _generate_html(self, findings: List[Finding], stats: Dict, path: Path) -> None:
        """Generate interactive HTML report."""
        sorted_findings = sorted(findings, key=lambda f: f.confidence.score, reverse=True)

        findings_rows = ""
        for f in sorted_findings:
            sev = f.confidence.severity.upper()
            sev_class = sev.lower()
            claimable = "✅ Yes" if (f.claimability and f.claimability.is_claimable) else "❓ Unknown"

            screenshot_cell = ""
            if f.screenshot_path:
                screenshot_cell = f'<a href="{f.screenshot_path}" target="_blank">📸 View</a>'

            evidence_cell = ""
            if f.evidence and f.evidence.evidence_dir:
                evidence_cell = f'<a href="{f.evidence.evidence_dir}" target="_blank">📁 Open</a>'

            reasons_html = "<br>".join(f.confidence.reasons) if f.confidence.reasons else "N/A"

            findings_rows += f"""
            <tr class="sev-{sev_class}">
                <td><code>{f.subdomain}</code></td>
                <td>{f.provider}</td>
                <td><span class="badge {sev_class}">{sev}</span></td>
                <td><div class="confidence-bar"><div class="confidence-fill" style="width:{f.confidence.score}%"></div></div>{f.confidence.score}%</td>
                <td><code>{f.cname or "N/A"}</code></td>
                <td>{f.http_status or "N/A"}</td>
                <td>{claimable}</td>
                <td class="reasons">{reasons_html}</td>
                <td>{screenshot_cell}</td>
                <td>{evidence_cell}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubSentinel Report - {self.config.domain or 'Scan'}</title>
    <style>
        :root {{
            --bg: #0a0e1a;
            --surface: #111827;
            --surface2: #1f2937;
            --border: #374151;
            --text: #f9fafb;
            --muted: #9ca3af;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #6b7280;
            --success: #22c55e;
            --cyan: #06b6d4;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 40px; border-bottom: 2px solid var(--cyan); }}
        .header h1 {{ font-size: 2.5rem; color: var(--cyan); letter-spacing: 4px; text-transform: uppercase; }}
        .header .subtitle {{ color: var(--muted); margin-top: 8px; }}
        .warning {{ background: #7f1d1d; border-left: 4px solid var(--critical); padding: 12px 20px; margin: 20px; border-radius: 4px; font-size: 0.9rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; padding: 30px; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-card .value {{ font-size: 2.5rem; font-weight: bold; }}
        .stat-card .label {{ color: var(--muted); font-size: 0.85rem; margin-top: 4px; }}
        .stat-card.critical {{ border-color: var(--critical); }}
        .stat-card.critical .value {{ color: var(--critical); }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        .stat-card.low .value {{ color: var(--low); }}
        .container {{ padding: 0 30px 30px; }}
        h2 {{ color: var(--cyan); border-bottom: 1px solid var(--border); padding-bottom: 10px; margin: 30px 0 20px; letter-spacing: 2px; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; font-size: 0.85rem; }}
        th {{ background: var(--surface2); padding: 12px; text-align: left; color: var(--cyan); font-weight: bold; border-bottom: 2px solid var(--border); }}
        td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        tr:hover {{ background: var(--surface2); }}
        code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; color: var(--cyan); word-break: break-all; }}
        .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
        .badge.critical {{ background: #7f1d1d; color: var(--critical); }}
        .badge.high {{ background: #7c2d12; color: var(--high); }}
        .badge.medium {{ background: #713f12; color: var(--medium); }}
        .badge.low {{ background: #1e3a5f; color: var(--low); }}
        .badge.info {{ background: #1f2937; color: var(--info); }}
        .confidence-bar {{ height: 6px; background: var(--border); border-radius: 3px; margin-bottom: 4px; }}
        .confidence-fill {{ height: 100%; background: linear-gradient(90deg, #3b82f6, #06b6d4); border-radius: 3px; }}
        .reasons {{ font-size: 0.78rem; color: var(--muted); max-width: 250px; }}
        .sev-critical td {{ border-left: 3px solid var(--critical); }}
        .sev-high td {{ border-left: 3px solid var(--high); }}
        .sev-medium td {{ border-left: 3px solid var(--medium); }}
        .sev-low td {{ border-left: 3px solid var(--low); }}
        a {{ color: var(--cyan); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ text-align: center; padding: 30px; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); }}
        .no-findings {{ text-align: center; padding: 60px; color: var(--success); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ SubSentinel</h1>
        <div class="subtitle">Subdomain Takeover Report | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | Target: {self.config.domain or 'Multiple'}</div>
    </div>

    <div class="warning">
        ⚠️ <strong>CONFIDENTIAL SECURITY REPORT</strong> — For authorized security testing only. Handle with care. Do not distribute without authorization.
    </div>

    <div class="stats">
        <div class="stat-card"><div class="value">{stats.get('total', 0)}</div><div class="label">Subdomains Scanned</div></div>
        <div class="stat-card"><div class="value">{stats.get('vulnerable', 0)}</div><div class="label">Vulnerable</div></div>
        <div class="stat-card critical"><div class="value">{stats.get('critical', 0)}</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="value">{stats.get('high', 0)}</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="value">{stats.get('medium', 0)}</div><div class="label">Medium</div></div>
        <div class="stat-card low"><div class="value">{stats.get('low', 0)}</div><div class="label">Low</div></div>
    </div>

    <div class="container">
        <h2>FINDINGS</h2>
        {"<div class='no-findings'>✅ No subdomain takeover vulnerabilities detected</div>" if not findings else f'''
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Provider</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>CNAME</th>
                    <th>HTTP</th>
                    <th>Claimable</th>
                    <th>Evidence</th>
                    <th>Screenshot</th>
                    <th>Proof</th>
                </tr>
            </thead>
            <tbody>{findings_rows}</tbody>
        </table>'''}
    </div>

    <div class="footer">
        Generated by SubSentinel v2.0.0 | For authorized security testing only
    </div>

    <script>
        // Sort table by confidence
        document.querySelectorAll('th').forEach((th, i) => {{
            th.style.cursor = 'pointer';
            th.addEventListener('click', () => {{
                const table = th.closest('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const dir = th.dataset.dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
                rows.sort((a, b) => {{
                    const aVal = a.cells[i].textContent.trim();
                    const bVal = b.cells[i].textContent.trim();
                    return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                }});
                rows.forEach(r => tbody.appendChild(r));
            }});
        }});
    </script>
</body>
</html>"""
        path.write_text(html)

    def _generate_markdown(self, findings: List[Finding], stats: Dict, path: Path) -> None:
        """Generate Markdown report."""
        lines = [
            "# SubSentinel - Subdomain Takeover Report",
            "",
            f"> **Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"> **Target:** {self.config.domain or 'Multiple'}",
            f"> **Tool:** SubSentinel v2.0.0",
            "",
            "> ⚠️ **CONFIDENTIAL** — Authorized security testing only.",
            "",
            "## Statistics",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Subdomains Scanned | {stats.get('total', 0)} |",
            f"| Vulnerable | {stats.get('vulnerable', 0)} |",
            f"| Critical | {stats.get('critical', 0)} |",
            f"| High | {stats.get('high', 0)} |",
            f"| Medium | {stats.get('medium', 0)} |",
            f"| Low | {stats.get('low', 0)} |",
            "",
            "## Findings",
            "",
        ]

        if not findings:
            lines.append("✅ No subdomain takeover vulnerabilities detected.")
        else:
            lines += [
                "| Subdomain | Provider | Severity | Confidence | CNAME | HTTP | Claimable |",
                "|-----------|----------|----------|------------|-------|------|-----------|",
            ]
            for f in sorted(findings, key=lambda x: x.confidence.score, reverse=True):
                claimable = "✅" if (f.claimability and f.claimability.is_claimable) else "❓"
                lines.append(
                    f"| `{f.subdomain}` | {f.provider} | **{f.confidence.severity.upper()}** | "
                    f"{f.confidence.score}% | `{f.cname or 'N/A'}` | {f.http_status or 'N/A'} | {claimable} |"
                )

            lines.append("")
            lines.append("## Detailed Findings")
            lines.append("")

            for f in sorted(findings, key=lambda x: x.confidence.score, reverse=True):
                sev = f.confidence.severity.upper()
                lines += [
                    f"### {sev}: {f.subdomain}",
                    "",
                    f"**Provider:** {f.provider}  ",
                    f"**Confidence:** {f.confidence.score}%  ",
                    f"**CNAME Chain:** `{'` → `'.join(f.cname_chain) if f.cname_chain else 'N/A'}`  ",
                    f"**HTTP Status:** {f.http_status or 'N/A'}  ",
                    f"**Fingerprint:** `{f.fingerprint_matched or 'N/A'}`  ",
                    "",
                    "**Evidence:**",
                ]
                for reason in f.confidence.reasons:
                    lines.append(f"- {reason}")

                if f.evidence and f.evidence.reproduction_steps:
                    lines.append("")
                    lines.append("**Reproduction Steps:**")
                    for step in f.evidence.reproduction_steps:
                        lines.append(f"```")
                        lines.append(step)
                        lines.append("```")

                if f.evidence and f.evidence.poc_command:
                    lines.append("")
                    lines.append("**PoC Command:**")
                    lines.append(f"```bash\n{f.evidence.poc_command}\n```")

                lines.append("")
                lines.append(f"**Remediation:** {f._get_remediation()}")
                lines.append("")
                lines.append("---")
                lines.append("")

        path.write_text("\n".join(lines))

    def _generate_csv(self, findings: List[Finding], path: Path) -> None:
        """Generate CSV report."""
        fields = [
            "subdomain", "provider", "severity", "confidence",
            "cname", "cname_chain", "fingerprint", "http_status",
            "claimable", "claimability_evidence", "screenshot_path", "timestamp"
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "subdomain": finding.subdomain,
                    "provider": finding.provider,
                    "severity": finding.confidence.severity.upper(),
                    "confidence": finding.confidence.score,
                    "cname": finding.cname or "",
                    "cname_chain": " -> ".join(finding.cname_chain),
                    "fingerprint": finding.fingerprint_matched or "",
                    "http_status": finding.http_status or "",
                    "claimable": finding.claimability.is_claimable if finding.claimability else "",
                    "claimability_evidence": finding.claimability.evidence if finding.claimability else "",
                    "screenshot_path": str(finding.screenshot_path) if finding.screenshot_path else "",
                    "timestamp": finding.timestamp.isoformat(),
                })
