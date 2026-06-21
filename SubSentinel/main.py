#!/usr/bin/env python3
"""
SubSentinel v4 — Elite Subdomain Takeover Detection Platform
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠  AUTHORIZED TESTING ONLY. Unauthorized use is illegal.
"""

from __future__ import annotations

import asyncio
import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import print as rprint

console = Console()

# ─────────────────────────────────────────────────────────────
# BANNER — red cyberpunk aesthetic
# ─────────────────────────────────────────────────────────────

BANNER_LINES = [
    r"  ██████╗ ██╗   ██╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ",
    r"  ██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ",
    r"  ███████╗██║   ██║██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ",
    r"  ╚════██║██║   ██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ",
    r"  ███████║╚██████╔╝██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗",
    r"  ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝",
]

def print_banner() -> None:
    console.print()
    for i, line in enumerate(BANNER_LINES):
        # Gradient: bright red top → dark red bottom
        shade = "bold red" if i < 2 else ("red" if i < 4 else "dark_red")
        console.print(f"[{shade}]{line}[/{shade}]")

    console.print()
    console.print(
        Align.center(
            Text("✦  S U N S H I N E  ✦", style="bold red")
        )
    )
    console.print(
        Align.center(
            Text("Elite Subdomain Takeover Detection Platform  •  v4.0", style="dim red")
        )
    )
    console.print(
        Align.center(
            Text("by SubSentinel Project", style="dim")
        )
    )
    console.print()
    console.print(
        Panel(
            "[bold red]⚠  AUTHORIZED TESTING ONLY[/bold red]  "
            "[dim]Unauthorized use violates CFAA, Computer Misuse Act & equivalents.[/dim]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subsentinel",
        description="SubSentinel v4 — Elite Subdomain Takeover Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  python main.py -d target.com --html --json
  python main.py -d target.com --subfinder --vt-key KEY --html
  python main.py -l domains.txt --threads 100 --accept-legal
  python main.py -d target.com --watch --interval 1800 --discord-webhook URL
  python main.py -d target.com --api-keys keys.yaml --no-screenshot
        """,
    )

    # Target
    t = p.add_argument_group("Target")
    t.add_argument("-d", "--domain",     help="Single target domain")
    t.add_argument("-l", "--list",       help="File containing domains (one per line)")
    t.add_argument("-s", "--subdomains", help="File with pre-enumerated subdomains (skip enum)")

    # Output
    o = p.add_argument_group("Output")
    o.add_argument("--json",     action="store_true", help="JSON report")
    o.add_argument("--html",     action="store_true", help="HTML report")
    o.add_argument("--markdown", action="store_true", help="Markdown report")
    o.add_argument("--csv",      action="store_true", help="CSV report")
    o.add_argument("-o", "--output", default="output", help="Output directory (default: output)")

    # Scanning
    sc = p.add_argument_group("Scanning")
    sc.add_argument("--threads",        type=int,   default=50,   help="Concurrent workers (default: 50)")
    sc.add_argument("--timeout",        type=int,   default=12,   help="Request timeout seconds (default: 12)")
    sc.add_argument("--retries",        type=int,   default=3,    help="Retry attempts (default: 3)")
    sc.add_argument("--rate-limit",     type=int,   default=100,  help="Max req/sec (default: 100)")
    sc.add_argument("--no-screenshot",  action="store_true",      help="Disable screenshots")
    sc.add_argument("--min-confidence", type=int,   default=30,   help="Min confidence score to report (default: 30)")

    # Enumeration
    en = p.add_argument_group("Enumeration")
    en.add_argument("--subfinder",    action="store_true", help="Use subfinder binary")
    en.add_argument("--amass",        action="store_true", help="Use amass binary")
    en.add_argument("--assetfinder",  action="store_true", help="Use assetfinder binary")
    en.add_argument("--findomain",    action="store_true", help="Use findomain binary")
    en.add_argument("--chaos",        action="store_true", help="Use Chaos dataset (requires --chaos-key)")
    en.add_argument("--chaos-key",    help="Chaos API key")
    en.add_argument("--api-keys",     dest="api_keys",  help="YAML/JSON file with API keys")

    # Individual API keys
    k = p.add_argument_group("API Keys")
    k.add_argument("--vt-key",         dest="vt_key",         help="VirusTotal")
    k.add_argument("--shodan-key",     dest="shodan_key",     help="Shodan")
    k.add_argument("--st-key",         dest="st_key",         help="SecurityTrails")
    k.add_argument("--censys-id",      dest="censys_id",      help="Censys ID")
    k.add_argument("--censys-secret",  dest="censys_secret",  help="Censys Secret")
    k.add_argument("--be-key",         dest="binaryedge_key", help="BinaryEdge")
    k.add_argument("--fh-key",         dest="fullhunt_key",   help="FullHunt")
    k.add_argument("--netlas-key",     dest="netlas_key",     help="Netlas")
    k.add_argument("--zoomeye-key",    dest="zoomeye_key",    help="ZoomEye")
    k.add_argument("--bevigil-key",    dest="bevigil_key",    help="BeVigil")
    k.add_argument("--whoisxml-key",   dest="whoisxml_key",   help="WhoisXML")
    k.add_argument("--fb-app-id",      dest="fb_app_id",      help="Facebook App ID")
    k.add_argument("--fb-app-secret",  dest="fb_app_secret",  help="Facebook App Secret")

    # OPSEC
    op = p.add_argument_group("OPSEC")
    op.add_argument("--proxy",       help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    op.add_argument("--proxy-list",  help="File with proxy list for rotation")
    op.add_argument("--user-agent",  help="Custom User-Agent")
    op.add_argument("--delay",       type=float, default=0.0, help="Delay between requests (seconds)")

    # Alerting
    al = p.add_argument_group("Alerting")
    al.add_argument("--telegram-token",   help="Telegram bot token")
    al.add_argument("--telegram-chat",    help="Telegram chat ID")
    al.add_argument("--discord-webhook",  help="Discord webhook URL")
    al.add_argument("--slack-webhook",    help="Slack webhook URL")
    al.add_argument("--webhook",          help="Generic webhook URL")
    al.add_argument("--email",            help="Alert email address")
    al.add_argument("--smtp-host",        help="SMTP host")
    al.add_argument("--min-severity",     default="medium",
                    choices=["low","medium","high","critical"],
                    help="Minimum alert severity (default: medium)")

    # Monitoring
    mo = p.add_argument_group("Monitoring")
    mo.add_argument("--watch",     action="store_true", help="Continuous monitoring mode")
    mo.add_argument("--interval",  type=int, default=3600, help="Watch interval seconds (default: 3600)")
    mo.add_argument("--db",        default="subsentinel.db", help="SQLite DB path")

    # Fingerprints
    fp = p.add_argument_group("Fingerprints")
    fp.add_argument("--update-fingerprints", action="store_true", help="Download latest fingerprints")
    fp.add_argument("--fingerprint-url",     help="Custom fingerprint source URL")

    # Meta
    p.add_argument("--accept-legal", action="store_true", help="Accept legal disclaimer (for CI/CD)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--debug",        action="store_true", help="Debug mode")

    return p


def legal_prompt() -> bool:
    console.print(Panel(
        "[bold red]LEGAL DISCLAIMER[/bold red]\n\n"
        "SubSentinel is a professional security research tool.\n"
        "It is intended [bold]exclusively[/bold] for:\n"
        "  • Authorized penetration testing\n"
        "  • Bug bounty programs (within scope)\n"
        "  • Security auditing of infrastructure you own\n\n"
        "[bold red]Unauthorized use may violate:[/bold red]\n"
        "  • Computer Fraud and Abuse Act (CFAA) — USA\n"
        "  • Computer Misuse Act — UK\n"
        "  • Equivalent laws in your jurisdiction\n\n"
        "[dim]The authors accept zero liability for unauthorized or illegal use.[/dim]",
        title="[bold red]⚠  AUTHORIZED USE ONLY[/bold red]",
        border_style="red",
        padding=(1, 3),
    ))
    reply = console.input("\n[bold red]▸[/bold red] Do you have authorization to test these targets? [yes/no]: ")
    return reply.strip().lower() in ("yes", "y")


async def run(args: argparse.Namespace) -> None:
    from core.scanner import SubSentinelScanner
    from core.config import ScanConfig
    config = ScanConfig.from_args(args)
    scanner = SubSentinelScanner(config)
    await scanner.run()


def main() -> None:
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.domain and not args.list and not args.subdomains:
        parser.print_help()
        sys.exit(1)

    if not args.accept_legal:
        if not legal_prompt():
            console.print("\n[red]✗ Aborted — authorization required.[/red]")
            sys.exit(1)
    else:
        console.print("[dim]Legal disclaimer accepted via --accept-legal.[/dim]\n")

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚡ Interrupted.[/yellow]")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            console.print(f"[bold red]✗ Fatal:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
