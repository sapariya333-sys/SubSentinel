"""
core/config.py - Centralized configuration with API key management
"""

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, List


@dataclass
class ScanConfig:
    """Central configuration for all scan components."""

    # Target
    domain: Optional[str]       = None
    domain_list: Optional[str]  = None
    subdomains_file: Optional[str] = None

    # Output
    output_dir: str    = "output"
    json_output: bool  = False
    html_output: bool  = False
    markdown_output: bool = False
    csv_output: bool   = False

    # Scanning
    threads: int    = 50
    timeout: int    = 12
    retries: int    = 3
    rate_limit: int = 100
    no_screenshot: bool = False
    verbose: bool   = False
    debug: bool     = False
    delay: float    = 0.0

    # Enumeration — sources
    use_crtsh: bool       = True
    use_subfinder: bool   = False
    use_amass: bool       = False
    use_assetfinder: bool = False
    use_findomain: bool   = False
    use_chaos: bool       = False   # kept for backward compat

    # API keys dictionary (populated from --api-keys file or individual flags)
    api_keys: Dict[str, str] = field(default_factory=dict)

    # OPSEC
    proxy: Optional[str]       = None
    proxy_list: Optional[str]  = None
    user_agent: str            = "Mozilla/5.0 (compatible; SecurityScanner/2.0)"
    proxies: List[str]         = field(default_factory=list)

    # Alerting
    telegram_token: Optional[str]   = None
    telegram_chat_id: Optional[str] = None
    discord_webhook: Optional[str]  = None
    slack_webhook: Optional[str]    = None
    generic_webhook: Optional[str]  = None
    alert_email: Optional[str]      = None
    smtp_host: Optional[str]        = None
    min_alert_severity: str         = "medium"

    # Confidence
    min_confidence: int = 30

    # Monitoring
    watch_mode: bool    = False
    watch_interval: int = 3600
    db_path: str        = "subsentinel.db"

    # Fingerprints
    update_fingerprints: bool     = False
    fingerprint_url: Optional[str] = None

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "ScanConfig":
        config = cls(
            domain          = args.domain,
            domain_list     = args.list,
            subdomains_file = args.subdomains,
            output_dir      = args.output,
            json_output     = args.json,
            html_output     = args.html,
            markdown_output = getattr(args, "markdown", False),
            csv_output      = getattr(args, "csv", False),
            threads         = args.threads,
            timeout         = args.timeout,
            retries         = args.retries,
            rate_limit      = args.rate_limit,
            no_screenshot   = args.no_screenshot,
            verbose         = args.verbose,
            debug           = args.debug,
            delay           = args.delay,
            use_subfinder   = args.subfinder,
            use_amass       = args.amass,
            use_assetfinder = getattr(args, "assetfinder", False),
            use_findomain   = getattr(args, "findomain", False),
            proxy           = args.proxy,
            proxy_list      = args.proxy_list,
            user_agent      = args.user_agent or "Mozilla/5.0 (compatible; SecurityScanner/2.0)",
            telegram_token  = args.telegram_token,
            telegram_chat_id= args.telegram_chat,
            discord_webhook = args.discord_webhook,
            slack_webhook   = args.slack_webhook,
            generic_webhook = args.webhook,
            alert_email     = args.email,
            smtp_host       = args.smtp_host,
            min_alert_severity = args.min_severity,
            min_confidence  = args.min_confidence,
            watch_mode      = args.watch,
            watch_interval  = args.interval,
            db_path         = args.db,
            update_fingerprints = args.update_fingerprints,
            fingerprint_url = args.fingerprint_url,
        )

        # Load API keys from YAML/JSON file
        if hasattr(args, "api_keys") and args.api_keys:
            config.api_keys = cls._load_api_keys(args.api_keys)

        # Also accept individual flags
        direct_keys = {
            "virustotal":      getattr(args, "vt_key", None),
            "shodan":          getattr(args, "shodan_key", None),
            "securitytrails":  getattr(args, "st_key", None),
            "chaos":           getattr(args, "chaos_key", None),
            "censys_id":       getattr(args, "censys_id", None),
            "censys_secret":   getattr(args, "censys_secret", None),
            "binaryedge":      getattr(args, "binaryedge_key", None),
            "fullhunt":        getattr(args, "fullhunt_key", None),
            "netlas":          getattr(args, "netlas_key", None),
            "zoomeye":         getattr(args, "zoomeye_key", None),
            "bevigil":         getattr(args, "bevigil_key", None),
            "whoisxml":        getattr(args, "whoisxml_key", None),
            "facebook_app_id": getattr(args, "fb_app_id", None),
            "facebook_app_secret": getattr(args, "fb_app_secret", None),
        }
        for k, v in direct_keys.items():
            if v:
                config.api_keys[k] = v

        # Backward compat: use_chaos -> api_keys["chaos"]
        if args.chaos and getattr(args, "chaos_key", None):
            config.api_keys["chaos"] = args.chaos_key

        # Proxy list
        if config.proxy_list:
            p = Path(config.proxy_list)
            if p.exists():
                config.proxies = [l.strip() for l in p.read_text().splitlines() if l.strip()]

        # Create output dirs
        for d in ("", "screenshots", "evidence"):
            Path(config.output_dir, d).mkdir(parents=True, exist_ok=True)

        return config

    @staticmethod
    def _load_api_keys(path: str) -> Dict[str, str]:
        """Load API keys from YAML or JSON file."""
        p = Path(path)
        if not p.exists():
            return {}
        try:
            if path.endswith(".yaml") or path.endswith(".yml"):
                import yaml
                return yaml.safe_load(p.read_text()) or {}
            else:
                import json
                return json.loads(p.read_text())
        except Exception as e:
            print(f"Warning: could not load API keys from {path}: {e}")
            return {}
