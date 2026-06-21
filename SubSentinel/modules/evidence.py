"""
modules/evidence.py - Structured evidence collection for findings
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.config import ScanConfig
from core.models import DNSData, HTTPData, FingerprintMatch, Evidence

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Collect and store structured evidence for findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.evidence_base = Path(config.output_dir) / "evidence"
        self.evidence_base.mkdir(parents=True, exist_ok=True)

    async def collect(
        self,
        subdomain: str,
        dns_data: Optional[DNSData],
        http_data: Optional[HTTPData],
        fingerprint: Optional[FingerprintMatch],
        screenshot_path: Optional[Path]
    ) -> Evidence:
        """Collect all evidence for a finding."""
        timestamp = datetime.utcnow()

        evidence = Evidence(
            subdomain=subdomain,
            timestamp=timestamp,
            screenshot_path=str(screenshot_path) if screenshot_path else None
        )

        # DNS records
        if dns_data:
            evidence.dns_records = {
                "a_records": dns_data.a_records,
                "aaaa_records": dns_data.aaaa_records,
                "cname_chain": dns_data.cname_chain,
                "ns_records": dns_data.ns_records,
                "is_nxdomain": dns_data.is_nxdomain,
                "is_dangling": dns_data.is_dangling,
                "is_wildcard": dns_data.is_wildcard,
            }
            evidence.cname_chain = dns_data.cname_chain

        # HTTP response
        if http_data:
            evidence.response_text = http_data.body
            evidence.response_headers = http_data.headers
            evidence.html_title = http_data.title

        # Build raw proof
        evidence.raw_proof = {
            "timestamp": timestamp.isoformat(),
            "subdomain": subdomain,
            "dns": evidence.dns_records,
            "http": {
                "status": http_data.status_code if http_data else None,
                "title": http_data.title if http_data else None,
                "headers": http_data.headers if http_data else {},
            } if http_data else None,
            "fingerprint": {
                "service": fingerprint.service if fingerprint else None,
                "cname_pattern": fingerprint.cname_pattern if fingerprint else None,
                "body_pattern": fingerprint.fingerprint if fingerprint else None,
                "matched_on": fingerprint.matched_on if fingerprint else None,
            } if fingerprint else None,
        }

        # Generate PoC
        evidence.poc_command = self._generate_poc_command(subdomain, fingerprint, dns_data)
        evidence.reproduction_steps = self._generate_reproduction_steps(subdomain, fingerprint, dns_data)

        # Save evidence to disk
        evidence_dir = await self._save_evidence(subdomain, evidence, screenshot_path)
        evidence.evidence_dir = str(evidence_dir)

        return evidence

    def _generate_poc_command(
        self,
        subdomain: str,
        fingerprint: Optional[FingerprintMatch],
        dns_data: Optional[DNSData]
    ) -> Optional[str]:
        """Generate a proof-of-concept command."""
        if not fingerprint:
            return None

        poc_commands = {
            "Surge.sh": f"echo 'Vulnerable' > index.html && surge --domain {subdomain}",
            "GitHub Pages": f"# Create repo {subdomain.split('.')[0]}.github.io\n# Push index.html with gh-pages branch",
            "Heroku": f"heroku create {subdomain.split('.')[0]} --region us",
            "AWS S3": f"aws s3api create-bucket --bucket {subdomain} --region us-east-1",
            "Firebase": f"firebase init hosting && firebase use --add && firebase deploy",
            "Netlify": f"netlify sites:create --name {subdomain.split('.')[0]}",
            "Vercel": f"vercel --name {subdomain.split('.')[0]}",
            "Render": f"# Create a new Render web service and add custom domain: {subdomain}",
            "Railway": f"# Create a Railway project and add custom domain: {subdomain}",
        }

        return poc_commands.get(fingerprint.service, f"# Claim the {fingerprint.service} resource pointed to by {subdomain}")

    def _generate_reproduction_steps(
        self,
        subdomain: str,
        fingerprint: Optional[FingerprintMatch],
        dns_data: Optional[DNSData]
    ) -> list:
        """Generate human-readable reproduction steps."""
        steps = []

        # Step 1: DNS verification
        steps.append(f"1. Verify CNAME chain: dig CNAME {subdomain}")
        if dns_data and dns_data.cname_chain:
            steps.append(f"   Expected chain: {' -> '.join(dns_data.cname_chain)}")

        # Step 2: HTTP verification
        steps.append(f"2. Verify HTTP response: curl -v https://{subdomain}")
        if fingerprint and fingerprint.fingerprint:
            steps.append(f"   Look for: '{fingerprint.fingerprint}'")

        # Step 3: Claimability
        if fingerprint:
            steps.append(f"3. Claim the {fingerprint.service} resource:")
            if fingerprint.notes:
                steps.append(f"   {fingerprint.notes}")

        # Step 4: Report
        steps.append(f"4. Report to the domain owner via responsible disclosure")

        return steps

    async def _save_evidence(
        self,
        subdomain: str,
        evidence: Evidence,
        screenshot_path: Optional[Path]
    ) -> Path:
        """Save all evidence files to disk."""
        # Create evidence directory for this subdomain
        safe_name = subdomain.replace(".", "_").replace("/", "_")
        evidence_dir = self.evidence_base / safe_name
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Save DNS records
        dns_file = evidence_dir / "dns.json"
        dns_file.write_text(json.dumps(evidence.dns_records, indent=2, default=str))

        # Save HTTP response
        if evidence.response_text:
            response_file = evidence_dir / "response.txt"
            response_file.write_text(evidence.response_text[:100_000])  # Limit size

        # Save headers
        if evidence.response_headers:
            headers_file = evidence_dir / "headers.json"
            headers_file.write_text(json.dumps(evidence.response_headers, indent=2, default=str))

        # Save proof
        proof_file = evidence_dir / "proof.json"
        proof_data = {
            **evidence.raw_proof,
            "reproduction_steps": evidence.reproduction_steps,
            "poc_command": evidence.poc_command,
        }
        proof_file.write_text(json.dumps(proof_data, indent=2, default=str))

        # Copy screenshot if exists
        if screenshot_path and Path(screenshot_path).exists():
            import shutil
            dest = evidence_dir / "screenshot.png"
            shutil.copy2(screenshot_path, dest)

        logger.debug(f"Evidence saved to: {evidence_dir}")
        return evidence_dir
