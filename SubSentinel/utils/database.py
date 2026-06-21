"""
utils/database.py - SQLite persistence layer
"""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.models import Finding

logger = logging.getLogger(__name__)


class Database:
    """Async SQLite database for persisting findings."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create database tables if they don't exist."""
        async with self._lock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._create_tables)

    def _create_tables(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain TEXT NOT NULL,
                    provider TEXT,
                    severity TEXT,
                    confidence INTEGER,
                    cname TEXT,
                    cname_chain TEXT,
                    fingerprint TEXT,
                    http_status INTEGER,
                    claimable BOOLEAN,
                    claimability_evidence TEXT,
                    screenshot_path TEXT,
                    evidence_dir TEXT,
                    reasons TEXT,
                    poc_command TEXT,
                    timestamp TEXT,
                    scan_date TEXT,
                    UNIQUE(subdomain, scan_date)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    total_subdomains INTEGER,
                    vulnerable_count INTEGER,
                    scan_start TEXT,
                    scan_end TEXT,
                    config TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_subdomain ON findings(subdomain);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """)
            conn.commit()
        logger.debug(f"Database initialized at {self.db_path}")

    async def save_finding(self, finding: Finding) -> None:
        """Save a finding to the database."""
        async with self._lock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._insert_finding, finding)

    def _insert_finding(self, finding: Finding) -> None:
        scan_date = datetime.utcnow().strftime("%Y-%m-%d")
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO findings
                    (subdomain, provider, severity, confidence, cname, cname_chain,
                     fingerprint, http_status, claimable, claimability_evidence,
                     screenshot_path, evidence_dir, reasons, poc_command, timestamp, scan_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.subdomain,
                    finding.provider,
                    finding.confidence.severity,
                    finding.confidence.score,
                    finding.cname,
                    json.dumps(finding.cname_chain),
                    finding.fingerprint_matched,
                    finding.http_status,
                    finding.claimability.is_claimable if finding.claimability else None,
                    finding.claimability.evidence if finding.claimability else None,
                    str(finding.screenshot_path) if finding.screenshot_path else None,
                    str(finding.evidence.evidence_dir) if finding.evidence and finding.evidence.evidence_dir else None,
                    json.dumps(finding.confidence.reasons),
                    finding.evidence.poc_command if finding.evidence else None,
                    finding.timestamp.isoformat(),
                    scan_date
                ))
                conn.commit()
            except Exception as e:
                logger.debug(f"DB insert error: {e}")

    async def get_findings_by_domain(self, domain: str) -> List[dict]:
        """Retrieve all findings for a domain."""
        async with self._lock:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._query_findings, domain)

    def _query_findings(self, domain: str) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM findings WHERE subdomain LIKE ? ORDER BY confidence DESC",
                (f"%.{domain}",)
            )
            return [dict(row) for row in cursor.fetchall()]

    async def get_historical_subdomains(self, domain: str) -> List[str]:
        """Get all historically known subdomains for a domain."""
        async with self._lock:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._query_subdomains, domain)

    def _query_subdomains(self, domain: str) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT DISTINCT subdomain FROM findings WHERE subdomain LIKE ?",
                (f"%.{domain}",)
            )
            return [row[0] for row in cursor.fetchall()]
