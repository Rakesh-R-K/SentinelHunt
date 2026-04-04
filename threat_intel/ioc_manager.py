"""
SentinelHunt — IOC (Indicator of Compromise) Manager

Manages indicators of compromise with STIX 2.1 compatibility:
    - Import/export IOCs in structured format
    - Track IPs, domains, file hashes, JA3 fingerprints
    - IOC matching against live traffic flows
    - Confidence decay over time (older IOCs = lower confidence)
    - SQLite-backed persistent storage
"""

import json
import sqlite3
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set
from contextlib import contextmanager

logger = logging.getLogger("sentinelhunt.threat_intel.ioc_manager")


class IOCManager:
    """
    Indicator of Compromise management system.

    Stores and queries IOCs from a local SQLite database with
    automatic confidence decay for aging indicators.
    """

    IOC_TYPES = {"ip", "domain", "md5", "sha256", "ja3", "url", "email"}

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(
                Path(__file__).resolve().parent / "data" / "ioc_database.db"
            )

        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Thread-safe database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self) -> None:
        """Initialize the IOC database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    threat_type TEXT DEFAULT 'unknown',
                    confidence REAL DEFAULT 0.8,
                    source TEXT DEFAULT 'manual',
                    description TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expiry_date TEXT,
                    is_active INTEGER DEFAULT 1,
                    hit_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(ioc_type, value)
                );

                CREATE INDEX IF NOT EXISTS idx_ioc_type_value
                    ON iocs(ioc_type, value);
                CREATE INDEX IF NOT EXISTS idx_ioc_active
                    ON iocs(is_active);
                CREATE INDEX IF NOT EXISTS idx_ioc_type
                    ON iocs(ioc_type);

                CREATE TABLE IF NOT EXISTS ioc_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_id INTEGER NOT NULL,
                    alert_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    matched_at TEXT NOT NULL,
                    flow_metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                );

                CREATE INDEX IF NOT EXISTS idx_match_ioc
                    ON ioc_matches(ioc_id);
            """)
        logger.info("IOC database initialized at %s", self.db_path)

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        threat_type: str = "unknown",
        confidence: float = 0.8,
        source: str = "manual",
        description: str = "",
        tags: Optional[List[str]] = None,
        expiry_days: Optional[int] = 90,
    ) -> bool:
        """Add or update an IOC in the database."""
        if ioc_type not in self.IOC_TYPES:
            logger.warning("Invalid IOC type: %s", ioc_type)
            return False

        now = datetime.utcnow().isoformat() + "Z"
        expiry = None
        if expiry_days:
            expiry = (datetime.utcnow() + timedelta(days=expiry_days)).isoformat() + "Z"

        with self._get_connection() as conn:
            try:
                conn.execute("""
                    INSERT INTO iocs (ioc_type, value, threat_type, confidence,
                                     source, description, tags, first_seen,
                                     last_seen, expiry_date, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ioc_type, value) DO UPDATE SET
                        confidence = MAX(excluded.confidence, iocs.confidence),
                        last_seen = excluded.last_seen,
                        updated_at = excluded.updated_at,
                        is_active = 1
                """, (
                    ioc_type, value.lower().strip(), threat_type, confidence,
                    source, description, json.dumps(tags or []),
                    now, now, expiry, now, now,
                ))
                return True
            except Exception as e:
                logger.error("Failed to add IOC: %s", e)
                return False

    def bulk_add_iocs(self, iocs: List[Dict[str, Any]]) -> int:
        """Add multiple IOCs at once. Returns count of successfully added."""
        added = 0
        for ioc in iocs:
            if self.add_ioc(**ioc):
                added += 1
        logger.info("Bulk added %d/%d IOCs", added, len(iocs))
        return added

    def match_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match a flow against all active IOCs.

        Checks:
            - Source IP against IP IOCs
            - Destination IP against IP IOCs
            - DNS query against domain IOCs
        """
        matches = []
        now = datetime.utcnow().isoformat() + "Z"

        with self._get_connection() as conn:
            # Check IPs
            for ip_field in ("src_ip", "dst_ip"):
                ip = flow.get(ip_field, "")
                if ip:
                    rows = conn.execute("""
                        SELECT * FROM iocs
                        WHERE ioc_type = 'ip' AND value = ? AND is_active = 1
                        AND (expiry_date IS NULL OR expiry_date > ?)
                    """, (ip.lower(), now)).fetchall()

                    for row in rows:
                        match = self._row_to_dict(row)
                        match["matched_field"] = ip_field
                        match["matched_value"] = ip
                        matches.append(match)

                        # Record match and increment hit count
                        conn.execute(
                            "UPDATE iocs SET hit_count = hit_count + 1 WHERE id = ?",
                            (row["id"],)
                        )
                        conn.execute("""
                            INSERT INTO ioc_matches (ioc_id, src_ip, dst_ip, matched_at, flow_metadata)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            row["id"],
                            flow.get("src_ip", ""),
                            flow.get("dst_ip", ""),
                            now,
                            json.dumps({"dst_port": flow.get("dst_port"), "protocol": flow.get("protocol")}),
                        ))

            # Check domains (from DNS features, if available)
            # The domain might be encoded in dns_query_length > 0 scenario
            dns_query = flow.get("dns_query", "")
            if dns_query:
                rows = conn.execute("""
                    SELECT * FROM iocs
                    WHERE ioc_type = 'domain' AND ? LIKE '%' || value || '%'
                    AND is_active = 1
                    AND (expiry_date IS NULL OR expiry_date > ?)
                """, (dns_query.lower(), now)).fetchall()

                for row in rows:
                    match = self._row_to_dict(row)
                    match["matched_field"] = "dns_query"
                    match["matched_value"] = dns_query
                    matches.append(match)
                    conn.execute(
                        "UPDATE iocs SET hit_count = hit_count + 1 WHERE id = ?",
                        (row["id"],)
                    )

        return matches

    def search(
        self,
        query: str,
        ioc_type: Optional[str] = None,
        active_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """Search IOCs by value pattern."""
        with self._get_connection() as conn:
            sql = "SELECT * FROM iocs WHERE value LIKE ?"
            params = [f"%{query.lower()}%"]

            if ioc_type:
                sql += " AND ioc_type = ?"
                params.append(ioc_type)

            if active_only:
                sql += " AND is_active = 1"

            sql += " ORDER BY confidence DESC LIMIT 100"
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(row) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Get IOC database statistics."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM iocs WHERE is_active = 1").fetchone()[0]
            by_type = {}
            for row in conn.execute("SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type"):
                by_type[row[0]] = row[1]
            total_matches = conn.execute("SELECT COUNT(*) FROM ioc_matches").fetchone()[0]

        return {
            "total_iocs": total,
            "active_iocs": active,
            "by_type": by_type,
            "total_matches": total_matches,
        }

    def apply_confidence_decay(self, decay_days: int = 90) -> int:
        """
        Apply confidence decay to old IOCs.
        IOCs older than decay_days get reduced confidence.
        """
        cutoff = (datetime.utcnow() - timedelta(days=decay_days)).isoformat() + "Z"

        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE iocs
                SET confidence = MAX(confidence * 0.8, 0.1),
                    updated_at = ?
                WHERE last_seen < ? AND is_active = 1
            """, (datetime.utcnow().isoformat() + "Z", cutoff))
            decay_count = result.rowcount

        if decay_count > 0:
            logger.info("Applied confidence decay to %d IOCs", decay_count)
        return decay_count

    def export_stix(self) -> Dict[str, Any]:
        """Export all active IOCs in STIX 2.1 format."""
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()}",
            "objects": [],
        }

        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM iocs WHERE is_active = 1").fetchall()

        for row in rows:
            ioc = self._row_to_dict(row)
            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hashlib.md5(f'{ioc[\"ioc_type\"]}:{ioc[\"value\"]}'.encode()).hexdigest()}",
                "created": ioc["created_at"],
                "modified": ioc["updated_at"],
                "name": f"{ioc['ioc_type'].upper()}: {ioc['value']}",
                "description": ioc.get("description", ""),
                "indicator_types": [ioc.get("threat_type", "unknown-threat")],
                "pattern": self._to_stix_pattern(ioc["ioc_type"], ioc["value"]),
                "pattern_type": "stix",
                "valid_from": ioc["first_seen"],
                "confidence": int(ioc["confidence"] * 100),
            }
            stix_bundle["objects"].append(stix_indicator)

        return stix_bundle

    def import_stix(self, stix_data: Dict[str, Any]) -> int:
        """Import IOCs from a STIX 2.1 bundle."""
        if stix_data.get("type") != "bundle":
            logger.warning("Invalid STIX bundle")
            return 0

        imported = 0
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "indicator":
                ioc_type, value = self._from_stix_pattern(obj.get("pattern", ""))
                if ioc_type and value:
                    self.add_ioc(
                        ioc_type=ioc_type,
                        value=value,
                        threat_type=obj.get("indicator_types", ["unknown"])[0],
                        confidence=obj.get("confidence", 80) / 100.0,
                        source="stix_import",
                        description=obj.get("description", ""),
                    )
                    imported += 1

        logger.info("Imported %d IOCs from STIX bundle", imported)
        return imported

    @staticmethod
    def _to_stix_pattern(ioc_type: str, value: str) -> str:
        """Convert IOC to STIX 2.1 pattern string."""
        type_map = {
            "ip": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "md5": f"[file:hashes.'MD5' = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "url": f"[url:value = '{value}']",
            "email": f"[email-addr:value = '{value}']",
            "ja3": f"[x-ja3:hash = '{value}']",
        }
        return type_map.get(ioc_type, f"[x-custom:value = '{value}']")

    @staticmethod
    def _from_stix_pattern(pattern: str) -> tuple:
        """Extract IOC type and value from STIX pattern."""
        if "ipv4-addr:value" in pattern:
            value = pattern.split("'")[1] if "'" in pattern else ""
            return "ip", value
        elif "domain-name:value" in pattern:
            value = pattern.split("'")[1] if "'" in pattern else ""
            return "domain", value
        elif "MD5" in pattern:
            value = pattern.split("'")[1] if "'" in pattern else ""
            return "md5", value
        elif "SHA-256" in pattern:
            value = pattern.split("'")[1] if "'" in pattern else ""
            return "sha256", value
        return None, None

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        """Convert a sqlite3.Row to a dictionary."""
        return dict(row)
