"""
SentinelHunt — OSINT Threat Feed Ingester

Ingests threat intelligence feeds from public OSINT sources:
    - AlienVault OTX (Open Threat Exchange)
    - Abuse.ch threat feeds (Feodo Tracker, URLhaus, etc.)
    - Emerging Threats IP blocklist

Automatically correlates ingested IOCs with detected alerts.
"""

import json
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger("sentinelhunt.threat_intel.feed_ingester")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ====================================================
# Built-in OSINT Feed Definitions
# ====================================================
THREAT_FEEDS = {
    "feodo_tracker": {
        "name": "Feodo Tracker (Abuse.ch)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "format": "json",
        "ioc_type": "ip",
        "description": "Botnet C2 IP addresses tracked by Abuse.ch",
        "refresh_hours": 6,
    },
    "urlhaus_recent": {
        "name": "URLhaus Recent URLs",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "format": "json",
        "ioc_type": "url",
        "description": "Recently observed malware distribution URLs",
        "refresh_hours": 1,
    },
    "emerging_threats": {
        "name": "Emerging Threats Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "format": "text_lines",
        "ioc_type": "ip",
        "description": "Known compromised IP addresses",
        "refresh_hours": 12,
    },
    "blocklist_de": {
        "name": "Blocklist.de All Attacks",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "format": "text_lines",
        "ioc_type": "ip",
        "description": "IPs reported for attacks in the last 48 hours",
        "refresh_hours": 12,
    },
    "cinsscore": {
        "name": "CI Army Bad IPs",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "format": "text_lines",
        "ioc_type": "ip",
        "description": "Collective Intelligence Network Security bad actors",
        "refresh_hours": 6,
    },
}


class FeedIngester:
    """
    Threat feed ingestion engine.

    Downloads, parses, and imports IOCs from configured OSINT feeds
    into the IOC database for live traffic matching.
    """

    def __init__(self, ioc_manager=None, cache_dir: Optional[str] = None):
        from threat_intel.ioc_manager import IOCManager

        self.ioc_manager = ioc_manager or IOCManager()
        self.cache_dir = Path(cache_dir or (
            Path(__file__).resolve().parent / "data" / "feed_cache"
        ))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._session = requests.Session() if REQUESTS_AVAILABLE else None
        self._feed_history: Dict[str, Dict] = {}

    def ingest_all_feeds(self) -> Dict[str, Any]:
        """Download and ingest all configured threat feeds."""
        results = {}

        for feed_id, feed_config in THREAT_FEEDS.items():
            try:
                result = self.ingest_feed(feed_id, feed_config)
                results[feed_id] = result
            except Exception as e:
                logger.error("Failed to ingest feed '%s': %s", feed_id, e)
                results[feed_id] = {"error": str(e)}

        return results

    def ingest_feed(
        self, feed_id: str, feed_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Download and ingest a single threat feed."""
        if not self._session:
            return {"error": "requests library not installed"}

        # Check if feed needs refresh
        if not self._needs_refresh(feed_id, feed_config):
            return {"status": "skipped", "reason": "within refresh interval"}

        logger.info("Ingesting feed: %s", feed_config["name"])

        try:
            response = self._session.get(
                feed_config["url"],
                timeout=30,
                headers={"User-Agent": "SentinelHunt/1.0 Threat Intel Ingester"},
            )
            response.raise_for_status()
        except Exception as e:
            logger.error("Feed download failed: %s", e)
            return {"error": f"download_failed: {e}"}

        # Parse based on format
        iocs = self._parse_feed(feed_config, response)

        # Import into IOC database
        imported = 0
        for ioc in iocs:
            if self.ioc_manager.add_ioc(
                ioc_type=feed_config["ioc_type"],
                value=ioc["value"],
                threat_type=ioc.get("threat_type", "malicious"),
                confidence=ioc.get("confidence", 0.7),
                source=feed_config["name"],
                description=ioc.get("description", ""),
                tags=ioc.get("tags", [feed_id]),
            ):
                imported += 1

        # Update feed history
        self._feed_history[feed_id] = {
            "last_ingested": datetime.utcnow().isoformat() + "Z",
            "iocs_imported": imported,
            "total_parsed": len(iocs),
        }

        # Cache the raw data
        cache_file = self.cache_dir / f"{feed_id}_latest.json"
        with open(cache_file, "w") as f:
            json.dump({
                "feed_id": feed_id,
                "ingested_at": datetime.utcnow().isoformat() + "Z",
                "ioc_count": len(iocs),
            }, f, indent=2)

        logger.info(
            "Feed '%s': parsed %d IOCs, imported %d",
            feed_config["name"], len(iocs), imported,
        )

        return {
            "status": "success",
            "feed": feed_config["name"],
            "parsed": len(iocs),
            "imported": imported,
        }

    def _parse_feed(
        self, feed_config: Dict[str, Any], response
    ) -> List[Dict[str, str]]:
        """Parse feed response based on configured format."""
        fmt = feed_config.get("format", "text_lines")
        iocs = []

        if fmt == "json":
            iocs = self._parse_json_feed(feed_config, response.json())
        elif fmt == "text_lines":
            iocs = self._parse_text_feed(feed_config, response.text)
        elif fmt == "csv":
            iocs = self._parse_csv_feed(feed_config, response.text)

        return iocs

    def _parse_json_feed(
        self, feed_config: Dict, data: Any
    ) -> List[Dict[str, str]]:
        """Parse JSON-format threat feeds."""
        iocs = []

        # Feodo Tracker format
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    ip = entry.get("ip_address", entry.get("ip", ""))
                    if ip:
                        iocs.append({
                            "value": ip,
                            "threat_type": entry.get("malware", "botnet_c2"),
                            "confidence": 0.85,
                            "description": f"Botnet: {entry.get('malware', 'unknown')}",
                            "tags": [entry.get("malware", "unknown")],
                        })
                elif isinstance(entry, str):
                    iocs.append({"value": entry, "confidence": 0.7})

        # URLhaus format
        elif isinstance(data, dict):
            urls = data.get("urls", data.get("data", []))
            if isinstance(urls, list):
                for entry in urls[:1000]:  # Limit to 1000
                    if isinstance(entry, dict):
                        url = entry.get("url", "")
                        if url:
                            iocs.append({
                                "value": url,
                                "threat_type": entry.get("threat", "malware_distribution"),
                                "confidence": 0.8,
                                "tags": entry.get("tags", []),
                            })

        return iocs

    def _parse_text_feed(
        self, feed_config: Dict, text: str
    ) -> List[Dict[str, str]]:
        """Parse line-separated IOC lists."""
        iocs = []

        for line in text.strip().split("\n"):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Handle IP:port format
            value = line.split(":")[0].strip() if ":" in line else line.strip()

            # Basic validation
            if feed_config["ioc_type"] == "ip":
                parts = value.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    iocs.append({
                        "value": value,
                        "confidence": 0.7,
                        "threat_type": "malicious_ip",
                    })
            else:
                if len(value) > 3:
                    iocs.append({"value": value, "confidence": 0.7})

        return iocs

    def _parse_csv_feed(
        self, feed_config: Dict, text: str
    ) -> List[Dict[str, str]]:
        """Parse CSV-format threat feeds."""
        iocs = []
        lines = text.strip().split("\n")

        for line in lines[1:]:  # Skip header
            if line.startswith("#"):
                continue
            parts = line.split(",")
            if parts:
                iocs.append({
                    "value": parts[0].strip().strip('"'),
                    "confidence": 0.7,
                })

        return iocs

    def _needs_refresh(self, feed_id: str, feed_config: Dict) -> bool:
        """Check if a feed needs to be re-downloaded."""
        history = self._feed_history.get(feed_id)
        if not history:
            return True

        last = history.get("last_ingested", "")
        if not last:
            return True

        try:
            last_dt = datetime.fromisoformat(last.replace("Z", ""))
            hours_since = (datetime.utcnow() - last_dt).total_seconds() / 3600
            return hours_since >= feed_config.get("refresh_hours", 6)
        except (ValueError, TypeError):
            return True

    def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all configured feeds."""
        status = {}
        for feed_id, config in THREAT_FEEDS.items():
            history = self._feed_history.get(feed_id, {})
            status[feed_id] = {
                "name": config["name"],
                "url": config["url"],
                "ioc_type": config["ioc_type"],
                "last_ingested": history.get("last_ingested", "never"),
                "iocs_imported": history.get("iocs_imported", 0),
            }
        return status


if __name__ == "__main__":
    from streaming.config import setup_logging, get_config

    config = get_config()
    setup_logging(config)

    ingester = FeedIngester()
    results = ingester.ingest_all_feeds()

    print("\n📡 Feed Ingestion Results:")
    for feed_id, result in results.items():
        status = result.get("status", result.get("error", "unknown"))
        imported = result.get("imported", 0)
        print(f"  {feed_id}: {status} ({imported} IOCs imported)")

    print("\n📊 IOC Database Stats:")
    stats = ingester.ioc_manager.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
