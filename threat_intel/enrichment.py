"""
SentinelHunt — Threat Intelligence Enrichment Engine

Enriches alerts with external threat intelligence from multiple sources:
    - VirusTotal: IP/domain reputation
    - AbuseIPDB: Abuse confidence scoring
    - Shodan: Host exposure data
    - MaxMind GeoIP2: IP geolocation

All lookups are cached to respect API rate limits and improve latency.
"""

import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from collections import OrderedDict
from functools import lru_cache

logger = logging.getLogger("sentinelhunt.threat_intel.enrichment")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not installed — threat intel enrichment disabled")


class LRUCache:
    """Simple LRU cache with TTL expiry."""

    def __init__(self, max_size: int = 10_000, ttl_seconds: int = 3600):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[Dict]:
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self._ttl:
                self._cache.move_to_end(key)
                return value
            else:
                del self._cache[key]
        return None

    def set(self, key: str, value: Dict) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (value, time.time())
        if len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    @property
    def size(self) -> int:
        return len(self._cache)


class ThreatIntelEnricher:
    """
    Multi-source threat intelligence enrichment engine.

    Queries external threat intel APIs and enriches alerts with:
        - IP reputation scores
        - Domain reputation
        - Geolocation data
        - Known malware associations
        - Historical abuse reports
    """

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
        cache_ttl: int = 3600,
        max_cache_size: int = 10_000,
    ):
        self.vt_key = virustotal_api_key
        self.abuseipdb_key = abuseipdb_api_key
        self.shodan_key = shodan_api_key
        self._cache = LRUCache(max_size=max_cache_size, ttl_seconds=cache_ttl)
        self._request_count = 0
        self._session = requests.Session() if REQUESTS_AVAILABLE else None

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich an IP address with threat intelligence from all configured sources.
        """
        # Check cache first
        cache_key = f"ip:{ip_address}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        result = {
            "ip": ip_address,
            "enriched_at": datetime.utcnow().isoformat() + "Z",
            "sources": {},
            "overall_risk": "unknown",
            "risk_score": 0.0,
        }

        # Query each configured source
        if self.vt_key:
            vt_result = self._query_virustotal_ip(ip_address)
            if vt_result:
                result["sources"]["virustotal"] = vt_result

        if self.abuseipdb_key:
            abuse_result = self._query_abuseipdb(ip_address)
            if abuse_result:
                result["sources"]["abuseipdb"] = abuse_result

        if self.shodan_key:
            shodan_result = self._query_shodan(ip_address)
            if shodan_result:
                result["sources"]["shodan"] = shodan_result

        # Calculate overall risk score
        result["risk_score"] = self._calculate_risk_score(result["sources"])
        result["overall_risk"] = self._risk_level(result["risk_score"])

        # Cache the result
        self._cache.set(cache_key, result)
        return result

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich a domain with threat intelligence."""
        cache_key = f"domain:{domain}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        result = {
            "domain": domain,
            "enriched_at": datetime.utcnow().isoformat() + "Z",
            "sources": {},
            "overall_risk": "unknown",
            "risk_score": 0.0,
        }

        if self.vt_key:
            vt_result = self._query_virustotal_domain(domain)
            if vt_result:
                result["sources"]["virustotal"] = vt_result

        result["risk_score"] = self._calculate_risk_score(result["sources"])
        result["overall_risk"] = self._risk_level(result["risk_score"])

        self._cache.set(cache_key, result)
        return result

    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with threat intelligence for its source and destination IPs.
        """
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")

        enrichment = {
            "threat_intel": {
                "enriched": True,
                "enriched_at": datetime.utcnow().isoformat() + "Z",
            }
        }

        # Enrich source IP
        if src_ip and not self._is_private_ip(src_ip):
            src_intel = self.enrich_ip(src_ip)
            enrichment["threat_intel"]["source"] = src_intel
        else:
            enrichment["threat_intel"]["source"] = {
                "ip": src_ip, "note": "Internal IP — no external intel"
            }

        # Enrich destination IP
        if dst_ip and not self._is_private_ip(dst_ip):
            dst_intel = self.enrich_ip(dst_ip)
            enrichment["threat_intel"]["destination"] = dst_intel
        else:
            enrichment["threat_intel"]["destination"] = {
                "ip": dst_ip, "note": "Internal IP — no external intel"
            }

        # Merge enrichment into alert
        alert.update(enrichment)
        return alert

    def _query_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Query VirusTotal IP address report."""
        if not self._session or not self.vt_key:
            return None

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_key}
            response = self._session.get(url, headers=headers, timeout=10)
            self._request_count += 1

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious_detections": stats.get("malicious", 0),
                    "suspicious_detections": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country", "unknown"),
                    "as_owner": data.get("as_owner", "unknown"),
                    "network": data.get("network", "unknown"),
                }
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit reached")
            return None
        except Exception as e:
            logger.debug("VirusTotal query failed for %s: %s", ip, e)
            return None

    def _query_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Query VirusTotal domain report."""
        if not self._session or not self.vt_key:
            return None

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_key}
            response = self._session.get(url, headers=headers, timeout=10)
            self._request_count += 1

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious_detections": stats.get("malicious", 0),
                    "suspicious_detections": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()),
                    "reputation": data.get("reputation", 0),
                    "registrar": data.get("registrar", "unknown"),
                    "creation_date": data.get("creation_date", "unknown"),
                }
            return None
        except Exception as e:
            logger.debug("VirusTotal domain query failed for %s: %s", domain, e)
            return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB for IP reputation."""
        if not self._session or not self.abuseipdb_key:
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            }
            response = self._session.get(url, headers=headers, params=params, timeout=10)
            self._request_count += 1

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "domain": data.get("domain", "unknown"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", "unknown"),
                }
            return None
        except Exception as e:
            logger.debug("AbuseIPDB query failed for %s: %s", ip, e)
            return None

    def _query_shodan(self, ip: str) -> Optional[Dict]:
        """Query Shodan for host information."""
        if not self._session or not self.shodan_key:
            return None

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": self.shodan_key}
            response = self._session.get(url, params=params, timeout=10)
            self._request_count += 1

            if response.status_code == 200:
                data = response.json()
                return {
                    "open_ports": data.get("ports", []),
                    "os": data.get("os", "unknown"),
                    "organization": data.get("org", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "country": data.get("country_name", "unknown"),
                    "city": data.get("city", "unknown"),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                }
            return None
        except Exception as e:
            logger.debug("Shodan query failed for %s: %s", ip, e)
            return None

    def _calculate_risk_score(self, sources: Dict[str, Dict]) -> float:
        """Calculate combined risk score from all intelligence sources."""
        scores = []

        # VirusTotal score
        vt = sources.get("virustotal", {})
        if vt:
            total = vt.get("total_engines", 1)
            malicious = vt.get("malicious_detections", 0) + vt.get("suspicious_detections", 0)
            if total > 0:
                scores.append(min(malicious / total * 2, 1.0))

        # AbuseIPDB score
        abuse = sources.get("abuseipdb", {})
        if abuse:
            confidence = abuse.get("abuse_confidence_score", 0)
            scores.append(confidence / 100.0)

        # Shodan score (based on exposed services/vulns)
        shodan = sources.get("shodan", {})
        if shodan:
            vulns = len(shodan.get("vulns", []))
            open_ports = len(shodan.get("open_ports", []))
            exposure_score = min((vulns * 0.2 + open_ports * 0.05), 1.0)
            scores.append(exposure_score)

        if not scores:
            return 0.0

        return round(sum(scores) / len(scores), 2)

    def _risk_level(self, score: float) -> str:
        """Map numeric risk score to human-readable level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.3:
            return "medium"
        elif score > 0:
            return "low"
        return "unknown"

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in a private range."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except (ValueError, TypeError):
            return True

    def get_stats(self) -> Dict[str, Any]:
        """Get enrichment engine statistics."""
        return {
            "cache_size": self._cache.size,
            "total_requests": self._request_count,
            "configured_sources": {
                "virustotal": bool(self.vt_key),
                "abuseipdb": bool(self.abuseipdb_key),
                "shodan": bool(self.shodan_key),
            },
        }
