"""
SentinelHunt — MITRE ATT&CK Mapping Engine

Maps all detection rules to the MITRE ATT&CK framework, providing
tactic and technique context for every alert. Generates ATT&CK
Navigator layer JSON for visualization.

Reference: MITRE ATT&CK Enterprise Matrix v14
https://attack.mitre.org/
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("sentinelhunt.detection.mitre")


# ====================================================
# Complete MITRE ATT&CK Mapping for SentinelHunt Rules
# ====================================================
RULE_MITRE_MAPPING: Dict[str, Dict[str, Any]] = {
    "DNS_BEACONING": {
        "tactic": {
            "id": "TA0011",
            "name": "Command and Control",
        },
        "techniques": [
            {
                "id": "T1071.004",
                "name": "Application Layer Protocol: DNS",
                "description": "Adversaries use DNS for C2 communication to blend with legitimate traffic",
            },
            {
                "id": "T1568.002",
                "name": "Dynamic Resolution: Domain Generation Algorithms",
                "description": "Malware uses algorithmically generated domains for C2 resilience",
            },
        ],
        "severity_weight": 0.8,
        "investigation_guidance": [
            "Check DNS query patterns for periodicity (beaconing interval)",
            "Analyze resolved IPs — are they known C2 infrastructure?",
            "Look for encoded data in DNS query/response payloads",
            "Cross-reference with threat intelligence feeds",
        ],
    },

    "PORT_SCAN": {
        "tactic": {
            "id": "TA0043",
            "name": "Reconnaissance",
        },
        "techniques": [
            {
                "id": "T1046",
                "name": "Network Service Scanning",
                "description": "Adversary scans for open ports to map attack surface",
            },
        ],
        "severity_weight": 0.5,
        "investigation_guidance": [
            "Identify the scan type (SYN, connect, UDP)",
            "Check if scanner is internal (pivot) or external",
            "Correlate with any subsequent exploitation attempts",
            "Look for scanning of specific service ports (445, 3389, 22)",
        ],
    },

    "LATERAL_MOVEMENT": {
        "tactic": {
            "id": "TA0008",
            "name": "Lateral Movement",
        },
        "techniques": [
            {
                "id": "T1021",
                "name": "Remote Services",
                "description": "Use of legitimate remote services for lateral movement",
            },
            {
                "id": "T1021.001",
                "name": "Remote Desktop Protocol",
                "description": "RDP used to move between internal systems",
            },
            {
                "id": "T1021.002",
                "name": "SMB/Windows Admin Shares",
                "description": "SMB shares used for file transfer and execution",
            },
            {
                "id": "T1021.004",
                "name": "SSH",
                "description": "SSH used to remotely access systems",
            },
        ],
        "severity_weight": 0.85,
        "investigation_guidance": [
            "Verify if source host is authorized to access target(s)",
            "Check authentication logs for success/failure patterns",
            "Look for new admin tool deployments (PsExec, mimikatz)",
            "Map the lateral movement path through the network",
        ],
    },

    "DGA_DETECTED": {
        "tactic": {
            "id": "TA0011",
            "name": "Command and Control",
        },
        "techniques": [
            {
                "id": "T1568.002",
                "name": "Dynamic Resolution: Domain Generation Algorithms",
                "description": "Algorithmically generated domains for C2 infrastructure",
            },
        ],
        "severity_weight": 0.9,
        "investigation_guidance": [
            "Capture and decode the DGA-generated domains",
            "Check if domains resolve — active vs inactive DGA",
            "Identify the malware family based on DGA pattern",
            "Block DGA domains and monitor for new patterns",
        ],
    },

    "SUSPICIOUS_TLS": {
        "tactic": {
            "id": "TA0011",
            "name": "Command and Control",
        },
        "techniques": [
            {
                "id": "T1573.002",
                "name": "Encrypted Channel: Asymmetric Cryptography",
                "description": "TLS/SSL used to encrypt C2 communications",
            },
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "description": "HTTPS used for C2 to blend with legitimate traffic",
            },
        ],
        "severity_weight": 0.7,
        "investigation_guidance": [
            "Extract and match JA3 hash against known malware fingerprints",
            "Inspect certificate details (self-signed, unusual CA, short validity)",
            "Check if destination IP is hosted on bulletproof infrastructure",
            "Analyze TLS handshake for anomalies (e.g., unusual cipher suites)",
        ],
    },

    "PROTOCOL_ANOMALY": {
        "tactic": {
            "id": "TA0011",
            "name": "Command and Control",
        },
        "techniques": [
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "description": "Using unexpected ports for known protocols to evade detection",
            },
            {
                "id": "T1572",
                "name": "Protocol Tunneling",
                "description": "Encapsulating traffic within legitimate protocols",
            },
        ],
        "severity_weight": 0.6,
        "investigation_guidance": [
            "Identify the actual protocol being tunneled",
            "Check if traffic is bypassing firewall rules",
            "Look for data encoding within protocol payloads",
            "Compare against approved protocol/port policies",
        ],
    },

    "CREDENTIAL_ABUSE": {
        "tactic": {
            "id": "TA0006",
            "name": "Credential Access",
        },
        "techniques": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "description": "Systematic password guessing to gain unauthorized access",
            },
            {
                "id": "T1110.001",
                "name": "Password Guessing",
                "description": "Trying common passwords against accounts",
            },
            {
                "id": "T1110.003",
                "name": "Password Spraying",
                "description": "Using one password against many accounts",
            },
            {
                "id": "T1110.004",
                "name": "Credential Stuffing",
                "description": "Using stolen credentials from data breaches",
            },
        ],
        "severity_weight": 0.75,
        "investigation_guidance": [
            "Check authentication logs for success after failures",
            "Identify compromised accounts from successful brute force",
            "Check source IP against threat intelligence",
            "Implement account lockout policies if not present",
        ],
    },

    "DATA_EXFILTRATION": {
        "tactic": {
            "id": "TA0010",
            "name": "Exfiltration",
        },
        "techniques": [
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "description": "Data exfiltrated using existing C2 communication channel",
            },
            {
                "id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "description": "Data exfiltrated using alternative network protocols",
            },
            {
                "id": "T1048.003",
                "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
                "description": "Using DNS, ICMP, or other protocols for data theft",
            },
        ],
        "severity_weight": 0.95,
        "investigation_guidance": [
            "Identify what data may have been exfiltrated",
            "Track total bytes transferred to external destinations",
            "Check if destination is known cloud storage or file sharing",
            "Look for encoding/compression in transfer payloads",
            "Initiate incident response if confirmed",
        ],
    },

    # Generic fallback for ML-only detections
    "ANOMALOUS_FLOW": {
        "tactic": {
            "id": "TA0043",
            "name": "Reconnaissance",
        },
        "techniques": [
            {
                "id": "T1595",
                "name": "Active Scanning",
                "description": "ML-detected anomalous network behavior",
            },
        ],
        "severity_weight": 0.4,
        "investigation_guidance": [
            "Review ML model explanation (SHAP values) for this alert",
            "Check if behavior matches any known attack pattern",
            "Compare with historical baseline for this source IP",
        ],
    },
}


def get_mitre_context(rule_name: str) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK context for a detection rule.

    Returns tactic, techniques, severity weight, and investigation guidance.
    """
    # Normalize rule name
    rule_name = rule_name.upper().replace(" ", "_")

    mapping = RULE_MITRE_MAPPING.get(rule_name)
    if not mapping:
        # Try partial match
        for key, value in RULE_MITRE_MAPPING.items():
            if key in rule_name or rule_name in key:
                mapping = value
                break

    if not mapping:
        mapping = RULE_MITRE_MAPPING.get("ANOMALOUS_FLOW", {})

    return mapping


def enrich_alert_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert with MITRE ATT&CK context.

    Adds tactic/technique information, investigation guidance,
    and ATT&CK Navigator compatibility fields.
    """
    rule_names = alert.get("triggered_rules", [])
    threat_label = alert.get("threat_label", "ANOMALOUS_FLOW")

    # Collect MITRE context from all triggered rules
    tactics = set()
    techniques = []
    guidance = []

    # Primary mapping from threat label
    primary_context = get_mitre_context(threat_label)
    if primary_context:
        tactics.add(primary_context["tactic"]["id"])
        techniques.extend(primary_context.get("techniques", []))
        guidance.extend(primary_context.get("investigation_guidance", []))

    # Additional mappings from triggered rules
    for rule_name in rule_names:
        context = get_mitre_context(rule_name)
        if context:
            tactics.add(context["tactic"]["id"])
            for tech in context.get("techniques", []):
                if tech["id"] not in [t["id"] for t in techniques]:
                    techniques.append(tech)
            for g in context.get("investigation_guidance", []):
                if g not in guidance:
                    guidance.append(g)

    # Enrich the alert
    alert["mitre_attack"] = {
        "tactics": list(tactics),
        "techniques": [
            {"id": t["id"], "name": t["name"]}
            for t in techniques
        ],
        "technique_ids": [t["id"] for t in techniques],
    }
    alert["investigation_guidance"] = guidance[:5]  # Top 5 recommendations

    return alert


def generate_navigator_layer(
    alerts: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a MITRE ATT&CK Navigator layer JSON showing
    which techniques have been detected and their frequency.

    Compatible with: https://mitre-attack.github.io/attack-navigator/
    """
    # Count technique detections
    technique_counts: Dict[str, int] = {}
    technique_names: Dict[str, str] = {}

    for alert in alerts:
        mitre = alert.get("mitre_attack", {})
        for tech in mitre.get("techniques", []):
            tid = tech["id"]
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
            technique_names[tid] = tech["name"]

    # Build navigator layer
    max_count = max(technique_counts.values()) if technique_counts else 1

    layer = {
        "name": "SentinelHunt Detections",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"SentinelHunt detection coverage — {len(alerts)} alerts analyzed",
        "filters": {
            "platforms": ["Linux", "Windows", "macOS", "Network"],
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "metadata": [
            {
                "name": "generated_by",
                "value": "SentinelHunt Threat Hunting Platform",
            },
            {
                "name": "generated_at",
                "value": datetime.utcnow().isoformat() + "Z",
            },
            {
                "name": "total_alerts",
                "value": str(len(alerts)),
            },
        ],
    }

    for tid, count in technique_counts.items():
        layer["techniques"].append({
            "techniqueID": tid,
            "tactic": "",
            "color": "",
            "comment": f"Detected {count} times by SentinelHunt",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": True,
            "score": count,
        })

    if output_path:
        with open(output_path, "w") as f:
            json.dump(layer, f, indent=2)
        logger.info(
            "ATT&CK Navigator layer saved to %s (%d techniques covered)",
            output_path, len(technique_counts),
        )

    return layer


def get_technique_coverage_summary() -> Dict[str, Any]:
    """
    Get a summary of MITRE ATT&CK technique coverage.
    """
    all_tactics = set()
    all_techniques = set()

    for rule_name, mapping in RULE_MITRE_MAPPING.items():
        all_tactics.add(mapping["tactic"]["id"])
        for tech in mapping.get("techniques", []):
            all_techniques.add(tech["id"])

    return {
        "total_rules_mapped": len(RULE_MITRE_MAPPING),
        "tactics_covered": len(all_tactics),
        "techniques_covered": len(all_techniques),
        "tactic_ids": sorted(all_tactics),
        "technique_ids": sorted(all_techniques),
    }
