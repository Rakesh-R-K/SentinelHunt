"""
SentinelHunt — Domain Generation Algorithm (DGA) Detection Rule

Detects algorithmically generated domain names used by malware for
Command & Control communication (MITRE ATT&CK: T1568.002).

Detection approach:
    - Character-level n-gram frequency analysis
    - Shannon entropy of domain labels
    - Vowel/consonant ratio anomalies
    - Consecutive consonant sequences
    - Domain length heuristics
    - Numeric character ratio

Research basis:
    - Woodbridge, J. et al. (2016). Predicting DGA with LSTM
    - Schiavoni, S. et al. (2014). Phoenix: DGA-Based Botnet Tracking
"""

import math
import re
from collections import Counter
from typing import Dict, Any, Tuple, Optional

import logging

logger = logging.getLogger("sentinelhunt.rules.dga_detector")

# Known legitimate high-entropy domains (false positive suppression)
LEGITIMATE_HIGH_ENTROPY = {
    "amazonaws.com", "cloudfront.net", "akamaihd.net",
    "googleapis.com", "googleusercontent.com",
    "cloudflare.com", "fastly.net",
}

# English language bigram frequencies (top pairs)
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at",
    "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar", "st", "nt", "ng", "se",
    "ha", "as", "ou", "io", "le", "ve", "co", "me",
}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _vowel_consonant_ratio(s: str) -> float:
    """Calculate ratio of vowels to consonants."""
    s = s.lower()
    vowels = sum(1 for c in s if c in "aeiou")
    consonants = sum(1 for c in s if c.isalpha() and c not in "aeiou")
    if consonants == 0:
        return 5.0 if vowels > 0 else 0.0
    return vowels / consonants


def _max_consecutive_consonants(s: str) -> int:
    """Find longest run of consecutive consonants."""
    s = s.lower()
    max_run = 0
    current_run = 0
    for c in s:
        if c.isalpha() and c not in "aeiou":
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 0
    return max_run


def _bigram_legitimacy_score(s: str) -> float:
    """
    Score how much a string's bigrams match common English patterns.
    Lower score = more random/DGA-like.
    """
    s = s.lower()
    if len(s) < 2:
        return 1.0

    bigrams = [s[i:i + 2] for i in range(len(s) - 1)]
    matches = sum(1 for bg in bigrams if bg in COMMON_BIGRAMS)
    return matches / len(bigrams) if bigrams else 0.0


def _numeric_ratio(s: str) -> float:
    """Ratio of numeric characters in the string."""
    if not s:
        return 0.0
    digits = sum(1 for c in s if c.isdigit())
    return digits / len(s)


def _extract_domain_label(domain: str) -> str:
    """Extract the second-level domain label for analysis."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]  # e.g., 'example' from 'sub.example.com'
    return parts[0] if parts else ""


def calculate_dga_score(domain: str) -> Dict[str, float]:
    """
    Calculate a comprehensive DGA probability score.

    Returns individual feature scores and a combined DGA score.
    """
    label = _extract_domain_label(domain)

    if not label or len(label) < 3:
        return {"dga_score": 0.0, "reason": "too_short"}

    # Feature extraction
    entropy = _shannon_entropy(label)
    vc_ratio = _vowel_consonant_ratio(label)
    max_consonants = _max_consecutive_consonants(label)
    bigram_score = _bigram_legitimacy_score(label)
    num_ratio = _numeric_ratio(label)
    length = len(label)

    # Scoring (each contributes to overall DGA likelihood)
    scores = {}

    # High entropy → random characters → DGA
    scores["entropy"] = min(entropy / 4.5, 1.0) if entropy > 2.5 else 0.0

    # Abnormal vowel/consonant ratio
    if vc_ratio < 0.2 or vc_ratio > 1.5:
        scores["vc_ratio"] = 0.3
    else:
        scores["vc_ratio"] = 0.0

    # Long consecutive consonant sequences → unpronounceable → DGA
    scores["consonant_run"] = min(max_consonants / 6.0, 1.0) if max_consonants > 3 else 0.0

    # Low bigram legitimacy → random combinations → DGA
    scores["bigram"] = (1.0 - bigram_score) * 0.5

    # High numeric ratio → random generation with numbers
    scores["numeric"] = num_ratio * 0.8

    # Very long domain labels → DGA or tunnel
    scores["length"] = min((length - 10) / 20.0, 0.5) if length > 12 else 0.0

    # Weighted combination
    weights = {
        "entropy": 0.30,
        "vc_ratio": 0.10,
        "consonant_run": 0.15,
        "bigram": 0.25,
        "numeric": 0.10,
        "length": 0.10,
    }

    dga_score = sum(
        scores[k] * weights[k] for k in weights
    )

    return {
        "dga_score": round(min(dga_score, 1.0), 4),
        "entropy": round(entropy, 4),
        "vc_ratio": round(vc_ratio, 4),
        "max_consonants": max_consonants,
        "bigram_legitimacy": round(bigram_score, 4),
        "numeric_ratio": round(num_ratio, 4),
        "label_length": length,
        "features": scores,
    }


def detect(flow: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Detect potential DGA-generated domains in DNS queries.

    Criteria:
        - DNS traffic (UDP port 53 or known DNS query)
        - Domain label exhibits DGA characteristics
        - Combined DGA score exceeds threshold
    """
    protocol = flow.get("protocol", "").upper()
    dst_port = flow.get("dst_port", -1)
    dns_entropy = flow.get("dns_entropy", 0)
    dns_query_length = flow.get("dns_query_length", 0)
    dns_subdomain_depth = flow.get("dns_subdomain_depth", 0)

    # Only process DNS traffic
    if not (protocol == "UDP" and dst_port == 53):
        if dns_query_length == 0:
            return False, None

    # Use available DNS features
    indicators = []
    dga_score = 0.0

    # High entropy in DNS query is primary DGA signal
    if dns_entropy > 3.8:
        dga_score += 0.35
        indicators.append(f"High DNS entropy ({dns_entropy:.2f})")

    if dns_entropy > 3.5 and dns_query_length > 30:
        dga_score += 0.15
        indicators.append(f"Long high-entropy domain ({dns_query_length} chars)")

    # Deep subdomain structure (DGA + tunneling)
    if dns_subdomain_depth >= 4:
        dga_score += 0.20
        indicators.append(f"Deep subdomain nesting (depth={dns_subdomain_depth})")

    # Very long DNS queries (> 50 chars)
    if dns_query_length > 50:
        dga_score += 0.15
        indicators.append(f"Unusually long DNS query ({dns_query_length} chars)")

    # Combined entropy and depth
    if dns_entropy > 3.2 and dns_subdomain_depth >= 3:
        dga_score += 0.15
        indicators.append("Combined high entropy + deep subdomain pattern")

    # Threshold check
    DGA_THRESHOLD = 0.35
    if dga_score < DGA_THRESHOLD or not indicators:
        return False, None

    return True, {
        "rule": "DGA_DETECTED",
        "severity_boost": min(dga_score * 0.5, 0.4),
        "indicator": "; ".join(indicators),
        "dga_score": round(dga_score, 4),
        "mitre_tactic": "TA0011",
        "mitre_technique": "T1568.002",
    }
