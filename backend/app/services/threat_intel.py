"""
UMEagleEye - Threat Intelligence Service (FR-04).
AlienVault OTX ingestion, IoC cross-referencing, MITRE ATT&CK mapping.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.db.enums import IndicatorType, Severity

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique mapping for common threat patterns
MITRE_ATTACK_MAP = {
    "ip": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "domain": {"tactic": "Command and Control", "technique": "T1071.001", "name": "Web Protocols"},
    "url": {"tactic": "Initial Access", "technique": "T1566.002", "name": "Spearphishing Link"},
    "hash": {"tactic": "Execution", "technique": "T1204.002", "name": "Malicious File"},
    "email": {"tactic": "Initial Access", "technique": "T1566.001", "name": "Spearphishing Attachment"},
    "cve": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "mutex": {"tactic": "Execution", "technique": "T1106", "name": "Native API"},
    "filepath": {"tactic": "Persistence", "technique": "T1547", "name": "Boot or Logon Autostart Execution"},
}

# Extended MITRE ATT&CK tactics for the matrix view
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]


class ThreatIntelService:
    """Handles CTI ingestion from AlienVault OTX and MITRE ATT&CK mapping."""

    # ═══════════════════════════════════════════════════════════
    # FR-04-01: CTI Ingestion Pipeline (AlienVault OTX)
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    async def fetch_otx_pulses(days: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent threat pulses from AlienVault OTX API.

        Args:
            days: Number of days to look back
            limit: Maximum number of pulses to fetch

        Returns:
            List of normalized indicator dictionaries
        """
        if not settings.OTX_API_KEY:
            logger.warning("OTX_API_KEY not configured")
            return []

        indicators = []
        try:
            headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
            base_url = "https://otx.alienvault.com/api/v1"

            async with httpx.AsyncClient(timeout=30) as client:
                # Fetch subscribed pulses (most relevant)
                resp = await client.get(
                    f"{base_url}/pulses/subscribed",
                    headers=headers,
                    params={"modified_since": f"{days}d", "limit": limit},
                )
                if resp.status_code != 200:
                    logger.error(f"OTX API returned {resp.status_code}")
                    return []

                data = resp.json()
                if not isinstance(data, dict):
                    logger.error(f"OTX API returned unexpected format: {type(data)}")
                    return []
                    
                pulses = data.get("results", [])
                if not isinstance(pulses, list):
                    logger.error(f"OTX API results is not a list: {type(pulses)}")
                    return []

                for pulse in pulses:
                    if not isinstance(pulse, dict):
                        continue
                        
                    pulse_name = pulse.get("name", "Unknown Pulse")
                    pulse_tags = pulse.get("tags", [])
                    attack_ids = pulse.get("attack_ids", [])

                    # Extract MITRE ATT&CK info from pulse
                    attack_tactic = ""
                    attack_technique = ""
                    if attack_ids and isinstance(attack_ids, list) and len(attack_ids) > 0:
                        aid = attack_ids[0]
                        if isinstance(aid, dict):
                            attack_technique = aid.get("id", "")
                            attack_tactic = aid.get("name", "")

                    for ind in pulse.get("indicators", []):
                        if not isinstance(ind, dict):
                            continue
                            
                        indicator_type = ThreatIntelService._map_otx_type(ind.get("type", ""))
                        if not indicator_type:
                            continue

                        indicators.append({
                            "source": "AlienVault OTX",
                            "indicator_type": indicator_type,
                            "value": ind.get("indicator", ""),
                            "confidence_score": 0.7,
                            "attack_tactic": attack_tactic or MITRE_ATTACK_MAP.get(
                                indicator_type.value, {}
                            ).get("tactic", ""),
                            "attack_technique": attack_technique or MITRE_ATTACK_MAP.get(
                                indicator_type.value, {}
                            ).get("technique", ""),
                            "pulse_name": pulse_name,
                            "tags": pulse_tags,
                            "first_seen": ind.get("created", datetime.now(timezone.utc).isoformat()),
                        })

                logger.info(f"Fetched {len(indicators)} indicators from {len(pulses)} OTX pulses")

        except Exception:
            logger.exception("OTX fetch error")

        return indicators

    @staticmethod
    async def fetch_abusech_threatfox(days: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent IoCs from abuse.ch ThreatFox API."""
        indicators = []
        try:
            headers = {"User-Agent": "UMEagleEye/2.0 CAASM Threat Intel Engine"}
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "get_iocs", "days": days},
                    headers=headers,
                )

                if resp.status_code != 200:
                    logger.warning(f"ThreatFox API returned {resp.status_code}: {resp.text[:100]}")
                    return []

                data = resp.json()
                for ioc in data.get("data", [])[:200]:  # Limit to 200
                    ioc_type = ioc.get("ioc_type", "")
                    indicator_type = None
                    if "ip" in ioc_type:
                        indicator_type = IndicatorType.IP
                    elif "domain" in ioc_type:
                        indicator_type = IndicatorType.DOMAIN
                    elif "url" in ioc_type:
                        indicator_type = IndicatorType.URL
                    elif "md5" in ioc_type or "sha" in ioc_type:
                        indicator_type = IndicatorType.HASH

                    if not indicator_type:
                        continue

                    indicators.append({
                        "source": "abuse.ch ThreatFox",
                        "indicator_type": indicator_type,
                        "value": ioc.get("ioc", ""),
                        "confidence_score": min(ioc.get("confidence_level", 50) / 100, 1.0),
                        "attack_tactic": "Command and Control",
                        "attack_technique": ioc.get("threat_type", ""),
                        "first_seen": ioc.get("first_seen_utc", ""),
                    })

                logger.info(f"Fetched {len(indicators)} indicators from ThreatFox")

        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")

        return indicators

    # ═══════════════════════════════════════════════════════════
    # FR-04-02: Proximity & Triage Scoring Engine
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def compute_triage_score(
        indicator_confidence: float,
        matched_asset_criticality: int,
        is_internet_facing: bool,
        indicator_type: str,
    ) -> int:
        """Cross-reference IoC against internal asset and compute triage score (1-100).

        A MyCERT/OTX-flagged IP talking to an internal database server = Critical score.
        """
        base = indicator_confidence * 40  # 0-40 from confidence

        # Asset criticality contribution (0-30)
        criticality_contrib = (matched_asset_criticality / 10) * 30

        # Exposure multiplier (0-20)
        exposure = 20 if is_internet_facing else 5

        # Indicator type weight (0-10)
        type_weights = {"ip": 10, "domain": 8, "url": 7, "hash": 6, "email": 5}
        type_contrib = type_weights.get(indicator_type, 5)

        score = int(min(base + criticality_contrib + exposure + type_contrib, 100))
        return max(score, 1)

    @staticmethod
    def classify_triage_severity(score: int) -> Severity:
        """Convert triage score to severity level."""
        if score >= 80:
            return Severity.CRITICAL
        elif score >= 60:
            return Severity.HIGH
        elif score >= 40:
            return Severity.MEDIUM
        return Severity.LOW

    # ═══════════════════════════════════════════════════════════
    # FR-04-03: MITRE ATT&CK Data Mapper
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def map_to_mitre_attack(
        indicator_type: str,
        tags: List[str] = None,
        existing_technique: str = None,
    ) -> Dict[str, str]:
        """Map indicator/vulnerability to MITRE ATT&CK tactic/technique.

        Returns dict with tactic, technique_id, technique_name.
        """
        if existing_technique and existing_technique.startswith("T"):
            return {
                "technique_id": existing_technique,
                "tactic": MITRE_ATTACK_MAP.get(indicator_type, {}).get("tactic", "Unknown"),
                "technique_name": existing_technique,
            }

        mapping = MITRE_ATTACK_MAP.get(indicator_type, {})
        return {
            "technique_id": mapping.get("technique", ""),
            "tactic": mapping.get("tactic", "Unknown"),
            "technique_name": mapping.get("name", ""),
        }

    @staticmethod
    def get_attack_matrix_data(indicators: List[Dict]) -> Dict[str, List[Dict]]:
        """Build MITRE ATT&CK matrix data from indicators for frontend rendering."""
        matrix = {tactic: [] for tactic in MITRE_TACTICS}

        seen_techniques = set()
        for ind in indicators:
            tactic = ind.get("attack_tactic", "")
            technique = ind.get("attack_technique", "")

            if tactic in matrix and technique and technique not in seen_techniques:
                seen_techniques.add(technique)
                matrix[tactic].append({
                    "technique_id": technique,
                    "count": 1,
                    "source": ind.get("source", ""),
                })

        # Merge duplicates and count
        for tactic in matrix:
            tech_counts = {}
            for t in matrix[tactic]:
                tid = t["technique_id"]
                if tid in tech_counts:
                    tech_counts[tid]["count"] += 1
                else:
                    tech_counts[tid] = t
            matrix[tactic] = list(tech_counts.values())

        return matrix

    @staticmethod
    def _map_otx_type(otx_type: str) -> Optional[IndicatorType]:
        """Map OTX indicator type to our IndicatorType enum."""
        mapping = {
            "IPv4": IndicatorType.IP,
            "IPv6": IndicatorType.IP,
            "domain": IndicatorType.DOMAIN,
            "hostname": IndicatorType.DOMAIN,
            "URL": IndicatorType.URL,
            "URI": IndicatorType.URL,
            "FileHash-MD5": IndicatorType.HASH,
            "FileHash-SHA1": IndicatorType.HASH,
            "FileHash-SHA256": IndicatorType.HASH,
            "email": IndicatorType.EMAIL,
        }
        return mapping.get(otx_type)
