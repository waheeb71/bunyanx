"""
bunyanx NGFW — AEGIS v3: Simulated CTI Feed
================================================

Static Threat Intelligence Feed (STIX-like, simulated).

Rationale for Simulation (as per Section IV of the paper):
    For academic reproducibility, the CTI feed is simulated using
    calibrated data from IBM X-Force 2024 and Mandiant M-Trends 2024.
    The module implements ThreatIntelFeedProtocol, enabling future
    replacement with a live STIX/TAXII source (e.g., MISP, AlienVault OTX)
    without modifying ThreatProbabilityEngine.

Future Work (noted in paper §VII):
    Live feed integration via:
        from taxii2client.v21 import Server
        server = Server("https://cti.example.org/taxii/")

Reference:
    STIX 2.1 Specification — OASIS, 2021
    TAXII 2.1 Specification — OASIS, 2021
"""

from __future__ import annotations

import logging

from modules.predictive_ai.engine.tpe.risk_context import (
    AttackVector,
    OrgSector,
    ThreatIntelFeedProtocol,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Campaign Database (simulated STIX bundles, IBM X-Force + Mandiant 2024)
# ---------------------------------------------------------------------------

# Each campaign entry represents an active threat campaign in Q1-Q2 2024.
# Format: list of campaign dicts per sector.
# Fields:
#   name       : Campaign identifier
#   actor      : Threat actor group
#   likelihood : P(org targeted | sector) for this specific campaign
#   vector     : Primary initial access method
#   ttps       : Top 3 MITRE ATT&CK technique IDs

_CAMPAIGNS: dict[OrgSector, list[dict]] = {

    OrgSector.BANKING: [
        {
            "name": "OPERATION_CARBANAK_RELOADED",
            "actor": "CARBANAK",
            "likelihood": 0.45,
            "vector": AttackVector.PHISHING,
            "ttps": ["T1566.001", "T1059.001", "T1041"],
        },
        {
            "name": "LAZARUS_SWIFT_HEIST_2024",
            "actor": "Lazarus Group (DPRK)",
            "likelihood": 0.35,
            "vector": AttackVector.EXTERNAL_EXPLOIT,
            "ttps": ["T1190", "T1055", "T1041"],
        },
        {
            "name": "FIN7_VISHING_CAMPAIGN",
            "actor": "FIN7",
            "likelihood": 0.30,
            "vector": AttackVector.CREDENTIAL_THEFT,
            "ttps": ["T1078", "T1059.001", "T1486"],
        },
    ],

    OrgSector.GOVERNMENT: [
        {
            "name": "APT29_MIDNIGHT_BLIZZARD",
            "actor": "APT29 (Cozy Bear / SVR)",
            "likelihood": 0.55,
            "vector": AttackVector.PHISHING,
            "ttps": ["T1566.002", "T1078", "T1560"],
        },
        {
            "name": "APT28_FOREST_BLIZZARD",
            "actor": "APT28 (Fancy Bear / GRU)",
            "likelihood": 0.40,
            "vector": AttackVector.SUPPLY_CHAIN,
            "ttps": ["T1195.002", "T1190", "T1083"],
        },
    ],

    OrgSector.HEALTHCARE: [
        {
            "name": "LOCKBIT_HEALTHCARE_SURGE_2024",
            "actor": "LockBit 3.0",
            "likelihood": 0.60,
            "vector": AttackVector.RANSOMWARE,
            "ttps": ["T1486", "T1133", "T1489"],
        },
        {
            "name": "BLACKCAT_MEDICAL_EXTORTION",
            "actor": "BlackCat (ALPHV)",
            "likelihood": 0.45,
            "vector": AttackVector.EXTERNAL_EXPLOIT,
            "ttps": ["T1190", "T1486", "T1048"],
        },
    ],

    OrgSector.ENERGY: [
        {
            "name": "VOLT_TYPHOON_OT_PREPOSITION",
            "actor": "Volt Typhoon (PRC)",
            "likelihood": 0.50,
            "vector": AttackVector.OT_ICS,
            "ttps": ["T1190", "T0816", "T1078"],
        },
        {
            "name": "SANDWORM_INDUSTROYER2",
            "actor": "Sandworm (GRU)",
            "likelihood": 0.35,
            "vector": AttackVector.SUPPLY_CHAIN,
            "ttps": ["T0816", "T1195", "T0831"],
        },
    ],

    OrgSector.TECH: [
        {
            "name": "APT41_SUPPLY_CHAIN_PIVOT",
            "actor": "APT41 (China-nexus)",
            "likelihood": 0.40,
            "vector": AttackVector.SUPPLY_CHAIN,
            "ttps": ["T1195.001", "T1059.003", "T1574"],
        },
        {
            "name": "UNC3944_OKTA_SMISHING",
            "actor": "UNC3944 (Scattered Spider)",
            "likelihood": 0.35,
            "vector": AttackVector.CREDENTIAL_THEFT,
            "ttps": ["T1078", "T1621", "T1110"],
        },
    ],

    OrgSector.DEFENSE: [
        {
            "name": "APT40_DEFENCE_ESPIONAGE",
            "actor": "APT40 (China MSS)",
            "likelihood": 0.55,
            "vector": AttackVector.PHISHING,
            "ttps": ["T1566.002", "T1560", "T1048"],
        },
        {
            "name": "CHARMING_KITTEN_CONTRACTOR_OPS",
            "actor": "Charming Kitten (IRGC)",
            "likelihood": 0.45,
            "vector": AttackVector.ZERO_DAY,
            "ttps": ["T1190", "T1059.006", "T1560"],
        },
    ],

    OrgSector.RETAIL: [
        {
            "name": "MAGECART_SKIMMING_2024",
            "actor": "Magecart",
            "likelihood": 0.40,
            "vector": AttackVector.WEB_SKIMMING,
            "ttps": ["T1185", "T1059.007", "T1078"],
        },
    ],

    OrgSector.EDUCATION: [
        {
            "name": "VICE_SOCIETY_SCHOOL_RANSOMWARE",
            "actor": "Vice Society",
            "likelihood": 0.38,
            "vector": AttackVector.RANSOMWARE,
            "ttps": ["T1486", "T1110", "T1566"],
        },
    ],

    OrgSector.TELECOM: [
        {
            "name": "SALT_TYPHOON_LAWFUL_INTERCEPT",
            "actor": "Salt Typhoon (China MSS)",
            "likelihood": 0.50,
            "vector": AttackVector.EXTERNAL_EXPLOIT,
            "ttps": ["T1190", "T1078", "T1083"],
        },
    ],

    OrgSector.CRITICAL_INFRA: [
        {
            "name": "VOLT_TYPHOON_CI_PREPOSITION",
            "actor": "Volt Typhoon (PRC)",
            "likelihood": 0.60,
            "vector": AttackVector.OT_ICS,
            "ttps": ["T0816", "T1190", "T1078"],
        },
        {
            "name": "SANDWORM_GRID_ATTACK",
            "actor": "Sandworm (GRU)",
            "likelihood": 0.50,
            "vector": AttackVector.SUPPLY_CHAIN,
            "ttps": ["T0816", "T1195", "T0831"],
        },
    ],
}


# ---------------------------------------------------------------------------
# StaticCTIFeed — implements ThreatIntelFeedProtocol
# ---------------------------------------------------------------------------

class StaticCTIFeed:
    """
    Simulated Cyber Threat Intelligence Feed.

    Implements ThreatIntelFeedProtocol using calibrated static data
    from IBM X-Force 2024 and Mandiant M-Trends 2024.

    Designed as an interface:
        To integrate a Live STIX/TAXII feed in future work,
        create a class LiveSTIXFeed(ThreatIntelFeedProtocol) and
        inject it into ThreatProbabilityEngine — no engine changes needed.

    Parameters
    ----------
    geopolitical_multiplier : float
        External geopolitical tension factor (from GeopoliticalZone).
        Acts as a campaign-intensity amplifier.
    """

    def __init__(self, geopolitical_multiplier: float = 1.0) -> None:
        self._geo_mult = geopolitical_multiplier
        _log.debug("StaticCTIFeed initialized (geo_mult=%.1f)", geopolitical_multiplier)

    def get_active_campaigns(self, sector: OrgSector) -> list[dict]:
        """Return active campaigns targeting the given sector."""
        campaigns = _CAMPAIGNS.get(sector, [])
        # Apply geopolitical amplification to likelihood
        result = []
        for c in campaigns:
            amplified = dict(c)
            amplified["likelihood"] = min(1.0, c["likelihood"] * self._geo_mult)
            result.append(amplified)
        return result

    def get_campaign_intensity(self, sector: OrgSector) -> float:
        """
        Aggregate CTI signal: max campaign likelihood for the sector.
        Returns 0.0 if no campaigns are active.
        """
        campaigns = self.get_active_campaigns(sector)
        if not campaigns:
            return 0.0
        intensity = max(c["likelihood"] for c in campaigns)
        _log.debug(
            "CTI intensity for sector=%s: %.3f (geo_mult=%.1f)",
            sector.value, intensity, self._geo_mult,
        )
        return intensity

    def get_dominant_campaign(self, sector: OrgSector) -> dict | None:
        """Return the highest-likelihood campaign for the sector."""
        campaigns = self.get_active_campaigns(sector)
        if not campaigns:
            return None
        return max(campaigns, key=lambda c: c["likelihood"])
