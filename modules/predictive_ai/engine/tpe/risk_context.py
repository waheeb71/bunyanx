"""
bunyanx NGFW — AEGIS v3: Threat Probability Engine (TPE)
============================================================
Risk Context Data Models

Defines the organizational profile inputs for Stage 1 (pre-attack prediction).
All data models are immutable (frozen dataclasses) to ensure thread-safety
and reproducibility in academic benchmarks.

Design principle:
    Interface-first — ThreatIntelFeed is an abstract protocol so future
    work can swap in a live STIX/TAXII feed without changing the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class OrgSector(str, Enum):
    """
    Industry vertical classification.
    Base attack-rate priors derived from:
      - Verizon DBIR 2024 (industries + breach patterns)
      - IBM X-Force Threat Intelligence Index 2024
    """
    BANKING     = "BANKING"      # Financial services (banks, insurance)
    GOVERNMENT  = "GOVERNMENT"   # Public sector, ministries
    HEALTHCARE  = "HEALTHCARE"   # Hospitals, pharma, medical devices
    ENERGY      = "ENERGY"       # Oil & gas, power grids, utilities
    TECH        = "TECH"         # Software, SaaS, cloud providers
    DEFENSE     = "DEFENSE"      # Military, defense contractors
    RETAIL      = "RETAIL"       # E-commerce, retail chains
    EDUCATION   = "EDUCATION"    # Universities, research centres
    TELECOM     = "TELECOM"      # ISPs, mobile operators
    CRITICAL_INFRA = "CRITICAL_INFRA"  # Water, transport, airports


class GeopoliticalZone(str, Enum):
    """
    Environmental threat multiplier based on regional geopolitical tension.
    Calibrated from Recorded Future Geopolitical Risk Index 2024.
    """
    WAR_ZONE     = "WAR_ZONE"      # Active armed conflict  (×2.0)
    HIGH_TENSION = "HIGH_TENSION"  # Sanctions, proxy ops   (×1.5)
    MODERATE     = "MODERATE"      # Political instability  (×1.2)
    STABLE       = "STABLE"        # Low-threat region      (×1.0)


class OrgSize(str, Enum):
    """Organization size — larger orgs have wider attack surfaces."""
    ENTERPRISE = "ENTERPRISE"   # >5000 employees
    MID        = "MID"          # 250–5000 employees
    SMB        = "SMB"          # <250 employees


class RiskLevel(str, Enum):
    """Final threat assessment output level."""
    HIGH   = "HIGH"    # Score ≥ 0.75  →  Pre-arm AEGIS
    MEDIUM = "MEDIUM"  # Score 0.50–0.75 →  Elevated monitoring
    LOW    = "LOW"     # Score < 0.50   →  Normal posture


class AttackVector(str, Enum):
    """Most likely initial access vector predicted by TPE."""
    PHISHING        = "PHISHING"
    EXTERNAL_EXPLOIT= "EXTERNAL_EXPLOIT"
    SUPPLY_CHAIN    = "SUPPLY_CHAIN"
    INSIDER         = "INSIDER"
    OT_ICS          = "OT_ICS"
    WEB_SKIMMING    = "WEB_SKIMMING"
    CREDENTIAL_THEFT= "CREDENTIAL_THEFT"
    RANSOMWARE      = "RANSOMWARE"
    ZERO_DAY        = "ZERO_DAY"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VulnerabilityContext:
    """
    Technical exposure snapshot for the organization's asset inventory.

    In production, these scores are populated by the VulnerabilityPredictor.
    In academic evaluation, they are provided by benchmark scenarios.

    Parameters
    ----------
    avg_epss : float
        Average EPSS (Exploit Prediction Scoring System) score across all
        internet-facing assets. Range: [0.0, 1.0].
        Source: https://www.first.org/epss
    max_cvss : float
        Maximum CVSS v3 base score across known unpatched vulnerabilities.
        Range: [0.0, 10.0].
    num_critical_vulns : int
        Count of critical (CVSS ≥ 9.0) or CISA KEV-listed vulnerabilities.
    internet_exposed_assets : int
        Number of publicly reachable services (ports open to internet).
    days_since_last_patch : int
        Days since last security patch cycle. Older = higher risk.
    """
    avg_epss:                float = 0.05
    max_cvss:                float = 5.0
    num_critical_vulns:      int   = 0
    internet_exposed_assets: int   = 10
    days_since_last_patch:   int   = 30


@dataclass(frozen=True)
class HistoricalBreachRecord:
    """
    Organization's breach history for Prior probability estimation.

    Parameters
    ----------
    breaches_last_12m : int
        Number of confirmed security incidents in the past 12 months.
    avg_dwell_days : float
        Average attacker dwell time before detection (days).
        Industry average: 204 days (IBM Cost of a Breach 2024).
    ransomware_history : bool
        True if the org has been hit by ransomware before.
    """
    breaches_last_12m: int   = 0
    avg_dwell_days:    float = 60.0
    ransomware_history: bool = False


@dataclass(frozen=True)
class OrganizationProfile:
    """
    Complete organizational risk profile — the primary input to TPE.

    This is the "context" that the doctor requested:
    the algorithm needs to know *who* the organization is
    before predicting *what* threat they will face.

    Parameters
    ----------
    sector : OrgSector
        Industry vertical (banking, government, etc.)
    geo_zone : GeopoliticalZone
        Current geopolitical environment of the org's primary operations.
    size : OrgSize
        Organization size class.
    vuln_context : VulnerabilityContext
        Asset vulnerability snapshot.
    breach_history : HistoricalBreachRecord
        Past breach records.
    has_ot_environment : bool
        True if org has Operational Technology / ICS systems (higher risk).
    is_critical_infrastructure : bool
        True if org operates critical national infrastructure.
    name : str
        Human-readable label (for reports/logging).
    """
    sector:                   OrgSector
    geo_zone:                 GeopoliticalZone
    size:                     OrgSize              = OrgSize.ENTERPRISE
    vuln_context:             VulnerabilityContext  = field(default_factory=VulnerabilityContext)
    breach_history:           HistoricalBreachRecord = field(default_factory=HistoricalBreachRecord)
    has_ot_environment:       bool                 = False
    is_critical_infrastructure: bool               = False
    name:                     str                  = "Unknown Organization"


# ---------------------------------------------------------------------------
# TPE Output
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackLikelihoodReport:
    """
    Stage 1 (TPE) output report — pre-attack threat assessment.

    All component scores are preserved for transparency and paper reporting.
    """
    # Final scores
    threat_score:       float            # [0.0, 1.0]
    risk_level:         RiskLevel

    # Prediction outputs
    most_likely_vector: AttackVector
    most_likely_actor:  str              # e.g. "APT29 / FIN7"
    expected_ttps:      list[str]        # Top 3 MITRE ATT&CK TTPs predicted

    # Component scores (for ablation / paper)
    p_sector:           float            # P(attack | sector)
    p_geo:              float            # P(attack | geopolitical_zone)
    p_vuln:             float            # P(attack | CVSS/EPSS)
    p_cti:              float            # P(attack | active CTI campaigns)
    p_history:          float            # P(attack | historical breaches)

    # Weights used (supports Dynamic Weighting audit)
    alpha_weights:      tuple[float, ...] # (α1, α2, α3, α4, α5)

    # Tactical recommendations
    recommendations:    list[str]        # Prioritized action items

    # Pre-arm directive to AEGIS Stage 2
    pre_arm_AEGIS:     bool             # True if AEGIS should lower threshold
    deploy_honeypots:   bool             # True if score > 0.80

    # Context
    org_name:           str
    sector:             str
    geo_zone:           str

    def __str__(self) -> str:
        emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[self.risk_level.value]
        return (
            f"{emoji} [{self.risk_level.value}] ThreatScore={self.threat_score:.3f} | "
            f"Org={self.org_name} | Sector={self.sector} | "
            f"Vector={self.most_likely_vector.value} | "
            f"Actor={self.most_likely_actor}"
        )


# ---------------------------------------------------------------------------
# CTI Feed Protocol (interface for STIX/TAXII extensibility)
# ---------------------------------------------------------------------------

@runtime_checkable
class ThreatIntelFeedProtocol(Protocol):
    """
    Abstract interface for Threat Intelligence Feeds.

    Current implementation: StaticCTIFeed (simulated, DBIR/X-Force calibrated).
    Future work: LiveSTIXFeed (connect to MISP or AlienVault OTX via TAXII).

    By programming to this interface, swapping data sources requires
    zero changes to ThreatProbabilityEngine — only a new Feed class.
    """

    def get_active_campaigns(self, sector: OrgSector) -> list[dict]:
        """
        Return active threat campaigns targeting the given sector.

        Returns
        -------
        list[dict] with keys:
            name (str), actor (str), likelihood (float 0-1),
            primary_vector (AttackVector), top_ttps (list[str])
        """
        ...

    def get_campaign_intensity(self, sector: OrgSector) -> float:
        """
        Aggregate CTI signal intensity for the sector.
        Returns float in [0.0, 1.0]. Higher = more active campaigns.
        """
        ...
