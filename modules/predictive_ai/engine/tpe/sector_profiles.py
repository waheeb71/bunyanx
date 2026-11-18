"""
bunyanx NGFW — AEGIS v3: TPE Sector Risk Profiles
======================================================

Empirically calibrated risk data per industry sector.

Data Sources (cited in paper):
  - Verizon Data Breach Investigations Report (DBIR) 2024
  - IBM X-Force Threat Intelligence Index 2024
  - CISA Sector Risk Assessments 2023-2024
  - Mandiant M-Trends 2024

Structure per sector:
  - base_attack_rate: P(breach | sector per year) — from DBIR 2024
  - risk_weight: Composite attractiveness to adversaries [0,1]
  - primary_vectors: Ranked list of most common initial access vectors
  - top_threat_actors: Nation-state/criminal groups most active in sector
  - top_ttps: MITRE ATT&CK techniques most observed in sector breaches
  - avg_dwell_days: Average attacker dwell time before detection
"""

from __future__ import annotations

from modules.predictive_ai.engine.tpe.risk_context import (
    AttackVector,
    OrgSector,
)


# ---------------------------------------------------------------------------
# Sector profiles (DBIR 2024 + X-Force 2024 calibrated)
# ---------------------------------------------------------------------------

SECTOR_PROFILES: dict[OrgSector, dict] = {

    OrgSector.BANKING: {
        # Verizon DBIR 2024: Financial sector — 35% of breaches involve
        # external actors, 92% financially motivated.
        "base_attack_rate": 0.35,
        "risk_weight":      0.85,
        "primary_vectors": [
            AttackVector.PHISHING,
            AttackVector.EXTERNAL_EXPLOIT,
            AttackVector.CREDENTIAL_THEFT,
        ],
        "top_threat_actors": "FIN7 / CARBANAK / Lazarus Group",
        "top_ttps": [
            "T1566.001 (Spearphishing Attachment)",
            "T1059.001 (PowerShell)",
            "T1041 (Exfiltration Over C2)",
        ],
        "avg_dwell_days": 45,
        "dbir_ref": "DBIR 2024 §Finance: Figure 81",
    },

    OrgSector.GOVERNMENT: {
        # IBM X-Force 2024: Government sector #1 targeted globally.
        # 40% of incidents involve nation-state actors.
        "base_attack_rate": 0.40,
        "risk_weight":      0.90,
        "primary_vectors": [
            AttackVector.PHISHING,
            AttackVector.SUPPLY_CHAIN,
            AttackVector.EXTERNAL_EXPLOIT,
        ],
        "top_threat_actors": "APT29 (Cozy Bear) / APT28 (Fancy Bear) / APT41",
        "top_ttps": [
            "T1566.002 (Spearphishing Link)",
            "T1195.002 (Compromise Software Supply Chain)",
            "T1078 (Valid Accounts)",
        ],
        "avg_dwell_days": 120,
        "dbir_ref": "IBM X-Force 2024 §Public Sector",
    },

    OrgSector.HEALTHCARE: {
        # DBIR 2024: Healthcare #1 in internal actors.
        # Ransomware accounts for 54% of breaches.
        "base_attack_rate": 0.45,
        "risk_weight":      0.95,
        "primary_vectors": [
            AttackVector.RANSOMWARE,
            AttackVector.PHISHING,
            AttackVector.EXTERNAL_EXPLOIT,
        ],
        "top_threat_actors": "BlackCat / LockBit / Vice Society",
        "top_ttps": [
            "T1486 (Data Encrypted for Impact)",
            "T1133 (External Remote Services)",
            "T1566.001 (Spearphishing Attachment)",
        ],
        "avg_dwell_days": 60,
        "dbir_ref": "DBIR 2024 §Healthcare: Figure 91",
    },

    OrgSector.ENERGY: {
        # CISA 2024: Energy sector faces nation-state sponsored OT/ICS attacks.
        # Sandworm (Russian GRU) responsible for 30% of ICS incidents.
        "base_attack_rate": 0.30,
        "risk_weight":      0.88,
        "primary_vectors": [
            AttackVector.OT_ICS,
            AttackVector.PHISHING,
            AttackVector.SUPPLY_CHAIN,
        ],
        "top_threat_actors": "Sandworm / Volt Typhoon / XENOTIME",
        "top_ttps": [
            "T0816 (Device Restart/Shutdown — ICS)",
            "T1190 (Exploit Public-Facing Application)",
            "T1195 (Supply Chain Compromise)",
        ],
        "avg_dwell_days": 200,
        "dbir_ref": "CISA ICS-CERT Advisory 2024",
    },

    OrgSector.TECH: {
        # IBM X-Force 2024: Tech sector ≈ 25% of incidents involve
        # supply chain or code injection targeting developer pipelines.
        "base_attack_rate": 0.25,
        "risk_weight":      0.75,
        "primary_vectors": [
            AttackVector.SUPPLY_CHAIN,
            AttackVector.EXTERNAL_EXPLOIT,
            AttackVector.PHISHING,
        ],
        "top_threat_actors": "Lazarus Group / APT41 / UNC3944",
        "top_ttps": [
            "T1195.001 (Compromise Software Dependencies)",
            "T1059.003 (Windows Command Shell)",
            "T1566.001 (Spearphishing Attachment)",
        ],
        "avg_dwell_days": 55,
        "dbir_ref": "IBM X-Force 2024 §Technology",
    },

    OrgSector.DEFENSE: {
        # Mandiant M-Trends 2024: Defense contractors highest nation-state
        # targeting. 50% involve advanced persistent threat (APT) groups.
        "base_attack_rate": 0.50,
        "risk_weight":      0.99,
        "primary_vectors": [
            AttackVector.PHISHING,
            AttackVector.ZERO_DAY,
            AttackVector.SUPPLY_CHAIN,
        ],
        "top_threat_actors": "APT29 / APT40 / Lazarus / Charming Kitten",
        "top_ttps": [
            "T1566.002 (Spearphishing Link)",
            "T1190 (Exploit Public-Facing Application)",
            "T1560 (Archive Collected Data)",
        ],
        "avg_dwell_days": 250,
        "dbir_ref": "Mandiant M-Trends 2024 §Defense",
    },

    OrgSector.RETAIL: {
        # DBIR 2024: Retail 87% web-application attacks, web skimming primary.
        "base_attack_rate": 0.20,
        "risk_weight":      0.65,
        "primary_vectors": [
            AttackVector.WEB_SKIMMING,
            AttackVector.CREDENTIAL_THEFT,
            AttackVector.EXTERNAL_EXPLOIT,
        ],
        "top_threat_actors": "FIN8 / Magecart / TA505",
        "top_ttps": [
            "T1185 (Browser Session Hijacking)",
            "T1078 (Valid Accounts — stolen credentials)",
            "T1059.007 (JavaScript)",
        ],
        "avg_dwell_days": 30,
        "dbir_ref": "DBIR 2024 §Retail: Figure 99",
    },

    OrgSector.EDUCATION: {
        # DBIR 2024: Education has high breach volume but lower severity.
        # Ransomware and credential attacks are dominant.
        "base_attack_rate": 0.28,
        "risk_weight":      0.60,
        "primary_vectors": [
            AttackVector.CREDENTIAL_THEFT,
            AttackVector.RANSOMWARE,
            AttackVector.PHISHING,
        ],
        "top_threat_actors": "Vice Society / TA505 / Generic cybercriminals",
        "top_ttps": [
            "T1110 (Brute Force)",
            "T1486 (Data Encrypted for Impact)",
            "T1566 (Phishing)",
        ],
        "avg_dwell_days": 40,
        "dbir_ref": "DBIR 2024 §Education",
    },

    OrgSector.TELECOM: {
        # IBM X-Force: Telecom targeted for call detail records (CDR) + SS7 attacks.
        "base_attack_rate": 0.30,
        "risk_weight":      0.80,
        "primary_vectors": [
            AttackVector.EXTERNAL_EXPLOIT,
            AttackVector.SUPPLY_CHAIN,
            AttackVector.CREDENTIAL_THEFT,
        ],
        "top_threat_actors": "APT41 / Salt Typhoon / Earth Estries",
        "top_ttps": [
            "T1190 (Exploit Public-Facing Application)",
            "T1078 (Valid Accounts)",
            "T1083 (File and Directory Discovery)",
        ],
        "avg_dwell_days": 90,
        "dbir_ref": "IBM X-Force 2024 §Telecommunications",
    },

    OrgSector.CRITICAL_INFRA: {
        # CISA 2024: Critical infrastructure under persistent state-level threat.
        "base_attack_rate": 0.45,
        "risk_weight":      0.97,
        "primary_vectors": [
            AttackVector.OT_ICS,
            AttackVector.SUPPLY_CHAIN,
            AttackVector.PHISHING,
        ],
        "top_threat_actors": "Volt Typhoon / Sandworm / XENOTIME",
        "top_ttps": [
            "T0816 (Device Restart — ICS)",
            "T1195 (Supply Chain Compromise)",
            "T1190 (Exploit Public-Facing Application)",
        ],
        "avg_dwell_days": 300,
        "dbir_ref": "CISA Critical Infrastructure Threat Assessment 2024",
    },
}


# ---------------------------------------------------------------------------
# Geopolitical multipliers (Recorded Future GRI 2024)
# ---------------------------------------------------------------------------

GEO_MULTIPLIERS: dict[str, float] = {
    "WAR_ZONE":     2.0,   # Active armed conflict — cyber ops escalate dramatically
    "HIGH_TENSION": 1.5,   # Sanctions, proxy operations, diplomatic breakdown
    "MODERATE":     1.2,   # Political instability, regional disputes
    "STABLE":       1.0,   # Low geopolitical threat environment
}


# ---------------------------------------------------------------------------
# Organization size modifiers
# ---------------------------------------------------------------------------

SIZE_MODIFIERS: dict[str, float] = {
    "ENTERPRISE": 1.20,   # Larger attack surface, higher value target
    "MID":        1.00,   # Baseline
    "SMB":        0.85,   # Smaller footprint but fewer defenses
}
