#!/usr/bin/env python3
"""
bunyanx NGFW -- Audio Alert Sound Pack Merger & Manifest Enhancer
===================================================================
Merges the new Dark Cyber Threat sounds with existing alert sounds,
organizes audio files with clean descriptive names in var/audio/alerts/,
and builds a multi-sound array manifest.json so NativePlayer randomly
picks from multiple distinct audio tones for every attack type!
"""

import json
import shutil
from pathlib import Path

THIS_FILE     = Path(__file__).resolve()
PROJECT_ROOT  = THIS_FILE.parent.parent
ALERTS_DIR    = PROJECT_ROOT / "var" / "audio" / "alerts"
SCARY_DIR     = PROJECT_ROOT / "var" / "audio" / "cyber_scary_alerts"
MANIFEST_PATH = ALERTS_DIR / "manifest.json"


def main():
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    print("Merging and organizing sound files in var/audio/alerts/...")

    # Copy new Dark Cyber sound files with clean descriptive names
    copy_map = {
        "threat_detected.wav":     "cyber_threat_stinger.wav",
        "malware_critical.wav":    "cyber_malware_siren.wav",
        "auth_brute_force.wav":    "cyber_hacker_alarm.wav",
        "dlp_incident.wav":        "cyber_data_breach.wav",
        "ids_port_scan.wav":       "cyber_sonar_ping.wav",
        "system_core_failure.wav": "cyber_system_horn.wav",
    }

    if SCARY_DIR.exists():
        for src_name, dst_name in copy_map.items():
            src_file = SCARY_DIR / src_name
            if src_file.exists():
                dst_file = ALERTS_DIR / dst_name
                shutil.copy2(src_file, dst_file)
                print(f"  [+] Copied & Renamed: {src_name} -> {dst_name}")

    # Build comprehensive multi-sound manifest mapping
    # Maps every attack type to an array of sound files for random selection!
    comprehensive_manifest = {
        # ── WAF & Specific Attacks ─────────────────────────────────────
        "waf.block": [
            "response_block.mp3",
            "cyber_threat_stinger.wav",
            "response_block1.mp3"
        ],
        "waf_block": [
            "response_block.mp3",
            "cyber_threat_stinger.wav",
            "response_block1.mp3"
        ],
        "sqli": [
            "response_block.mp3",
            "cyber_threat_stinger.wav"
        ],
        "rce": [
            "response_block.mp3",
            "cyber_threat_stinger.wav"
        ],
        "xss": [
            "response_alert.mp3",
            "cyber_threat_stinger.wav"
        ],
        "path_traversal": [
            "response_block.mp3",
            "cyber_threat_stinger.wav"
        ],
        "abusive_bot": [
            "response_alert.mp3",
            "cyber_threat_stinger.wav"
        ],
        "waf.alert": [
            "response_alert.mp3",
            "cartoon_music-security-alarm-543921.mp3"
        ],
        "waf_alert": [
            "response_alert.mp3",
            "cartoon_music-security-alarm-543921.mp3"
        ],

        # ── Malware & Antivirus ────────────────────────────────────────
        "malware.detected": [
            "malware_detected.mp3",
            "cyber_malware_siren.wav",
            "malware_critical.mp3"
        ],
        "malware_detected": [
            "malware_detected.mp3",
            "cyber_malware_siren.wav",
            "malware_critical.mp3"
        ],

        # ── IDS / IPS Port Scans ───────────────────────────────────────
        "ids.port_scan": [
            "ids_port_scan.mp3",
            "cyber_sonar_ping.wav",
            "ids_port_scan_warning.mp3"
        ],
        "ids_port_scan": [
            "ids_port_scan.mp3",
            "cyber_sonar_ping.wav",
            "ids_port_scan_warning.mp3"
        ],

        # ── Auth & Brute Force ────────────────────────────────────────
        "auth.brute_force": [
            "auth_brute_force.mp3",
            "cyber_hacker_alarm.wav",
            "auth_hacker_alarm.mp3"
        ],
        "auth_brute_force": [
            "auth_brute_force.mp3",
            "cyber_hacker_alarm.wav",
            "auth_hacker_alarm.mp3"
        ],
        "auth.login_failure": [
            "auth_login_failure.mp3"
        ],
        "auth_login_failure": [
            "auth_login_failure.mp3"
        ],
        "auth.login_success": [
            "p3_generic.mp3"
        ],
        "auth_login_success": [
            "p3_generic.mp3"
        ],

        # ── DLP Data Exfiltration ──────────────────────────────────────
        "dlp.incident": [
            "cyber_data_breach.wav",
            "response_block.mp3"
        ],
        "dlp_incident": [
            "cyber_data_breach.wav",
            "response_block.mp3"
        ],

        # ── DNS Security ──────────────────────────────────────────────
        "dns.threat": [
            "dns_suspicious.mp3",
            "freesound_community-alarm-clock-90867.mp3"
        ],
        "dns_threat": [
            "dns_suspicious.mp3",
            "freesound_community-alarm-clock-90867.mp3"
        ],
        "dns.suspicious": [
            "dns_suspicious.mp3"
        ],
        "dns_suspicious": [
            "dns_suspicious.mp3"
        ],

        # ── Web Filter ────────────────────────────────────────────────
        "web_filter.block": [
            "response_alert.mp3"
        ],
        "web_filter_block": [
            "response_alert.mp3"
        ],

        # ── Email Security ─────────────────────────────────────────────
        "email.threat": [
            "siem_incident_escalated.mp3"
        ],
        "email_threat": [
            "siem_incident_escalated.mp3"
        ],

        # ── VPN ────────────────────────────────────────────────────────
        "vpn.failure": [
            "vpn_failure.mp3",
            "cyber_system_horn.wav"
        ],
        "vpn_failure": [
            "vpn_failure.mp3",
            "cyber_system_horn.wav"
        ],
        "vpn.restored": [
            "p3_generic.mp3"
        ],
        "vpn_restored": [
            "p3_generic.mp3"
        ],

        # ── PKI & SSL Certificates ─────────────────────────────────────
        "pki.cert_expiring": [
            "pki_cert_expiring.mp3"
        ],
        "pki_cert_expiring": [
            "pki_cert_expiring.mp3"
        ],
        "pki.cert_invalid": [
            "pki_cert_invalid.mp3",
            "cyber_system_horn.wav"
        ],
        "pki_cert_invalid": [
            "pki_cert_invalid.mp3",
            "cyber_system_horn.wav"
        ],

        # ── High Availability & Core Failures ─────────────────────────
        "system.core_failure": [
            "system_core_failure.mp3",
            "cyber_system_horn.wav"
        ],
        "system_core_failure": [
            "system_core_failure.mp3",
            "cyber_system_horn.wav"
        ],
        "system.memory_critical": [
            "system_memory_critical.mp3"
        ],
        "system_memory_critical": [
            "system_memory_critical.mp3"
        ],
        "system.cpu_critical": [
            "system_cpu_critical.mp3"
        ],
        "system_cpu_critical": [
            "system_cpu_critical.mp3"
        ],
        "ha.failover": [
            "ha_failover.mp3",
            "cyber_system_horn.wav"
        ],
        "ha_failover": [
            "ha_failover.mp3",
            "cyber_system_horn.wav"
        ],

        # ── Response & Correlation ────────────────────────────────────
        "threat.detected": [
            "threat_detected.mp3",
            "cyber_threat_stinger.wav",
            "threat_detected_alt1.mp3"
        ],
        "threat_detected": [
            "threat_detected.mp3",
            "cyber_threat_stinger.wav",
            "threat_detected_alt1.mp3"
        ],
        "response.block": [
            "response_block.mp3",
            "cyber_threat_stinger.wav",
            "response_block1.mp3"
        ],
        "response_block": [
            "response_block.mp3",
            "cyber_threat_stinger.wav",
            "response_block1.mp3"
        ],
        "response.quarantine": [
            "response_alert.mp3",
            "cyber_system_horn.wav"
        ],
        "response_quarantine": [
            "response_alert.mp3",
            "cyber_system_horn.wav"
        ],
        "response.alert": [
            "response_alert.mp3"
        ],
        "response_alert": [
            "response_alert.mp3"
        ],
        "correlation.triggered": [
            "correlation_triggered.mp3",
            "cyber_threat_stinger.wav"
        ],
        "correlation_triggered": [
            "correlation_triggered.mp3",
            "cyber_threat_stinger.wav"
        ],
        "anomaly.scored": [
            "anomaly_scored.mp3"
        ],
        "anomaly_scored": [
            "anomaly_scored.mp3"
        ],

        # ── SIEM ───────────────────────────────────────────────────────
        "siem.incident_created": [
            "siem_incident_created.mp3"
        ],
        "siem_incident_created": [
            "siem_incident_created.mp3"
        ],
        "siem.incident_escalated": [
            "siem_incident_escalated.mp3",
            "cyber_malware_siren.wav"
        ],
        "siem_incident_escalated": [
            "siem_incident_escalated.mp3",
            "cyber_malware_siren.wav"
        ],
        "siem.incident_closed": [
            "siem_incident_created.mp3"
        ],
        "siem_incident_closed": [
            "siem_incident_created.mp3"
        ],

        # ── System Lifecycle ───────────────────────────────────────────
        "system.started": [
            "p3_generic.mp3"
        ],
        "system_started": [
            "p3_generic.mp3"
        ],
        "system.shutdown": [
            "p3_generic.mp3"
        ],
        "system_shutdown": [
            "p3_generic.mp3"
        ],
        "module.started": [
            "p3_generic.mp3"
        ],
        "module_started": [
            "p3_generic.mp3"
        ],
        "module.stopped": [
            "p3_generic.mp3"
        ],
        "module_stopped": [
            "p3_generic.mp3"
        ],
        "module.health": [
            "p3_generic.mp3"
        ],
        "module_health": [
            "p3_generic.mp3"
        ],
        "config.saved": [
            "p3_generic.mp3"
        ],
        "config_saved": [
            "p3_generic.mp3"
        ],
        "config.reloaded": [
            "p3_generic.mp3"
        ],
        "config_reloaded": [
            "p3_generic.mp3"
        ],
        "intel.updated": [
            "p3_generic.mp3"
        ],
        "intel_updated": [
            "p3_generic.mp3"
        ],
        "ai.score_generated": [
            "p3_generic.mp3"
        ],
        "ai_score_generated": [
            "p3_generic.mp3"
        ],

        # ── Priority Level Fallbacks ──────────────────────────────────
        "p3_generic": [
            "p3_generic.mp3"
        ],
        "p4_generic": [
            "p4_generic.mp3",
            "cyber_threat_stinger.wav"
        ],
        "p5_generic": [
            "p4_generic.mp3",
            "cyber_threat_stinger.wav"
        ],
        "p6_generic": [
            "p4_generic.mp3",
            "cyber_malware_siren.wav"
        ]
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(comprehensive_manifest, f, indent=2, ensure_ascii=False)

    print("=" * 65)
    print("SUCCESS: Sound files merged & manifest.json updated with multi-sound selection!")
    print(f"Manifest Path: {MANIFEST_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    main()
