"""
Enterprise bunyanx — User Behavior Analytics (UBA) Module

Adaptive behavioral profiling engine for detecting insider threats,
compromised accounts, and privilege escalation through multi-dimensional
anomaly detection with causal deception verification.

Key Components:
  - UserProfiler:      Adaptive baseline engine with EMA learning
  - RiskAggregator:    Weighted multi-detector score fusion
  - UBAPlugin:         InspectorPlugin bridge for the inspection pipeline
  - Detectors:         Time, Location, Exfil, Privilege, Peer Group
  - Deception Engine:  Honeytoken injection for intent verification
  - Active Perturbation: Bot/Human discrimination via micro-fault injection

MITRE ATT&CK Coverage:
  - T1078: Valid Accounts (compromised credential detection)
  - T1071: Application Layer Protocol (behavioral anomaly)
  - T1567: Exfiltration Over Web Service (volume anomaly)
  - T1068: Exploitation for Privilege Escalation (service anomaly)
"""

__version__ = "2.0.0"
__module_name__ = "uba"
