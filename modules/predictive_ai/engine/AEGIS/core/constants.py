"""
bunyanx NGFW — AEGIS Engine: Central Constants & Taxonomy
=============================================================

All numerical matrices and categorical definitions used across the
AEGIS sub-package are defined here in a single, authoritative location.

Design rationale
----------------
* One source of truth — every module imports from this file rather than
  duplicating magic numbers.
* Matrices stored as plain Python lists so they can be converted to
  numpy arrays lazily inside modules that need GPU/CPU acceleration.
* MITRE ATT&CK stage ordering follows the Unified Kill Chain (UKC) 2.0
  condensed to 8 tactical phases for computational tractability.

References
----------
* MITRE ATT&CK Enterprise v14.1  (https://attack.mitre.org)
* Unified Kill Chain 2.0          (https://unifiedkillchain.com)
* AEGIS research paper — bunyanx AI Division, April 2026
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# 1. MITRE ATT&CK Kill-Chain Stage Taxonomy (8-stage UKC model)
# ---------------------------------------------------------------------------

KILL_CHAIN_STAGES: Final[tuple[str, ...]] = (
    "RECONNAISSANCE",       # 0 — T1595, T1589, T1590
    "INITIAL_ACCESS",       # 1 — T1566, T1190, T1133
    "EXECUTION",            # 2 — T1059, T1203, T1053
    "PERSISTENCE",          # 3 — T1547, T1053, T1078
    "PRIVILEGE_ESCALATION", # 4 — T1068, T1134, T1055
    "LATERAL_MOVEMENT",     # 5 — T1021, T1570, T1534
    "COLLECTION",           # 6 — T1114, T1056, T1074
    "EXFILTRATION",         # 7 — T1048, T1041, T1567
)

NUM_STAGES: Final[int] = len(KILL_CHAIN_STAGES)

# Reverse lookup: stage name → index
STAGE_INDEX: Final[dict[str, int]] = {s: i for i, s in enumerate(KILL_CHAIN_STAGES)}

# ---------------------------------------------------------------------------
# 2. Attacker TTP Action Space (9 observable event types)
# ---------------------------------------------------------------------------

TTP_NAMES: Final[tuple[str, ...]] = (
    "SCAN",               # 0
    "WAF_EXPLOIT",        # 1
    "MALWARE",            # 2
    "DGA_C2",             # 3
    "PRIV_ESC",           # 4
    "LATERAL",            # 5
    "DLP_EXFIL",          # 6
    "RANSOMWARE",         # 7
    "PERSISTENCE",        # 8
)

NUM_TTPS: Final[int] = len(TTP_NAMES)

# Reverse lookup: TTP name → index
TTP_INDEX: Final[dict[str, int]] = {t: i for i, t in enumerate(TTP_NAMES)}

# ---------------------------------------------------------------------------
# 3. Bayesian Emission Model  P(event | stage)
# ---------------------------------------------------------------------------
# Rows = TTP events (9), Cols = Kill-Chain stages (8).
# Calibrated from MITRE ATT&CK frequency data across 3 000+ CTI reports.
# Row sums need NOT equal 1; these are likelihoods, not probabilities.

EMISSION_MODEL: Final[list[list[float]]] = [
    # RECON   INIT   EXEC   PERS   PRIV   LAT    COLL   EXFIL
    [0.90,  0.05,  0.01,  0.01,  0.01,  0.01,  0.01,  0.00],  # SCAN
    [0.05,  0.70,  0.15,  0.03,  0.04,  0.02,  0.01,  0.00],  # WAF_EXPLOIT
    [0.01,  0.10,  0.65,  0.15,  0.05,  0.02,  0.01,  0.01],  # MALWARE
    [0.01,  0.05,  0.20,  0.10,  0.05,  0.20,  0.30,  0.09],  # DGA_C2
    [0.00,  0.02,  0.08,  0.05,  0.75,  0.05,  0.03,  0.02],  # PRIV_ESC
    [0.00,  0.01,  0.03,  0.05,  0.10,  0.75,  0.05,  0.01],  # LATERAL
    [0.00,  0.01,  0.01,  0.02,  0.02,  0.04,  0.20,  0.70],  # DLP_EXFIL
    [0.00,  0.01,  0.05,  0.03,  0.03,  0.05,  0.08,  0.75],  # RANSOMWARE
    [0.00,  0.02,  0.15,  0.55,  0.20,  0.05,  0.02,  0.01],  # PERSISTENCE
]

# ---------------------------------------------------------------------------
# 4. Kill-Chain Stage Transition Model  P(s' | s)
# ---------------------------------------------------------------------------
# Rows = from-stage, Cols = to-stage.
# Each row sums to 1.0 (valid left-stochastic column for prediction step).

TRANSITION_MODEL: Final[list[list[float]]] = [
    # → RECON   INIT   EXEC   PERS   PRIV   LAT    COLL   EXFIL
    [0.50, 0.45, 0.03, 0.01, 0.01, 0.00, 0.00, 0.00],  # RECON
    [0.10, 0.30, 0.50, 0.08, 0.01, 0.01, 0.00, 0.00],  # INIT_ACCESS
    [0.01, 0.05, 0.35, 0.35, 0.15, 0.05, 0.03, 0.01],  # EXECUTION
    [0.00, 0.01, 0.10, 0.40, 0.25, 0.20, 0.03, 0.01],  # PERSISTENCE
    [0.00, 0.00, 0.05, 0.10, 0.35, 0.40, 0.05, 0.05],  # PRIV_ESC
    [0.00, 0.00, 0.02, 0.05, 0.08, 0.35, 0.35, 0.15],  # LATERAL
    [0.00, 0.00, 0.01, 0.02, 0.02, 0.05, 0.30, 0.60],  # COLLECTION
    [0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.10, 0.90],  # EXFILTRATION
]

# ---------------------------------------------------------------------------
# 5. Attacker Q-Table Initial Values  Q_A(stage, ttp)
# ---------------------------------------------------------------------------
# Rows = Kill-Chain stage (8), Cols = TTP action (9).
# Initialised from MITRE ATT&CK technique frequency data.
# Updated online during system operation via AdversarialIntentSimulator.

Q_ATTACKER_INIT: Final[list[list[float]]] = [
    # SCAN   WAF    MAL    DGA    PRIV  LAT    EXFIL  RANSOM PERS
    [0.80, 0.40, 0.20, 0.10, 0.05, 0.15, 0.05, 0.02, 0.05],  # RECON
    [0.10, 0.70, 0.60, 0.20, 0.20, 0.15, 0.10, 0.05, 0.25],  # INIT_ACCESS
    [0.05, 0.20, 0.50, 0.55, 0.45, 0.30, 0.15, 0.20, 0.55],  # EXECUTION
    [0.02, 0.10, 0.25, 0.40, 0.35, 0.45, 0.20, 0.10, 0.70],  # PERSISTENCE
    [0.01, 0.05, 0.15, 0.25, 0.30, 0.75, 0.30, 0.20, 0.35],  # PRIV_ESC
    [0.01, 0.03, 0.10, 0.30, 0.20, 0.40, 0.65, 0.30, 0.25],  # LATERAL
    [0.00, 0.02, 0.05, 0.15, 0.10, 0.20, 0.80, 0.45, 0.15],  # COLLECTION
    [0.00, 0.01, 0.02, 0.05, 0.02, 0.05, 0.95, 0.85, 0.08],  # EXFILTRATION
]

# ---------------------------------------------------------------------------
# 6. Defender Action Space (12 graduated responses)
# ---------------------------------------------------------------------------

DEFENDER_ACTIONS: Final[tuple[str, ...]] = (
    "MONITOR",            # 0  — covert observation; zero operational risk
    "DECOY_TRAP",         # 1  — deploy lightweight decoy asset
    "ISOLATE_PARTIAL",    # 2  — block lateral paths only
    "HONEYPOT_REDIRECT",  # 3  — silently redirect to honeypot
    "RATE_LIMIT",         # 4  — throttle inbound traffic from source
    "KILL_SESSIONS",      # 5  — terminate active sessions
    "ISOLATE_FULL",       # 6  — full network segment isolation
    "CREDENTIAL_ROTATE",  # 7  — force credential rotation on target
    "FAKE_PATCH",         # 8  — deploy decoy vulnerability patch signal
    "ALERT_ONLY",         # 9  — human-analyst alert, no automated action
    "BLOCK_IP",           # 10 — hard block at firewall / eBPF XDP
    "EMERGENCY_ISOLATE",  # 11 — complete host quarantine
)

NUM_ACTIONS: Final[int] = len(DEFENDER_ACTIONS)

# ---------------------------------------------------------------------------
# 7. Disruption Matrix  D[action, ttp]
# ---------------------------------------------------------------------------
# How well each defender action disrupts each attacker TTP.
# Scale: 0.0 = no effect, 1.0 = fully neutralises the TTP.

DISRUPTION_MATRIX: Final[list[list[float]]] = [
    # SCAN  WAF   MAL   DGA   PRIV  LAT   EXFIL RANSOM PERS
    [0.10, 0.10, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05],  # MONITOR
    [0.30, 0.60, 0.20, 0.40, 0.20, 0.50, 0.30, 0.10, 0.20],  # DECOY_TRAP
    [0.50, 0.60, 0.40, 0.30, 0.55, 0.70, 0.60, 0.40, 0.50],  # ISOLATE_PARTIAL
    [0.20, 0.50, 0.30, 0.60, 0.25, 0.70, 0.35, 0.15, 0.25],  # HONEYPOT_REDIRECT
    [0.60, 0.40, 0.20, 0.30, 0.10, 0.20, 0.30, 0.10, 0.10],  # RATE_LIMIT
    [0.30, 0.70, 0.50, 0.60, 0.55, 0.65, 0.70, 0.40, 0.45],  # KILL_SESSIONS
    [0.80, 0.85, 0.80, 0.75, 0.85, 0.90, 0.85, 0.75, 0.80],  # ISOLATE_FULL
    [0.10, 0.20, 0.30, 0.15, 0.70, 0.30, 0.40, 0.10, 0.60],  # CREDENTIAL_ROTATE
    [0.15, 0.10, 0.60, 0.20, 0.55, 0.20, 0.30, 0.50, 0.70],  # FAKE_PATCH
    [0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05],  # ALERT_ONLY
    [0.90, 0.80, 0.75, 0.70, 0.70, 0.75, 0.80, 0.65, 0.70],  # BLOCK_IP
    [0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99],  # EMERGENCY_ISOLATE
]

# ---------------------------------------------------------------------------
# 8. Operational Cost per Defender Action
# ---------------------------------------------------------------------------
# Range: 0.0 (free / transparent) to 1.0 (maximum disruption to operations).

OPERATIONAL_COST: Final[tuple[float, ...]] = (
    0.00,  # MONITOR
    0.05,  # DECOY_TRAP
    0.30,  # ISOLATE_PARTIAL
    0.10,  # HONEYPOT_REDIRECT
    0.15,  # RATE_LIMIT
    0.35,  # KILL_SESSIONS
    0.70,  # ISOLATE_FULL
    0.25,  # CREDENTIAL_ROTATE
    0.20,  # FAKE_PATCH
    0.00,  # ALERT_ONLY
    0.75,  # BLOCK_IP
    1.00,  # EMERGENCY_ISOLATE
)

# ---------------------------------------------------------------------------
# 9. Escalation Risk per Defender Action
# ---------------------------------------------------------------------------
# P(attacker detects our response and escalates | we apply this action).
# High values indicate the action reveals defender presence.

ESCALATION_RISK: Final[tuple[float, ...]] = (
    0.00,  # MONITOR           — fully covert
    0.08,  # DECOY_TRAP        — low; attacker suspects nothing
    0.35,  # ISOLATE_PARTIAL   — medium; partial block is noticeable
    0.05,  # HONEYPOT_REDIRECT — low; attacker believes they succeeded
    0.20,  # RATE_LIMIT        — noticeable but ambiguous
    0.40,  # KILL_SESSIONS     — reveals detection
    0.70,  # ISOLATE_FULL      — high; forces pivot or dormancy
    0.25,  # CREDENTIAL_ROTATE — medium; implies anomaly detection
    0.10,  # FAKE_PATCH        — subtle; looks like normal maintenance
    0.00,  # ALERT_ONLY        — fully covert
    0.85,  # BLOCK_IP          — very high; confirms detection to attacker
    0.90,  # EMERGENCY_ISOLATE — extreme; network-visible response
)

# ---------------------------------------------------------------------------
# 10. Deception Value per Defender Action
# ---------------------------------------------------------------------------
# How much each action contributes to strategic shaping of the attack path.
# Range: 0.0 = no shaping, 1.0 = perfectly redirects attacker.

DECEPTION_VALUE: Final[tuple[float, ...]] = (
    0.05,  # MONITOR
    0.70,  # DECOY_TRAP
    0.20,  # ISOLATE_PARTIAL
    0.90,  # HONEYPOT_REDIRECT  — best strategic shaping action
    0.10,  # RATE_LIMIT
    0.25,  # KILL_SESSIONS
    0.00,  # ISOLATE_FULL       — no deception, pure containment
    0.30,  # CREDENTIAL_ROTATE
    0.80,  # FAKE_PATCH         — high; attacker thinks patch failed
    0.05,  # ALERT_ONLY
    0.00,  # BLOCK_IP
    0.00,  # EMERGENCY_ISOLATE
)

# ---------------------------------------------------------------------------
# 11. CSO Optimiser Hyper-parameters (defaults, tunable via config)
# ---------------------------------------------------------------------------

CSO_ALPHA: Final[float] = 0.55   # weight — expected disruption
CSO_BETA:  Final[float] = 0.20   # weight — operational cost
CSO_GAMMA: Final[float] = 0.15   # weight — deception value
CSO_LAMBDA: Final[float] = 0.10  # weight — escalation risk penalty

# ---------------------------------------------------------------------------
# 12. ASE / AIS Hyper-parameters
# ---------------------------------------------------------------------------

ASE_UNIFORM_PRIOR: Final[float] = 1.0 / NUM_STAGES   # 0.125 per stage
AIS_DEFAULT_TEMPERATURE: Final[float] = 0.50          # Boltzmann softmax τ
AIS_ONLINE_LEARNING_RATE: Final[float] = 0.05         # Q_A update lr

# ---------------------------------------------------------------------------
# 13. Transformer Predictor Hyper-parameters
# ---------------------------------------------------------------------------

TRANSFORMER_WINDOW_SIZE: Final[int] = 10          # Extended from LSTM's 5
TRANSFORMER_D_MODEL: Final[int] = 64              # Must match LSTM hidden for parity
TRANSFORMER_N_HEADS: Final[int] = 4               # Multi-head attention heads
TRANSFORMER_N_LAYERS: Final[int] = 2              # Encoder depth
TRANSFORMER_D_FF: Final[int] = 256                # Feed-forward inner dimension
TRANSFORMER_DROPOUT: Final[float] = 0.1           # Dropout rate
TRANSFORMER_MODEL_PATH: Final[str] = "models/ttp_transformer.pt"
