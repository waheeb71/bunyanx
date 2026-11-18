"""
Enterprise bunyanx — WAF Explainable AI (XAI)

Generates human-readable, SIEM-friendly explanations for Risk Scoring Engine decisions.
Uses weighted attribution (SHAP-style) across all 7 risk signal sources.
"""
import logging

logger = logging.getLogger(__name__)


# Engine weights — must stay in sync with risk_engine.py defaults
_W = {
    "nlp":        0.25,
    "anomaly":    0.15,
    "bot":        0.15,
    "reputation": 0.10,
    "honeypot":   0.05,
    "gaf":        0.15,
    "temporal":   0.15,
}

_LABELS = {
    "nlp":        "NLP Payload Attack",
    "anomaly":    "Behavioral Anomaly",
    "bot":        "Bot Signature",
    "reputation": "IP Reputation",
    "honeypot":   "Deception / Honeypot",
    "gaf":        "GAF Prompt Injection",
    "temporal":   "Temporal APT Sequence",
}


class WAFExplainer:
    """
    Transparent breakdown of why a request was blocked or challenged.
    Uses weighted-score attribution across all 7 AI signal layers.
    """
    def __init__(self, explainer_type: str = "shap"):
        self.explainer_type = explainer_type

    def explain(self, breakdown) -> str:
        """
        Takes a RiskBreakdown object (or dict) from RiskScoringEngine and returns
        a weighted, SHAP-style explanation string suitable for SOC analysts and SIEM.

        Output format:
            XAI Attribution [Decision=BLOCK | Risk=0.912]: 45% NLP Payload Attack |
            30% GAF Prompt Injection | 15% Temporal APT Sequence | 10% IP Reputation
        """
        # Handle dataclass or plain dict
        if hasattr(breakdown, "to_dict"):
            data = breakdown.to_dict()
        else:
            data = dict(breakdown)

        final_score = float(data.get("final_score", 0.0))
        decision    = str(data.get("decision", "unknown")).upper()

        if final_score == 0.0:
            return "XAI: Request appears completely benign."

        # Weighted contribution = raw_score × engine_weight (SHAP-style additive)
        contributions: dict[str, float] = {}
        for key, weight in _W.items():
            raw = float(data.get(key, 0.0))
            contrib = raw * weight
            if contrib > 0.0:
                contributions[_LABELS[key]] = contrib

        if not contributions:
            return (
                f"XAI Attribution [Decision={decision} | Risk={final_score:.3f}]: "
                "Blocked via deterministic rule — no AI signals active."
            )

        total = sum(contributions.values())
        parts = []
        for label, contrib in sorted(contributions.items(), key=lambda x: x[1], reverse=True):
            pct = (contrib / total) * 100
            if pct >= 5.0:
                parts.append(f"{pct:.0f}% {label}")

        return (
            f"XAI Attribution [Decision={decision} | Risk={final_score:.3f}]: "
            + " | ".join(parts)
        )
