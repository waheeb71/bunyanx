import math
from typing import Tuple, Dict

class RiskScorer:
    """
    Applies the Non-Linear Sigmoid transformation on the Multi-Signal Hypervectors.
    """
    def __init__(self, w_dga: float = 12.0, w_phish: float = 8.0, w_benign: float = 15.0, bias: float = -3.5, threshold: float = 0.70):
        # Default weights derived theoretically. Will be adjusted offline via trainer.
        self.w_dga = w_dga
        self.w_phish = w_phish
        self.w_benign = w_benign
        self.bias = bias
        self.threshold = threshold
        
    def sigmoid(self, x: float) -> float:
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 0.0 if x < 0 else 1.0
            
    def compute_risk(self, s_dga: float, s_phish: float, s_benign: float) -> Tuple[float, Dict[str, float]]:
        """
        $$ R = \sigma(w_1 \cdot S_{dga} + w_2 \cdot S_{phish} - w_3 \cdot S_{benign} + b) $$
        """
        # Linear Margin
        margin = (self.w_dga * s_dga) + (self.w_phish * s_phish) - (self.w_benign * s_benign) + self.bias
        
        # Map to Probability [0, 1]
        risk = self.sigmoid(margin)
        
        details = {
            "score_dga": s_dga,
            "score_phish": s_phish,
            "score_benign": s_benign,
            "margin": margin
        }
        
        return risk, details

    def get_action_band(self, risk: float, th_med: float = 0.50) -> str:
        """Translates risk score to routing policy action."""
        if risk >= self.threshold:
            return "BLOCK"
        elif risk >= th_med:
            return "CHALLENGE" # Or Sinkhole
        return "ALLOW"
