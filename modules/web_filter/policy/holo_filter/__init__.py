from .encoder import HDCEncoder
from .vector_store import VectorStore
from .similarity import SimilarityEngine
from .risk_scorer import RiskScorer
import os
import logging

logger = logging.getLogger(__name__)

class HoloFilter:
    """
    Facade for the HoloFilter HDC Engine v2.
    """
    def __init__(self, model_path=None, config=None):
        self._cfg = config or {}
        dim = self._cfg.get("vector_dimensions", 10048)
        
        self.encoder = HDCEncoder(dimensions=dim)
        self.store = VectorStore(dimensions=dim)
        self.similarity = SimilarityEngine(dimensions=dim)
        
        w_cfg = self._cfg.get("weights", {})
        w_dga = w_cfg.get("w_dga", 12.0)
        w_phish = w_cfg.get("w_phish", 8.0)
        w_benign = w_cfg.get("w_benign", 4.0)
        b = self._cfg.get("bias", -12.0)
        t = self._cfg.get("action_threshold_score", 70)
        
        self.scorer = RiskScorer(w_dga=w_dga, w_phish=w_phish, w_benign=w_benign, bias=b, threshold=t/100.0)
        
        self.ready = False
        
        if model_path and os.path.exists(model_path):
            try:
                self.store.load(model_path)
                self.ready = True
                logger.info(f"HoloFilter loaded offline vectors from {model_path}.")
            except Exception as e:
                logger.error(f"Failed to load HoloFilter vectors: {e}")
        else:
            logger.warning("HoloFilter starting in EMPTY state. No prototypes loaded.")

    def evaluate(self, domain: str) -> dict:
        """
        Evaluates a domain and returns the risk formulation.
        """
        if not self.ready:
            return {"risk": 0.0, "action": "ALLOW", "reason": "System unprepared"}
            
        # 1. Encode Target Domain
        target_hv = self.encoder.encode_domain(domain)
        
        # 2. Compute Similarities against Prototypes
        dga_mat, phish_mat, benign_mat = self.store.get_matrices()
        s_dga, s_phish, s_benign = self.similarity.compute_all_signals(
            target_hv, dga_mat, phish_mat, benign_mat
        )
        
        # 3. Calculate Non-Linear Risk Score
        risk, details = self.scorer.compute_risk(s_dga, s_phish, s_benign)
        
        # 4. Routing Band
        action = self.scorer.get_action_band(risk)
        
        # For Explainability: Find the dominant signal
        dominant = None
        if s_dga > s_phish and s_dga > s_benign:
            dominant = "DGA"
        elif s_phish > s_benign:
            dominant = "Phishing"
        else:
            dominant = "Benign Base"
            
        reason = f"High contribution mapping to {dominant} subspace."
        
        return {
            "risk": risk,
            "action": action,
            "reason": reason,
            "details": details
        }
