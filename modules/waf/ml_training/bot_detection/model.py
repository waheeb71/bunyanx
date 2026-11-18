import os
import numpy as np
import xgboost as xgb

class BotDetectionModel:
    """
    Layer 4b: XGBoost Bot Detection Model.
    Categorizes client sessions into: legitimate_user, headless_browser, scraper, scanner, abusive_bot.
    """
    def __init__(self, model_path: str = "ml/models/waf/bot_model.json"):
        self.model_path = model_path
        self.bst = xgb.Booster()
        self.loaded = False
        self.labels = ["legitimate_user", "headless_browser", "scraper", "scanner", "abusive_bot"]
        
        self.feature_names = [
            "request_rate",
            "iat_variance",
            "session_duration",
            "unique_endpoints",
            "user_agent_entropy",
            "header_count",
            "accept_language_valid",
            "cookie_count",
            "referer_present",
            "method_diversity"
        ]
        
        if os.path.exists(self.model_path):
            try:
                self.bst.load_model(self.model_path)
                self.loaded = True
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error("Error loading WAF Bot model weights: %s", e)
        else:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("WAF Bot model file not found at %s. Model remains uninitialized.", self.model_path)

    def is_loaded(self) -> bool:
        return self.loaded

    def predict(self, features_dict: dict) -> tuple[float, str]:
        """
        Predict threat score (probability of being a bot) and bot class.
        Returns:
            (threat_score, bot_label)
        """
        if not self.loaded:
            # Fallback if model not loaded
            ua_entropy = features_dict.get("user_agent_entropy", 0.5)
            req_rate = features_dict.get("request_rate", 1.0)
            if req_rate > 20.0 or ua_entropy < 0.2:
                return 0.75, "scraper"
            return 0.0, "legitimate_user"

        try:
            # Construct feature array in correct order
            feature_vector = []
            for name in self.feature_names:
                val = features_dict.get(name, 0.0)
                try:
                    feature_vector.append(float(val))
                except (ValueError, TypeError):
                    feature_vector.append(0.0)
            
            # Make prediction
            dmatrix = xgb.DMatrix(np.array([feature_vector], dtype=np.float32))
            raw_preds = self.bst.predict(dmatrix)
            probs = np.atleast_1d(np.squeeze(raw_preds))
            
            if probs.size == 1:
                # Binary classification probability
                prob_bot = float(probs[0])
                label = "abusive_bot" if prob_bot >= 0.5 else "legitimate_user"
                return prob_bot, label
            else:
                class_id = int(np.argmax(probs))
                label = self.labels[class_id] if class_id < len(self.labels) else "abusive_bot"
                threat_score = 1.0 - float(probs[0])
                return threat_score, label
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error("Bot model predict error: %s", e)
            return 0.0, "legitimate_user"
