"""
Psycho-Linguistic Sender Profiler (PLSF) - Neural Edition

Defeats Business Email Compromise (BEC) and AI-generated social engineering by
analyzing the semantic and cognitive fingerprint of the sender's text against
their historical behavioral baseline using Deep Learning Vector Embeddings.

Implements Contrastive Linguistic Verification using Cosine Similarity.
"""
import logging
import sqlite3
import threading
import os
import json
import numpy as np
import unicodedata
import re
from collections import OrderedDict
from typing import Dict, Any, Optional
from modules.email_security.engine.core.settings import PLSFSettings

# ── Dynamic base paths (no hardcoded absolute paths) ─────────────────
_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_ENGINE_ROOT = os.path.abspath(os.path.join(_MODULE_DIR, "..", ".."))          # engine/
_MODULE_ROOT = os.path.abspath(os.path.join(_ENGINE_ROOT, ".."))               # email_security/
_NGFW_ROOT   = os.path.abspath(os.path.join(_MODULE_ROOT, "..", ".."))         # enterprise_ngfw/
_DEFAULT_DB_PATH     = os.path.join(_MODULE_ROOT, "config", "plsf_profiles_ai.db")
_DEFAULT_MODELS_DIR  = os.path.join(_MODULE_ROOT, "models")

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

logger = logging.getLogger(__name__)

class PsychoLinguisticProfiler:
    def __init__(self, db_path: Optional[str] = None, settings: Optional[PLSFSettings] = None):
        self.settings = settings or PLSFSettings()
        self.enabled = self.settings.enabled
        # Use dynamic default path if not explicitly provided
        self.db_path = db_path or _DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._db_lock = threading.Lock()
        self._db_conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db_conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()
        
        self._model_pool = OrderedDict()
        self._models_map = {
            "en": "all-MiniLM-L6-v2",
            "multi": "paraphrase-multilingual-MiniLM-L12-v2"
        }
        
        if AI_AVAILABLE:
            # Pre-download/Warmup phase
            self._ensure_models_downloaded()
            if self.settings.model_mode == "auto" or self.settings.model_mode == "english_only":
                warmup_tag = self.settings.warmup_model if self.settings.model_mode == "auto" else "en"
                self._get_model(warmup_tag)
            logger.info("✅ Psycho-Linguistic Profiler (Dual-Model LRU Pool) Initialized")
        else:
            logger.error("❌ 'sentence-transformers' or 'scikit-learn' is missing. PLSF ML Pipeline will fail.")

    def _ensure_models_downloaded(self):
        """Ensures both enterprise models are locally saved on disk before normal operation."""
        base_dir = _DEFAULT_MODELS_DIR
        os.makedirs(base_dir, exist_ok=True)

        for tag, model_name in self._models_map.items():
            model_dest_path = os.path.join(base_dir, model_name)
            if not (os.path.exists(model_dest_path) and os.path.exists(os.path.join(model_dest_path, 'config.json'))):
                logger.info(f"⬇️ Downloading '{model_name}' ({tag}) for local Air-Gapped storage...")
                temp_model = SentenceTransformer(model_name)
                temp_model.save(model_dest_path)
                logger.info(f"💾 Saved permanently to {model_dest_path}")

    def _get_model(self, model_tag: str):
        """LRU Model Pool getter."""
        if model_tag in self._model_pool:
            self._model_pool.move_to_end(model_tag)
            return self._model_pool[model_tag]

        model_name = self._models_map.get(model_tag, "all-MiniLM-L6-v2")
        model_dest_path = os.path.join(_DEFAULT_MODELS_DIR, model_name)

        logger.info(f"🧠 Loading SentenceTransformer ({model_tag}) into RAM from {model_dest_path}...")
        model = SentenceTransformer(model_dest_path)

        if len(self._model_pool) >= self.settings.max_models_in_memory:
            evicted_tag, evicted_model = self._model_pool.popitem(last=False)
            del evicted_model
            import gc
            gc.collect()
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass
            logger.info(f"🧹 Evicted model ({evicted_tag}) from RAM and cleared GPU cache (LRU Strategy)")

        self._model_pool[model_tag] = model
        return model

    def _init_db(self):
        # We drop the old table seamlessly and recreate it with the composite primary key.
        with self._db_lock:
            self._db_conn.execute('''CREATE TABLE IF NOT EXISTS sender_ai_profiles_v2 (
                              sender TEXT,
                              model_tag TEXT,
                              vector_embedding TEXT,
                              message_count INTEGER DEFAULT 1,
                              last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                              PRIMARY KEY (sender, model_tag)
                            )''')

    def _get_profile(self, sender: str, model_tag: str) -> Optional[Dict[str, Any]]:
        with self._db_lock:
            cur = self._db_conn.execute("SELECT vector_embedding, message_count FROM sender_ai_profiles_v2 WHERE sender = ? AND model_tag = ?", (sender, model_tag))
            row = cur.fetchone()
            if row:
                return {
                    "vector": np.array(json.loads(row[0])),
                    "count": row[1]
                }
        return None

    def _save_profile(self, sender: str, model_tag: str, vector: np.ndarray, count: int = 1):
        vec_json = json.dumps(vector.tolist())
        with self._db_lock:
            self._db_conn.execute("""
                INSERT INTO sender_ai_profiles_v2 (sender, model_tag, vector_embedding, message_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sender, model_tag) DO UPDATE SET 
                vector_embedding=excluded.vector_embedding, 
                message_count=excluded.message_count,
                last_updated=CURRENT_TIMESTAMP
            """, (sender, model_tag, vec_json, count))
            self._db_conn.commit()

    # ----------------------------------------------------------------
    # BEC Lexical Risk Indicators
    # High-signal terms consistently absent in normal executive comms
    # but present in AI-generated BEC and financial fraud attacks.
    # ----------------------------------------------------------------
    BEC_INDICATORS = {
        # ── Financial / Wire Transfer ─────────────────────────────────
        "wire transfer": 0.55, "bank transfer": 0.45, "wire the": 0.45,
        "wire of": 0.45, "initiate a wire": 0.45, "initiate the wire": 0.45,
        "execute the wire": 0.45, "process the wire": 0.45,
        "offshore": 0.55, "offshore account": 0.45, "offshore holding": 0.45,
        "offshore vendor": 0.45,
        "payment of": 0.45, "emergency payment": 0.55, "immediate payment": 0.45,
        "emergency wire": 0.45, "international wire": 0.45,
        "remit": 0.45, "remittance": 0.45, "remit the": 0.45,
        "forward the": 0.45, "forward $": 0.45,
        "wire $": 0.45, "wire before": 0.45,
        "acquisition closing": 0.45, "before market close": 0.35,

        # ── Gift Card Fraud ────────────────────────────────────────────
        "gift card": 0.45, "gift cards": 0.45,
        "redemption codes": 0.45, "redemption code": 0.55,
        "scratch and email": 0.45, "itunes gift": 0.45,
        "amazon gift": 0.45, "google play": 0.45, "steam gift": 0.45,
        "prepaid visa": 0.45, "netflix gift": 0.45,
        "send the codes": 0.45, "email me codes": 0.45,
        "vouchers": 0.35,

        # ── Cryptocurrency / Wallet ───────────────────────────────────
        "cryptocurrency": 0.45, "bitcoin": 0.55, "crypto": 0.55,
        "ethereum": 0.45, "usdc": 0.45, "usdt": 0.45,
        "nft": 0.45, "nft assets": 0.45,
        "wallet": 0.45, "wallet address": 0.45, "crypto wallet": 0.45,
        "transfer to wallet": 0.45, "send to wallet": 0.45,
        "forward to the wallet": 0.45, "convert to bitcoin": 0.45,
        "convert to ethereum": 0.45, "convert $": 0.45,
        "procure cryptocurrency": 0.45, "purchase cryptocurrency": 0.45,
        "treasury diversification": 0.45,

        # ── Invoice / Vendor Fraud ────────────────────────────────────
        "overdue invoice": 0.45, "outstanding invoice": 0.45,
        "bank account changed": 0.45, "bank details have changed": 0.45,
        "updated bank account": 0.45, "new bank account": 0.45,
        "new account details": 0.45, "updated account": 0.45,
        "payment details": 0.45, "new payment details": 0.45,
        "vendor has updated": 0.45, "recently changed": 0.45,
        "avoid penalty": 0.45, "avoid contract penalty": 0.45,
        "service suspension": 0.45, "contractual penalty": 0.45,
        "overdue": 0.45, "past due": 0.45,
        "clear today": 0.45, "settle today": 0.45,
        "before close of business": 0.45, "before noon": 0.45,

        # ── Payroll Diversion (PREVIOUSLY UNDETECTED) ─────────────────
        "direct deposit": 0.45, "direct deposit to": 0.45,
        "payroll cycle": 0.45, "next payroll": 0.45, "before payroll": 0.45,
        "before next payroll": 0.45, "payroll system": 0.45,
        "payroll changes": 0.45, "routing number": 0.45,
        "bank routing": 0.45, "wire today": 0.55, "pay the $": 0.45,
        "vendor settlement": 0.45, "new account below": 0.55,
        "process my payroll": 0.55, "old bank details": 0.55,
        "new bank details": 0.45, "new banking details": 0.45,
        "banking arrangement": 0.35, "new financial institution": 0.45,
        "divert": 0.55, "divert my": 0.45, "divert executive": 0.45,
        "redirect my": 0.45, "redirect salary": 0.45,
        "redirect payroll": 0.45, "reroute": 0.45,
        "salary to": 0.45, "salary payment": 0.45,
        "monthly salary": 0.45, "next paycheck": 0.45,
        "deposit to the": 0.45, "deposit details": 0.35,
        "tax optimization": 0.35, "update payroll": 0.45,

        # ── Authority Impersonation (PREVIOUSLY UNDETECTED) ───────────
        "board-level": 0.45, "board-level instruction": 0.45,
        "board resolution": 0.45,
        "executive committee": 0.35,
        "no approval needed": 0.45, "no further approval": 0.45,
        "no additional approval": 0.45, "retroactive auth": 0.35,
        "supersedes": 0.45, "supersedes standard": 0.45,
        "ignore standard": 0.55, "ignore standard protocols": 0.45,
        "outside normal channels": 0.45, "outside normal": 0.55,
        "act immediately": 0.45, "act now": 0.45,
        "do not escalate": 0.45, "do not contact compliance": 0.45,
        "do not contact it": 0.45, "do not seek approval": 0.45,
        "do not seek further approval": 0.45,
        "legal directive": 0.45, "regulatory action follows": 0.45,
        "legal consequences": 0.45, "without deviation": 0.45,
        "emergency board": 0.45, "emergency board call": 0.45,
        "governance committee": 0.45, "audit committee": 0.45,
        "by order of": 0.45, "at the chairman": 0.45,
        "supervisory board": 0.45,

        # ── Urgency / Time Pressure ───────────────────────────────────
        "immediately": 0.45, "without fail": 0.45, "time-critical": 0.45,
        "time-sensitive": 0.45, "prior to noon": 0.45,
        "hurry": 0.45, "urgent": 0.45,
        "before 3 pm": 0.45, "within 30 minutes": 0.45,
        "within 24 hours": 0.45, "within 60 minutes": 0.45,
        "end of business": 0.45, "close of business": 0.45,
        "before end of day": 0.45,

        # ── Secrecy / Social Engineering ──────────────────────────────
        "discreetly": 0.45, "privately": 0.45,
        "this channel only": 0.45, "via this channel": 0.45,
        "via this email": 0.45, "via this secure channel": 0.45,
        "do not discuss": 0.45, "do not tell": 0.45,
        "keep this confidential": 0.45, "confidential executive": 0.45,
        "handle discreetly": 0.45, "handle privately": 0.45,
        "handle personally": 0.45, "handle confidentially": 0.45,
        "cannot be reached": 0.45, "unreachable": 0.45,
        "closed negotiations": 0.45, "personally monitoring": 0.45,
        "confirm by email only": 0.45, "confirm here only": 0.45,
        "send codes only": 0.45, "send the card details": 0.45,
        "send details only": 0.45,
        "do not use old account": 0.45,
        "private executive": 0.45, "private matter": 0.45,

        "on behalf of executive": 0.45, "i authorize": 0.45,
        "esteemed team": 0.45, "esteemed colleague": 0.45,
        "it is imperative": 0.45,
        
        # ── Arabic Indicators (Added for local Middle Eastern Enterprise Support) ──────
        "حوالة": 0.45, "حوالة مالية": 0.55, "تحويل مالي": 0.55, "تحويل بنكي": 0.45,
        "فوراً": 0.45, "عاجل": 0.45, "سري": 0.45, "سري للغاية": 0.55,
        "لا تخبر أحدا": 0.55, "لا تخبر أحداً": 0.55, "تكتم شديد": 0.55,
        "حساب المورد": 0.45, "تفاصيل الحساب": 0.45, "رقم الحساب": 0.45, 
        "بطاقات": 0.45, "بطاقات هدايا": 0.45, "ايتونز": 0.45, "أمازون": 0.45,
        "دفع عاجل": 0.55, "فاتورة غير مدفوعة": 0.45, "الفواتير المستحقة": 0.45,
        "عملات رقمية": 0.45, "بيتكوين": 0.45, "كريبتو": 0.45, "محفظة": 0.45,
        "خارج القنوات المعتادة": 0.55, "تعليمات الإدارة": 0.45, "المدير التنفيذي": 0.35,
        "proceed discreetly": 0.45, "confirm via this channel": 0.45,
        "board has authorized": 0.45, "board authorized": 0.45,
        "executive board": 0.45, "executive instruction": 0.45,
        "i am personally monitoring": 0.45,
        "i am monitoring": 0.45,
    }

    def _compute_lexical_bec_score(self, text: str) -> float:
        """
        Computes a Lexical BEC Risk Score in [0.00, 1.0] by scanning for
        high-signal financial fraud and social engineering indicators.
        Scores are accumulated and clamped to prevent over-counting.
        """
        text_lower = text.lower()
        risk = 0.0
        for phrase, weight in self.BEC_INDICATORS.items():
            if phrase in text_lower:
                risk += weight
        return min(risk, 1.0)

    def _classify_language(self, text: str) -> Dict[str, Any]:
        """
        Multi-factor Language Classification with Zero-Tolerance option
        and Unicode Normalization resistance.
        """
        # 1. Normalize Homoglyphs
        clean_text = unicodedata.normalize('NFKC', text)
        
        # 2. Short Text Safeguard
        if len(clean_text) < self.settings.min_routing_length:
            return {"tag": "multi", "arabic_char_count": 0, "ratio": 0.0, "reason": "short_text_fallback"}
            
        # 3. Precise Arabic Char count
        arabic_chars = len(re.findall(r'[\u0600-\u06FF]', clean_text))
        total_chars = len(clean_text.strip())
        
        if total_chars == 0:
             return {"tag": "multi", "arabic_char_count": 0, "ratio": 0.0, "reason": "empty_text"}
             
        ratio = arabic_chars / total_chars
        
        # 4. Strict Mode vs Threshold Mode
        if self.settings.strict_language_routing and arabic_chars > 0:
            return {"tag": "multi", "arabic_char_count": arabic_chars, "ratio": ratio, "reason": "strict_zero_tolerance"}
            
        if ratio > 0.15:
            return {"tag": "multi", "arabic_char_count": arabic_chars, "ratio": ratio, "reason": "threshold_upper_bound"}
            
        if ratio < 0.05 and arabic_chars == 0:
            return {"tag": "en", "arabic_char_count": arabic_chars, "ratio": ratio, "reason": "pure_english"}
            
        return {"tag": "multi", "arabic_char_count": arabic_chars, "ratio": ratio, "reason": "gray_zone_fallback"}

    def analyze(self, sender: str, text_content: str) -> Dict[str, Any]:
        """
        Hybrid PLSF Engine: combines Semantic Cosine Deviation + Lexical BEC Risk Score.
        Autonomously routes to the optimal Neural Vector DB based on Deep Language Analysis.
        """
        if not self.enabled or not sender or not text_content or not AI_AVAILABLE:
            # Return 0.0 (not 0.45) to avoid spurious proximity to λ_opt threshold
            return {"anomaly_score": 0.0, "is_suspected_mimicry": False, "details": "Disabled or missing ML deps"}

        # Determine target model
        routing_meta = self._classify_language(text_content)
        
        if self.settings.model_mode == "english_only":
            model_tag = "en"
        elif self.settings.model_mode == "multilingual_only":
            model_tag = "multi"
        else:
            model_tag = routing_meta["tag"]

        # Step 1: Securely fetch model and create neural embedding
        target_model = self._get_model(model_tag)
        current_vector = target_model.encode([text_content])[0]

        # Step 2: Retrieve isolated baseline profile
        baseline = self._get_profile(sender, model_tag)

        if not baseline:
            self._save_profile(sender, model_tag, current_vector, count=1)
            return {
                "anomaly_score": 0.0,
                "is_suspected_mimicry": False,
                "is_new_sender": True,
                "telemetry": routing_meta,
                "details": f"Neural Baseline created ({model_tag}), insufficient history"
            }

        # Step 3: Semantic cosine deviation
        base_vec = baseline["vector"].reshape(1, -1)
        curr_vec = current_vector.reshape(1, -1)
        similarity = float(cosine_similarity(base_vec, curr_vec)[0][0])
        semantic_deviation = 1.0 - max(similarity, 0.0)

        # Step 4: Lexical BEC risk scan
        lexical_score = self._compute_lexical_bec_score(text_content)

        # Step 5: Composite Hybrid Score
        composite_score = (self.settings.w_semantic * semantic_deviation) + (self.settings.w_lexical * lexical_score)

        # FIX-5: Enforce min_baseline_count — do not issue verdict until baseline is reliable.
        # An attacker who sends 1-2 "clean" messages would otherwise immediately get a
        # trusted baseline that BEC messages are compared against.
        min_count = getattr(self.settings, 'min_baseline_count', 3)
        if baseline["count"] < min_count:
            # Still update EMA baseline so it keeps accumulating
            alpha = self.settings.ema_alpha
            updated_vector = (baseline["vector"] * (1 - alpha)) + (current_vector * alpha)
            self._save_profile(sender, model_tag, updated_vector, count=baseline["count"] + 1)
            return {
                "anomaly_score": 0.0,
                "is_suspected_mimicry": False,
                "is_building_baseline": True,
                "baseline_count": baseline["count"] + 1,
                "baseline_required": min_count,
                "details": (
                    f"Baseline building ({baseline['count']+1}/{min_count} messages). "
                    f"Verdict withheld until minimum history reached."
                ),
            }

        # Step 6: Update baseline with EMA
        alpha = self.settings.ema_alpha
        updated_vector = (baseline["vector"] * (1 - alpha)) + (current_vector * alpha)
        self._save_profile(sender, model_tag, updated_vector, count=baseline["count"] + 1)

        result = {
            "anomaly_score": round(composite_score, 3),
            "semantic_deviation": round(semantic_deviation, 3),
            "lexical_bec_score": round(lexical_score, 3),
            "is_suspected_mimicry": composite_score > self.settings.lambda_opt,
            "details": f"Hybrid Score: {composite_score:.3f} (S:{semantic_deviation:.3f}/L:{lexical_score:.3f}) [Engine: {model_tag}]"
        }
        
        if self.settings.telemetry_level == "verbose":
            result["telemetry_routing"] = routing_meta
            
        return result

    def export_for_predictive_ai(self, sender: str, model_tag: str) -> Optional[Dict]:
        """Export sender profile for cross-module AI correlation."""
        profile = self._get_profile(sender, model_tag)
        if not profile:
            return None
        return {
            "sender": sender,
            "model_tag": model_tag,
            "vector_dim": len(profile["vector"]),
            "message_count": profile["count"],
        }
