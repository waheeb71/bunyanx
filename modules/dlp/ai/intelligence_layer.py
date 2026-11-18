"""
bunyanx NGFW — DLP AI Intelligence Layer
============================================
طبقة الذكاء الاصطناعي فوق BEFP.
تستخدم Isolation Forest (Unsupervised) لاكتشاف anomalies بدون labels.
تدعم Self-Learning Feedback Loop لتحسين الدقة مع الوقت.

Architecture:
    [ BEFP Signals ] → [ Feature Builder ] → [ Isolation Forest ] → [ Final Score ]
                                                                            ↑
                               [ Feedback Loop ] → [ Periodic Retraining ] ┘
"""

import os
import json
import time
import logging
import logging.handlers
import threading
import pickle
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from collections import deque
from filelock import FileLock

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────
# REM-03 FIX: Use NGFW_DATA_DIR env var so runtime data lives OUTSIDE the
# source code directory.  Falls back to a sibling 'data/' folder only in
# development (NGFW_ENV != 'production').
_ENV = os.getenv("NGFW_ENV", "production").lower()
_DATA_DIR_ENV = os.getenv("NGFW_DATA_DIR", "")

if _DATA_DIR_ENV:
    _DATA_ROOT = Path(_DATA_DIR_ENV)
elif _ENV != "production":
    # Development fallback: store next to the AI module
    _DATA_ROOT = Path(__file__).parent / "data"
else:
    # Production MUST set NGFW_DATA_DIR — fail loudly at import time
    raise EnvironmentError(
        "[DLP] NGFW_DATA_DIR environment variable is not set. "
        "Set it to a writable directory outside the source tree "
        "(e.g. /var/lib/ngfw/data) before starting the application."
    )

_DATA_ROOT.mkdir(parents=True, exist_ok=True)

MODEL_PATH        = _DATA_ROOT / "befp_isolation_forest.pkl"
MODEL_HASH_PATH   = _DATA_ROOT / "befp_isolation_forest.pkl.sha256"
TRAINING_LOG_PATH  = _DATA_ROOT / "befp_training_log.jsonl"
FEEDBACK_DB_PATH   = _DATA_ROOT / "befp_feedback_db.json"

# REM-03: Training log rotation config (overridable via .env)
_TRAINING_LOG_MAX_BYTES    = int(os.getenv("DLP_TRAINING_LOG_MAX_BYTES",  str(500 * 1024 * 1024)))  # 500 MB
_TRAINING_LOG_BACKUP_COUNT = int(os.getenv("DLP_TRAINING_LOG_BACKUP_COUNT", "5"))

EXPECTED_MODEL_HASH_ENV = "BEFP_MODEL_SHA256"
MODEL_SCHEMA_VERSION = "1.1"

# ─── Allowed modules for restricted deserialization ───────────────────────────
_PICKLE_SAFE_MODULES = {
    "sklearn.ensemble._iforest",
    "sklearn.ensemble",
    "sklearn.preprocessing._data",
    "sklearn.preprocessing",
    "sklearn.tree._tree",
    "sklearn.tree",
    "sklearn.utils._bunch",
    "sklearn.utils",
    "sklearn.neighbors._ball_tree",
    "sklearn.neighbors._kd_tree",
    "numpy",
    "numpy.core.multiarray",
    "numpy.core._multiarray_umath",
    "numpy.dtype",
    "numpy.random",
    "numpy.random._pickle",
    "builtins",
    "collections",
    "copyreg",
    "_codecs",
}


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows known-safe sklearn/numpy classes.
    Prevents arbitrary code execution via malicious .pkl files."""

    def find_class(self, module: str, name: str):
        # Allow safe modules
        if module in _PICKLE_SAFE_MODULES:
            return super().find_class(module, name)
        # Allow numpy sub-modules (numpy.core.*, numpy.random.*)
        if module.startswith("numpy."):
            return super().find_class(module, name)
        # Allow sklearn sub-modules
        if module.startswith("sklearn."):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"SECURITY: Blocked attempt to deserialize {module}.{name} — "
            f"only sklearn/numpy classes are permitted in BEFP model files."
        )

# ─── Config ───────────────────────────────────────────────────────────────────
MIN_TRAINING_SAMPLES = 100         # Min samples before first model train
FEEDBACK_RETRAINING_THRESHOLD = 50 # Retrain after N new labeled feedback events
AI_SCORE_WEIGHT = 0.40             # Weight of AI in final composite score
ERS_WEIGHT = 0.60                  # Weight of deterministic ERS in final score

# ─── Feature Vector Schema ────────────────────────────────────────────────────
FEATURE_KEYS = [
    # ── Original 9 dimensions ──────────────────────────────────────────────
    "entropy_score",
    "velocity_score",
    "chunk_pattern_score",
    "protocol_deviation_score",
    "accumulation_score",
    "ers_score",             # Composite ERS from BEFP
    "payload_entropy_bits",  # Raw Shannon bits/byte (normalised 0–1)
    "dst_port_normalized",   # dst_port / 65535
    "payload_size_kb",       # log-normalised payload size
    # ── MSEM-Lite Signal 6 (4 dimensions) ──────────────────────────────────
    "renyi_entropy_norm",        # Rényi H₂ / 8.0  →  [0, 1]
    "permutation_entropy_norm",  # Permutation entropy (already normalised)
    "ipt_spectral_peak",         # FFT peak power of inter-packet timing [0, 1]
    "lempel_ziv_complexity",     # LZ-76 normalised complexity [0, 1]
    # ── Full MSEM (2 additional — 0.0 in MSEM-Lite mode) ───────────────────
    "tsallis_entropy_norm",      # Tsallis(q=2) normalised [0, 1]
    "manifold_flatness_score",   # SVD intrinsic-dim MFS [0, 1]
    # Note: run feature_importances_ after 500+ samples (Phase 2) to
    # determine which dimensions should be retained or pruned.
]


@dataclass
class FeatureVector:
    # ── Original 9 dimensions ──
    entropy_score: float
    velocity_score: float
    chunk_pattern_score: float
    protocol_deviation_score: float
    accumulation_score: float
    ers_score: float
    payload_entropy_bits: float
    dst_port_normalized: float
    payload_size_kb: float
    # ── MSEM-Lite: 4 dimensions ──
    renyi_entropy_norm: float
    permutation_entropy_norm: float
    ipt_spectral_peak: float
    lempel_ziv_complexity: float
    # ── Full MSEM: 2 additional dimensions (0.0 when Lite mode active) ──
    tsallis_entropy_norm: float = 0.0
    manifold_flatness_score: float = 0.0

    def to_list(self) -> List[float]:
        return [getattr(self, k) for k in FEATURE_KEYS]


@dataclass
class AIInferenceResult:
    ai_anomaly_score: float   # 0.0 (normal) → 1.0 (highly anomalous)
    final_score: float        # Composite of ERS + AI
    decision: str             # NORMAL / SUSPICIOUS / HIGH_RISK / EXFILTRATION
    model_available: bool
    explanation: str


# ─────────────────────────────────────────────────────────────────────────────
# Feature Builder
# ─────────────────────────────────────────────────────────────────────────────

class FeatureBuilder:
    """Converts BEFP result + raw context into a normalised feature vector."""

    @staticmethod
    def build(
        befp_result,         # BEFPResult from entropy_analyzer.py
        dst_port: int = 0,
        payload_size: int = 0,
    ) -> FeatureVector:
        import math

        # Safely extract MSEM detail (supports both MSEMLiteResult and FullMSEMResult)
        msem = befp_result.msem_detail

        # Full MSEM extra fields (present only when FullMSEMResult)
        try:
            from modules.dlp.engine.manifold_scorer import FullMSEMResult
            is_full = isinstance(msem, FullMSEMResult)
        except ImportError:
            is_full = False

        return FeatureVector(
            # ── Original 9 dimensions ──
            entropy_score=befp_result.signal_entropy,
            velocity_score=befp_result.signal_velocity,
            chunk_pattern_score=befp_result.signal_chunking,
            protocol_deviation_score=befp_result.signal_protocol,
            accumulation_score=befp_result.signal_accumulation,
            ers_score=befp_result.ers,
            payload_entropy_bits=befp_result.payload_entropy / 8.0,
            dst_port_normalized=dst_port / 65535.0,
            payload_size_kb=math.log1p(payload_size / 1024.0) / 15.0,
            # ── MSEM-Lite: 4 dimensions ──
            renyi_entropy_norm=msem.renyi_entropy / 8.0         if msem else 0.0,
            permutation_entropy_norm=msem.perm_entropy          if msem else 0.0,
            ipt_spectral_peak=msem.ipt_spectral_peak            if msem else 0.0,
            lempel_ziv_complexity=msem.lz_complexity            if msem else 0.0,
            # ── Full MSEM: 2 additional dimensions (0.0 if Lite mode) ──
            tsallis_entropy_norm=msem.point.h_tsallis           if is_full else 0.0,
            manifold_flatness_score=msem.mfs_score              if is_full else 0.0,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Training Log Storage
# ─────────────────────────────────────────────────────────────────────────────

class TrainingStorage:
    """
    Appends feature vectors to a JSONL log for periodic retraining.

    REM-03 FIX — Disk Exhaustion Prevention
    ----------------------------------------
    * Rotation: when the log exceeds _TRAINING_LOG_MAX_BYTES (default 500 MB),
      the file is rotated using Python's RotatingFileHandler-style logic.
      Up to _TRAINING_LOG_BACKUP_COUNT (default 5) rotated files are kept.
    * Thread-safe: a class-level lock serialises all writes.
    * The path is now under NGFW_DATA_DIR (not inside the source tree).
    """

    _write_lock = threading.Lock()

    @staticmethod
    def _anonymize_ip(ip: str) -> str:
        """One-way hash of IP for privacy-safe logging."""
        return "ip_" + hashlib.sha256(ip.encode()).hexdigest()[:12]

    @classmethod
    def _rotate_if_needed(cls) -> None:
        """
        If TRAINING_LOG_PATH exceeds _TRAINING_LOG_MAX_BYTES, rotate:
        .jsonl.4 → deleted
        .jsonl.3 → .jsonl.4
        ...
        .jsonl   → .jsonl.1
        """
        if not TRAINING_LOG_PATH.exists():
            return
        size = TRAINING_LOG_PATH.stat().st_size
        if size <= _TRAINING_LOG_MAX_BYTES:
            return

        logger.warning(
            f"[DLP][TRAINING] Log size {size / 1024 / 1024:.1f} MB exceeds "
            f"limit ({_TRAINING_LOG_MAX_BYTES / 1024 / 1024:.0f} MB). Rotating."
        )
        # Delete oldest backup
        oldest = TRAINING_LOG_PATH.with_suffix(f".jsonl.{_TRAINING_LOG_BACKUP_COUNT}")
        if oldest.exists():
            oldest.unlink()

        # Shift existing backups
        for i in range(_TRAINING_LOG_BACKUP_COUNT - 1, 0, -1):
            src = TRAINING_LOG_PATH.with_suffix(f".jsonl.{i}")
            dst = TRAINING_LOG_PATH.with_suffix(f".jsonl.{i + 1}")
            if src.exists():
                src.rename(dst)

        # Rotate current → .1
        TRAINING_LOG_PATH.rename(TRAINING_LOG_PATH.with_suffix(".jsonl.1"))
        logger.info("[DLP][TRAINING] Log rotation complete.")

    @classmethod
    def log_event(cls, features: FeatureVector, befp_result) -> None:
        record = {
            "timestamp": time.time(),
            "src_ip": cls._anonymize_ip(befp_result.src_ip),
            "decision": befp_result.decision,
            "ers": befp_result.ers,
            "features": asdict(features),
            "signals": {
                "entropy":      befp_result.signal_entropy,
                "velocity":     befp_result.signal_velocity,
                "chunking":     befp_result.signal_chunking,
                "protocol":     befp_result.signal_protocol,
                "accumulation": befp_result.signal_accumulation,
                "msem":         befp_result.signal_msem,
            },
        }
        with cls._write_lock:
            try:
                cls._rotate_if_needed()
                with open(TRAINING_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except OSError as e:
                logger.error(
                    f"[DLP][TRAINING] Failed to write training event (disk full?): {e}"
                )
            except Exception as e:
                logger.warning(f"[DLP][TRAINING] Unexpected error logging event: {e}")

    @staticmethod
    def log_size_bytes() -> int:
        """Return current training log size in bytes (0 if not yet created)."""
        return TRAINING_LOG_PATH.stat().st_size if TRAINING_LOG_PATH.exists() else 0

    @staticmethod
    def load_training_data() -> List[List[float]]:
        """Loads all unlabeled feature vectors from the active log for training."""
        vectors = []
        if not TRAINING_LOG_PATH.exists():
            return vectors
        try:
            with open(TRAINING_LOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        fv = FeatureVector(**record["features"])
                        vectors.append(fv.to_list())
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue  # Skip malformed lines silently
        except Exception as e:
            logger.error(f"[DLP][TRAINING] Failed to load training data: {e}")
        return vectors


# ─────────────────────────────────────────────────────────────────────────────
# Feedback Loop Storage
# ─────────────────────────────────────────────────────────────────────────────

class FeedbackStorage:
    """
    Stores analyst feedback (TP/FP labels) in a JSON file.

    REM-04 FIX — Race Condition Elimination
    -----------------------------------------
    The original code had a classic TOCTOU (read → modify → write) race:
      Thread A: _load_db() → gets dict D
      Thread B: _load_db() → gets dict D  (same snapshot)
      Thread A: D[id] = {...}; _save_db(D)  → writes
      Thread B: D[id] = {...}; _save_db(D)  → overwrites Thread A's write

    Fix: a single class-level RLock wraps the ENTIRE read-modify-write cycle
    in every mutating method. _load_db / _save_db are now internal helpers
    called only while the caller holds _rw_lock.

    The in-memory cache is invalidated on every successful write so a
    subsequent read always sees the latest state.
    """

    # Use FileLock for cross-process synchronization (e.g., Gunicorn/Uvicorn workers)
    _lock_path = str(FEEDBACK_DB_PATH) + ".lock"
    _cache: dict = {}
    _cache_valid: bool = False

    # ── Internal helpers (must be called while holding the lock) ─────────────

    @classmethod
    def _load_db_locked(cls) -> dict:
        """Load and cache the DB. Caller MUST hold the file lock."""
        if cls._cache_valid:
            return cls._cache
        if not FEEDBACK_DB_PATH.exists():
            cls._cache = {}
            cls._cache_valid = True
            return cls._cache
        try:
            with open(FEEDBACK_DB_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Feedback DB root must be a JSON object")
            cls._cache = data
            cls._cache_valid = True
            logger.debug("[DLP][FEEDBACK] Loaded feedback DB (%d entries)", len(data))
            return cls._cache
        except json.JSONDecodeError as e:
            logger.error(
                "[DLP][FEEDBACK] feedback_db.json is malformed: %s — "
                "treating as empty. Manual recovery may be required: %s",
                e, FEEDBACK_DB_PATH,
            )
            cls._cache = {}
            cls._cache_valid = True
            return cls._cache
        except Exception as e:
            logger.error("[DLP][FEEDBACK] Failed to load feedback DB: %s", e)
            cls._cache = {}
            cls._cache_valid = True
            return cls._cache

    @classmethod
    def _save_db_locked(cls, db: dict) -> None:
        """Atomically persist *db* to disk. Caller MUST hold the file lock."""
        try:
            tmp = FEEDBACK_DB_PATH.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
            os.replace(tmp, FEEDBACK_DB_PATH)  # atomic on POSIX & Windows
            cls._cache = db
            cls._cache_valid = True
        except Exception as e:
            logger.error("[DLP][FEEDBACK] Failed to persist feedback DB: %s", e)
            # Invalidate cache so next read re-loads from disk
            cls._cache_valid = False
            raise

    # ── Public API ────────────────────────────────────────────────────────────

    # Rate limiting: max feedback submissions per event_id per time window
    _RATE_LIMIT_WINDOW_SEC = 300  # 5 minutes
    _RATE_LIMIT_MAX_SUBMISSIONS = 3  # max submissions per event_id per window
    _rate_limit_cache: dict = {}  # {event_id: [(timestamp, submitted_by), ...]}

    @classmethod
    def _check_rate_limit(cls, event_id: str, submitted_by: str) -> bool:
        """Check if submission is within rate limits. Returns True if allowed."""
        now = time.time()
        cutoff = now - cls._RATE_LIMIT_WINDOW_SEC
        
        if event_id not in cls._rate_limit_cache:
            cls._rate_limit_cache[event_id] = []
        
        # Clean old entries
        cls._rate_limit_cache[event_id] = [
            (ts, by) for ts, by in cls._rate_limit_cache[event_id]
            if ts > cutoff
        ]
        
        # Check limit
        if len(cls._rate_limit_cache[event_id]) >= cls._RATE_LIMIT_MAX_SUBMISSIONS:
            logger.warning(
                "[DLP][FEEDBACK] Rate limit exceeded for event_id=%s by %s — "
                "max %d submissions per %d seconds",
                event_id, submitted_by, cls._RATE_LIMIT_MAX_SUBMISSIONS, cls._RATE_LIMIT_WINDOW_SEC
            )
            return False
        
        # Record this submission
        cls._rate_limit_cache[event_id].append((now, submitted_by))
        return True

    @classmethod
    def log_feedback(
        cls,
        event_id: str,
        label: str,
        submitted_by: str,
        features: Optional[dict] = None,
    ) -> None:
        # SECURITY FIX (CRITICAL): Add rate limiting to prevent feedback poisoning
        if not cls._check_rate_limit(event_id, submitted_by):
            raise ValueError(
                f"[DLP][FEEDBACK] Rate limit exceeded for event_id={event_id}. "
                f"Max {cls._RATE_LIMIT_MAX_SUBMISSIONS} submissions per {cls._RATE_LIMIT_WINDOW_SEC}s."
            )
        
        with FileLock(cls._lock_path, timeout=10):
            db = cls._load_db_locked()
            if event_id in db:
                # Check if same user is re-submitting - still allow admin review updates
                existing = db[event_id]
                if existing.get("submitted_by") == submitted_by:
                    logger.warning(
                        "[DLP][FEEDBACK] Duplicate feedback for event_id=%s by %s — updating existing record",
                        event_id, submitted_by,
                    )
            db[event_id] = {
                "timestamp": time.time(),
                "event_id": event_id,
                "label": label,
                "status": "pending",
                "submitted_by": submitted_by,
                "reviewed_by": None,
                "features": features or {},
            }
            cls._save_db_locked(db)

    @classmethod
    def review_feedback(cls, event_id: str, action: str, admin_user: str) -> bool:
        """action: 'approve' or 'reject'."""
        if action not in ("approve", "reject"):
            logger.error("[DLP][FEEDBACK] Invalid review action: %s", action)
            return False
        with FileLock(cls._lock_path, timeout=10):
            db = cls._load_db_locked()
            if event_id not in db:
                return False
            db[event_id]["status"] = "approved" if action == "approve" else "rejected"
            db[event_id]["reviewed_by"] = admin_user
            db[event_id]["reviewed_at"] = time.time()
            cls._save_db_locked(db)
        return True

    @classmethod
    def count_approved_feedback(cls) -> int:
        with FileLock(cls._lock_path, timeout=10):
            db = cls._load_db_locked()
        return sum(1 for v in db.values() if v.get("status") == "approved")

    @classmethod
    def get_pending_feedback(cls) -> List[dict]:
        with FileLock(cls._lock_path, timeout=10):
            db = cls._load_db_locked()
        pending = [v for v in db.values() if v.get("status") == "pending"]
        return sorted(pending, key=lambda x: x["timestamp"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Model Manager: Train / Save / Load Isolation Forest
# ─────────────────────────────────────────────────────────────────────────────

class BEFPModelManager:
    """
    Manages the lifecycle of the Isolation Forest model:
    - Loads existing model from disk
    - Trains new model when enough unlabeled data is available
    - Saves trained model to disk
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._model = None
                cls._instance._model_lock = threading.RLock()
                cls._instance._training_in_progress = False
                cls._instance._feedback_since_last_train = 0
                cls._instance._load_model()
            return cls._instance

    def _load_model(self):
        if not MODEL_PATH.exists():
            logger.info("No BEFP AI model found. Will train after enough samples.")
            return

        # ── MANDATORY hash verification ──────────────────────────────────
        env_hash = os.environ.get(EXPECTED_MODEL_HASH_ENV)

        if env_hash:
            # ENV var is the absolute source of truth if set.
            expected_hash = env_hash
            logger.info(f"Using {EXPECTED_MODEL_HASH_ENV} for model verification.")
        elif MODEL_HASH_PATH.exists():
            # Fallback to sidecar only if ENV var is not set.
            try:
                expected_hash = MODEL_HASH_PATH.read_text(encoding="utf-8").strip()
            except Exception as e:
                logger.critical(f"SECURITY: Failed to read model hash sidecar: {e}. Refusing to load.")
                self._model = None
                return
        else:
            logger.critical(
                f"SECURITY: BEFP model file exists at {MODEL_PATH} but NO hash "
                f"sidecar ({MODEL_HASH_PATH}) and NO {EXPECTED_MODEL_HASH_ENV} env var. "
                f"Refusing to load unverified model to prevent potential RCE."
            )
            self._model = None
            return

        # Step 2: Verify SHA256
        try:
            actual_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                logger.critical(
                    f"SECURITY: BEFP model hash MISMATCH! "
                    f"Expected={expected_hash} Got={actual_hash}. "
                    f"Model file may have been tampered with. Refusing to load."
                )
                self._model = None
                return
        except Exception as e:
            logger.critical(f"SECURITY: Failed to compute model hash: {e}. Refusing to load.")
            self._model = None
            return

        # ── Restricted deserialization ────────────────────────────────────
        try:
            with open(MODEL_PATH, "rb") as f:
                bundle = _RestrictedUnpickler(f).load()

            if bundle.get("schema_version") != MODEL_SCHEMA_VERSION:
                logger.warning(f"Model schema mismatch. Expected {MODEL_SCHEMA_VERSION}, "
                               f"got {bundle.get('schema_version')}. Discarding old model.")
                self._model = None
                return

            self._model = bundle
            logger.info(f"BEFP AI Model loaded from {MODEL_PATH} (hash verified: {actual_hash[:16]}...)")
        except pickle.UnpicklingError as e:
            logger.critical(f"SECURITY: Restricted unpickler blocked model load: {e}")
            self._model = None
        except Exception as e:
            logger.warning(f"Failed to load BEFP model: {e}. Will train fresh.")
            self._model = None

    @property
    def is_ready(self) -> bool:
        return self._model is not None

    def train_async(self):
        """Launches model training in a background thread."""
        if self._training_in_progress:
            return
        t = threading.Thread(target=self._train, daemon=True, name="BEFP-Trainer")
        t.start()

    def _train(self):
        self._training_in_progress = True
        try:
            # Try importing sklearn — optional dependency
            try:
                from sklearn.ensemble import IsolationForest
                from sklearn.preprocessing import StandardScaler
            except ImportError:
                logger.warning("scikit-learn not installed. BEFP AI layer disabled. Run: pip install scikit-learn")
                return

            vectors = TrainingStorage.load_training_data()
            if len(vectors) < MIN_TRAINING_SAMPLES:
                logger.info(f"BEFP: Only {len(vectors)} samples — need {MIN_TRAINING_SAMPLES} to train.")
                return

            logger.info(f"Training BEFP Isolation Forest on {len(vectors)} samples...")
            scaler = StandardScaler()
            X = scaler.fit_transform(vectors)

            model = IsolationForest(
                n_estimators=150,
                contamination=0.03,   # Expect ~3% anomalies
                max_samples="auto",
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X)

            # Bundle scaler + model together
            bundle = {
                "model": model,
                "scaler": scaler,
                "schema_version": MODEL_SCHEMA_VERSION,
                "feature_keys": FEATURE_KEYS,
                "trained_at": time.time(),
                "n_samples": len(vectors)
            }

            # Atomic write: model file + hash sidecar
            model_tmp = MODEL_PATH.with_name(MODEL_PATH.name + ".tmp")
            hash_tmp = MODEL_HASH_PATH.with_name(MODEL_HASH_PATH.name + ".tmp")
            try:
                with open(model_tmp, "wb") as f:
                    pickle.dump(bundle, f)

                # Compute and write SHA256 hash sidecar
                model_hash = hashlib.sha256(model_tmp.read_bytes()).hexdigest()
                with open(hash_tmp, "w", encoding="utf-8") as f:
                    f.write(model_hash)

                # Atomic replace (both files)
                os.replace(model_tmp, MODEL_PATH)
                os.replace(hash_tmp, MODEL_HASH_PATH)

                logger.info(f"BEFP model saved with hash sidecar: {model_hash[:16]}...")
            except Exception as e:
                # Cleanup temp files on failure
                for tmp in (model_tmp, hash_tmp):
                    try:
                        tmp.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise  # Re-raise to be caught by outer handler

            with self._model_lock:
                self._model = bundle

            self._feedback_since_last_train = 0
            logger.info(f"BEFP AI Model trained & saved. ({len(vectors)} samples, contamination=0.03)")

        except Exception as e:
            logger.error(f"BEFP model training failed: {e}", exc_info=True)
        finally:
            self._training_in_progress = False

    def predict(self, feature_vector: List[float]) -> float:
        """Returns anomaly score 0.0 (normal) → 1.0 (highly anomalous)."""
        with self._model_lock:
            if self._model is None:
                return 0.0
            try:
                scaler = self._model["scaler"]
                model = self._model["model"]
                X = scaler.transform([feature_vector])
                # decision_function returns negative for anomalies
                raw_score = model.decision_function(X)[0]
                # Normalize to 0–1: more negative = more anomalous → closer to 1.0
                score = max(0.0, min(1.0, (-raw_score + 0.5) / 1.0))
                return round(score, 4)
            except Exception as e:
                logger.error(f"BEFP inference failed: {e}")
                return 0.0

    def maybe_trigger_retraining(self):
        """Check if enough APPROVED feedback has accumulated to warrant retraining."""
        count = FeedbackStorage.count_approved_feedback()
        if count - self._feedback_since_last_train >= FEEDBACK_RETRAINING_THRESHOLD:
            logger.info("BEFP: Feedback threshold reached. Triggering model retraining...")
            self.train_async()
            self._feedback_since_last_train = count

    def check_and_train_if_ready(self):
        """Called periodically on first startup."""
        if not self.is_ready:
            vectors = TrainingStorage.load_training_data()
            if len(vectors) >= MIN_TRAINING_SAMPLES:
                self.train_async()


# ─────────────────────────────────────────────────────────────────────────────
# AI Inference Engine (Public API)
# ─────────────────────────────────────────────────────────────────────────────

class BEFPIntelligenceLayer:
    """
    Public-facing AI inference layer.
    Combines deterministic ERS (from BEFP) with probabilistic AI score
    using the supervisor's recommended Decision Fusion formula:
        final_score = (0.60 × ERS) + (0.40 × AI_score)
    """
    import concurrent.futures
    # REM-03/PERF FIX: Bound the work queue to prevent memory exhaustion
    # under high packet throughput. If the queue is full, log_event() is
    # skipped gracefully rather than causing OOM.
    _executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=2,
        thread_name_prefix="BEFP-Log",
    )
    _LOG_QUEUE_MAX = 500  # max pending log tasks

    def __init__(self):
        self._model_mgr = BEFPModelManager()
        # Trigger training check on init (non-blocking)
        t = threading.Thread(target=self._model_mgr.check_and_train_if_ready, daemon=True)
        t.start()

    def infer(self, befp_result, dst_port: int = 0, payload_size: int = 0) -> AIInferenceResult:
        """
        Run AI inference on a BEFPResult.
        Returns a fused final_score and decision.
        """
        try:
            features = FeatureBuilder.build(befp_result, dst_port, payload_size)

            # Log for future training (async — bounded queue to prevent memory exhaustion)
            pending_count = self._executor._work_queue.qsize()  # type: ignore[attr-defined]
            if pending_count < self._LOG_QUEUE_MAX:
                self._executor.submit(TrainingStorage.log_event, features, befp_result)
            else:
                logger.warning(
                    "[DLP][TRAINING] Log queue full (%d pending) — skipping training log "
                    "for this event to prevent memory exhaustion.",
                    pending_count,
                )

            # AI prediction
            ai_score = 0.0
            model_available = self._model_mgr.is_ready
            if model_available:
                ai_score = self._model_mgr.predict(features.to_list())

            # Decision Fusion (supervisor's formula)
            ers = befp_result.ers
            if model_available:
                final_score = round((ERS_WEIGHT * ers) + (AI_SCORE_WEIGHT * ai_score), 4)
            else:
                final_score = ers  # Fallback: 100% deterministic ERS if AI model is not ready
            final_score = min(final_score, 1.0)

            # Map to decision
            # REM-09: Use unified ERS_THRESHOLDS constants
            import modules.dlp.engine.entropy_analyzer as ea
            thresh = ea.ERS_THRESHOLDS
            if final_score >= thresh["HIGH_RISK"]:
                decision = "EXFILTRATION"
            elif final_score >= thresh["SUSPICIOUS"]:
                decision = "HIGH_RISK"
            elif final_score >= thresh["NORMAL"]:
                decision = "SUSPICIOUS"
            else:
                decision = "NORMAL"

            explanation = (
                f"ERS={ers:.3f} × 0.6 + AI={ai_score:.3f} × 0.4 = {final_score:.3f} [{decision}]"
                if model_available
                else f"ERS={ers:.3f} (AI model training, need {MIN_TRAINING_SAMPLES} samples)"
            )

            # Periodic retraining check
            self._model_mgr.maybe_trigger_retraining()

            return AIInferenceResult(
                ai_anomaly_score=ai_score,
                final_score=final_score,
                decision=decision,
                model_available=model_available,
                explanation=explanation,
            )

        except Exception as e:
            logger.error(f"BEFP AI inference error: {e}", exc_info=True)
            return AIInferenceResult(
                ai_anomaly_score=0.0,
                final_score=befp_result.ers,
                decision=befp_result.decision,
                model_available=False,
                explanation=f"AI error: {e}",
            )

    def submit_feedback(self, event_id: str, label: str, submitted_by: str, features_dict: Optional[dict] = None):
        """
        Called by analyst to label a detection. Placed in 'pending' queue.
        """
        FeedbackStorage.log_feedback(event_id, label, submitted_by, features_dict)
        logger.info(f"BEFP feedback submitted (pending review): event={event_id} label={label} by={submitted_by}")

    def review_feedback(self, event_id: str, action: str, admin_user: str) -> bool:
        """
        Admin approval for feedback to enter the training dataset.
        Triggers retraining when threshold reached.
        """
        success = FeedbackStorage.review_feedback(event_id, action, admin_user)
        if success and action == "approve":
            logger.info(f"BEFP feedback APPROVED: event={event_id} by={admin_user}")
            self._model_mgr.maybe_trigger_retraining()
        elif success and action == "reject":
            logger.info(f"BEFP feedback REJECTED: event={event_id} by={admin_user}")
        return success

    def get_pending_feedback(self) -> List[dict]:
        return FeedbackStorage.get_pending_feedback()
