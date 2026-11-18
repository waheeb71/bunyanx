"""
bunyanx NGFW — ERS Weight Optimizer
=======================================
Offline Grid Search tool to find the optimal ERS signal weights.

Usage (run from project root after collecting enough training data)
-----------------------------------------------------------------
    python -m modules.dlp.engine.weight_optimizer

The optimizer reads the existing BEFP training log (JSONL), evaluates all
weight combinations against the labelled feedback database, and writes the
best-performing weights to ``modules/dlp/config/dlp_weights.json``.

``entropy_analyzer.py`` loads this file at startup if it exists, so the
system will automatically use the optimised weights on the next restart.

Phase 2 Task
------------
Run this script once at least 200 labelled (analyst-approved) feedback events
have accumulated in ``befp_feedback_db.json``.  After running, execute:

    pytest modules/dlp/tests/ -v

to verify that detection metrics improve over the default weights.
"""

from __future__ import annotations

import json
import logging
import math
import itertools
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────
import os
_ENV = os.getenv("NGFW_ENV", "production").lower()
_DATA_DIR_ENV = os.getenv("NGFW_DATA_DIR", "")
_MODULE_DIR = Path(__file__).parent
_CONFIG_DIR = _MODULE_DIR.parent / "config"

if _DATA_DIR_ENV:
    _DATA_ROOT = Path(_DATA_DIR_ENV)
elif _ENV != "production":
    _DATA_ROOT = _MODULE_DIR.parent / "ai" / "data"
else:
    _DATA_ROOT = _MODULE_DIR.parent / "ai"

TRAINING_LOG_PATH = _DATA_ROOT / "befp_training_log.jsonl"
FEEDBACK_DB_PATH  = _DATA_ROOT / "befp_feedback_db.json"
OUTPUT_WEIGHTS    = _CONFIG_DIR / "dlp_weights.json"

# ─── Grid Search Config ───────────────────────────────────────────────────────

# Candidate weight values for each signal.
# Coarse resolution first — refine manually after inspecting initial results.
_WEIGHT_CANDIDATES = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35]

# Signal names — must match keys in ERS_WEIGHTS (entropy_analyzer.py)
SIGNAL_NAMES = ["entropy", "velocity", "chunking", "protocol", "accumulation", "msem"]

# Minimum number of approved feedback labels required before optimising
MIN_FEEDBACK_SAMPLES = 50

# ERS threshold above which a sample is classified as anomalous
ERS_ANOMALY_THRESHOLD = 0.60


# ─── Helper: weight generator ─────────────────────────────────────────────────

def _weight_combinations(
    signals: list[str],
    candidates: list[float],
    tolerance: float = 0.01,
) -> Iterator[dict[str, float]]:
    """
    Yield all weight dicts where values are drawn from *candidates* and their
    sum is within *tolerance* of 1.0.

    This is a constrained grid search: we fix the last signal's weight so the
    sum equals exactly 1.0 (after rounding), reducing the search space from
    O(k^n) to O(k^(n-1)).
    """
    n = len(signals)
    for combo in itertools.product(candidates, repeat=n - 1):
        remainder = round(1.0 - sum(combo), 4)
        if remainder < 0.0 or remainder > max(candidates) + tolerance:
            continue
        weights = dict(zip(signals[:-1], combo))
        weights[signals[-1]] = remainder
        if abs(sum(weights.values()) - 1.0) < tolerance:
            yield weights


# ─── Data Loaders ─────────────────────────────────────────────────────────────

def _load_training_records() -> list[dict[str, Any]]:
    """Load all records from the BEFP training log."""
    records: list[dict] = []
    if not TRAINING_LOG_PATH.exists():
        logger.error(f"Training log not found: {TRAINING_LOG_PATH}")
        return records
    with open(TRAINING_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    return records


def _load_approved_labels() -> dict[str, str]:
    """
    Return a mapping of {src_ip: label} for all APPROVED feedback events.
    label is 'true_positive' or 'false_positive'.
    """
    labels: dict[str, str] = {}
    if not FEEDBACK_DB_PATH.exists():
        return labels
    try:
        with open(FEEDBACK_DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception as e:
        logger.error(f"Cannot load feedback DB: {e}")
        return labels

    for entry in db.values():
        if entry.get("status") == "approved":
            src_ip = entry.get("features", {}).get("src_ip")
            if src_ip:
                labels[src_ip] = entry["label"]

    return labels


# ─── Evaluation ───────────────────────────────────────────────────────────────

def _compute_ers(signals: dict[str, float], weights: dict[str, float]) -> float:
    """Re-compute ERS for a training record given a candidate weight set."""
    ers = sum(weights.get(k, 0.0) * signals.get(k, 0.0) for k in SIGNAL_NAMES)
    return min(max(ers, 0.0), 1.0)


def _evaluate_weights(
    records: list[dict],
    labels: dict[str, str],
    weights: dict[str, float],
) -> dict[str, float]:
    """
    Evaluate a weight configuration against labelled records.

    Returns a metrics dict: {f1, precision, recall, accuracy}.
    Only records whose src_ip appears in *labels* contribute to the score.
    """
    tp = fp = tn = fn = 0

    for rec in records:
        src_ip = rec.get("src_ip")
        label  = labels.get(src_ip)
        if label is None:
            continue  # No ground-truth label for this record

        features = rec.get("features", {})
        signals = rec.get("signals", {})
        signal_vals = {
            "entropy":      signals.get("entropy", features.get("entropy_score", 0.0)),
            "velocity":     signals.get("velocity", features.get("velocity_score", 0.0)),
            "chunking":     signals.get("chunking", features.get("chunk_pattern_score", 0.0)),
            "protocol":     signals.get("protocol", features.get("protocol_deviation_score", 0.0)),
            "accumulation": signals.get("accumulation", features.get("accumulation_score", 0.0)),
            "msem":         signals.get("msem", features.get("ers_score", 0.0)),
        }

        ers = _compute_ers(signal_vals, weights)
        predicted_anomaly = ers >= ERS_ANOMALY_THRESHOLD
        actual_anomaly = label == "true_positive"

        if predicted_anomaly and actual_anomaly:
            tp += 1
        elif predicted_anomaly and not actual_anomaly:
            fp += 1
        elif not predicted_anomaly and not actual_anomaly:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    if total == 0:
        return {"f1": 0.0, "precision": 0.0, "recall": 0.0, "accuracy": 0.0}

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / total

    return {
        "f1":        round(f1, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "accuracy":  round(accuracy, 4),
    }


# ─── Main: Grid Search ────────────────────────────────────────────────────────

class ERSWeightOptimizer:
    """
    Offline Grid Search optimiser for ERS signal weights.

    Iterates over all valid weight combinations, evaluates each against the
    labelled feedback dataset, and selects the configuration that maximises
    the F1-score (balancing precision and recall).
    """

    def run(self) -> dict[str, float] | None:
        """
        Execute the grid search.

        Returns the best weight dict, or None if there is insufficient data.
        Also saves the result to ``dlp_weights.json``.
        """
        logger.info("ERS Weight Optimizer: loading data ...")
        records = _load_training_records()
        labels  = _load_approved_labels()

        if not records:
            logger.error("No training records found. Collect data first.")
            return None

        if len(labels) < MIN_FEEDBACK_SAMPLES:
            logger.warning(
                f"Only {len(labels)} approved labels found "
                f"(need {MIN_FEEDBACK_SAMPLES}). Results may be unreliable."
            )

        logger.info(
            f"Grid search on {len(records)} records, "
            f"{len(labels)} labelled IPs, "
            f"{len(SIGNAL_NAMES)} signals ..."
        )

        best_weights: dict[str, float] | None = None
        best_metrics: dict[str, float] = {"f1": -1.0}
        n_evaluated = 0

        for weights in _weight_combinations(SIGNAL_NAMES, _WEIGHT_CANDIDATES):
            metrics = _evaluate_weights(records, labels, weights)
            n_evaluated += 1

            if metrics["f1"] > best_metrics["f1"]:
                best_metrics = metrics
                best_weights = dict(weights)

        logger.info(
            f"Grid search complete — evaluated {n_evaluated} combinations.\n"
            f"Best F1={best_metrics['f1']:.4f}  "
            f"P={best_metrics['precision']:.4f}  "
            f"R={best_metrics['recall']:.4f}  "
            f"Acc={best_metrics['accuracy']:.4f}\n"
            f"Best weights: {best_weights}"
        )

        if best_weights:
            self._save(best_weights, best_metrics)

        return best_weights

    def _save(self, weights: dict[str, float], metrics: dict[str, float]) -> None:
        """Persist the optimal weights to ``dlp_weights.json``."""
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "weights": weights,
            "metrics": metrics,
            "note": (
                "Auto-generated by weight_optimizer.py Grid Search. "
                "Loaded at startup by entropy_analyzer.py. "
                "Re-run after collecting more feedback data."
            ),
        }
        with open(OUTPUT_WEIGHTS, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info(f"Optimal weights saved to {OUTPUT_WEIGHTS}")


# ─── Auto-load helper (called by entropy_analyzer.py at startup) ──────────────

def load_weights_from_config() -> dict[str, float] | None:
    """
    Load ERS weights from ``dlp_weights.json`` if it exists.

    Called by ``entropy_analyzer.py`` at module load time so that the
    Grid-Search-derived weights take effect immediately without code changes.

    Returns None if the config file is absent (caller keeps its defaults).
    """
    if not OUTPUT_WEIGHTS.exists():
        return None
    try:
        with open(OUTPUT_WEIGHTS, "r", encoding="utf-8") as f:
            data = json.load(f)
        weights = data.get("weights")
        if weights and isinstance(weights, dict):
            # Validate: all expected signals present, sum ≈ 1.0
            if set(weights.keys()) == set(SIGNAL_NAMES):
                total = sum(weights.values())
                if abs(total - 1.0) < 0.02:
                    logger.info(
                        f"Loaded optimised ERS weights from {OUTPUT_WEIGHTS} "
                        f"(F1={data.get('metrics', {}).get('f1', 'N/A')})"
                    )
                    return weights
    except Exception as e:
        logger.warning(f"Could not load ERS weights config: {e}")
    return None


# ─── CLI entry-point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    result = ERSWeightOptimizer().run()
    if result:
        print("\n✅ Optimal weights found and saved:")
        for signal, w in result.items():
            print(f"   {signal:15s}: {w:.4f}")
    else:
        print("\n❌ Optimisation failed — check logs above.")
