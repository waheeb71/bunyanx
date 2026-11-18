import os
import sys
import time

# Resolve and add project root to python path dynamically
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def _phase(num: int, title: str):
    print(f"\n{'-' * 65}")
    print(f"  Phase {num}: {title}")
    print(f"{'-' * 65}")


def main():
    print("=" * 65)
    print("  bunyanx WAF — Full Model Rebuild & Training Pipeline")
    print("  5 AI Models: GAF | NLP | TemporalBiLSTM | Bot | GNN")
    print("=" * 65)
    start_all = time.time()
    failed: list[str] = []

    # ── Phase 1: GAF Semantic Intent (Layer 4b) ─────────────────────
    _phase(1, "GAF Semantic Intent Model (Layer 4b)")
    try:
        from modules.waf.ml_training.semantic_intent.train import train_model as train_gaf
        train_gaf(
            train_path=os.path.join(project_root, "modules/waf/ml_training/semantic_intent/datasets/train.csv"),
            val_path=os.path.join(project_root,   "modules/waf/ml_training/semantic_intent/datasets/val.csv"),
            save_path=os.path.join(project_root,  "ml/models/waf/semantic_intent"),
            epochs=1,
        )
    except Exception as e:
        print(f"  WARNING  GAF training failed: {e}")
        failed.append("GAF")

    # ── Phase 2: WAF NLP Classifier (Layer 4a — 1D-CNN + BiLSTM) ────
    _phase(2, "WAF NLP Attack Classifier (Layer 4a)")
    try:
        from modules.waf.ml_training.waf_nlp.train import train_nlp
        train_nlp(epochs=1)
    except Exception as e:
        print(f"  WARNING  NLP training failed: {e}")
        failed.append("NLP")

    # ── Phase 3: Temporal BiLSTM APT Tracker (Layer 4e) ─────────────
    # NEW: reads ALL CIC-IDS2018 files + UNSW-NB15 automatically.
    # No csv_path argument — paths are resolved inside train_temporal.
    _phase(3, "Temporal BiLSTM APT Tracker (Layer 4e) — Multi-File")
    try:
        from modules.waf.ml_training.waf_gnn.train_temporal import train_temporal
        train_temporal(
            save_path=os.path.join(project_root, "ml/models/waf/temporal_lstm.pt"),
            epochs=3,
        )
    except Exception as e:
        print(f"  WARNING  Temporal BiLSTM training failed: {e}")
        failed.append("Temporal")

    # ── Phase 4: Bot Detection XGBoost (Layer 4c) ────────────────────
    # NEW: loads Kaggle + UNSW-NB15 + CIC-DDoS2019, oversample minority.
    _phase(4, "Bot Detection XGBoost Classifier (Layer 4c) — Multi-Dataset")
    try:
        from modules.waf.ml_training.bot_detection.train import train_bot_model
        train_bot_model()
    except Exception as e:
        print(f"  WARNING  Bot training failed: {e}")
        failed.append("Bot")

    # ── Phase 5: GNN Session Graph (Layer 4d) ────────────────────────
    # NOTE: The GNN is a SELF-TRAINING model.
    # - During runtime, WAFInspectorPlugin accumulates session_logs.csv
    #   automatically from live traffic via SessionLogCollector.
    # - The live retraining API (POST /api/v1/waf/gnn/train) then
    #   retrains from that real data without any manual intervention.
    # - This phase trains a WARM-START model from synthetic sessions
    #   so the GNN is not cold on first deployment.
    _phase(5, "GNN Session Graph — Warm-Start (Layer 4d)")
    try:
        from modules.waf.ml_training.waf_gnn.train_gnn import train_gnn
        train_gnn(epochs=20)
    except Exception as e:
        print(f"  WARNING  GNN warm-start training failed: {e}")
        failed.append("GNN")

    # ── Summary ────────────────────────────────────────────────────
    elapsed = time.time() - start_all
    print("\n" + "=" * 65)
    print(f"  Training Pipeline Complete in {elapsed:.1f}s")
    if failed:
        print(f"  Phases with errors: {', '.join(failed)}")
        print("     (Remaining phases completed successfully)")
    else:
        print("  All 5 WAF models trained and saved successfully!")
    print("=" * 65)


if __name__ == "__main__":
    main()
