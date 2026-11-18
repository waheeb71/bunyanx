"""
Enterprise bunyanx — WAF Bot Detection XGBoost Training Script

Trains an XGBoost binary classifier (human=0 / bot=1) on the
Kaggle Human-or-Robot dataset, then saves as bot_model.json.

The 10 features in the dataset map to BotDetectionModel.feature_names:
    bidder_id       → dropped (ID column)
    outcome         → label (0=human, 1=bot)
    total_bids      → request_rate (proxy)
    total_auctions  → unique_endpoints
    bids_per_auction→ iat_variance (inverse IAT)
    mean_time_diff  → session_duration (proxy)
    mean_response   → header_count (proxy)
    min_response    → cookie_count (proxy)
    ip_entropy      → user_agent_entropy
    url_entropy     → method_diversity (proxy)
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

# ── Path resolution ──────────────────────────────────────────────────────────
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

TRAIN_CSV  = os.path.join(project_root, "modules/waf/ml_training/bot_detection/datasets/Kaggle-Human-or-Robot_train.csv")
SAVE_PATH  = os.path.join(project_root, "ml/models/waf/bot_model.json")

# Supplementary datasets
UNSW_TRAIN = os.path.join(project_root, "ml/data/NUSW-NB15/UNSW_NB15_training-set.csv")
CIC_DDOS   = os.path.join(project_root, "ml/data/CIC-DDoS2019")


def load_and_map_features(csv_path: str, is_test: bool = False) -> tuple:
    """
    Load the Kaggle Human-or-Robot CSV and map columns to BotDetectionModel
    feature_names so the trained model is compatible with runtime inference.

    BotDetectionModel.feature_names order:
        0  request_rate
        1  iat_variance
        2  session_duration
        3  unique_endpoints
        4  user_agent_entropy
        5  header_count
        6  accept_language_valid  (constant=1, not in dataset)
        7  cookie_count
        8  referer_present        (constant=1, not in dataset)
        9  method_diversity
    """
    df = pd.read_csv(csv_path)
    print(f"  Loaded {len(df)} rows from {os.path.basename(csv_path)}")

    # Drop the ID column
    df = df.drop(columns=["bidder_id"], errors="ignore")

    # Fill NaN values
    df = df.fillna(0.0)

    # Extract label (training set only)
    if not is_test and "outcome" in df.columns:
        y = df["outcome"].astype(float).values
        df = df.drop(columns=["outcome"])
    else:
        y = None

    # Build the 10-feature vector matching BotDetectionModel.feature_names
    X = pd.DataFrame({
        "request_rate":         df.get("total_bids",       pd.Series([0.0] * len(df))),
        "iat_variance":         df.get("bids_per_auction",  pd.Series([0.0] * len(df))),
        "session_duration":     df.get("mean_time_diff",    pd.Series([0.0] * len(df))),
        "unique_endpoints":     df.get("total_auctions",    pd.Series([0.0] * len(df))),
        "user_agent_entropy":   df.get("ip_entropy",        pd.Series([0.0] * len(df))),
        "header_count":         df.get("mean_response",     pd.Series([0.0] * len(df))),
        "accept_language_valid": 1.0,   # constant — not in dataset
        "cookie_count":         df.get("min_response",      pd.Series([0.0] * len(df))),
        "referer_present":      1.0,    # constant — not in dataset
        "method_diversity":     df.get("url_entropy",       pd.Series([0.0] * len(df))),
    })

    return X.values.astype(np.float32), y


def load_unsw_as_bot_data(csv_path: str, max_per_class: int = 4000) -> tuple:
    """
    UNSW-NB15: map attack records → bot=1, benign → human=0.
    Capped at max_per_class per class to avoid dominating the Kaggle dataset.
    """
    if not os.path.exists(csv_path):
        return None, None
    try:
        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = [c.strip().lower() for c in df.columns]
        label_col = 'label' if 'label' in df.columns else None
        if label_col is None:
            return None, None
        y_all = df[label_col].astype(int).values

        def _get(col):
            """Safely get column as Series — returns zeros if column missing."""
            if col in df.columns:
                return pd.to_numeric(df[col], errors='coerce').fillna(0)
            return pd.Series(np.zeros(len(df)))

        X_all = np.stack([
            _get('rate').values,
            _get('sinpkt').values,
            _get('dur').values,
            _get('ct_dst_ltm').values,
            _get('ct_src_ltm').values,
            _get('spkts').values,
            np.ones(len(df)),
            _get('dpkts').values,
            np.ones(len(df)),
            _get('ct_state_ttl').values,
        ], axis=1).astype(np.float32)

        # Normalize to [0, 5]
        col_max = np.abs(X_all).max(axis=0) + 1e-8
        X_all = X_all / col_max * 5.0

        # Cap per class to prevent UNSW from dominating
        rng = np.random.default_rng(0)
        idx_attack = np.where(y_all == 1)[0]
        idx_benign = np.where(y_all == 0)[0]
        idx_attack = rng.choice(idx_attack, min(len(idx_attack), max_per_class), replace=False)
        idx_benign = rng.choice(idx_benign, min(len(idx_benign), max_per_class), replace=False)
        idx = np.concatenate([idx_attack, idx_benign])
        rng.shuffle(idx)
        X, y = X_all[idx], y_all[idx]
        print(f"  [UNSW-NB15] Sampled {len(X)} rows | attacks={y.sum()}/{len(y)} (capped at {max_per_class}/class)")
        return X, y
    except Exception as e:
        print(f"  [UNSW-NB15] Skipped: {e}")
        return None, None


def load_ddos_as_bot_data(ddos_dir: str, max_rows: int = 3000) -> tuple:
    """
    CIC-DDoS2019 parquet: DDoS attack flows → bot=1, BENIGN → human=0.
    Uses network features mapped to BotDetectionModel behavioral space.
    """
    if not os.path.isdir(ddos_dir):
        return None, None
    import glob
    parquet_files = sorted(glob.glob(os.path.join(ddos_dir, "*.parquet")))[:6]
    if not parquet_files:
        return None, None
    all_X, all_y = [], []
    for fpath in parquet_files:
        try:
            df = pd.read_parquet(fpath)
            df.columns = [c.strip() for c in df.columns]
            label_col = next((c for c in df.columns if c.lower() == 'label'), None)
            if label_col is None:
                continue
            y = (df[label_col] != 'BENIGN').astype(int).values

            # gcol: safely get column as numpy array, zeros if missing
            def gcol(col):
                if col in df.columns:
                    return pd.to_numeric(df[col], errors='coerce').fillna(0).values
                return np.zeros(len(df), dtype=np.float32)

            X = np.stack([
                gcol('Flow Duration') / 1e6,
                gcol('Tot Fwd Pkts'),
                gcol('Tot Bwd Pkts'),
                gcol('Fwd Pkt Len Mean'),
                gcol('Bwd Pkt Len Mean'),
                gcol('Flow Pkts/s'),
                np.ones(len(df)),
                gcol('Pkt Len Mean'),
                np.ones(len(df)),
                gcol('Flow Byts/s'),
            ], axis=1).astype(np.float32)

            X = np.clip(X, 0, 1e6)
            col_max = X.max(axis=0) + 1e-8
            X = X / col_max * 5.0
            all_X.append(X[:max_rows])
            all_y.append(y[:max_rows])
            print(f"  [DDoS2019] {os.path.basename(fpath)}: {len(X[:max_rows])} rows | attacks={y[:max_rows].sum()}")
        except Exception as e:
            print(f"  [DDoS2019] {os.path.basename(fpath)}: skip ({e})")

    if not all_X:
        return None, None
    return np.concatenate(all_X), np.concatenate(all_y)


def oversample_minority(X: np.ndarray, y: np.ndarray, target_ratio: float = 0.35) -> tuple:
    """
    Balance bot/human ratio to target_ratio.
    - If bots < target: oversample with Gaussian jitter.
    - If bots > (1 - target): downsample bots to prevent reverse imbalance.
    """
    rng     = np.random.default_rng(42)
    n_bot   = int((y == 1).sum())
    n_human = int((y == 0).sum())
    current_ratio = n_bot / max(n_bot + n_human, 1)

    # Case 1: Too few bots → oversample
    target_bots = int(n_human * target_ratio)
    if n_bot < target_bots:
        needed = target_bots - n_bot
        bot_X  = X[y == 1]
        copies = np.tile(bot_X, (needed // max(len(bot_X), 1) + 2, 1))[:needed]
        copies += rng.normal(0, 0.05, copies.shape)
        X_aug = np.concatenate([X, copies])
        y_aug = np.concatenate([y, np.ones(needed)])
        idx   = rng.permutation(len(X_aug))
        print(f"  Oversampled bots: {n_bot} -> {target_bots} | total={len(X_aug)}")
        return X_aug[idx], y_aug[idx]

    # Case 2: Too many bots (> 50%) → downsample bots
    max_bots = int(n_human / (1.0 - target_ratio) * target_ratio)
    if n_bot > max_bots:
        bot_idx    = np.where(y == 1)[0]
        human_idx  = np.where(y == 0)[0]
        bot_idx    = rng.choice(bot_idx, max_bots, replace=False)
        idx        = np.concatenate([bot_idx, human_idx])
        rng.shuffle(idx)
        print(f"  Downsampled bots: {n_bot} -> {max_bots} | total={len(idx)}")
        return X[idx], y[idx]

    print(f"  Bot ratio {current_ratio*100:.1f}% already in range — no resampling needed")
    return X, y


def train_bot_model():
    print("=" * 60)
    print("  bunyanx WAF Bot Detection — XGBoost Training (Multi-Dataset)")
    print("=" * 60)
    t0 = time.time()

    # ── Load Kaggle base dataset ───────────────────────────────
    print("\n[1/5] Loading datasets...")
    X_base, y_base = load_and_map_features(TRAIN_CSV, is_test=False)
    print(f"  [Kaggle] {X_base.shape} | bots={int(y_base.sum())} / humans={int((y_base==0).sum())}")

    all_X = [X_base]
    all_y = [y_base]

    # ── UNSW-NB15 ──────────────────────────────────────────────
    X_unsw, y_unsw = load_unsw_as_bot_data(UNSW_TRAIN)
    if X_unsw is not None:
        all_X.append(X_unsw)
        all_y.append(y_unsw.astype(float))

    # ── CIC-DDoS2019 ───────────────────────────────────────────
    X_ddos, y_ddos = load_ddos_as_bot_data(CIC_DDOS)
    if X_ddos is not None:
        all_X.append(X_ddos)
        all_y.append(y_ddos.astype(float))

    # ── Merge ──────────────────────────────────────────────────
    X = np.concatenate(all_X, axis=0).astype(np.float32)
    y = np.concatenate(all_y, axis=0)
    print(f"\n  Combined: {X.shape} | bots={int(y.sum())} ({100*y.mean():.1f}%) / humans={int((y==0).sum())}")

    # ── Oversample minority (bot) class ───────────────────────
    print("\n[2/5] Oversampling bot class...")
    X, y = oversample_minority(X, y, target_ratio=0.35)
    print(f"  Final: {X.shape} | bots={int(y.sum())} ({100*y.mean():.1f}%)")

    # ── Train / val split ──────────────────────────────────────
    print("\n[3/5] Splitting train/val...")
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)} | Val: {len(X_val)}")

    dtrain = xgb.DMatrix(X_train, label=y_train)
    dval   = xgb.DMatrix(X_val,   label=y_val)

    # ── Model params ───────────────────────────────────────────
    scale_pw = float((y_train == 0).sum()) / max(float((y_train == 1).sum()), 1)
    params = {
        "objective":        "binary:logistic",
        "eval_metric":      ["logloss", "auc"],
        "max_depth":        6,
        "eta":              0.05,
        "subsample":        0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "scale_pos_weight": scale_pw,
        "seed":             42,
        "nthread":          4,
    }
    print(f"  scale_pos_weight = {scale_pw:.2f}")

    # ── Train ──────────────────────────────────────────────────
    print("\n[4/5] Training XGBoost (200 rounds)...")
    evals_result = {}
    bst = xgb.train(
        params,
        dtrain,
        num_boost_round=200,
        evals=[(dtrain, "train"), (dval, "val")],
        evals_result=evals_result,
        verbose_eval=40,
        early_stopping_rounds=20,
    )

    # ── Evaluate ───────────────────────────────────────────────
    print("\n[5/5] Evaluating on validation set...")
    y_prob = bst.predict(dval)
    y_pred = (y_prob >= 0.35).astype(int)
    print(classification_report(y_val, y_pred, target_names=["human", "bot"]))
    auc = roc_auc_score(y_val, y_prob)
    print(f"  ROC-AUC: {auc:.4f}")

    # ── Save ───────────────────────────────────────────────────
    print(f"\n[4/4] Saving model to {SAVE_PATH}...")
    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    bst.save_model(SAVE_PATH)

    elapsed = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"  Training complete in {elapsed:.1f}s | AUC={auc:.4f}")
    print(f"  Model saved: {SAVE_PATH}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    train_bot_model()
