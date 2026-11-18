"""
retrain_plsf.py v4.0.0 — Publication-ready PLSF retraining
==========================================================

Key improvements over v3.1.0
----------------------------
- Supports portable path resolution and CLI configuration.
- Validates schema more robustly and accepts common text/label column names.
- Adds lexical BEC risk features to complement sentence embeddings.
- Uses out-of-fold (OOF) predictions for threshold selection and evaluation.
- Produces publication-ready figures in PNG/PDF/SVG formats.
- Exports fold metrics, score summaries, lexical feature weights, and a rich JSON report.
- Measures encoding / inference timing empirically instead of hard-coding values.

Expected label convention
-------------------------
0 = safe / benign email
1 = threat / BEC-like email
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D
from sentence_transformers import SentenceTransformer
from sklearn.base import clone
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("retrain_plsf")

VERSION = "4.0.0"
RANDOM_STATE = 42
DEFAULT_N_SPLITS = 5
DEFAULT_MAX_TRAIN_ROWS = 30000
DEFAULT_MINORITY_SHARE = 0.05
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
EXPORT_FORMATS = ("png", "pdf", "svg")

TEXT_COLUMN_CANDIDATES = [
    "body",
    "text",
    "content",
    "email_body",
    "message",
    "raw_text",
]
LABEL_COLUMN_CANDIDATES = [
    "label",
    "target",
    "y",
    "is_attack",
    "class",
]

LEXICON = {
    "urgency": [
        "urgent",
        "immediately",
        "asap",
        "right away",
        "today",
        "now",
        "priority",
        "time-sensitive",
        "expedite",
    ],
    "payment": [
        "wire transfer",
        "payment",
        "invoice",
        "remittance",
        "bank details",
        "iban",
        "swift",
        "beneficiary",
        "settlement",
        "outstanding balance",
    ],
    "credential": [
        "password",
        "credential",
        "login",
        "verify account",
        "sign in",
        "authentication",
        "mfa",
        "token",
        "security code",
    ],
    "gift_card": [
        "gift card",
        "apple card",
        "itunes",
        "google play",
        "scratch card",
    ],
    "payroll_finance": [
        "payroll",
        "salary",
        "direct deposit",
        "bank account",
        "routing number",
        "account number",
        "financial",
    ],
    "impersonation": [
        "ceo",
        "cfo",
        "executive",
        "director",
        "on behalf of",
        "kindly",
        "trusted",
        "confidential task",
    ],
    "secrecy": [
        "confidential",
        "do not share",
        "keep this between us",
        "privately",
        "discreet",
        "sensitive",
    ],
    "attachment_document": [
        "attached",
        "attachment",
        "document",
        "pdf",
        "spreadsheet",
        "invoice attached",
        "review the file",
    ],
    "account_change": [
        "change bank",
        "updated banking",
        "new account",
        "change beneficiary",
        "update payment",
        "redirect payment",
    ],
    "action_request": [
        "please process",
        "please handle",
        "take care of this",
        "complete the transfer",
        "confirm once done",
        "reply only",
        "approve",
    ],
}

CURRENCY_RE = re.compile(r"[$€£¥]|\b(?:usd|eur|gbp|aed|sar|qar|try)\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://|www\.", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
DIGIT_RE = re.compile(r"\d")
TOKEN_RE = re.compile(r"\b\w+\b", re.UNICODE)


def configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 140,
            "savefig.dpi": 600,
            "font.family": "DejaVu Sans",
            "axes.titlesize": 13,
            "axes.titleweight": "semibold",
            "axes.labelsize": 11,
            "axes.labelweight": "regular",
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 9.5,
            "legend.fontsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.22,
            "grid.linestyle": "--",
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain the PLSF classifier and generate publication-ready outputs.")
    parser.add_argument("--data-dir", type=Path, default=None, help="Directory containing dataset CSV files.")
    parser.add_argument("--models-dir", type=Path, default=None, help="Directory to save model/report JSON files.")
    parser.add_argument("--figures-dir", type=Path, default=None, help="Directory to save figure files.")
    parser.add_argument("--n-splits", type=int, default=DEFAULT_N_SPLITS)
    parser.add_argument("--max-train-rows", type=int, default=DEFAULT_MAX_TRAIN_ROWS)
    parser.add_argument("--minority-share-threshold", type=float, default=DEFAULT_MINORITY_SHARE)
    parser.add_argument("--bootstrap-iterations", type=int, default=200)
    return parser.parse_args()


def candidate_roots(script_path: Path) -> List[Path]:
    return [
        script_path.parent,
        script_path.parent.parent,
        Path.cwd(),
        Path.cwd().parent,
    ]


def resolve_default_dirs(script_path: Path) -> Tuple[Path, Path, Path]:
    for root in candidate_roots(script_path):
        candidate = root / "training_pipeline" / "data"
        if candidate.exists():
            data_dir = candidate
            base_root = root
            break
    else:
        data_dir = script_path.parent / "data"
        base_root = script_path.parent

    models_dir = base_root / "models"
    figures_dir = data_dir
    models_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    return data_dir, models_dir, figures_dir


def resolve_dirs(args: argparse.Namespace) -> Tuple[Path, Path, Path]:
    script_path = Path(__file__).resolve()
    default_data_dir, default_models_dir, default_figures_dir = resolve_default_dirs(script_path)

    data_dir = args.data_dir or default_data_dir
    models_dir = args.models_dir or default_models_dir
    figures_dir = args.figures_dir or default_figures_dir

    data_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    return data_dir, models_dir, figures_dir


def find_dataset_file(data_dir: Path) -> Tuple[Path, str]:
    priority = [
        (data_dir / "dataset_balanced.csv", "dataset_balanced.csv"),
        (data_dir / "dataset_train.csv", "dataset_train.csv"),
        (data_dir / "dataset_combined.csv", "dataset_combined.csv"),
    ]
    for path, label in priority:
        if path.exists():
            return path, label

    discovered = sorted(data_dir.glob("*.csv"))
    if discovered:
        return discovered[0], discovered[0].name
    raise SystemExit(f"No CSV dataset found in {data_dir}")


def find_first_column(columns: Sequence[str], candidates: Sequence[str]) -> str | None:
    lower_map = {c.lower(): c for c in columns}
    for candidate in candidates:
        if candidate.lower() in lower_map:
            return lower_map[candidate.lower()]
    return None


def load_training_dataset(data_dir: Path) -> Tuple[pd.DataFrame, Dict[str, str]]:
    source_path, source_name = find_dataset_file(data_dir)
    df = pd.read_csv(source_path)
    if df.empty:
        raise SystemExit(f"Dataset is empty: {source_path}")

    text_col = find_first_column(df.columns, TEXT_COLUMN_CANDIDATES)
    label_col = find_first_column(df.columns, LABEL_COLUMN_CANDIDATES)
    if text_col is None or label_col is None:
        raise SystemExit(
            f"Invalid dataset schema in {source_path}. Expected text column in {TEXT_COLUMN_CANDIDATES} "
            f"and label column in {LABEL_COLUMN_CANDIDATES}. Found columns: {list(df.columns)}"
        )

    out = df[[text_col, label_col]].copy()
    out.columns = ["body", "label"]
    out["body"] = out["body"].fillna("").astype(str).str.strip()
    out["label"] = pd.to_numeric(out["label"], errors="coerce")
    if out["label"].isna().any():
        raise SystemExit(f"Dataset contains non-numeric labels in {source_path}")

    out["label"] = out["label"].astype(int)
    out = out[out["label"].isin([0, 1])]
    out = out[out["body"].str.len() > 0].drop_duplicates().reset_index(drop=True)
    if out.empty:
        raise SystemExit(f"Dataset became empty after cleaning: {source_path}")

    metadata = {
        "dataset_path": str(source_path),
        "dataset_source": source_name,
        "original_text_column": text_col,
        "original_label_column": label_col,
    }
    return out, metadata


def validate_imbalance(df: pd.DataFrame, minority_share_threshold: float) -> Dict[str, float]:
    counts = df["label"].value_counts().sort_index()
    if len(counts) != 2:
        raise SystemExit(f"Binary classification requires labels 0 and 1. Found: {counts.to_dict()}")

    total = int(len(df))
    safe_n = int(counts.get(0, 0))
    threat_n = int(counts.get(1, 0))
    minority = min(safe_n, threat_n)
    minority_share = float(minority / total)
    imbalance_ratio = float(max(safe_n, threat_n) / max(1, minority))

    logger.info("Dataset distribution — safe=%d, threat=%d, minority_share=%.4f", safe_n, threat_n, minority_share)
    if minority_share < minority_share_threshold:
        raise SystemExit(
            f"Training blocked: minority class share {minority_share:.4%} is below threshold {minority_share_threshold:.2%}."
        )

    return {
        "total": total,
        "safe": safe_n,
        "threat": threat_n,
        "minority_share": minority_share,
        "imbalance_ratio": imbalance_ratio,
    }


def maybe_downsample_for_speed(df: pd.DataFrame, max_train_rows: int) -> pd.DataFrame:
    if len(df) <= max_train_rows:
        return df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)

    logger.info("Downsampling from %d to %d rows for runtime control.", len(df), max_train_rows)
    sampled, _ = train_test_split(
        df,
        train_size=max_train_rows,
        stratify=df["label"],
        random_state=RANDOM_STATE,
    )
    return sampled.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)


def count_occurrences(text: str, phrase: str) -> int:
    return text.count(phrase)


def lexical_features_for_text(text: str) -> List[float]:
    lower = text.lower()
    token_count = max(1, len(TOKEN_RE.findall(lower)))
    char_count = max(1, len(text))
    upper_chars = sum(1 for ch in text if ch.isupper())
    digit_chars = len(DIGIT_RE.findall(text))

    category_counts = []
    distinct_category_hits = 0
    total_lexicon_hits = 0
    for terms in LEXICON.values():
        hits = sum(count_occurrences(lower, term) for term in terms)
        category_counts.append(float(hits) / token_count)
        if hits > 0:
            distinct_category_hits += 1
            total_lexicon_hits += hits

    features = [
        float(total_lexicon_hits) / token_count,
        float(distinct_category_hits) / max(1, len(LEXICON)),
        text.count("!") / char_count,
        text.count("?") / char_count,
        upper_chars / char_count,
        digit_chars / char_count,
        len(CURRENCY_RE.findall(text)) / token_count,
        len(URL_RE.findall(text)) / token_count,
        len(EMAIL_RE.findall(text)) / token_count,
        min(1.0, token_count / 500.0),
        min(1.0, char_count / 4000.0),
    ]
    features.extend(category_counts)
    return features


def build_lexical_feature_matrix(texts: Sequence[str]) -> Tuple[np.ndarray, List[str]]:
    base_names = [
        "lexicon_hit_rate",
        "lexicon_category_coverage",
        "exclamation_ratio",
        "question_ratio",
        "uppercase_ratio",
        "digit_ratio",
        "currency_rate",
        "url_rate",
        "email_rate",
        "token_count_scaled",
        "char_count_scaled",
    ]
    category_names = [f"cat_{name}_rate" for name in LEXICON]
    feature_names = base_names + category_names
    matrix = np.asarray([lexical_features_for_text(text) for text in texts], dtype=np.float32)
    return matrix, feature_names


def encode_texts(model: SentenceTransformer, texts: Sequence[str]) -> Tuple[np.ndarray, Dict[str, float]]:
    start = time.perf_counter()
    embeddings = model.encode(
        list(texts),
        show_progress_bar=True,
        batch_size=128,
        convert_to_numpy=True,
        normalize_embeddings=False,
    )
    elapsed = time.perf_counter() - start
    embeddings = np.asarray(embeddings, dtype=np.float32)
    timing = {
        "embedding_total_seconds": float(elapsed),
        "embedding_ms_per_email": float((elapsed / max(1, len(texts))) * 1000.0),
    }
    return embeddings, timing


def choose_threshold(y_true: np.ndarray, y_prob: np.ndarray, num_steps: int = 1001) -> Tuple[float, float]:
    best_threshold = 0.5
    best_j = -np.inf
    for threshold in np.linspace(0.0, 1.0, num_steps):
        y_pred = (y_prob >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        j_stat = tpr - fpr
        if j_stat > best_j:
            best_j = j_stat
            best_threshold = float(threshold)
    return best_threshold, float(best_j)


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, float | list]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    mcc = matthews_corrcoef(y_true, y_pred)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    npv = tn / (tn + fn) if (tn + fn) else 0.0

    return {
        "accuracy": float(accuracy),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "mcc": float(mcc),
        "specificity": float(specificity),
        "npv": float(npv),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "predicted_safe": int((y_pred == 0).sum()),
        "predicted_threat": int((y_pred == 1).sum()),
    }


def compute_fold_metrics(y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    threshold, _ = choose_threshold(y_true, y_prob, num_steps=501)
    metrics = compute_metrics(y_true, y_prob, threshold)
    return {
        "roc_auc": metrics["roc_auc"],
        "pr_auc": metrics["pr_auc"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "mcc": metrics["mcc"],
        "threshold": float(threshold),
    }


def bootstrap_confidence_intervals(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    iterations: int,
) -> Dict[str, Dict[str, float]]:
    if iterations <= 0:
        return {}

    rng = np.random.default_rng(RANDOM_STATE)
    metric_store: Dict[str, List[float]] = {
        "accuracy": [],
        "roc_auc": [],
        "pr_auc": [],
        "precision": [],
        "recall": [],
        "f1": [],
        "mcc": [],
        "specificity": [],
        "npv": [],
        "fpr": [],
        "fnr": [],
    }

    n = len(y_true)
    for _ in range(iterations):
        idx = rng.integers(0, n, n)
        sample_y = y_true[idx]
        sample_prob = y_prob[idx]
        if len(np.unique(sample_y)) < 2:
            continue
        m = compute_metrics(sample_y, sample_prob, threshold)
        for key in metric_store:
            metric_store[key].append(float(m[key]))

    ci: Dict[str, Dict[str, float]] = {}
    for key, values in metric_store.items():
        if not values:
            continue
        arr = np.asarray(values, dtype=float)
        ci[key] = {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
            "ci95_low": float(np.percentile(arr, 2.5)),
            "ci95_high": float(np.percentile(arr, 97.5)),
        }
    return ci


def class_score_summary(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> pd.DataFrame:
    rows = []
    for label, name in [(0, "Safe"), (1, "Threat")]:
        scores = y_prob[y_true == label]
        rows.append(
            {
                "class": name,
                "label": label,
                "n": int(len(scores)),
                "mean": float(np.mean(scores)),
                "median": float(np.median(scores)),
                "std": float(np.std(scores, ddof=1)) if len(scores) > 1 else 0.0,
                "q1": float(np.percentile(scores, 25)),
                "q3": float(np.percentile(scores, 75)),
                "min": float(np.min(scores)),
                "max": float(np.max(scores)),
                "threshold": float(threshold),
            }
        )
    return pd.DataFrame(rows)


def save_figure_all_formats(fig: plt.Figure, base_path: Path) -> Dict[str, str]:
    paths = {}
    for ext in EXPORT_FORMATS:
        out = base_path.with_suffix(f".{ext}")
        fig.savefig(out, bbox_inches="tight", dpi=600 if ext == "png" else None)
        paths[ext] = str(out)
    plt.close(fig)
    return paths


def plot_cv_folds(fold_df: pd.DataFrame, out_base: Path) -> Dict[str, str]:
    fig, ax = plt.subplots(figsize=(8.2, 4.8))
    x = np.arange(1, len(fold_df) + 1)

    ax.plot(x, fold_df["roc_auc"], marker="o", linewidth=1.8, color="#0F766E", label="ROC-AUC")
    ax.plot(x, fold_df["pr_auc"], marker="s", linewidth=1.8, color="#B45309", label="PR-AUC")

    roc_mean = float(fold_df["roc_auc"].mean())
    pr_mean = float(fold_df["pr_auc"].mean())
    roc_std = float(fold_df["roc_auc"].std(ddof=1)) if len(fold_df) > 1 else 0.0
    pr_std = float(fold_df["pr_auc"].std(ddof=1)) if len(fold_df) > 1 else 0.0

    ax.axhline(roc_mean, color="#0F766E", linestyle="--", alpha=0.45, linewidth=1.2)
    ax.axhline(pr_mean, color="#B45309", linestyle="--", alpha=0.45, linewidth=1.2)

    for xi, roc_v, pr_v in zip(x, fold_df["roc_auc"], fold_df["pr_auc"]):
        ax.text(xi, roc_v + 0.004, f"{roc_v:.3f}", ha="center", va="bottom", fontsize=8, color="#0F766E")
        ax.text(xi, pr_v - 0.010, f"{pr_v:.3f}", ha="center", va="top", fontsize=8, color="#B45309")

    ax.set_xticks(x)
    ax.set_xticklabels([f"Fold {i}" for i in x])
    ax.set_ylim(max(0.0, min(fold_df[["roc_auc", "pr_auc"]].min()) - 0.04), 1.005)
    ax.set_xlabel("Cross-validation fold")
    ax.set_ylabel("Score")
    ax.set_title("PLSF cross-validation performance")
    ax.legend(frameon=False, loc="lower right")
    ax.text(
        0.01,
        0.02,
        f"Mean±SD  ROC-AUC={roc_mean:.3f}±{roc_std:.3f}   PR-AUC={pr_mean:.3f}±{pr_std:.3f}",
        transform=ax.transAxes,
        fontsize=8.8,
        color="#374151",
    )
    return save_figure_all_formats(fig, out_base)


def plot_confusion_matrix(report: dict, out_base: Path) -> Dict[str, str]:
    metrics = report["metrics"]
    cm = np.asarray(metrics["confusion_matrix"], dtype=int)
    row_sums = cm.sum(axis=1, keepdims=True)
    row_pct = np.divide(cm, row_sums, out=np.zeros_like(cm, dtype=float), where=row_sums != 0)

    fig, ax = plt.subplots(figsize=(6.8, 5.6))
    im = ax.imshow(row_pct, cmap="Blues", vmin=0.0, vmax=1.0)
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Row-normalized proportion")

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Predicted Safe", "Predicted Threat"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Actual Safe", "Actual Threat"])
    ax.set_xlabel("Prediction")
    ax.set_ylabel("Reference class")
    ax.set_title("Out-of-fold confusion matrix")

    for i in range(2):
        for j in range(2):
            value = cm[i, j]
            pct = row_pct[i, j] * 100.0
            ax.text(
                j,
                i,
                f"{value:,}\n{pct:.1f}%",
                ha="center",
                va="center",
                fontsize=11,
                fontweight="semibold",
                color="white" if row_pct[i, j] > 0.58 else "#111827",
            )

    subtitle = (
        f"n={report['dataset_info']['total']:,}   λ={report['threshold']:.3f}   "
        f"Accuracy={metrics['accuracy']:.3f}   F1={metrics['f1']:.3f}   MCC={metrics['mcc']:.3f}"
    )
    ax.text(0.5, -0.14, subtitle, transform=ax.transAxes, ha="center", va="top", fontsize=9, color="#374151")
    return save_figure_all_formats(fig, out_base)


def plot_score_distribution(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, out_base: Path) -> Dict[str, str]:
    safe_scores = y_prob[y_true == 0]
    threat_scores = y_prob[y_true == 1]

    fig = plt.figure(figsize=(8.2, 6.0))
    gs = fig.add_gridspec(2, 1, height_ratios=[3.5, 1.2], hspace=0.10)
    ax = fig.add_subplot(gs[0])
    ax_box = fig.add_subplot(gs[1], sharex=ax)

    bins = np.linspace(0.0, 1.0, 36)
    ax.hist(safe_scores, bins=bins, density=True, alpha=0.45, color="#2563EB", edgecolor="white", label="Safe")
    ax.hist(threat_scores, bins=bins, density=True, alpha=0.45, color="#DC2626", edgecolor="white", label="Threat")
    ax.axvline(threshold, color="black", linestyle="--", linewidth=1.5, label=f"Threshold = {threshold:.3f}")
    ax.axvline(np.median(safe_scores), color="#1D4ED8", linestyle=":", linewidth=1.3)
    ax.axvline(np.median(threat_scores), color="#B91C1C", linestyle=":", linewidth=1.3)
    ax.set_ylabel("Density")
    ax.set_title("Anomaly-score distribution by class")
    ax.legend(frameon=False, loc="upper center", ncol=3)

    box = ax_box.boxplot(
        [safe_scores, threat_scores],
        vert=False,
        patch_artist=True,
        labels=["Safe", "Threat"],
        widths=0.55,
        medianprops={"color": "#111827", "linewidth": 1.3},
        boxprops={"linewidth": 1.0},
        whiskerprops={"linewidth": 1.0},
        capprops={"linewidth": 1.0},
    )
    for patch, color in zip(box["boxes"], ["#93C5FD", "#FCA5A5"]):
        patch.set_facecolor(color)
        patch.set_alpha(0.9)
    ax_box.axvline(threshold, color="black", linestyle="--", linewidth=1.2)
    ax_box.set_xlabel("PLSF anomaly score")
    ax_box.grid(axis="y", visible=False)
    return save_figure_all_formats(fig, out_base)


def plot_ranked_scores(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, out_base: Path) -> Dict[str, str]:
    order = np.argsort(y_prob)[::-1]
    ranked_scores = y_prob[order]
    ranked_labels = y_true[order]
    x = np.arange(1, len(ranked_scores) + 1)
    threat_mask = ranked_labels == 1
    safe_mask = ~threat_mask

    predicted_threat = int(np.sum(ranked_scores >= threshold))
    crossing_x = max(1, predicted_threat)

    fig, ax = plt.subplots(figsize=(9.2, 4.9))
    ax.plot(x, ranked_scores, color="#111827", linewidth=1.0, alpha=0.8)
    ax.scatter(x[safe_mask], ranked_scores[safe_mask], s=7, color="#2563EB", alpha=0.20, label="Safe")
    ax.scatter(x[threat_mask], ranked_scores[threat_mask], s=7, color="#DC2626", alpha=0.20, label="Threat")
    ax.axhline(threshold, color="black", linestyle="--", linewidth=1.4, label=f"Threshold = {threshold:.3f}")
    ax.axvline(crossing_x, color="#6B7280", linestyle=":", linewidth=1.2)
    ax.fill_between(x, threshold, ranked_scores, where=ranked_scores >= threshold, color="#FEE2E2", alpha=0.35)
    ax.fill_between(x, ranked_scores, threshold, where=ranked_scores < threshold, color="#DBEAFE", alpha=0.35)

    ax.set_xlim(1, len(ranked_scores))
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("Emails ranked by out-of-fold score")
    ax.set_ylabel("PLSF score")
    ax.set_title("Ranked out-of-fold PLSF scores")
    ax.legend(frameon=False, ncol=3, loc="upper right")
    ax.text(
        0.01,
        0.02,
        f"Predicted threat above λ: {predicted_threat:,} / {len(ranked_scores):,}",
        transform=ax.transAxes,
        fontsize=8.8,
        color="#374151",
    )
    return save_figure_all_formats(fig, out_base)


def plot_roc_pr_curves(y_true: np.ndarray, y_prob: np.ndarray, out_base: Path) -> Dict[str, str]:
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    roc_auc = roc_auc_score(y_true, y_prob)
    pr_auc = average_precision_score(y_true, y_prob)
    prevalence = float(np.mean(y_true))

    fig, axes = plt.subplots(1, 2, figsize=(10.0, 4.2))
    axes[0].plot(fpr, tpr, color="#0F766E", linewidth=2.0)
    axes[0].plot([0, 1], [0, 1], linestyle="--", color="#9CA3AF", linewidth=1.0)
    axes[0].set_xlabel("False positive rate")
    axes[0].set_ylabel("True positive rate")
    axes[0].set_title(f"ROC curve (AUC={roc_auc:.3f})")

    axes[1].plot(recall, precision, color="#B45309", linewidth=2.0)
    axes[1].axhline(prevalence, linestyle="--", color="#9CA3AF", linewidth=1.0)
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title(f"PR curve (AUC={pr_auc:.3f})")
    axes[1].text(0.03, 0.05, f"Class prevalence = {prevalence:.3f}", transform=axes[1].transAxes, fontsize=8.5)

    fig.suptitle("Supplementary operating-characteristic curves", fontsize=12.5, y=1.02)
    return save_figure_all_formats(fig, out_base)


def extract_lexical_weights(clf: LogisticRegression, lexical_feature_names: Sequence[str], embedding_dim: int) -> pd.DataFrame:
    coefs = np.asarray(clf.coef_[0], dtype=float)
    lexical_coefs = coefs[embedding_dim : embedding_dim + len(lexical_feature_names)]
    df = pd.DataFrame(
        {
            "feature": list(lexical_feature_names),
            "coefficient": lexical_coefs,
            "abs_coefficient": np.abs(lexical_coefs),
        }
    ).sort_values("abs_coefficient", ascending=False)
    return df.reset_index(drop=True)


def run_cross_validation(X: np.ndarray, y: np.ndarray, n_splits: int, base_clf: LogisticRegression) -> Tuple[np.ndarray, pd.DataFrame]:
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    y_prob_oof = np.zeros(len(y), dtype=np.float32)
    rows = []

    for fold_idx, (train_idx, val_idx) in enumerate(cv.split(X, y), start=1):
        clf = clone(base_clf)
        clf.fit(X[train_idx], y[train_idx])
        val_prob = clf.predict_proba(X[val_idx])[:, 1].astype(np.float32)
        y_prob_oof[val_idx] = val_prob
        fold_metrics = compute_fold_metrics(y[val_idx], val_prob)
        row = {
            "fold": fold_idx,
            "n_validation": int(len(val_idx)),
            "n_safe": int((y[val_idx] == 0).sum()),
            "n_threat": int((y[val_idx] == 1).sum()),
            **fold_metrics,
        }
        rows.append(row)
        logger.info(
            "Fold %d — ROC-AUC=%.4f PR-AUC=%.4f F1=%.4f MCC=%.4f λ=%.3f",
            fold_idx,
            row["roc_auc"],
            row["pr_auc"],
            row["f1"],
            row["mcc"],
            row["threshold"],
        )

    return y_prob_oof, pd.DataFrame(rows)


def main() -> None:
    configure_matplotlib()
    args = parse_args()
    data_dir, models_dir, figures_dir = resolve_dirs(args)

    logger.info("=" * 84)
    logger.info("PLSF retraining v%s", VERSION)
    logger.info("Data dir: %s", data_dir)
    logger.info("Models dir: %s", models_dir)
    logger.info("Figures dir: %s", figures_dir)
    logger.info("=" * 84)

    df, data_meta = load_training_dataset(data_dir)
    dataset_stats = validate_imbalance(df, args.minority_share_threshold)
    df = maybe_downsample_for_speed(df, args.max_train_rows)

    texts = df["body"].tolist()
    y = df["label"].astype(int).to_numpy()

    logger.info("Loading sentence-transformer model: %s", EMBED_MODEL_NAME)
    st_model = SentenceTransformer(EMBED_MODEL_NAME)

    logger.info("Encoding %d emails", len(texts))
    X_emb, timing = encode_texts(st_model, texts)
    X_lex, lexical_feature_names = build_lexical_feature_matrix(texts)
    X = np.hstack([X_emb, X_lex]).astype(np.float32)

    logger.info("Feature matrix: embeddings=%d lexical=%d total_dim=%d", X_emb.shape[1], X_lex.shape[1], X.shape[1])

    base_clf = LogisticRegression(
        max_iter=2500,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        C=1.0,
        solver="lbfgs",
    )

    cv_start = time.perf_counter()
    y_prob_oof, fold_df = run_cross_validation(X, y, args.n_splits, base_clf)
    timing["cross_validation_total_seconds"] = float(time.perf_counter() - cv_start)

    threshold, youden_j = choose_threshold(y, y_prob_oof)
    metrics = compute_metrics(y, y_prob_oof, threshold)
    ci = bootstrap_confidence_intervals(y, y_prob_oof, threshold, args.bootstrap_iterations)

    infer_start = time.perf_counter()
    final_clf = clone(base_clf)
    final_clf.fit(X, y)
    _ = final_clf.predict_proba(X[: min(len(X), 2000)])[:, 1]
    infer_elapsed = time.perf_counter() - infer_start
    timing["classifier_fit_plus_sample_inference_seconds"] = float(infer_elapsed)
    timing["sampled_classifier_ms_per_email"] = float((infer_elapsed / max(1, min(len(X), 2000))) * 1000.0)

    lexical_weights_df = extract_lexical_weights(final_clf, lexical_feature_names, X_emb.shape[1])
    score_summary_df = class_score_summary(y, y_prob_oof, threshold)

    model_out = models_dir / "plsf_classifier.joblib"
    metrics_out = models_dir / "plsf_train_metrics.json"
    report_out = models_dir / "plsf_training_report.json"
    threshold_out = models_dir / "plsf_threshold.json"
    folds_csv_out = models_dir / "plsf_fold_metrics.csv"
    score_summary_out = models_dir / "plsf_score_summary.csv"
    lexical_weights_out = models_dir / "plsf_lexical_weights.csv"

    figure3_base = figures_dir / "figure3_confusion_matrix"
    figure4_cv_base = figures_dir / "figure4_cv_folds"
    figure4_scores_base = figures_dir / "figure4_anomaly_scores"
    figure5_rank_base = figures_dir / "figure5_plsf_scores"
    supplementary_base = figures_dir / "supplementary_roc_pr_curves"

    figure_outputs = {
        "figure4_cv_folds": plot_cv_folds(fold_df, figure4_cv_base),
        "figure3_confusion_matrix": plot_confusion_matrix(
            {"metrics": metrics, "dataset_info": dataset_stats, "threshold": threshold}, figure3_base
        ),
        "figure4_anomaly_scores": plot_score_distribution(y, y_prob_oof, threshold, figure4_scores_base),
        "figure5_plsf_scores": plot_ranked_scores(y, y_prob_oof, threshold, figure5_rank_base),
        "supplementary_roc_pr_curves": plot_roc_pr_curves(y, y_prob_oof, supplementary_base),
    }

    model_payload = {
        "classifier": final_clf,
        "embedding_model_name": EMBED_MODEL_NAME,
        "lexical_feature_names": lexical_feature_names,
        "lambda_opt": float(threshold),
        "version": VERSION,
        "dataset_metadata": data_meta,
        "dataset_info": dataset_stats,
    }
    joblib.dump(model_payload, model_out)

    fold_summary = {
        metric: {
            "mean": float(fold_df[metric].mean()),
            "std": float(fold_df[metric].std(ddof=1)) if len(fold_df) > 1 else 0.0,
        }
        for metric in ["roc_auc", "pr_auc", "precision", "recall", "f1", "mcc", "threshold"]
    }

    report = {
        "version": VERSION,
        "dataset_metadata": data_meta,
        "dataset_info": dataset_stats,
        "model": {
            "embedding_model_name": EMBED_MODEL_NAME,
            "classifier": "LogisticRegression",
            "feature_space": {
                "embedding_dimensions": int(X_emb.shape[1]),
                "lexical_dimensions": int(X_lex.shape[1]),
                "total_dimensions": int(X.shape[1]),
            },
        },
        "threshold": float(threshold),
        "youden_j": float(youden_j),
        "metrics": metrics,
        "bootstrap_confidence_intervals": ci,
        "cross_validation": {
            "folds": int(args.n_splits),
            "strategy": f"StratifiedKFold(shuffle=True, random_state={RANDOM_STATE})",
            "fold_summary": fold_summary,
            "fold_metrics": fold_df.to_dict(orient="records"),
        },
        "score_summary_by_class": score_summary_df.to_dict(orient="records"),
        "timing": timing,
        "feature_importance": {
            "top_lexical_features": lexical_weights_df.head(15).to_dict(orient="records")
        },
        "outputs": {
            "model": str(model_out),
            "metrics_json": str(metrics_out),
            "report_json": str(report_out),
            "threshold_json": str(threshold_out),
            "fold_metrics_csv": str(folds_csv_out),
            "score_summary_csv": str(score_summary_out),
            "lexical_weights_csv": str(lexical_weights_out),
            "figures": figure_outputs,
        },
        "guards": {
            "minority_share_threshold": float(args.minority_share_threshold),
            "max_train_rows": int(args.max_train_rows),
            "bootstrap_iterations": int(args.bootstrap_iterations),
        },
    }

    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump({"threshold": threshold, "metrics": metrics, "fold_summary": fold_summary}, f, indent=2, ensure_ascii=False)

    with open(report_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(threshold_out, "w", encoding="utf-8") as f:
        json.dump(
            {
                "lambda_opt": float(threshold),
                "selection": "Youden J on out-of-fold predictions",
                "version": VERSION,
                "dataset_source": data_meta["dataset_source"],
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    fold_df.to_csv(folds_csv_out, index=False)
    score_summary_df.to_csv(score_summary_out, index=False)
    lexical_weights_df.to_csv(lexical_weights_out, index=False)

    logger.info("Training complete.")
    logger.info("Model: %s", model_out)
    logger.info("Report: %s", report_out)
    logger.info("Threshold: %.4f", threshold)
    logger.info("ROC-AUC: %.4f | PR-AUC: %.4f | F1: %.4f | MCC: %.4f", metrics["roc_auc"], metrics["pr_auc"], metrics["f1"], metrics["mcc"])
    logger.info("Figures written under: %s", figures_dir)
    logger.info("=" * 84)


if __name__ == "__main__":
    main()
