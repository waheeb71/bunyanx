"""
retrain_plsf.py v3.1.0 — Resilient PLSF retraining
===================================================
- Uses dataset_balanced.csv when available
- Validates label distribution before training
- Stops training if minority class < 5%
- Produces production-grade evaluation metrics:
  ROC-AUC, PR-AUC, MCC, Confusion Matrix, FPR, FNR
- Saves model, threshold, rich training report, and paper figures automatically
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Tuple

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.base import clone
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODULE_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = MODULE_ROOT / "training_pipeline" / "data"
MODELS_DIR = MODULE_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

BALANCED_CSV = DATA_DIR / "dataset_balanced.csv"
COMBINED_CSV = DATA_DIR / "dataset_combined.csv"
TRAIN_CSV = DATA_DIR / "dataset_train.csv"
MODEL_OUT = MODELS_DIR / "plsf_classifier.joblib"
METRICS_OUT = MODELS_DIR / "plsf_train_metrics.json"
REPORT_OUT = MODELS_DIR / "plsf_training_report.json"
THRESHOLD_OUT = MODELS_DIR / "plsf_threshold.json"
FIGURE3_OUT = DATA_DIR / "figure3_confusion_matrix.png"
FIGURE4_CV_FOLDS_OUT = DATA_DIR / "figure4_cv_folds.png"
FIGURE4_ANOMALY_SCORES_OUT = DATA_DIR / "figure4_anomaly_scores.png"
FIGURE5_PLSF_SCORES_OUT = DATA_DIR / "figure5_plsf_scores.png"

N_SPLITS = 5
RANDOM_STATE = 42
MINORITY_SHARE_THRESHOLD = 0.05
MAX_TRAIN_ROWS = 30000
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"


def load_training_dataset() -> Tuple[pd.DataFrame, str]:
    if BALANCED_CSV.exists():
        source = BALANCED_CSV
        reason = "dataset_balanced.csv"
    elif TRAIN_CSV.exists():
        source = TRAIN_CSV
        reason = "dataset_train.csv"
    elif COMBINED_CSV.exists():
        source = COMBINED_CSV
        reason = "dataset_combined.csv"
    else:
        raise SystemExit(f"No training dataset found in {DATA_DIR}")

    df = pd.read_csv(source)
    if "body" not in df.columns or "label" not in df.columns:
        raise SystemExit(f"Invalid dataset schema in {source}: expected columns body,label")

    df = df.copy()
    df["body"] = df["body"].fillna("").astype(str)
    df["label"] = pd.to_numeric(df["label"], errors="coerce")

    if df["label"].isna().any():
        raise SystemExit(f"Dataset contains non-numeric labels in {source}")

    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)

    if df.empty:
        raise SystemExit(f"Dataset became empty after label filtering: {source}")

    return df, reason


def validate_imbalance(df: pd.DataFrame) -> Dict[str, float]:
    counts = df["label"].value_counts().sort_index()
    if len(counts) != 2:
        raise SystemExit(f"Binary classification requires two labels, found: {counts.to_dict()}")

    total = int(len(df))
    minority = int(counts.min())
    minority_share = float(minority / total)

    logger.info("Dataset distribution")
    logger.info("  label 0: %s", int(counts.get(0, 0)))
    logger.info("  label 1: %s", int(counts.get(1, 0)))
    logger.info("  minority share: %.4f%%", minority_share * 100)

    if minority_share < MINORITY_SHARE_THRESHOLD:
        raise SystemExit(
            f"Training blocked: minority class share {minority_share:.4%} is below "
            f"threshold {MINORITY_SHARE_THRESHOLD:.2%}. Use a balanced dataset."
        )

    ratio = float(counts.max() / counts.min())
    return {
        "total": total,
        "normal": int(counts.get(0, 0)),
        "attack": int(counts.get(1, 0)),
        "minority_share": minority_share,
        "imbalance_ratio": ratio,
    }


def maybe_downsample_for_speed(df: pd.DataFrame) -> pd.DataFrame:
    if len(df) <= MAX_TRAIN_ROWS:
        return df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)

    logger.info("Downsampling training set from %d to %d rows for runtime control.", len(df), MAX_TRAIN_ROWS)
    sampled, _ = train_test_split(
        df,
        train_size=MAX_TRAIN_ROWS,
        random_state=RANDOM_STATE,
        stratify=df["label"],
    )
    return sampled.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)


def encode_texts(model: SentenceTransformer, texts: list[str]) -> np.ndarray:
    return model.encode(
        texts,
        show_progress_bar=True,
        batch_size=128,
        convert_to_numpy=True,
        normalize_embeddings=False,
    )


def choose_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> Tuple[float, float]:
    best_threshold = 0.5
    best_j = -1.0

    for threshold in np.linspace(0.0, 1.0, 101):
        y_pred = (y_prob >= threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        j_stat = tpr - fpr
        if j_stat > best_j:
            best_j = j_stat
            best_threshold = float(threshold)

    return best_threshold, best_j


def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, float | list]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    roc_auc = roc_auc_score(y_true, y_prob)
    pr_auc = average_precision_score(y_true, y_prob)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    mcc = matthews_corrcoef(y_true, y_pred)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "mcc": float(mcc),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def compute_fold_metrics(y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    return {
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
    }


def save_confusion_matrix_figure(report: dict) -> None:
    metrics = report.get("metrics", {})
    cm = np.array(metrics.get("confusion_matrix"))
    if cm.shape != (2, 2):
        raise SystemExit(f"Invalid confusion matrix in report: expected 2x2, got {cm.shape}")

    fig, ax = plt.subplots(figsize=(8.2, 6.2))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    classes = ["Actual Safe", "Actual Threat"]
    tick_marks = np.arange(len(classes))

    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(["Predicted Safe", "Predicted Threat"], fontsize=12)
    ax.set_yticklabels(classes, fontsize=12)

    ax.set_xlabel("Predicted Label", fontsize=14, fontweight="bold")
    ax.set_ylabel("Actual Label", fontsize=14, fontweight="bold")
    ax.set_title(
        f"Confusion Matrix\nDataset v4.0, n={report.get('dataset_info', {}).get('total', 0)}, λ={report.get('threshold', 0.0):.2f}",
        fontsize=14,
        fontweight="bold",
    )

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j,
                i,
                format(int(cm[i, j]), "d"),
                ha="center",
                va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=16,
                fontweight="bold",
            )

    accuracy = (cm[0, 0] + cm[1, 1]) / cm.sum() * 100 if cm.sum() else 0.0
    precision = cm[1, 1] / (cm[1, 1] + cm[0, 1]) if (cm[1, 1] + cm[0, 1]) else 0.0
    recall = cm[1, 1] / (cm[1, 1] + cm[1, 0]) if (cm[1, 1] + cm[1, 0]) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    summary_text = (
        f"Accuracy: {accuracy:.2f}%\n"
        f"Precision: {precision:.3f}\n"
        f"Recall: {recall:.3f}\n"
        f"F1: {f1:.3f}"
    )
    ax.text(
        1.12,
        0.52,
        summary_text,
        transform=ax.transAxes,
        fontsize=11,
        va="center",
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#F2F2F2", edgecolor="#666666", alpha=0.95),
    )

    plt.tight_layout()
    plt.savefig(FIGURE3_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def save_cv_folds_figure(fold_metrics: list[dict]) -> None:
    folds = [item["fold"] for item in fold_metrics]
    roc_aucs = [item["roc_auc"] for item in fold_metrics]
    pr_aucs = [item["pr_auc"] for item in fold_metrics]

    x = np.arange(len(folds))
    width = 0.36

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width / 2, roc_aucs, width, label="ROC-AUC", color="#2E86AB", edgecolor="black", linewidth=1.0)
    ax.bar(x + width / 2, pr_aucs, width, label="PR-AUC", color="#F18F01", edgecolor="black", linewidth=1.0)

    ax.set_ylim(0.0, 1.0)
    ax.set_xticks(x)
    ax.set_xticklabels([f"Fold {fold}" for fold in folds], fontsize=11)
    ax.set_ylabel("Score", fontsize=13, fontweight="bold")
    ax.set_xlabel("Cross-Validation Fold", fontsize=13, fontweight="bold")
    ax.set_title("Cross-Validation Fold Performance", fontsize=15, fontweight="bold")
    ax.legend(frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.35)

    for idx, value in enumerate(roc_aucs):
        ax.text(idx - width / 2, min(0.99, value + 0.02), f"{value:.3f}", ha="center", fontsize=9)
    for idx, value in enumerate(pr_aucs):
        ax.text(idx + width / 2, min(0.99, value + 0.02), f"{value:.3f}", ha="center", fontsize=9)

    plt.tight_layout()
    plt.savefig(FIGURE4_CV_FOLDS_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def save_anomaly_scores_figure(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, report: dict) -> None:
    normal_scores = y_prob[y_true == 0]
    attack_scores = y_prob[y_true == 1]

    fig, ax = plt.subplots(figsize=(10, 6))
    bins = np.linspace(0.0, 1.0, 40)

    ax.hist(normal_scores, bins=bins, alpha=0.65, label="Safe emails", color="#3B82F6", edgecolor="black")
    ax.hist(attack_scores, bins=bins, alpha=0.65, label="Threat emails", color="#EF4444", edgecolor="black")
    ax.axvline(threshold, color="black", linestyle="--", linewidth=2, label=f"Threshold = {threshold:.2f}")

    ax.set_xlim(0.0, 1.0)
    ax.set_xlabel("Anomaly / Threat Score", fontsize=13, fontweight="bold")
    ax.set_ylabel("Email Count", fontsize=13, fontweight="bold")
    ax.set_title(
        f"Anomaly Score Distribution\nn={report.get('dataset_info', {}).get('total', 0)}",
        fontsize=15,
        fontweight="bold",
    )
    ax.legend(frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(FIGURE4_ANOMALY_SCORES_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def save_plsf_scores_figure(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, report: dict) -> None:
    order = np.argsort(y_prob)[::-1]
    sorted_scores = y_prob[order]
    sorted_labels = y_true[order]
    x = np.arange(len(sorted_scores))

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(x, sorted_scores, color="#111111", linewidth=1.0, alpha=0.65, zorder=1, label="Sorted score curve")
    ax.scatter(
        x[sorted_labels == 0],
        sorted_scores[sorted_labels == 0],
        s=4,
        alpha=0.25,
        color="#2563EB",
        edgecolors="none",
        label="Safe",
        zorder=2,
    )
    ax.scatter(
        x[sorted_labels == 1],
        sorted_scores[sorted_labels == 1],
        s=4,
        alpha=0.25,
        color="#DC2626",
        edgecolors="none",
        label="Threat",
        zorder=3,
    )
    ax.axhspan(0.0, threshold, color="#2563EB", alpha=0.06)
    ax.axhspan(threshold, 1.0, color="#DC2626", alpha=0.05)
    ax.axhline(threshold, color="black", linestyle="--", linewidth=2, label=f"Threshold = {threshold:.2f}")

    ax.set_ylim(0.0, 1.0)
    ax.set_xlim(0, len(sorted_scores) - 1)
    ax.set_xlabel("Emails sorted by PLSF score", fontsize=13, fontweight="bold")
    ax.set_ylabel("PLSF score", fontsize=13, fontweight="bold")
    ax.set_title(
        f"PLSF Score Ranking\nn={report.get('dataset_info', {}).get('total', 0)}",
        fontsize=15,
        fontweight="bold",
    )
    ax.legend(frameon=True, ncol=2, fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.3)

    plt.tight_layout()
    plt.savefig(FIGURE5_PLSF_SCORES_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def generate_figures(report: dict, fold_metrics: list[dict], y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> None:
    save_confusion_matrix_figure(report)
    save_cv_folds_figure(fold_metrics)
    save_anomaly_scores_figure(y_true, y_prob, threshold, report)
    save_plsf_scores_figure(y_true, y_prob, threshold, report)


def main() -> None:
    logger.info("=" * 80)
    logger.info("PLSF Classifier Retraining v3.1.0")
    logger.info("=" * 80)

    df, dataset_source = load_training_dataset()
    stats = validate_imbalance(df)

    if dataset_source == "dataset_combined.csv":
        logger.warning(
            "Using unbalanced combined dataset because dataset_balanced.csv was not found. "
            "Training will still be blocked if minority share < %.2f%%.",
            MINORITY_SHARE_THRESHOLD * 100,
        )
    else:
        logger.info("Using training dataset source: %s", dataset_source)

    if len(df) > MAX_TRAIN_ROWS:
        df = maybe_downsample_for_speed(df)

    df = df[["body", "label"]].dropna().reset_index(drop=True)

    if df["label"].value_counts().min() / len(df) < MINORITY_SHARE_THRESHOLD:
        raise SystemExit(
            "Training blocked after preprocessing because class balance dropped below 5%."
        )

    texts = df["body"].tolist()
    y = df["label"].astype(int).to_numpy()

    logger.info("Training samples: %d", len(df))
    logger.info("Class 0: %d", int((y == 0).sum()))
    logger.info("Class 1: %d", int((y == 1).sum()))

    logger.info("Loading SentenceTransformer: %s", EMBED_MODEL_NAME)
    st_model = SentenceTransformer(EMBED_MODEL_NAME)

    logger.info("Encoding emails to embeddings")
    X_emb = encode_texts(st_model, texts)

    base_clf = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        C=1.0,
        n_jobs=None,
    )

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    logger.info("Running %d-fold stratified cross-validation", N_SPLITS)

    y_prob_cv = np.zeros(len(y), dtype=float)
    fold_metrics: list[dict] = []

    for fold_idx, (train_idx, val_idx) in enumerate(cv.split(X_emb, y), start=1):
        fold_clf = clone(base_clf)
        fold_clf.fit(X_emb[train_idx], y[train_idx])

        fold_prob = fold_clf.predict_proba(X_emb[val_idx])[:, 1]
        y_prob_cv[val_idx] = fold_prob

        fold_metrics.append(
            {
                "fold": fold_idx,
                "sample_count": int(len(val_idx)),
                **compute_fold_metrics(y[val_idx], fold_prob),
            }
        )

        logger.info(
            "Fold %d: ROC-AUC=%.6f, PR-AUC=%.6f",
            fold_idx,
            fold_metrics[-1]["roc_auc"],
            fold_metrics[-1]["pr_auc"],
        )

    threshold, youden_j = choose_threshold(y, y_prob_cv)
    metrics = compute_metrics(y, y_prob_cv, threshold)

    logger.info("Optimal threshold: %.4f", threshold)
    logger.info("Youden's J: %.6f", youden_j)
    logger.info("ROC-AUC: %.6f", metrics["roc_auc"])
    logger.info("PR-AUC: %.6f", metrics["pr_auc"])
    logger.info("MCC: %.6f", metrics["mcc"])
    logger.info("Confusion Matrix: %s", metrics["confusion_matrix"])
    logger.info("FPR: %.6f", metrics["fpr"])
    logger.info("FNR: %.6f", metrics["fnr"])

    logger.info("Training final classifier on full dataset")
    clf = clone(base_clf)
    clf.fit(X_emb, y)

    model_data = {
        "classifier": clf,
        "embedding_model_name": EMBED_MODEL_NAME,
        "lambda_opt": threshold,
        "version": "3.1.0",
        "dataset_source": dataset_source,
        "training_samples": int(len(df)),
        "dataset_info": stats,
        "minority_threshold": MINORITY_SHARE_THRESHOLD,
    }
    joblib.dump(model_data, MODEL_OUT)

    report = {
        "version": "3.1.0",
        "dataset_source": dataset_source,
        "dataset_info": stats,
        "threshold": float(threshold),
        "youden_j": float(youden_j),
        "cross_validation": {
            "folds": N_SPLITS,
            "strategy": "StratifiedKFold(shuffle=True, random_state=42)",
            "fold_metrics": fold_metrics,
        },
        "metrics": metrics,
        "figure_outputs": {
            "figure3_confusion_matrix": str(FIGURE3_OUT),
            "figure4_cv_folds": str(FIGURE4_CV_FOLDS_OUT),
            "figure4_anomaly_scores": str(FIGURE4_ANOMALY_SCORES_OUT),
            "figure5_plsf_scores": str(FIGURE5_PLSF_SCORES_OUT),
        },
        "model": {
            "embedding_model_name": EMBED_MODEL_NAME,
            "classifier": "LogisticRegression",
            "class_weight": "balanced",
        },
        "guards": {
            "minority_threshold": MINORITY_SHARE_THRESHOLD,
            "max_train_rows": MAX_TRAIN_ROWS,
        },
    }

    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(REPORT_OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(THRESHOLD_OUT, "w", encoding="utf-8") as f:
        json.dump(
            {
                "lambda_opt": float(threshold),
                "source": "retrain_plsf.py",
                "version": "3.1.0",
                "dataset_source": dataset_source,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    logger.info("Generating paper figures")
    generate_figures(report, fold_metrics, y, y_prob_cv, threshold)

    logger.info("=" * 80)
    logger.info("Training complete")
    logger.info("Model saved to: %s", MODEL_OUT)
    logger.info("Metrics saved to: %s", METRICS_OUT)
    logger.info("Report saved to: %s", REPORT_OUT)
    logger.info("Figure 3 saved to: %s", FIGURE3_OUT)
    logger.info("Figure 4 CV folds saved to: %s", FIGURE4_CV_FOLDS_OUT)
    logger.info("Figure 4 anomaly scores saved to: %s", FIGURE4_ANOMALY_SCORES_OUT)
    logger.info("Figure 5 PLSF scores saved to: %s", FIGURE5_PLSF_SCORES_OUT)
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
