from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
REPORT_JSON = Path("modules/email_security/models/plsf_training_report.json")
FIGURE3_OUT = DATA_DIR / "figure3_confusion_matrix.png"


def load_report() -> dict:
    with open(REPORT_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(cm: np.ndarray) -> tuple[float, float, float, float]:
    tn, fp = cm[0]
    fn, tp = cm[1]
    total = cm.sum()
    accuracy = (tn + tp) / total * 100 if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return accuracy, precision, recall, f1


def main() -> None:
    report = load_report()
    metrics = report.get("metrics", {})
    cm = np.array(metrics.get("confusion_matrix"))
    if cm.shape != (2, 2):
        raise SystemExit(f"Invalid confusion matrix in {REPORT_JSON}: expected 2x2, got {cm.shape}")

    accuracy, precision, recall, f1 = compute_metrics(cm)

    fig, ax = plt.subplots(figsize=(8, 6))
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

    summary_text = (
        f"Accuracy: {accuracy:.2f}%\n"
        f"Precision: {precision:.3f}\n"
        f"Recall: {recall:.3f}\n"
        f"F1: {f1:.3f}"
    )
    ax.text(
        1.5,
        0.5,
        summary_text,
        transform=ax.transAxes,
        fontsize=11,
        verticalalignment="center",
        bbox=dict(boxstyle="round", facecolor="lightgray", alpha=0.8),
    )

    plt.tight_layout()
    plt.savefig(FIGURE3_OUT, dpi=300, bbox_inches="tight")
    plt.close()

    print(f"Saved: {FIGURE3_OUT}")
    print(f"Confusion Matrix: TN={int(cm[0,0])}, FP={int(cm[0,1])}, FN={int(cm[1,0])}, TP={int(cm[1,1])}")
    print(f"Accuracy: {accuracy:.2f}%")
    print(f"Precision: {precision:.3f}, Recall: {recall:.3f}, F1: {f1:.3f}")


if __name__ == "__main__":
    main()
