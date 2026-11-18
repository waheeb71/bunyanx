from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from email import message_from_binary_file
from email.message import Message
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd


project_root = Path(__file__).resolve().parents[3]
DATASET_ROOT = project_root / "dataset"
OUT_DIR = project_root / "modules" / "email_security" / "training_pipeline" / "data"
OUT_DIR.mkdir(parents=True, exist_ok=True)

COMBINED_CSV = OUT_DIR / "dataset_combined.csv"
BALANCED_CSV = OUT_DIR / "dataset_balanced.csv"
TRAIN_CSV = OUT_DIR / "dataset_train.csv"
VAL_CSV = OUT_DIR / "dataset_val.csv"
TEST_CSV = OUT_DIR / "dataset_test.csv"
REPORT_JSON = OUT_DIR / "dataset_build_report.json"

EXPECTED_COLUMNS = ["body", "label"]

BODY_COLUMNS = ["body", "body_text", "text_combined", "text", "message", "content", "email"]
LABEL_COLUMNS = ["label", "class", "target", "spam"]

HTML_TAG_RE = re.compile(r"<[^>]+>")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"\b\d{10,}\b")

MIN_LEN = 50
MAX_LEN = 8000


def strip_html(text: str) -> str:
    return HTML_TAG_RE.sub(" ", text)


def redact_pii(text: str) -> str:
    text = EMAIL_RE.sub("[EMAIL]", text)
    text = PHONE_RE.sub("[PHONE]", text)
    return text


def clean_text(text: Any, *, min_len: int = MIN_LEN, max_len: int = MAX_LEN) -> Optional[str]:
    if text is None or (isinstance(text, float) and pd.isna(text)):
        return None
    text = str(text)
    text = strip_html(text)
    text = redact_pii(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) < min_len:
        return None
    return text[:max_len]


def normalize_label_value(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return default

    if isinstance(value, (int, np.integer)):
        numeric = int(value)
        return numeric if numeric in (0, 1) else default

    text = str(value).strip().lower()
    if text in {"0", "normal", "ham", "benign", "legit", "legitimate"}:
        return 0
    if text in {"1", "bec", "attack", "spam", "phishing", "fraud", "malicious"}:
        return 1

    try:
        numeric = int(float(text))
        if numeric in (0, 1):
            return numeric
    except Exception:
        pass

    return default


def extract_body_from_msg(msg: Message) -> str:
    try:
        if msg.is_multipart():
            parts: List[str] = []
            for part in msg.walk():
                if part.get_content_type() != "text/plain":
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                parts.append(payload.decode(errors="ignore"))
            if parts:
                return "\n".join(parts)

        payload = msg.get_payload(decode=True)
        if payload is None:
            payload = msg.get_payload()
            return str(payload) if payload is not None else ""
        return payload.decode(errors="ignore")
    except Exception:
        return ""


def find_column(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    normalized = {str(col).lower(): col for col in df.columns}
    for target in candidates:
        exact = normalized.get(target.lower())
        if exact is not None:
            return exact

    for target in candidates:
        target_lower = target.lower()
        for col in df.columns:
            if target_lower in str(col).lower():
                return col
    return None


def file_kind(p: Path) -> str:
    name = p.name.lower()
    for ext in [".tar.bz2", ".tar.gz", ".tgz"]:
        if name.endswith(ext):
            return ext.strip(".")
    return p.suffix.lower().lstrip(".") or "(no_ext)"


def infer_label_from_path_hint(fp: Path) -> Optional[int]:
    s = str(fp).lower()
    if any(k in s for k in ["spam", "attack", "bec", "mimic", "malicious", "nazario", "iwspa", "phishing", "fraud"]):
        return 1
    if any(k in s for k in ["ham", "normal", "benign", "easy_ham", "enron", "real_normal"]):
        return 0
    return None


def parse_enron_maildir(maildir_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for fp in maildir_path.rglob("*"):
        if not fp.is_file():
            continue
        try:
            with open(fp, "rb") as f:
                msg = message_from_binary_file(f)
            body = extract_body_from_msg(msg)
        except Exception:
            try:
                body = fp.read_text(errors="ignore")
            except Exception:
                continue

        cleaned = clean_text(body)
        if cleaned is None:
            continue

        rows.append(
            {
                "body": cleaned,
                "label": 0,
                "source_file": str(fp.relative_to(DATASET_ROOT)),
                "source_kind": "maildir",
            }
        )
    return rows


def parse_csv_dataset(csv_path: Path, default_label: Optional[int] = None) -> List[Dict[str, Any]]:
    try:
        df = pd.read_csv(csv_path)
    except Exception:
        return []

    body_col = find_column(df, BODY_COLUMNS)
    if body_col is None:
        return []

    label_col = find_column(df, LABEL_COLUMNS)
    fallback_label = default_label if default_label is not None else infer_label_from_path_hint(csv_path)

    rows: List[Dict[str, Any]] = []
    for idx, row in df.iterrows():
        cleaned = clean_text(row.get(body_col, ""))
        if cleaned is None:
            continue

        label_value = None
        if label_col is not None:
            label_value = normalize_label_value(row.get(label_col), default=None)
        if label_value is None:
            label_value = fallback_label
        if label_value is None:
            continue

        rows.append(
            {
                "body": cleaned,
                "label": int(label_value),
                "source_file": f"{csv_path.relative_to(DATASET_ROOT)}#{idx}",
                "source_kind": "csv",
            }
        )
    return rows


def parse_json_dataset(json_path: Path, default_label: Optional[int] = None) -> List[Dict[str, Any]]:
    try:
        df = pd.read_json(json_path)
    except Exception:
        return []

    if df is None or df.empty:
        return []

    body_col = find_column(df, BODY_COLUMNS)
    if body_col is None:
        return []

    label_col = find_column(df, LABEL_COLUMNS)
    fallback_label = default_label if default_label is not None else infer_label_from_path_hint(json_path)

    rows: List[Dict[str, Any]] = []
    for idx, row in df.iterrows():
        cleaned = clean_text(row.get(body_col, ""))
        if cleaned is None:
            continue

        label_value = None
        if label_col is not None:
            label_value = normalize_label_value(row.get(label_col), default=None)
        if label_value is None:
            label_value = fallback_label
        if label_value is None:
            continue

        rows.append(
            {
                "body": cleaned,
                "label": int(label_value),
                "source_file": f"{json_path.relative_to(DATASET_ROOT)}#{idx}",
                "source_kind": "json",
            }
        )
    return rows


def infer_and_parse(root: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    source_summary: DefaultDict[str, Counter] = defaultdict(Counter)

    def add_rows(new_rows: Iterable[Dict[str, Any]]) -> None:
        for item in new_rows:
            rows.append(item)
            source_summary[item["source_file"]].update([int(item["label"])])

    # 1) Enron maildir (normal)
    enron_dir = root / "enron" / "maildir"
    if enron_dir.exists():
        add_rows(parse_enron_maildir(enron_dir))

    # 2) Real normal CSV
    real_normal_csv = root / "real_normal" / "enron_normal_emails.csv"
    if real_normal_csv.exists():
        add_rows(parse_csv_dataset(real_normal_csv, default_label=0))

    # 3) IWSPA / CEAS / phishing / spam datasets with source labels
    iwspa_dir = root / "iwspa"
    if iwspa_dir.exists():
        for fp in sorted(iwspa_dir.rglob("*")):
            if not fp.is_file():
                continue
            ext = fp.suffix.lower()
            if ext == ".csv":
                add_rows(parse_csv_dataset(fp))
            elif ext == ".json":
                add_rows(parse_json_dataset(fp))

    # 4) Optional Arabic corpus — keep it out of English-only PLSF unless explicitly needed
    # If needed later, this can be enabled with a dedicated multilingual path.
    # arabic_csv = root / "arabic_dataset.csv"
    # if arabic_csv.exists():
    #     add_rows(parse_csv_dataset(arabic_csv))

    source_stats: List[Dict[str, Any]] = []
    for source_file, counts in sorted(source_summary.items()):
        source_stats.append(
            {
                "source_file": source_file,
                "rows": int(sum(counts.values())),
                "label_counts": {str(k): int(v) for k, v in sorted(counts.items())},
            }
        )

    return rows, source_stats


def build_quality_summary(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {
            "total_rows": 0,
            "label_counts": {},
            "imbalance_ratio": None,
            "duplicate_body_rows": 0,
            "empty_body_rows": 0,
            "cross_label_same_body": 0,
            "length_stats": {},
            "by_label": {},
            "examples": {},
        }

    bodies = df["body"].fillna("").astype(str)
    labels = df["label"].astype(int)
    counts = labels.value_counts().sort_index()

    length_series = bodies.str.len()
    by_label: Dict[str, Any] = {}
    examples: Dict[str, List[str]] = {}
    for label_value, subset in df.groupby("label"):
        label_body = subset["body"].fillna("").astype(str)
        by_label[str(int(label_value))] = {
            "n": int(len(subset)),
            "unique_body": int(subset["body"].nunique()),
            "dup_rows": int(subset.duplicated(subset=["body"]).sum()),
            "empty": int((label_body.str.strip() == "").sum()),
        }
        examples[str(int(label_value))] = subset["body"].head(3).tolist()

    min_count = int(counts.min())
    max_count = int(counts.max())
    imbalance_ratio = round(max_count / min_count, 2) if min_count > 0 else None
    cross_label_same_body = int((df.groupby("body")["label"].nunique() > 1).sum())

    return {
        "total_rows": int(len(df)),
        "label_counts": {str(int(k)): int(v) for k, v in counts.items()},
        "imbalance_ratio": imbalance_ratio,
        "duplicate_body_rows": int(df.duplicated(subset=["body"]).sum()),
        "empty_body_rows": int((bodies.str.strip() == "").sum()),
        "cross_label_same_body": cross_label_same_body,
        "length_stats": {
            "min": int(length_series.min()),
            "p50": float(length_series.quantile(0.5)),
            "p90": float(length_series.quantile(0.9)),
            "p99": float(length_series.quantile(0.99)),
            "max": int(length_series.max()),
        },
        "by_label": by_label,
        "examples": examples,
    }


def deduplicate_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
    before = len(df)
    dup_rows = int(df.duplicated(subset=["body"]).sum())
    cross_label_same_body = int((df.groupby("body")["label"].nunique() > 1).sum())
    df = df.drop_duplicates(subset=["body"]).reset_index(drop=True)
    removed = before - len(df)
    return df, {
        "rows_before": int(before),
        "rows_after": int(len(df)),
        "duplicate_body_rows": int(dup_rows),
        "cross_label_same_body": int(cross_label_same_body),
        "removed_rows": int(removed),
    }


def balance_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    counts = df["label"].value_counts().sort_index()
    if len(counts) != 2:
        raise SystemExit(f"Expected binary labels, found: {counts.to_dict()}")

    minority_count = int(counts.min())
    if minority_count <= 0:
        raise SystemExit(f"Cannot balance dataset with empty class distribution: {counts.to_dict()}")

    balanced_parts = []
    for label_value in sorted(counts.index.tolist()):
        subset = df[df["label"] == label_value].sample(n=minority_count, random_state=42)
        balanced_parts.append(subset)

    balanced_df = pd.concat(balanced_parts, ignore_index=True)
    balanced_df = balanced_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    balanced_summary = build_quality_summary(balanced_df)
    balanced_summary["strategy"] = "downsample_majority_to_minority"
    balanced_summary["target_per_class"] = int(minority_count)
    return balanced_df, balanced_summary


def split_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    from sklearn.model_selection import train_test_split

    X = df["body"]
    y = df["label"]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp,
    )

    train_out = pd.DataFrame({"body": X_train, "label": y_train})
    val_out = pd.DataFrame({"body": X_val, "label": y_val})
    test_out = pd.DataFrame({"body": X_test, "label": y_test})

    return train_out, val_out, test_out


def label_ratio_guard(df: pd.DataFrame, *, threshold: float = 0.05) -> None:
    counts = df["label"].value_counts()
    total = int(len(df))
    if len(counts) < 2:
        raise SystemExit("Training dataset must contain both classes.")

    minority_share = float(counts.min() / total) if total else 0.0
    if minority_share < threshold:
        raise SystemExit(
            f"Minority class share {minority_share:.4%} is below allowed threshold {threshold:.2%}. "
            f"Class counts: {counts.to_dict()}"
        )


def main() -> None:
    if not DATASET_ROOT.exists():
        raise SystemExit(f"DATASET_ROOT not found: {DATASET_ROOT}")

    raw_rows, source_stats = infer_and_parse(DATASET_ROOT)
    if not raw_rows:
        raise SystemExit("No rows extracted from raw dataset.")

    raw_df = pd.DataFrame(raw_rows)
    raw_df = raw_df.dropna(subset=["body", "label"]).copy()
    raw_df["label"] = raw_df["label"].astype(int)

    # Normalize to the schema expected by retraining
    raw_df = raw_df[["body", "label", "source_file", "source_kind"]].copy()

    # Build clean combined dataset
    combined_df = raw_df[["body", "label"]].copy()
    combined_df, dedup_info = deduplicate_dataframe(combined_df)
    combined_summary = build_quality_summary(combined_df)

    # Build balanced dataset for training
    balanced_df, balanced_summary = balance_dataframe(combined_df)

    # Persist outputs
    combined_df.to_csv(COMBINED_CSV, index=False)
    balanced_df[EXPECTED_COLUMNS].to_csv(BALANCED_CSV, index=False)

    train_out, val_out, test_out = split_dataframe(balanced_df[EXPECTED_COLUMNS])
    train_out.to_csv(TRAIN_CSV, index=False)
    val_out.to_csv(VAL_CSV, index=False)
    test_out.to_csv(TEST_CSV, index=False)

    report = {
        "dataset_root": str(DATASET_ROOT),
        "source_stats": source_stats,
        "issue_found": {
            "root_cause": "The previous build script hard-coded all IWSPA CSV rows as label=1 during parsing, overriding the dataset's own label columns.",
            "affected_sources": [
                "dataset/iwspa/CEAS_08.csv",
                "dataset/iwspa/Enron.csv",
                "dataset/iwspa/Ling.csv",
                "dataset/iwspa/SpamAssasin.csv",
                "dataset/iwspa/phishing_email.csv",
            ],
            "symptom": "Normal rows were collapsed to a tiny subset while attack rows were preserved, creating an extreme 482:1 imbalance in dataset_combined.csv.",
        },
        "deduplication": dedup_info,
        "combined": combined_summary,
        "balanced": balanced_summary,
        "splits": {
            "train": build_quality_summary(train_out),
            "val": build_quality_summary(val_out),
            "test": build_quality_summary(test_out),
        },
        "outputs": {
            "combined": str(COMBINED_CSV),
            "balanced": str(BALANCED_CSV),
            "train": str(TRAIN_CSV),
            "val": str(VAL_CSV),
            "test": str(TEST_CSV),
        },
        "balance_note": "Balanced dataset was created by downsampling the majority class to the minority class size after deduplication.",
    }

    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("[OK] dataset_combined saved:", COMBINED_CSV)
    print("[OK] dataset_balanced saved:", BALANCED_CSV)
    print("[OK] splits saved:", TRAIN_CSV, VAL_CSV, TEST_CSV)
    print("[OK] report saved:", REPORT_JSON)
    print("[INFO] combined labels:", combined_summary["label_counts"])
    print("[INFO] balanced labels:", balanced_summary["label_counts"])


if __name__ == "__main__":
    main()
