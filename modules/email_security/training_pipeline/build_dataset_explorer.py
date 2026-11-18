from __future__ import annotations

import os
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple


project_root = Path(__file__).resolve().parents[3]
DATASET_ROOT = project_root / "dataset"
OUT_DIR = project_root / "modules" / "email_security" / "training_pipeline" / "data"
OUT_DIR.mkdir(parents=True, exist_ok=True)

REPORT_CSV = OUT_DIR / "dataset_explorer_report.csv"
REPORT_JSON = OUT_DIR / "dataset_explorer_report.json"


EXT_TO_KIND = {
    ".mbox": "mbox",
    ".eml": "eml",
    ".txt": "txt",
    ".csv": "csv",
    ".json": "json",
    ".tar": "tar",
    ".gz": "gz",
    ".tgz": "tgz",
    ".zip": "zip",
    ".tar.gz": "tar.gz",
    ".tar.bz2": "tar.bz2",
    ".bz2": "bz2",
}


def file_kind(p: Path) -> str:
    name = p.name.lower()
    # handle compound extensions first
    for ext in [".tar.bz2", ".tar.gz", ".tgz"]:
        if name.endswith(ext):
            return ext.strip(".")
    return p.suffix.lower().lstrip(".") or "(no_ext)"


def infer_label_from_path(p: Path) -> Tuple[str, str | None]:
    # returns (source_group, label)
    s = str(p).lower()
    if "nazario" in s or "iwspa" in s:
        return ("attack", "1")
    if "spamassassin" in s:
        if "spam" in s:
            return ("attack", "1")
        if "easy_ham" in s or "ham" in s:
            return ("normal", "0")
    if "enron" in s:
        return ("normal", "0")
    if "real_normal" in s:
        return ("normal", "0")
    return ("unknown", None)


def clean_rel_dir(p: Path) -> str:
    try:
        return str(p.relative_to(DATASET_ROOT))
    except Exception:
        return str(p)


def main():
    # Aggregate by directory under root (directories that contain files)
    dir_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    file_stats: Dict[str, int] = defaultdict(int)
    label_stats: Dict[str, int] = defaultdict(int)

    rows = []

    if not DATASET_ROOT.exists():
        raise SystemExit(f"Dataset root not found: {DATASET_ROOT}")

    for p in DATASET_ROOT.rglob('*'):
        if not p.is_file():
            continue
        kind = file_kind(p)
        rel_dir = str(p.parent.relative_to(DATASET_ROOT))
        key_dir = rel_dir if rel_dir else "."
        dir_stats[key_dir][kind] += 1
        file_stats[kind] += 1

        group, label = infer_label_from_path(p)
        if label is not None:
            label_stats[label] += 1

    # Write CSV with per-directory counts by kind (sparse)
    all_kinds = sorted(file_stats.keys())

    # compute per directory totals
    for d, kind_map in sorted(dir_stats.items()):
        row = {
            "directory": d,
            "total_files": sum(kind_map.values()),
            "label_0_guess": (dir_stats[d].get('mbox',0) + 0)  # placeholder, overwritten below
        }
        # fill kind columns
        for k in all_kinds:
            row[f"kind_{k}"] = kind_map.get(k, 0)

        # guess label counts by scanning filenames in that directory for keywords
        # (approximation; extraction step will do real parsing later)
        dir_path = DATASET_ROOT / d
        c0 = 0
        c1 = 0
        for fp in dir_path.glob('**/*'):
            if not fp.is_file():
                continue
            _, lab = infer_label_from_path(fp)
            if lab == '0':
                c0 += 1
            elif lab == '1':
                c1 += 1
        row["label_0_guess"] = c0
        row["label_1_guess"] = c1

        rows.append(row)

    fieldnames = ["directory", "total_files", "label_0_guess", "label_1_guess"] + [f"kind_{k}" for k in all_kinds]

    with open(REPORT_CSV, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # JSON summary
    summary = {
        "dataset_root": str(DATASET_ROOT),
        "total_files_by_kind": dict(file_stats),
        "total_label_guess_counts": dict(label_stats),
        "num_directories": len(dir_stats),
        "output_csv": str(REPORT_CSV),
        "output_json": str(REPORT_JSON),
    }
    # enrich with top kinds
    summary["top_kinds"] = sorted(file_stats.items(), key=lambda x: x[1], reverse=True)[:30]

    import json

    with open(REPORT_JSON, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[OK] Wrote explorer report: {REPORT_CSV}")
    print(f"[OK] Wrote explorer summary: {REPORT_JSON}")
    print(f"[INFO] Total kinds: {len(file_stats)}  Directories scanned: {len(dir_stats)}")


if __name__ == "__main__":
    main()

