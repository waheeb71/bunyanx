"""
AEGIS Pipeline — Stage 0: Dataset Audit
=========================================
Role: Inspect all raw datasets BEFORE any normalization.
Rules:
  - NO modification of raw data
  - NO normalization during audit
  - CPU-safe: streaming + sleep intervals
  - All failures logged, never silently skipped
  - Outputs: dataset_audit_report.json, corruption_log.json, schema_inventory.json
"""

import os
import sys

# Force UTF-8 output on Windows Arabic terminals
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import json
import time
import hashlib
import chardet
import traceback
from datetime import datetime, timezone
from collections import defaultdict, Counter

import pandas as pd
import pyarrow.parquet as pq

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

PIPELINE_VERSION = "1.0.0"
RANDOM_SEED = 42

DATA_ROOT = r"F:\enterprise_ngfw\ml\data"
OUT_DIR   = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage0_audit"
LOG_DIR   = r"F:\enterprise_ngfw\modules\predictive_ai\logs"
CKPT_DIR  = r"F:\enterprise_ngfw\modules\predictive_ai\checkpoints"

# CPU-safety: sleep N seconds between every chunk
CHUNK_SLEEP_SECS = 0.05
CSV_CHUNK_SIZE   = 50_000   # rows per chunk
MAX_SAMPLE_ROWS  = 500_000  # max rows sampled for statistics on huge files

DATASETS = {
    "CIC-IDS2018": {
        "path": os.path.join(DATA_ROOT, "CSE-CIC-IDS2018"),
        "format": "csv_multi",
        "source_type": "network",
        "expected_label_col": "Label",
    },
    "CIC-DDoS2019": {
        "path": os.path.join(DATA_ROOT, "CIC-DDoS2019"),
        "format": "parquet_multi",
        "source_type": "network",
        "expected_label_col": "Label",
    },
    "UNSW-NB15": {
        "path": os.path.join(DATA_ROOT, "NUSW-NB15"),
        "format": "csv_multi",
        "source_type": "network",
        "expected_label_col": "label",
    },
    "CERT-r4.1": {
        "path": os.path.join(DATA_ROOT, r"CERT Insider Threat Dataset (r4.1)\extracted\r4.1"),
        "format": "csv_multi",
        "source_type": "endpoint",
        "expected_label_col": None,   # CERT has no unified label column
    },
    "Sysmon-SILRAD": {
        "path": os.path.join(DATA_ROOT, "JamilIsp-SILRAD-dataset"),
        "format": "csv_multi",
        "source_type": "endpoint",
        "expected_label_col": None,
    },
    "MITRE-ATT&CK": {
        "path": os.path.join(DATA_ROOT, r"mitre-attack-stix-data\enterprise-attack"),
        "format": "stix_json",
        "source_type": "threat_intel",
        "expected_label_col": None,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def ensure_dirs(*dirs):
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def sha256_of_file(filepath, chunk_bytes=1 << 20):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(chunk_bytes), b""):
                h.update(block)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

def detect_encoding_sample(filepath, sample_bytes=65536):
    """Read first N bytes to guess encoding."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read(sample_bytes)
        result = chardet.detect(raw)
        return result.get("encoding", "unknown"), result.get("confidence", 0.0)
    except Exception as e:
        return "unknown", 0.0

def write_jsonl_line(filepath, record):
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def write_json(filepath, data):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ─────────────────────────────────────────────────────────────────────────────
# CORRUPTION LOG
# ─────────────────────────────────────────────────────────────────────────────

CORRUPTION_LOG_PATH = os.path.join(OUT_DIR, "corruption_log.jsonl")

def log_corruption(dataset, source_file, record_id, reason, stage="stage0"):
    entry = {
        "timestamp": now_utc(),
        "dataset": dataset,
        "source_file": source_file,
        "record_id": str(record_id),
        "reason": reason,
        "stage": stage,
    }
    write_jsonl_line(CORRUPTION_LOG_PATH, entry)

# ─────────────────────────────────────────────────────────────────────────────
# CSV AUDIT
# ─────────────────────────────────────────────────────────────────────────────

def audit_csv_file(dataset_name, filepath):
    """
    Streams a CSV file in chunks.
    Returns a per-file audit result dict.
    Does NOT modify the file.
    """
    filename = os.path.basename(filepath)
    print(f"    [CSV] {filename}")

    encoding, enc_confidence = detect_encoding_sample(filepath)
    file_size_bytes = os.path.getsize(filepath)

    result = {
        "file": filename,
        "path": filepath,
        "size_bytes": file_size_bytes,
        "encoding_detected": encoding,
        "encoding_confidence": round(enc_confidence, 4),
        "sha256": sha256_of_file(filepath),
        "total_rows_sampled": 0,
        "total_rows_estimated": None,
        "columns": [],
        "dtype_map": {},
        "missing_per_column": {},
        "missing_pct_per_column": {},
        "duplicate_rows_sampled": 0,
        "duplicate_rate_sampled": 0.0,
        "label_distribution": {},
        "timestamp_columns_detected": [],
        "timestamp_format_samples": {},
        "parse_errors": 0,
        "corrupted_rows": 0,
        "schema_issues": [],
        "notes": [],
        "status": "ok",
    }

    total_rows = 0
    total_dup  = 0
    parse_err  = 0
    missing_counts = defaultdict(int)
    label_counts   = Counter()
    ts_samples     = defaultdict(list)

    # Try to detect timestamp columns by name heuristics
    TS_HINTS = {"timestamp", "ts", "time", "date", "datetime", "flow_start", "start_time",
                "date-time", "starttime", "date", " timestamp"}

    try:
        reader = pd.read_csv(
            filepath,
            chunksize=CSV_CHUNK_SIZE,
            encoding=encoding or "utf-8",
            encoding_errors="replace",
            low_memory=False,
            on_bad_lines="warn",
        )

        schema_captured = False

        for chunk_idx, chunk in enumerate(reader):
            if total_rows >= MAX_SAMPLE_ROWS:
                result["notes"].append(f"Stopped sampling at {MAX_SAMPLE_ROWS} rows (file larger).")
                break

            # Capture schema from first chunk
            if not schema_captured:
                result["columns"] = list(chunk.columns)
                result["dtype_map"] = {c: str(chunk[c].dtype) for c in chunk.columns}
                schema_captured = True

                # Detect timestamp columns
                for col in chunk.columns:
                    if col.strip().lower() in TS_HINTS:
                        result["timestamp_columns_detected"].append(col)

            rows_in_chunk = len(chunk)
            total_rows += rows_in_chunk

            # Missing values
            for col in chunk.columns:
                missing_counts[col] += int(chunk[col].isna().sum())

            # Duplicates (within chunk)
            dup_in_chunk = int(chunk.duplicated().sum())
            total_dup += dup_in_chunk

            # Label distribution
            for ds_name, ds_cfg in DATASETS.items():
                if ds_name == dataset_name:
                    label_col = ds_cfg.get("expected_label_col")
                    if label_col and label_col in chunk.columns:
                        for val, cnt in chunk[label_col].value_counts().items():
                            label_counts[str(val)] += int(cnt)

            # Timestamp samples
            for ts_col in result["timestamp_columns_detected"]:
                if ts_col in chunk.columns:
                    samples = chunk[ts_col].dropna().head(3).tolist()
                    ts_samples[ts_col].extend([str(s) for s in samples])

            time.sleep(CHUNK_SLEEP_SECS)

    except Exception as e:
        result["status"] = "error"
        result["schema_issues"].append(f"READ_ERROR: {e}")
        log_corruption(dataset_name, filename, "N/A", f"File read error: {e}")
        print(f"      [!] Read error: {e}")
        return result

    # Finalize
    result["total_rows_sampled"] = total_rows
    result["duplicate_rows_sampled"] = total_dup
    result["duplicate_rate_sampled"] = round(total_dup / total_rows, 6) if total_rows > 0 else 0
    result["label_distribution"] = dict(label_counts.most_common(50))
    result["timestamp_format_samples"] = {k: v[:5] for k, v in ts_samples.items()}

    # Missing per column (pct)
    for col, cnt in missing_counts.items():
        result["missing_per_column"][col] = int(cnt)
        result["missing_pct_per_column"][col] = round(cnt / total_rows * 100, 4) if total_rows > 0 else 0

    # Flag high-missing columns
    for col, pct in result["missing_pct_per_column"].items():
        if pct > 50:
            result["schema_issues"].append(f"HIGH_MISSING: {col} = {pct}%")

    print(f"      rows_sampled={total_rows:,}  dups={total_dup:,}  parse_err={parse_err}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PARQUET AUDIT
# ─────────────────────────────────────────────────────────────────────────────

def audit_parquet_file(dataset_name, filepath):
    filename = os.path.basename(filepath)
    print(f"    [PQ]  {filename}")

    file_size_bytes = os.path.getsize(filepath)

    result = {
        "file": filename,
        "path": filepath,
        "size_bytes": file_size_bytes,
        "encoding_detected": "parquet_binary",
        "sha256": sha256_of_file(filepath),
        "total_rows": 0,
        "columns": [],
        "dtype_map": {},
        "missing_per_column": {},
        "missing_pct_per_column": {},
        "duplicate_rows_sampled": 0,
        "duplicate_rate_sampled": 0.0,
        "label_distribution": {},
        "timestamp_columns_detected": [],
        "schema_issues": [],
        "notes": [],
        "status": "ok",
    }

    try:
        pf = pq.ParquetFile(filepath)
        total_rows = pf.metadata.num_rows
        result["total_rows"] = total_rows

        schema = pf.schema_arrow
        result["columns"] = [field.name for field in schema]
        result["dtype_map"] = {field.name: str(field.type) for field in schema}

        missing_counts = defaultdict(int)
        label_counts   = Counter()
        label_col = DATASETS.get(dataset_name, {}).get("expected_label_col")

        for batch in pf.iter_batches(batch_size=CSV_CHUNK_SIZE):
            df = batch.to_pandas()
            for col in df.columns:
                missing_counts[col] += int(df[col].isna().sum())
            if label_col and label_col in df.columns:
                for val, cnt in df[label_col].value_counts().items():
                    label_counts[str(val)] += int(cnt)
            time.sleep(CHUNK_SLEEP_SECS)

        result["missing_per_column"] = {c: int(v) for c, v in missing_counts.items()}
        result["missing_pct_per_column"] = {
            c: round(v / total_rows * 100, 4) if total_rows > 0 else 0
            for c, v in missing_counts.items()
        }
        result["label_distribution"] = dict(label_counts.most_common(50))

        for col, pct in result["missing_pct_per_column"].items():
            if pct > 50:
                result["schema_issues"].append(f"HIGH_MISSING: {col} = {pct}%")

        print(f"      rows={total_rows:,}")

    except Exception as e:
        result["status"] = "error"
        result["schema_issues"].append(f"READ_ERROR: {e}")
        log_corruption(dataset_name, filename, "N/A", f"Parquet read error: {e}")
        print(f"      [!] Read error: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# STIX JSON AUDIT (MITRE ATT&CK)
# ─────────────────────────────────────────────────────────────────────────────

def audit_stix_json(dataset_name, dirpath):
    """Walk all .json files in the STIX directory and summarise."""
    print(f"    [STIX] {dirpath}")

    json_files = [
        os.path.join(dp, f)
        for dp, dn, filenames in os.walk(dirpath)
        for f in filenames if f.endswith(".json")
    ]

    total_objects = 0
    type_counts   = Counter()
    technique_ids = []
    tactic_names  = set()
    schema_issues = []
    file_summaries = []

    for jf in json_files:
        fname = os.path.basename(jf)
        try:
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            objects = data.get("objects", [])
            total_objects += len(objects)

            for obj in objects:
                obj_type = obj.get("type", "unknown")
                type_counts[obj_type] += 1

                if obj_type == "attack-pattern":
                    ext = obj.get("external_references", [])
                    for ref in ext:
                        if ref.get("source_name") == "mitre-attack":
                            tid = ref.get("external_id", "")
                            if tid:
                                technique_ids.append(tid)
                    for phase in obj.get("kill_chain_phases", []):
                        tactic_names.add(phase.get("phase_name", ""))

            file_summaries.append({
                "file": fname,
                "size_bytes": os.path.getsize(jf),
                "objects": len(objects),
            })

        except Exception as e:
            schema_issues.append(f"JSON_PARSE_ERROR:{fname}:{e}")
            log_corruption(dataset_name, fname, "N/A", f"STIX JSON parse error: {e}")

        time.sleep(0.01)

    return {
        "stix_directory": dirpath,
        "json_files_found": len(json_files),
        "total_stix_objects": total_objects,
        "object_type_distribution": dict(type_counts.most_common()),
        "techniques_found": len(technique_ids),
        "tactics_found": sorted(tactic_names),
        "schema_issues": schema_issues,
        "file_summaries": file_summaries,
        "status": "ok" if not schema_issues else "warnings",
    }


# ─────────────────────────────────────────────────────────────────────────────
# DATASET-LEVEL AUDITOR
# ─────────────────────────────────────────────────────────────────────────────

def audit_dataset(name, cfg):
    fmt  = cfg["format"]
    path = cfg["path"]

    print(f"\n{'='*60}")
    print(f"  Auditing: {name}  [{fmt}]")
    print(f"  Path: {path}")
    print(f"{'='*60}")

    dataset_result = {
        "dataset_name": name,
        "source_type": cfg["source_type"],
        "format": fmt,
        "path": path,
        "audit_timestamp": now_utc(),
        "files": [],
        "schema_consistency": "consistent",
        "cross_file_schema_issues": [],
        "aggregate": {}
    }

    if not os.path.exists(path):
        dataset_result["error"] = f"PATH_NOT_FOUND: {path}"
        print(f"  [!] Path not found: {path}")
        return dataset_result

    # ── STIX ──
    if fmt == "stix_json":
        stix_result = audit_stix_json(name, path)
        dataset_result["files"] = [stix_result]
        dataset_result["aggregate"]["total_stix_objects"] = stix_result["total_stix_objects"]
        dataset_result["aggregate"]["techniques"] = stix_result["techniques_found"]
        dataset_result["aggregate"]["tactics"]    = stix_result["tactics_found"]
        return dataset_result

    # ── CSV / PARQUET ──
    all_columns = []
    total_rows  = 0
    total_size  = 0
    file_results = []

    # Collect files
    if fmt == "csv_multi":
        files = sorted([
            os.path.join(path, f)
            for f in os.listdir(path)
            if f.lower().endswith(".csv")
        ])
    elif fmt == "parquet_multi":
        files = sorted([
            os.path.join(path, f)
            for f in os.listdir(path)
            if f.lower().endswith(".parquet")
        ])
    else:
        files = []

    if not files:
        dataset_result["error"] = "NO_FILES_FOUND"
        print(f"  [!] No {fmt} files found in {path}")
        return dataset_result

    print(f"  Files found: {len(files)}")

    for fpath in files:
        if fmt == "csv_multi":
            fres = audit_csv_file(name, fpath)
        else:
            fres = audit_parquet_file(name, fpath)

        file_results.append(fres)
        all_columns.append(tuple(fres.get("columns", [])))

        rows = fres.get("total_rows_sampled") or fres.get("total_rows", 0)
        total_rows += rows
        total_size += fres.get("size_bytes", 0)

    dataset_result["files"] = file_results

    # Cross-file schema consistency check
    unique_schemas = list(set(all_columns))
    if len(unique_schemas) > 1:
        dataset_result["schema_consistency"] = "INCONSISTENT"
        dataset_result["cross_file_schema_issues"].append(
            f"{len(unique_schemas)} distinct column schemas found across {len(files)} files"
        )
        print(f"  [!] SCHEMA INCONSISTENCY detected across files!")

    # Aggregate
    dataset_result["aggregate"] = {
        "total_files": len(files),
        "total_size_bytes": total_size,
        "total_size_gb": round(total_size / (1024**3), 3),
        "total_rows_sampled": total_rows,
        "files_with_errors": sum(1 for f in file_results if f.get("status") == "error"),
        "files_with_schema_issues": sum(1 for f in file_results if f.get("schema_issues")),
    }

    print(f"  [OK] Done. Total: {total_rows:,} rows sampled, {total_size/(1024**3):.2f} GB")
    return dataset_result


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA INVENTORY
# ─────────────────────────────────────────────────────────────────────────────

def build_schema_inventory(audit_report):
    inventory = {}
    for ds_name, ds_data in audit_report.items():
        files = ds_data.get("files", [])
        schemas_found = {}
        for fdata in files:
            cols = fdata.get("columns", [])
            dtypes = fdata.get("dtype_map", {})
            if cols:
                schemas_found[fdata.get("file", "unknown")] = {
                    "columns": cols,
                    "dtypes": dtypes,
                    "column_count": len(cols),
                }
        inventory[ds_name] = {
            "source_type": ds_data.get("source_type"),
            "format": ds_data.get("format"),
            "schema_consistency": ds_data.get("schema_consistency", "N/A"),
            "schemas": schemas_found,
        }
    return inventory


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION GATES
# ─────────────────────────────────────────────────────────────────────────────

def validate_stage0(audit_report):
    """
    Gate: ALL datasets must be audited and no unrecoverable errors.
    Returns (passed: bool, gate_report: dict)
    """
    issues = []
    for ds_name, ds_data in audit_report.items():
        if "error" in ds_data and "PATH_NOT_FOUND" in ds_data["error"]:
            issues.append(f"GATE_FAIL: {ds_name} — path not found")
        agg = ds_data.get("aggregate", {})
        err_files = agg.get("files_with_errors", 0)
        total_files = agg.get("total_files", 0)
        if total_files > 0 and err_files == total_files:
            issues.append(f"GATE_FAIL: {ds_name} — ALL files failed to read ({err_files}/{total_files})")

    passed = len(issues) == 0
    return passed, {
        "gate": "stage0_to_stage1",
        "timestamp": now_utc(),
        "passed": passed,
        "issues": issues,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT
# ─────────────────────────────────────────────────────────────────────────────

def save_checkpoint(audit_report, gate_report):
    ckpt = {
        "stage": 0,
        "pipeline_version": PIPELINE_VERSION,
        "timestamp": now_utc(),
        "datasets_audited": list(audit_report.keys()),
        "gate_passed": gate_report["passed"],
        "gate_issues": gate_report["issues"],
    }
    path = os.path.join(CKPT_DIR, "checkpoint_stage_0.json")
    write_json(path, ckpt)
    print(f"\n  [OK] Checkpoint saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ensure_dirs(OUT_DIR, LOG_DIR, CKPT_DIR)

    print("=" * 70)
    print("  AEGIS Pipeline — Stage 0: Dataset Audit")
    print(f"  Started: {now_utc()}")
    print(f"  Pipeline Version: {PIPELINE_VERSION}")
    print("=" * 70)

    # Clear old corruption log for a fresh run
    if os.path.exists(CORRUPTION_LOG_PATH):
        os.remove(CORRUPTION_LOG_PATH)

    audit_report = {}

    for ds_name, ds_cfg in DATASETS.items():
        try:
            result = audit_dataset(ds_name, ds_cfg)
            audit_report[ds_name] = result
        except Exception as e:
            print(f"\n[!!] UNHANDLED ERROR auditing {ds_name}: {e}")
            traceback.print_exc()
            audit_report[ds_name] = {
                "dataset_name": ds_name,
                "error": f"UNHANDLED: {e}",
                "status": "error",
            }

    # Build outputs
    print("\n" + "=" * 70)
    print("  Building output reports...")

    # 1. Full audit report
    audit_report_path = os.path.join(OUT_DIR, "dataset_audit_report.json")
    write_json(audit_report_path, audit_report)
    print(f"  [OK] {audit_report_path}")

    # 2. Schema inventory
    inventory = build_schema_inventory(audit_report)
    inventory_path = os.path.join(OUT_DIR, "schema_inventory.json")
    write_json(inventory_path, inventory)
    print(f"  [OK] {inventory_path}")

    # 3. Corruption log summary (count lines)
    corruption_count = 0
    if os.path.exists(CORRUPTION_LOG_PATH):
        with open(CORRUPTION_LOG_PATH, "r", encoding="utf-8") as f:
            corruption_count = sum(1 for _ in f)
    print(f"  [OK] Corruption log: {corruption_count} entries -> {CORRUPTION_LOG_PATH}")

    # 4. Validation gate
    gate_passed, gate_report = validate_stage0(audit_report)

    # 5. Checkpoint
    save_checkpoint(audit_report, gate_report)

    # Summary
    print("\n" + "=" * 70)
    print("  STAGE 0 COMPLETE")
    print(f"  Datasets audited : {len(audit_report)}")
    print(f"  Corruption entries: {corruption_count}")
    print(f"  Validation gate  : {'[PASSED]' if gate_passed else '[FAILED]'}")
    if not gate_passed:
        for issue in gate_report["issues"]:
            print(f"    → {issue}")
        print("\n  [PIPELINE HALTED] Fix gate issues before proceeding to Stage 1.")
        sys.exit(1)
    else:
        print("\n  → Stage 1 (UEM) is cleared to run.")
    print("=" * 70)


if __name__ == "__main__":
    main()
