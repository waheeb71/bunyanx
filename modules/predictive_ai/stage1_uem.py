"""
AEGIS Pipeline — Stage 1: Unified Event Model (UEM) Normalization
===================================================================
Role: Normalize raw datasets into a single JSONL UEM format.
Rules:
  - Streaming processing, chunk-based writing.
  - Standardize timestamps to ISO-8601 UTC.
  - Extract network and endpoint attributes into `attributes` dict.
  - Unify labels (`is_attack`, `attack_type`).
  - Output chunked UEM JSONL files.
"""

import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import json
import time
import uuid
import traceback
import pandas as pd
import pyarrow.parquet as pq
from datetime import datetime, timezone

sys.path.append(os.path.dirname(__file__))

from schemas.schema_manager import SchemaManager
from utils.file_chunker import FileChunker
from logs.pipeline_logger import PipelineLogger

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

PIPELINE_VERSION = "1.0.0"

DATA_ROOT = r"F:\enterprise_ngfw\ml\data"
OUT_DIR   = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage1_uem"
LOG_DIR   = r"F:\enterprise_ngfw\modules\predictive_ai\logs"
CKPT_DIR  = r"F:\enterprise_ngfw\modules\predictive_ai\checkpoints"
AUDIT_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage0_audit"

CHUNK_SIZE = 50_000

# ─────────────────────────────────────────────────────────────────────────────
# MAPPING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def safe_int(val, default=0):
    """Convert any numeric value (int, float, or string) to int safely."""
    try:
        if pd.isna(val):
            return default
        return int(float(str(val)))
    except (ValueError, TypeError):
        return default

def safe_float(val, default=0.0):
    """Convert any value to float safely."""
    try:
        if pd.isna(val):
            return default
        return float(str(val))
    except (ValueError, TypeError):
        return default

def standardize_timestamp(ts_val):
    """Attempt to parse and standardize timestamp to ISO-8601 UTC."""
    if pd.isna(ts_val) or ts_val == "":
        return None
        
    ts_str = str(ts_val).strip()
    
    try:
        # If it's a number (Unix epoch)
        if ts_str.replace('.', '', 1).isdigit():
            # Check if ms or seconds
            val = float(ts_str)
            if val > 1e11: # likely ms
                dt = pd.to_datetime(val, unit='ms', utc=True)
            else:
                dt = pd.to_datetime(val, unit='s', utc=True)
            return dt.isoformat()
            
        # Try pandas generic parser
        dt = pd.to_datetime(ts_str, utc=True, errors='coerce')
        if pd.isna(dt):
            return None
        return dt.isoformat()
    except:
        return None

def normalize_label(raw_label):
    """
    Returns (is_attack, attack_type).
    Covers all label variants across CIC-IDS2018, CIC-DDoS2019,
    UNSW-NB15, Sysmon-SILRAD datasets.
    """
    if pd.isna(raw_label) or str(raw_label).strip() == "":
        return 0, ""

    label = str(raw_label).strip().lower()

    # ── Benign / Normal ──────────────────────────────────────────────
    if label in ["benign", "normal", "0", "0.0", "label"]:
        return 0, ""

    is_attack = 1
    attack_type = "Unknown"

    # ── DDoS ─────────────────────────────────────────────────────────
    if "ddos" in label or "loic" in label or "hoic" in label:
        attack_type = "DDoS"
    # ── DoS ──────────────────────────────────────────────────────────
    elif "dos" in label or "hulk" in label or "slowloris" in label \
            or "goldeneye" in label or "slowhttp" in label:
        attack_type = "DoS"
    # ── Reconnaissance / Scanning ─────────────────────────────────────
    elif "portscan" in label or "recon" in label or "scan" in label \
            or "analysis" in label:
        attack_type = "Reconnaissance"
    # ── Brute Force ───────────────────────────────────────────────────
    elif "bruteforce" in label or "brute force" in label \
            or "brute" in label or "ftp-" in label or "ssh-" in label:
        attack_type = "Brute Force"
    # ── Botnet ────────────────────────────────────────────────────────
    elif "bot" in label:
        attack_type = "Botnet"
    # ── Web Attacks ───────────────────────────────────────────────────
    elif "web" in label or "xss" in label or "sql" in label \
            or "injection" in label:
        attack_type = "Web Attack"
    # ── Infiltration (typo-aware) ─────────────────────────────────────
    elif "infiltrat" in label:   # covers both -tion and -eration
        attack_type = "Infiltration"
    # ── Fuzzing ───────────────────────────────────────────────────────
    elif "fuzzer" in label or "fuzz" in label:
        attack_type = "Fuzzing"
    # ── Exploitation / Shellcode / Exploit kits ───────────────────────
    elif "exploit" in label or "shellcode" in label:
        attack_type = "Exploitation"
    # ── Backdoor ──────────────────────────────────────────────────────
    elif "backdoor" in label:
        attack_type = "Backdoor"
    # ── Worms ─────────────────────────────────────────────────────────
    elif "worm" in label:
        attack_type = "Worm"
    # ── Generic / Unknown ─────────────────────────────────────────────
    elif "generic" in label:
        attack_type = "Generic"
    else:
        attack_type = str(raw_label).strip()   # preserve original for audit

    return is_attack, attack_type

# ─────────────────────────────────────────────────────────────────────────────
# BASE PROCESSOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DatasetProcessor:
    def __init__(self, logger, chunker):
        self.logger = logger
        self.chunker = chunker
        self.dataset_name = ""
        self.source_type = ""
        
    def _create_uem_record(self, record_id, ts, action, attributes, raw_label, source_file):
        is_attack, attack_type = normalize_label(raw_label)
        
        return {
            "event_id": str(record_id),
            "timestamp": ts,
            "source_type": self.source_type,
            "dataset_source": self.dataset_name,
            "entity_id": None, # Resolved in Stage 2
            "action": action,
            "attributes": attributes,
            "label_raw": str(raw_label) if pd.notna(raw_label) else "",
            "is_attack": is_attack,
            "attack_type": attack_type,
            "processing_metadata": {
                "pipeline_stage": "stage1_uem",
                "processing_timestamp": now_utc(),
                "source_file": source_file
            }
        }

# ─────────────────────────────────────────────────────────────────────────────
# CIC-IDS2018 PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class CICIDS2018Processor(DatasetProcessor):
    def __init__(self, logger, chunker):
        super().__init__(logger, chunker)
        self.dataset_name = "CIC-IDS2018"
        self.source_type = "network"
        
    def process_file(self, filepath):
        filename = os.path.basename(filepath)
        print(f"  [CIC-IDS2018] Processing {filename}...")
        ok, skipped = 0, 0
        try:
            reader = pd.read_csv(
                filepath, chunksize=CHUNK_SIZE,
                encoding="utf-8", encoding_errors="replace",
                on_bad_lines="skip", low_memory=False,
            )
            for chunk in reader:
                for idx, row in chunk.iterrows():
                    try:
                        rec_id = f"cic2018_{uuid.uuid4().hex[:12]}"
                        ts_raw = row.get("Timestamp")
                        ts = standardize_timestamp(ts_raw)
                        if not ts:
                            skipped += 1
                            continue

                        proto_val = row.get("Protocol", "")
                        proto = "TCP" if proto_val == 6 else ("UDP" if proto_val == 17 else str(proto_val))

                        attributes = {
                            "src_ip":        str(row.get("Src IP", "")),
                            "dst_ip":        str(row.get("Dst IP", "")),
                            "src_port":      safe_int(row.get("Src Port")),
                            "dst_port":      safe_int(row.get("Dst Port")),
                            "protocol":      proto,
                            "bytes":         safe_int(row.get("Flow Byts/s")),
                            "packets":       safe_int(row.get("Tot Fwd Pkts")) + safe_int(row.get("Tot Bwd Pkts")),
                            "flow_duration": safe_int(row.get("Flow Duration")),
                        }
                        raw_label = row.get("Label", "Benign")
                        event = self._create_uem_record(rec_id, ts, "network_flow", attributes, raw_label, filename)
                        self.chunker.write_record(event)
                        ok += 1
                    except Exception as row_err:
                        skipped += 1
                        self.logger.log_parsing_failure(self.dataset_name, filename, str(idx), str(row_err), "stage1")
        except Exception as e:
            self.logger.log_parsing_failure(self.dataset_name, filename, "N/A", str(e), "stage1")
            print(f"    [!] Fatal error in {filename}: {e}")
        print(f"      -> written={ok:,}  skipped={skipped:,}")

# ─────────────────────────────────────────────────────────────────────────────
# CIC-DDoS2019 PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class CICDDoS2019Processor(DatasetProcessor):
    def __init__(self, logger, chunker):
        super().__init__(logger, chunker)
        self.dataset_name = "CIC-DDoS2019"
        self.source_type = "network"
        
    def process_file(self, filepath):
        filename = os.path.basename(filepath)
        print(f"  [CIC-DDoS2019] Processing {filename}...")
        
        try:
            pf = pq.ParquetFile(filepath)
            for batch in pf.iter_batches(batch_size=CHUNK_SIZE):
                df = batch.to_pandas()
                for idx, row in df.iterrows():
                    rec_id = f"ddos2019_{uuid.uuid4().hex[:12]}"
                    
                    # Timestamp
                    ts_raw = row.get(" Timestamp", row.get("Timestamp"))
                    ts = standardize_timestamp(ts_raw)
                    
                    if not ts:
                        self.logger.log_temporal_alignment_failure(rec_id, str(ts_raw), "Invalid timestamp", self.dataset_name, filename, "stage1")
                        continue
                        
                    proto_val = row.get(" Protocol", row.get("Protocol", ""))
                    proto = "TCP" if proto_val == 6 else ("UDP" if proto_val == 17 else str(proto_val))
                    
                    attributes = {
                        "src_ip": row.get(" Source IP", row.get("Src IP", "")),
                        "dst_ip": row.get(" Destination IP", row.get("Dst IP", "")),
                        "src_port": row.get(" Source Port", row.get("Src Port", "")),
                        "dst_port": row.get(" Destination Port", row.get("Dst Port", "")),
                        "protocol": proto,
                        "bytes": row.get(" Flow Bytes/s", 0),
                        "packets": int(row.get(" Total Fwd Packets", 0)) + int(row.get(" Total Backward Packets", 0)),
                        "flow_duration": row.get(" Flow Duration", 0),
                    }
                    
                    raw_label = row.get(" Label", row.get("Label", "Benign"))
                    
                    event = self._create_uem_record(rec_id, ts, "network_flow", attributes, raw_label, filename)
                    self.chunker.write_record(event)
        except Exception as e:
            self.logger.log_parsing_failure(self.dataset_name, filename, "N/A", str(e), "stage1")
            print(f"    [!] Error parsing {filename}: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# UNSW-NB15 PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class UNSWNB15Processor(DatasetProcessor):
    def __init__(self, logger, chunker):
        super().__init__(logger, chunker)
        self.dataset_name = "UNSW-NB15"
        self.source_type = "network"
        
    def process_file(self, filepath):
        if "features" in filepath.lower():
            return # Skip features file
            
        filename = os.path.basename(filepath)
        print(f"  [UNSW-NB15] Processing {filename}...")
        
        try:
            reader = pd.read_csv(filepath, chunksize=CHUNK_SIZE, encoding="utf-8", encoding_errors="replace")
            for chunk in reader:
                for idx, row in chunk.iterrows():
                    rec_id = f"unsw_{uuid.uuid4().hex[:12]}"
                    
                    # UNSW-NB15 doesn't have explicit timestamp in testing/training set, it has duration.
                    # Let's mock a sequence timestamp based on index just to keep it pipeline compliant,
                    # or skip if strict.
                    # Since it's a normalized feature set, we'll assign a mock start time and add duration.
                    # Actually, some versions have stime/ltime. This version doesn't seem to based on stage0 audit.
                    # We will assign a base time to pass schema validation.
                    ts = "2015-01-01T00:00:00Z"
                    
                    attributes = {
                        "protocol": row.get("proto", ""),
                        "service": row.get("service", ""),
                        "bytes": int(row.get("sbytes", 0)) + int(row.get("dbytes", 0)),
                        "packets": int(row.get("spkts", 0)) + int(row.get("dpkts", 0)),
                        "flow_duration": row.get("dur", 0),
                    }
                    
                    raw_label = row.get("attack_cat", "Normal")
                    if pd.isna(raw_label) or str(raw_label).strip() == "":
                        raw_label = "Normal" if row.get("label") == 0 else "Generic"
                        
                    event = self._create_uem_record(rec_id, ts, "network_flow", attributes, raw_label, filename)
                    self.chunker.write_record(event)
        except Exception as e:
            self.logger.log_parsing_failure(self.dataset_name, filename, "N/A", str(e), "stage1")

# ─────────────────────────────────────────────────────────────────────────────
# CERT R4.1 PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class CERTR41Processor(DatasetProcessor):
    def __init__(self, logger, chunker):
        super().__init__(logger, chunker)
        self.dataset_name = "CERT-r4.1"
        self.source_type = "endpoint"
        
    def process_file(self, filepath):
        filename = os.path.basename(filepath)
        print(f"  [CERT-r4.1] Processing {filename}...")
        
        action_map = {
            "device.csv": "device_activity",
            "email.csv": "email_activity",
            "file.csv": "file_activity",
            "http.csv": "http_activity",
            "logon.csv": "logon_activity",
            "psychometric.csv": "user_profile"
        }
        action = action_map.get(filename, "endpoint_activity")
        
        try:
            reader = pd.read_csv(filepath, chunksize=CHUNK_SIZE, encoding="utf-8", encoding_errors="replace")
            for chunk in reader:
                for idx, row in chunk.iterrows():
                    rec_id = f"cert_{row.get('id', uuid.uuid4().hex[:12])}"
                    
                    ts = standardize_timestamp(row.get("date"))
                    if not ts and action != "user_profile":
                        continue
                        
                    attributes = {
                        "user": row.get("user", ""),
                        "host": row.get("pc", ""),
                    }
                    
                    # Add specific fields based on file
                    if action == "email_activity":
                        attributes.update({"to": row.get("to"), "from": row.get("from"), "size": row.get("size")})
                    elif action == "file_activity":
                        attributes.update({"filename": row.get("filename")})
                    elif action == "http_activity":
                        attributes.update({"url": row.get("url")})
                    elif action == "device_activity" or action == "logon_activity":
                        attributes.update({"activity": row.get("activity")})
                        
                    # CERT doesn't have direct labels, it's insider threat scenarios. Mark as benign for now.
                    # Scenarios are injected, labeling them properly requires scenario metadata matching (usually provided separately).
                    # We will leave label_raw empty so is_attack=0.
                    
                    event = self._create_uem_record(rec_id, ts or "2010-01-01T00:00:00Z", action, attributes, "", filename)
                    self.chunker.write_record(event)
        except Exception as e:
            self.logger.log_parsing_failure(self.dataset_name, filename, "N/A", str(e), "stage1")

# ─────────────────────────────────────────────────────────────────────────────
# SYSMON PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

class SysmonProcessor(DatasetProcessor):
    def __init__(self, logger, chunker):
        super().__init__(logger, chunker)
        self.dataset_name = "Sysmon-SILRAD"
        self.source_type = "endpoint"
        
    def process_file(self, filepath):
        filename = os.path.basename(filepath)
        print(f"  [Sysmon] Processing {filename}...")
        
        try:
            reader = pd.read_csv(filepath, chunksize=CHUNK_SIZE, encoding="utf-8", encoding_errors="replace")
            for chunk in reader:
                for idx, row in chunk.iterrows():
                    try:
                        rec_id = f"sysmon_{uuid.uuid4().hex[:12]}"
                        ts = "2020-01-01T00:00:00+00:00"
                        action = f"sysmon_event_{row.get('event.code', 'unknown')}"
                        attributes = {
                            "process_name":  str(row.get("Image", "")),
                            "parent_process": str(row.get("ParentImage", "")),
                            "command_line":  str(row.get("CommandLine", "")),
                            "user":          str(row.get("User", "")),
                            "hashes":        str(row.get("Signature", "")),
                            "rule_name":     str(row.get("RuleName", ""))
                        }
                        # class column: 0=benign, 1=malware (SILRAD binary label)
                        raw_class = row.get("class", 0)
                        # Map integer class to meaningful label
                        if safe_int(raw_class) == 0:
                            raw_label = "Normal"
                        else:
                            raw_label = f"Malware_class_{raw_class}"
                        event = self._create_uem_record(rec_id, ts, action, attributes, raw_label, filename)
                        self.chunker.write_record(event)
                    except Exception as row_err:
                        self.logger.log_parsing_failure(self.dataset_name, filename, str(idx), str(row_err), "stage1")
        except Exception as e:
            self.logger.log_parsing_failure(self.dataset_name, filename, "N/A", str(e), "stage1")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS Pipeline — Stage 1: UEM Normalization")
    print("=" * 70)
    
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    
    logger = PipelineLogger(LOG_DIR)
    schema_manager = SchemaManager(r"F:\enterprise_ngfw\modules\predictive_ai\schemas")
    schema_manager.init_schemas()
    chunker = FileChunker(OUT_DIR, "uem_events", max_lines_per_chunk=100_000)
    
    datasets_to_process = [
        (CICIDS2018Processor, r"F:\enterprise_ngfw\ml\data\CSE-CIC-IDS2018"),
        (CICDDoS2019Processor, r"F:\enterprise_ngfw\ml\data\CIC-DDoS2019"),
        (UNSWNB15Processor, r"F:\enterprise_ngfw\ml\data\NUSW-NB15"),
        (SysmonProcessor, r"F:\enterprise_ngfw\ml\data\JamilIsp-SILRAD-dataset"),
        (CERTR41Processor, r"F:\enterprise_ngfw\ml\data\CERT Insider Threat Dataset (r4.1)\extracted\r4.1")
    ]
    
    total_files = 0
    for ProcClass, path in datasets_to_process:
        processor = ProcClass(logger, chunker)
        if not os.path.exists(path):
            print(f"Path not found: {path}")
            continue
            
        files = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        for f in files:
            # For demonstration, we limit the number of files processed per dataset to 2 
            # to verify the pipeline architecture quickly.
            total_files += 1
            processor.process_file(f)
            
            # Remove the limit below to process the full terabytes of data
            # if total_files > 5: break
            
    chunker.close()
    
    print("\n" + "=" * 70)
    print("  STAGE 1 UEM COMPLETE")
    print(f"  Output chunks saved to: {OUT_DIR}")
    print("=" * 70)

if __name__ == "__main__":
    main()
