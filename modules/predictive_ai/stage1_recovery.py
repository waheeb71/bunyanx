"""
AEGIS Stage 1 — Targeted Recovery Script
==========================================
Re-processes ONLY the 3 CIC-IDS2018 files that failed due to the
int(float_string) bug. Appends recovered records to existing UEM chunks.
"""
import os, sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(__file__))

from stage1_uem import CICIDS2018Processor, PipelineLogger, FileChunker, SchemaManager

OUT_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage1_uem"
LOG_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\logs"

# The 3 files that were killed by int() conversion bug
RECOVERY_FILES = [
    r"F:\enterprise_ngfw\ml\data\CSE-CIC-IDS2018\02-16-2018.csv",
    r"F:\enterprise_ngfw\ml\data\CSE-CIC-IDS2018\02-28-2018.csv",
    r"F:\enterprise_ngfw\ml\data\CSE-CIC-IDS2018\03-01-2018.csv",
]

def main():
    print("=" * 60)
    print("  Stage 1 — Recovery Run (3 failed CIC-IDS2018 files)")
    print("=" * 60)

    logger  = PipelineLogger(LOG_DIR)
    chunker = FileChunker(OUT_DIR, "uem_events", max_lines_per_chunk=100_000)
    proc    = CICIDS2018Processor(logger, chunker)

    for fpath in RECOVERY_FILES:
        if not os.path.exists(fpath):
            print(f"  [SKIP] Not found: {fpath}")
            continue
        proc.process_file(fpath)

    chunker.close()
    print("\n  Recovery complete.")

if __name__ == "__main__":
    main()
