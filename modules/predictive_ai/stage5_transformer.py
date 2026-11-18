"""
AEGIS Pipeline — Stage 5: Transformer-Ready Dataset Generation
===============================================================
Input  : outputs/stage4_attack_stories/attack_stories_part_*.jsonl
Output : outputs/stage5_transformer_dataset/
  - transformer_dataset_part_*.jsonl  (one sample per story)
  - dataset_quality_report.json

Sample schema
─────────────
{
  "sample_id":       str,
  "input_sequence":  [str, ...],   # tokenized event tokens
  "attention_mask":  [1, ...],
  "modality_mask":   [0|1, ...],   # 0=network, 1=endpoint
  "sequence_length": int,
  "labels": {
    "is_attack":     int,
    "attack_types":  [str],
    "ttp_sequence":  [str],
    "intent":        str,
  },
  "metadata": {
    "story_id":      str,
    "entity_id":     str,
    "start_time":    str,
    "end_time":      str,
    "source":        "AEGIS_XDR",
  }
}
"""

import os, sys, json, uuid, glob
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(__file__))
from utils.file_chunker import FileChunker

# ─────────────────────────────────────────────────────────────────────────────
STORY_IN_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage4_attack_stories"
OUT_DIR      = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage5_transformer_dataset"

MAX_SEQ_LEN  = 512          # truncate long sessions to 

_ACTION_ALIASES = {
    "network_flow":      "NET_FLOW",
    "logon_activity":    "EP_LOGON",
    "device_activity":   "EP_DEVICE",
    "email_activity":    "EP_EMAIL",
    "file_activity":     "EP_FILE",
    "http_activity":     "EP_HTTP",
    "user_profile":      "EP_PROFILE",
}

def tokenize_event(event: dict) -> str:
    """
    Produce a readable event token string.
    Format: [SRC_TYPE] ACTION [ATTACK_TYPE?]
    """
    src  = event.get("source_type", "unk").upper()[:3]
    act  = event.get("action", "unknown")
    act  = _ACTION_ALIASES.get(act, act.upper()[:20])
    atk  = event.get("attack_type", "")
    tok  = f"[{src}] {act}"
    if atk:
        tok += f" [{atk.upper().replace(' ', '_')}]"
    return tok

# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_sample(story: dict) -> dict:
    events    = story.get("timeline", [])[:MAX_SEQ_LEN]
    seq_len   = len(events)

    tokens    = [tokenize_event(e) for e in events]
    att_mask  = [1] * seq_len
    mod_mask  = [0 if e.get("source_type") == "network" else 1 for e in events]

    ttp_ids   = [t["technique_id"] for t in story.get("ttp_chain", [])]
    intent    = story["ttp_chain"][0]["tactic"] if story.get("ttp_chain") else "Unknown"

    return {
        "sample_id":      f"smpl_{story.get('story_id', uuid.uuid4().hex[:14])}",
        "input_sequence": tokens,
        "attention_mask": att_mask,
        "modality_mask":  mod_mask,
        "sequence_length": seq_len,
        "labels": {
            "is_attack":    story.get("is_attack", 0),
            "attack_types": story.get("attack_types", []),
            "ttp_sequence": ttp_ids,
            "intent":       intent,
        },
        "metadata": {
            "story_id":   story.get("story_id"),
            "entity_id":  story.get("entity_id"),
            "start_time": story.get("start_time"),
            "end_time":   story.get("end_time"),
            "source":     "AEGIS_XDR",
        },
    }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS Pipeline — Stage 5: Transformer Dataset")
    print("=" * 70)

    os.makedirs(OUT_DIR, exist_ok=True)
    chunker = FileChunker(OUT_DIR, "transformer_dataset", max_lines_per_chunk=20_000)

    in_files = sorted(glob.glob(os.path.join(STORY_IN_DIR, "attack_stories_part_*.jsonl")))
    if not in_files:
        print("[!] No story files found. Run Stage 4 first.")
        return

    print(f"  Found {len(in_files)} story chunk files.")

    total_samples  = 0
    attack_samples = 0
    zero_len       = 0

    for i, fpath in enumerate(in_files, 1):
        if i % 20 == 0 or i == 1:
            print(f"  [{i}/{len(in_files)}] {os.path.basename(fpath)}")

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        story = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if not story.get("timeline"):
                        zero_len += 1
                        continue

                    sample = build_sample(story)
                    chunker.write_record(sample)
                    total_samples += 1
                    if sample["labels"]["is_attack"]:
                        attack_samples += 1

        except Exception as e:
            print(f"  [!] Error in {os.path.basename(fpath)}: {e}")

    chunker.close()

    report = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "total_samples":      total_samples,
        "attack_samples":     attack_samples,
        "benign_samples":     total_samples - attack_samples,
        "class_balance_ratio": round(attack_samples / max(1, total_samples), 4),
        "skipped_empty":      zero_len,
        "max_seq_len":        MAX_SEQ_LEN,
    }
    with open(os.path.join(OUT_DIR, "dataset_quality_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print()
    print("=" * 70)
    print("  STAGE 5 COMPLETE")
    print(f"  Total Samples  : {total_samples:,}")
    print(f"  Attack Samples : {attack_samples:,}")
    print(f"  Benign Samples : {total_samples - attack_samples:,}")
    print(f"  Attack Ratio   : {report['class_balance_ratio']*100:.2f}%")
    print("=" * 70)

if __name__ == "__main__":
    main()
