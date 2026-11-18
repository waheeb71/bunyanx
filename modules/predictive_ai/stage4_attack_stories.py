"""
AEGIS Pipeline — Stage 4: Attack Story Generation + MITRE TTP Mapping
=======================================================================
Input  : outputs/stage3_sessions/sessions_part_*.jsonl
Output : outputs/stage4_attack_stories/
  - attack_stories_part_*.jsonl
  - attack_story_report.json

Design:
  - Maps sessions to MITRE ATT&CK TTPs via keyword heuristics.
  - Only sessions with at least 1 attack event get TTP chains.
  - Confidence score reflects evidence density.
  - Benign sessions are emitted as baseline stories (is_attack=0).
"""

import os, sys, json, uuid, glob
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(__file__))
from utils.file_chunker import FileChunker

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────
SESS_IN_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage3_sessions"
OUT_DIR     = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage4_attack_stories"

# ─────────────────────────────────────────────────────────────────────────────
# MITRE TTP HEURISTIC MAP
# attack_type (lowercase) -> (tactic, technique_id, technique_name)
# ─────────────────────────────────────────────────────────────────────────────
TTP_MAP: dict[str, tuple[str, str, str]] = {
    "ddos":           ("Impact",              "T1498", "Network Denial of Service"),
    "dos":            ("Impact",              "T1499", "Endpoint Denial of Service"),
    "reconnaissance": ("Reconnaissance",      "T1595", "Active Scanning"),
    "brute force":    ("Credential Access",   "T1110", "Brute Force"),
    "botnet":         ("Command and Control", "T1071", "Application Layer Protocol"),
    "web attack":     ("Initial Access",      "T1190", "Exploit Public-Facing Application"),
    "infiltration":   ("Lateral Movement",    "T1210", "Exploitation of Remote Services"),
    "fuzzing":        ("Execution",           "T1203", "Exploitation for Client Execution"),
    "exploitation":   ("Execution",           "T1203", "Exploitation for Client Execution"),
    "backdoor":       ("Persistence",         "T1543", "Create or Modify System Process"),
    "worm":           ("Lateral Movement",    "T1570", "Lateral Tool Transfer"),
    "generic":        ("Defense Evasion",     "T1036", "Masquerading"),
    "shellcode":      ("Execution",           "T1059", "Command and Scripting Interpreter"),
}

def lookup_ttp(attack_type: str) -> dict | None:
    key = attack_type.lower().strip()
    for pattern, (tactic, tid, tname) in TTP_MAP.items():
        if pattern in key:
            return {
                "tactic":         tactic,
                "technique_id":   tid,
                "technique_name": tname,
                "source":         "heuristic",
            }
    return None

# ─────────────────────────────────────────────────────────────────────────────
# STORY BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_story(session: dict) -> dict:
    is_attack    = session.get("is_attack", 0)
    attack_types = session.get("attack_types", [])
    events       = session.get("events", [])

    ttp_chain: list[dict] = []
    tactic_chain: list[str] = []
    seen_ttps: set[str] = set()

    for at in attack_types:
        ttp = lookup_ttp(at)
        if ttp and ttp["technique_id"] not in seen_ttps:
            ttp_chain.append(ttp)
            tactic_chain.append(ttp["tactic"])
            seen_ttps.add(ttp["technique_id"])

    # Confidence = ratio of attack events
    evt_cnt = max(1, len(events))
    atk_cnt = session.get("attack_event_cnt", 0)
    confidence = round(atk_cnt / evt_cnt, 4) if is_attack else 0.0

    return {
        "story_id":               f"story_{uuid.uuid4().hex[:14]}",
        "session_id":             session.get("session_id"),
        "entity_id":              session.get("entity_id"),
        "start_time":             session.get("start_time"),
        "end_time":               session.get("end_time"),
        "event_count":            evt_cnt,
        "is_attack":              is_attack,
        "attack_types":           attack_types,
        "ttp_chain":              ttp_chain,
        "tactic_chain":           tactic_chain,
        "story_confidence":       confidence,
        "dataset_sources":        session.get("dataset_sources", []),
        "source_types":           session.get("source_types", []),
        "timeline":               events,       # full event sequence
    }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS Pipeline — Stage 4: Attack Story Generation")
    print("=" * 70)

    os.makedirs(OUT_DIR, exist_ok=True)
    chunker = FileChunker(OUT_DIR, "attack_stories", max_lines_per_chunk=20_000)

    in_files = sorted(glob.glob(os.path.join(SESS_IN_DIR, "sessions_part_*.jsonl")))
    if not in_files:
        print("[!] No session files found. Run Stage 3 first.")
        return

    print(f"  Found {len(in_files)} session chunk files.")

    total_stories = 0
    attack_stories = 0
    unique_ttps: set[str] = set()

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
                        session = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    story = build_story(session)
                    chunker.write_record(story)
                    total_stories += 1

                    if story["is_attack"]:
                        attack_stories += 1
                        for ttp in story["ttp_chain"]:
                            unique_ttps.add(ttp["technique_id"])

        except Exception as e:
            print(f"  [!] Error in {os.path.basename(fpath)}: {e}")

    chunker.close()

    report = {
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "total_stories":    total_stories,
        "attack_stories":   attack_stories,
        "benign_stories":   total_stories - attack_stories,
        "attack_rate_pct":  round(attack_stories / max(1, total_stories) * 100, 2),
        "unique_ttps":      sorted(unique_ttps),
        "unique_ttp_count": len(unique_ttps),
    }
    with open(os.path.join(OUT_DIR, "attack_story_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print()
    print("=" * 70)
    print("  STAGE 4 COMPLETE")
    print(f"  Total Stories  : {total_stories:,}")
    print(f"  Attack Stories : {attack_stories:,}  ({report['attack_rate_pct']}%)")
    print(f"  Unique TTPs    : {len(unique_ttps)}")
    print(f"  TTP IDs        : {', '.join(sorted(unique_ttps))}")
    print("=" * 70)

if __name__ == "__main__":
    main()
