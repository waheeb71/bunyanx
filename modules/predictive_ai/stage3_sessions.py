"""
AEGIS Pipeline — Stage 3: Session Segmentation
================================================
Input  : outputs/stage2_entities/resolved_events_part_*.jsonl
Output : outputs/stage3_sessions/
  - sessions_part_*.jsonl
  - session_stats.json

Design:
  - Group events by entity_id into behavioral sessions.
  - Use a configurable idle timeout (default 300s = 5 min) to split sessions.
  - Sort each chunk by timestamp before windowing.
  - Emit sessions with aggregated attack flag and label distribution.
  - Streaming: process one chunk at a time, flush completed sessions.
"""

import os, sys, json, uuid, glob
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(__file__))
from utils.file_chunker import FileChunker

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
ENT_IN_DIR      = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage2_entities"
OUT_DIR         = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage3_sessions"
IDLE_TIMEOUT_S  = 300          # 5-minute gap → new session
MIN_EVENTS      = 1            # include sessions with at least 1 event
MAX_SESSION_EVT = 10_000       # safety cap: forcibly flush at this many events

# ─────────────────────────────────────────────────────────────────────────────
# TIMESTAMP PARSER
# ─────────────────────────────────────────────────────────────────────────────

def to_epoch(ts_str: str | None) -> float:
    """Convert ISO-8601 / known mock timestamps to Unix epoch float."""
    if not ts_str:
        return 0.0
    # Fast path for known mock timestamps
    mocks = {
        "2015-01-01T00:00:00Z": 1420070400.0,
        "2020-01-01T00:00:00+00:00": 1577836800.0,
        "2010-01-01T00:00:00Z": 1262304000.0,
    }
    if ts_str in mocks:
        return mocks[ts_str]
    try:
        import pandas as pd
        return pd.to_datetime(ts_str, utc=True).timestamp()
    except Exception:
        return 0.0

# ─────────────────────────────────────────────────────────────────────────────
# SESSION BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_session(entity_id: str, events: list) -> dict:
    """Produce a session record from a list of temporally-contiguous events."""
    attack_events = [e for e in events if e.get("is_attack") == 1]
    is_attack     = 1 if attack_events else 0

    attack_types  = list({e["attack_type"] for e in attack_events if e.get("attack_type")})
    datasets      = list({e.get("dataset_source", "") for e in events})
    source_types  = list({e.get("source_type", "") for e in events})

    return {
        "session_id":       f"sess_{uuid.uuid4().hex[:14]}",
        "entity_id":        entity_id,
        "start_time":       events[0].get("timestamp"),
        "end_time":         events[-1].get("timestamp"),
        "event_count":      len(events),
        "is_attack":        is_attack,
        "attack_types":     attack_types,
        "attack_event_cnt": len(attack_events),
        "dataset_sources":  datasets,
        "source_types":     source_types,
        "events":           events,
    }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS Pipeline — Stage 3: Session Segmentation")
    print("=" * 70)

    os.makedirs(OUT_DIR, exist_ok=True)
    chunker = FileChunker(OUT_DIR, "sessions", max_lines_per_chunk=50_000)

    in_files = sorted(glob.glob(os.path.join(ENT_IN_DIR, "resolved_events_part_*.jsonl")))
    if not in_files:
        print("[!] No resolved event files found. Run Stage 2 first.")
        return

    print(f"  Found {len(in_files)} resolved event files.")

    # active_sessions[entity_id] = {last_ts_epoch, events: []}
    active: dict[str, dict] = {}
    total_sessions  = 0
    total_events    = 0
    attack_sessions = 0

    for i, fpath in enumerate(in_files, 1):
        if i % 100 == 0 or i == 1:
            print(f"  [{i}/{len(in_files)}] {os.path.basename(fpath)} | active sessions: {len(active):,}")

        try:
            # Load + sort chunk by timestamp epoch
            chunk_events = []
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            chunk_events.sort(key=lambda e: to_epoch(e.get("timestamp")))

            for event in chunk_events:
                total_events += 1
                eid = event.get("entity_id", "UNRESOLVED")
                ts  = to_epoch(event.get("timestamp"))

                if eid not in active:
                    active[eid] = {"last_ts": ts, "events": [event]}
                else:
                    sess = active[eid]
                    gap  = ts - sess["last_ts"]

                    if gap > IDLE_TIMEOUT_S or gap < 0 or len(sess["events"]) >= MAX_SESSION_EVT:
                        # Close current session
                        built = build_session(eid, sess["events"])
                        chunker.write_record(built)
                        total_sessions += 1
                        if built["is_attack"]:
                            attack_sessions += 1
                        # Start new session
                        active[eid] = {"last_ts": ts, "events": [event]}
                    else:
                        sess["events"].append(event)
                        sess["last_ts"] = ts

        except Exception as e:
            print(f"  [!] Error in {os.path.basename(fpath)}: {e}")

    # Flush remaining open sessions
    print(f"  Flushing {len(active):,} remaining open sessions...")
    for eid, sess in active.items():
        if len(sess["events"]) >= MIN_EVENTS:
            built = build_session(eid, sess["events"])
            chunker.write_record(built)
            total_sessions += 1
            if built["is_attack"]:
                attack_sessions += 1

    chunker.close()

    stats = {
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "total_events":        total_events,
        "total_sessions":      total_sessions,
        "attack_sessions":     attack_sessions,
        "benign_sessions":     total_sessions - attack_sessions,
        "attack_rate_pct":     round(attack_sessions / max(1, total_sessions) * 100, 2),
        "avg_events_per_session": round(total_events / max(1, total_sessions), 1),
        "idle_timeout_s":      IDLE_TIMEOUT_S,
    }
    with open(os.path.join(OUT_DIR, "session_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=4)

    print()
    print("=" * 70)
    print("  STAGE 3 COMPLETE")
    print(f"  Total Sessions : {total_sessions:,}")
    print(f"  Attack Sessions: {attack_sessions:,}  ({stats['attack_rate_pct']}%)")
    print(f"  Avg Events/Sess: {stats['avg_events_per_session']}")
    print("=" * 70)

if __name__ == "__main__":
    main()
