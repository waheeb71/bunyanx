"""
AEGIS Pipeline — Stage 2: Multi-Domain Entity Resolution
=========================================================
Role   : Build a unified Entity Graph and resolve entity_id for every UEM event.
Input  : outputs/stage1_uem/uem_events_part_*.jsonl
Output : outputs/stage2_entities/
  - resolved_events_part_*.jsonl  (UEM + entity_id filled)
  - entity_graph_part_0001.json   (nodes + edges)
  - entity_resolution_report.json (summary stats)

Design:
  - Evidence-based linkage only (no hallucination).
  - Confidence scoring per edge.
  - Unresolved entities kept intact as "UNRESOLVED".
  - Streaming: one chunk at a time, bounded RAM.
"""

import os, sys, json, uuid, glob, time
from collections import defaultdict
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(__file__))
from utils.file_chunker import FileChunker
from logs.pipeline_logger import PipelineLogger

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────
UEM_IN_DIR = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage1_uem"
OUT_DIR    = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage2_entities"
LOG_DIR    = r"F:\enterprise_ngfw\modules\predictive_ai\logs"

# ─────────────────────────────────────────────────────────────────────────────
# ENTITY GRAPH
# ─────────────────────────────────────────────────────────────────────────────

class EntityGraph:
    """
    Lightweight in-memory graph for entity resolution.
    Stores only canonical IDs — avoids holding raw event data.
    """
    def __init__(self):
        # value -> entity_id  (one dict per type)
        self._ip_map   : dict[str, str] = {}
        self._host_map : dict[str, str] = {}
        self._user_map : dict[str, str] = {}
        self._proc_map : dict[str, str] = {}

        self.nodes: dict[str, dict] = {}
        self.edges: list[dict]      = []
        self._edge_ids: set[str]    = set()  # dedup edges

    # ── helpers ──────────────────────────────────────────────────────────────
    def _make_node(self, ent_type: str, value: str) -> str:
        eid = f"ent_{ent_type}_{uuid.uuid4().hex[:12]}"
        self.nodes[eid] = {
            "entity_id":       eid,
            "entity_type":     ent_type,
            "value":           value,
            "linked_entities": [],
        }
        return eid

    def _resolve(self, mapping: dict, ent_type: str, value: str) -> str | None:
        if not value or str(value).strip() in ("", "nan", "None"):
            return None
        v = str(value).strip()
        if v not in mapping:
            mapping[v] = self._make_node(ent_type, v)
        return mapping[v]

    # ── public resolvers ─────────────────────────────────────────────────────
    def resolve_ip(self, v)    -> str | None: return self._resolve(self._ip_map,   "ip",   str(v) if v else "")
    def resolve_host(self, v)  -> str | None: return self._resolve(self._host_map, "host", str(v) if v else "")
    def resolve_user(self, v)  -> str | None: return self._resolve(self._user_map, "user", str(v) if v else "")
    def resolve_proc(self, v)  -> str | None: return self._resolve(self._proc_map, "proc", str(v) if v else "")

    # ── linking ───────────────────────────────────────────────────────────────
    def link(self, src: str, dst: str, rel: str, conf: float, evidence: list):
        if not src or not dst or src == dst:
            return
        eid = f"{src}::{dst}"
        if eid in self._edge_ids:
            return
        self._edge_ids.add(eid)
        self.edges.append({
            "edge_id":           eid,
            "source":            src,
            "target":            dst,
            "relationship_type": rel,
            "confidence_score":  conf,
            "evidence":          evidence,
        })
        self.nodes[src]["linked_entities"].append(dst)
        self.nodes[dst]["linked_entities"].append(src)

    # ── export ────────────────────────────────────────────────────────────────
    def export(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"nodes": list(self.nodes.values()), "edges": self.edges},
                      f, indent=2, ensure_ascii=False)

    # ── stats ─────────────────────────────────────────────────────────────────
    @property
    def stats(self) -> dict:
        return {
            "total_nodes":   len(self.nodes),
            "total_edges":   len(self.edges),
            "ip_nodes":      len(self._ip_map),
            "host_nodes":    len(self._host_map),
            "user_nodes":    len(self._user_map),
            "process_nodes": len(self._proc_map),
        }

# ─────────────────────────────────────────────────────────────────────────────
# RESOLUTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def resolve_event(event: dict, graph: EntityGraph) -> str:
    """
    Resolves the primary entity for a UEM event.
    Returns entity_id string (or "UNRESOLVED").
    """
    attrs      = event.get("attributes", {})
    src_type   = event.get("source_type", "")
    primary    = None

    if src_type == "network":
        src_ip = attrs.get("src_ip")
        dst_ip = attrs.get("dst_ip")
        e_src  = graph.resolve_ip(src_ip)
        e_dst  = graph.resolve_ip(dst_ip)
        if e_src and e_dst:
            graph.link(e_src, e_dst, "communicates_with", 1.0, ["network_flow"])
        primary = e_src or e_dst

    elif src_type == "endpoint":
        host = attrs.get("host")
        user = attrs.get("user")
        proc = attrs.get("process_name")
        e_host = graph.resolve_host(host)
        e_user = graph.resolve_user(user)
        e_proc = graph.resolve_proc(proc)
        if e_user and e_host:
            graph.link(e_user, e_host, "logs_into", 0.9, ["endpoint_event"])
        if e_user and e_proc:
            graph.link(e_user, e_proc, "executes",  1.0, ["endpoint_event"])
        primary = e_host or e_user or e_proc

    return primary if primary else "UNRESOLVED"

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS Pipeline — Stage 2: Entity Resolution")
    print("=" * 70)

    os.makedirs(OUT_DIR, exist_ok=True)
    logger  = PipelineLogger(LOG_DIR)
    graph   = EntityGraph()
    chunker = FileChunker(OUT_DIR, "resolved_events", max_lines_per_chunk=100_000)

    uem_files = sorted(glob.glob(os.path.join(UEM_IN_DIR, "uem_events_part_*.jsonl")))
    if not uem_files:
        print("[!] No UEM files found. Run Stage 1 first.")
        return

    print(f"  Found {len(uem_files)} UEM chunk files.")

    total_events   = 0
    resolved_count = 0
    unresolved_count = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for i, fpath in enumerate(uem_files, 1):
        basename = os.path.basename(fpath)
        if i % 50 == 0 or i == 1:
            print(f"  [{i}/{len(uem_files)}] Processing {basename} ...")

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    total_events += 1
                    eid = resolve_event(event, graph)

                    event["entity_id"] = eid
                    event["processing_metadata"]["pipeline_stage"]          = "stage2_entities"
                    event["processing_metadata"]["processing_timestamp"]    = now_iso

                    if eid == "UNRESOLVED":
                        unresolved_count += 1
                        logger.log_unresolved_entity(
                            event.get("event_id", "?"), "unknown", [],
                            event.get("dataset_source", "?"), fpath, "stage2"
                        )
                    else:
                        resolved_count += 1

                    chunker.write_record(event)

        except Exception as e:
            print(f"  [!] Error reading {basename}: {e}")

    chunker.close()

    # ── export entity graph ───────────────────────────────────────────────────
    graph_path = os.path.join(OUT_DIR, "entity_graph.json")
    graph.export(graph_path)
    print(f"  Entity graph saved: {graph_path}")

    # ── summary report ────────────────────────────────────────────────────────
    report = {
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "total_events_processed":  total_events,
        "events_resolved":         resolved_count,
        "events_unresolved":       unresolved_count,
        "resolution_rate_pct":     round(resolved_count / max(1, total_events) * 100, 2),
        "graph_stats":             graph.stats,
    }
    with open(os.path.join(OUT_DIR, "entity_resolution_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print()
    print("=" * 70)
    print("  STAGE 2 COMPLETE")
    print(f"  Events processed : {total_events:,}")
    print(f"  Resolved         : {resolved_count:,}  ({report['resolution_rate_pct']}%)")
    print(f"  Unresolved       : {unresolved_count:,}")
    print(f"  Graph nodes      : {graph.stats['total_nodes']:,}")
    print(f"  Graph edges      : {graph.stats['total_edges']:,}")
    print("=" * 70)

if __name__ == "__main__":
    main()
