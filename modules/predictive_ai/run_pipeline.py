"""
AEGIS Master Pipeline Runner
==============================
Runs all stages in sequence with gate checks between each stage.
Usage:
    python run_pipeline.py              # run all stages
    python run_pipeline.py --from 2     # start from stage 2
    python run_pipeline.py --only 3     # run only stage 3
"""

import os, sys, json, time, argparse
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.path.dirname(__file__)
sys.path.append(ROOT)

OUT_BASE = os.path.join(ROOT, "outputs")

# ── Gate definitions ─────────────────────────────────────────────────────────
GATES = {
    1: {
        "output_dir":  os.path.join(OUT_BASE, "stage1_uem"),
        "glob":        "uem_events_part_*.jsonl",
        "min_files":   1,
        "description": "Stage 1 UEM chunks",
    },
    2: {
        "output_dir":  os.path.join(OUT_BASE, "stage2_entities"),
        "glob":        "resolved_events_part_*.jsonl",
        "min_files":   1,
        "description": "Stage 2 resolved event chunks",
    },
    3: {
        "output_dir":  os.path.join(OUT_BASE, "stage3_sessions"),
        "glob":        "sessions_part_*.jsonl",
        "min_files":   1,
        "description": "Stage 3 session chunks",
    },
    4: {
        "output_dir":  os.path.join(OUT_BASE, "stage4_attack_stories"),
        "glob":        "attack_stories_part_*.jsonl",
        "min_files":   1,
        "description": "Stage 4 story chunks",
    },
    5: {
        "output_dir":  os.path.join(OUT_BASE, "stage5_transformer_dataset"),
        "glob":        "transformer_dataset_part_*.jsonl",
        "min_files":   1,
        "description": "Stage 5 transformer samples",
    },
}

def check_gate(stage_num: int) -> bool:
    import glob as _glob
    gate = GATES[stage_num]
    files = _glob.glob(os.path.join(gate["output_dir"], gate["glob"]))
    passed = len(files) >= gate["min_files"]
    status = "[PASSED]" if passed else "[FAILED]"
    print(f"  Gate {stage_num}: {status}  ({len(files)} files)  — {gate['description']}")
    return passed

def run_stage(stage_num: int):
    modules = {
        1: "stage1_uem",
        2: "stage2_entities",
        3: "stage3_sessions",
        4: "stage4_attack_stories",
        5: "stage5_transformer",
    }
    mod_name = modules[stage_num]
    print()
    print("=" * 70)
    print(f"  RUNNING STAGE {stage_num}: {mod_name}")
    print("=" * 70)

    import importlib
    mod = importlib.import_module(mod_name)
    t0 = time.time()
    mod.main()
    elapsed = time.time() - t0
    print(f"\n  Stage {stage_num} finished in {elapsed/60:.1f} min")

def main():
    parser = argparse.ArgumentParser(description="AEGIS Master Pipeline")
    parser.add_argument("--from",  dest="from_stage", type=int, default=1)
    parser.add_argument("--only",  dest="only_stage", type=int, default=None)
    args = parser.parse_args()

    print("=" * 70)
    print("  AEGIS XDR — Master Pipeline")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    stages_to_run = [args.only_stage] if args.only_stage else list(range(args.from_stage, 6))

    for stage in stages_to_run:
        # Check prerequisite gate (previous stage)
        if stage > 1 and stage not in (args.only_stage,):
            if not check_gate(stage - 1):
                print(f"  [ABORT] Stage {stage-1} gate failed. Cannot proceed.")
                sys.exit(1)

        run_stage(stage)
        check_gate(stage)

    print()
    print("=" * 70)
    print("  PIPELINE COMPLETE")
    print(f"  Finished: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

if __name__ == "__main__":
    main()
