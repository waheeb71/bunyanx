"""Inspect stage5 dataset structure to find usable fields."""
import json, pathlib, sys

sys.stdout.reconfigure(encoding='utf-8')

ds_dir = pathlib.Path(r'F:/enterprise_ngfw/modules/predictive_ai/outputs/stage5_transformer_dataset')
files  = sorted(ds_dir.glob('*.jsonl'))
print(f"Total JSONL files: {len(files)}")

# --- Scan first file completely ---
attack_count = 0
total = 0
with open(files[0], encoding='utf-8') as fh:
    for i, line in enumerate(fh):
        rec = json.loads(line)
        labels = rec.get('labels', {})
        is_atk  = labels.get('is_attack', 0)
        ttp_seq  = labels.get('ttp_sequence', [])
        atk_types = labels.get('attack_types', [])
        inp_seq  = rec.get('input_sequence', [])
        total += 1
        if is_atk:
            attack_count += 1
        if i < 8:
            print(f"\nRecord {i}: is_attack={is_atk}, ttp_seq={ttp_seq}, attack_types={atk_types}")
            print(f"  input_sequence[:4]={inp_seq[:4]}")
            print(f"  intent={labels.get('intent','?')}")

print(f"\nFile 0: {total} records, {attack_count} attacks")

# --- Find records with ttp_sequence >= 2 in first 50 files ---
found_with_ttp = 0
found_with_attack = 0
for f in files[:50]:
    with open(f, encoding='utf-8') as fh:
        for line in fh:
            rec = json.loads(line)
            labels = rec.get('labels', {})
            if len(labels.get('ttp_sequence', [])) >= 2:
                found_with_ttp += 1
            if labels.get('is_attack', 0):
                found_with_attack += 1

print(f"\nFirst 50 files: records_with_ttp_seq>=2={found_with_ttp}, is_attack=True={found_with_attack}")

# --- Look at attack records specifically ---
print("\n--- Attack records sample ---")
count = 0
for f in files:
    with open(f, encoding='utf-8') as fh:
        for line in fh:
            rec = json.loads(line)
            labels = rec.get('labels', {})
            if labels.get('is_attack', 0) and count < 5:
                print(f"  ttp_seq={labels.get('ttp_sequence')}")
                print(f"  attack_types={labels.get('attack_types')}")
                print(f"  intent={labels.get('intent')}")
                inp = rec.get('input_sequence', [])
                print(f"  input_seq (len={len(inp)}): {inp[:6]}")
                print()
                count += 1
    if count >= 5:
        break

print(f"Done.")
