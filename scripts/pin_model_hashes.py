#!/usr/bin/env python3
"""
pin_model_hashes.py — Utility to compute SHA-256 hashes for ML models and create .sha256 sidecar files.
"""

import os
import sys
import hashlib
from pathlib import Path

# Target file extensions for ML models
MODEL_EXTENSIONS = {".pkl", ".pt", ".pth", ".joblib", ".onnx", ".bin"}

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def pin_hashes_for_directory(root_dir: Path):
    if not root_dir.exists():
        print(f"Directory not found: {root_dir}")
        return 0

    count = 0
    for path in root_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in MODEL_EXTENSIONS:
            # Skip existing .sha256 files or checkpoints
            if path.name.endswith(".sha256"):
                continue

            sha256_hash = compute_sha256(path)
            sidecar_path = Path(str(path) + ".sha256")

            # Write standard sha256sum format: "<hash>  <filename>\n"
            content = f"{sha256_hash}  {path.name}\n"
            sidecar_path.write_text(content, encoding="utf-8")
            print(f"  [+] Pinned {path.relative_to(PROJECT_ROOT)} -> {sha256_hash[:16]}...")
            count += 1

    return count

if __name__ == "__main__":
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    print("=" * 80)
    print(" 🔒 Generating SHA-256 Model Integrity Sidecars")
    print("=" * 80)

    total_pinned = 0
    search_dirs = [
        PROJECT_ROOT / "ml" / "models",
        PROJECT_ROOT / "modules",
        PROJECT_ROOT / "var_lib_ngfw_data",
    ]

    for d in search_dirs:
        if d.exists():
            print(f"\nScanning: {d.relative_to(PROJECT_ROOT)}...")
            total_pinned += pin_hashes_for_directory(d)

    print("\n" + "=" * 80)
    print(f" ✅ Total sidecar files generated/updated: {total_pinned}")
    print("=" * 80)
