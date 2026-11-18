import os
import sys
import csv
import urllib.parse
import numpy as np
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from modules.web_filter.policy.holo_filter.encoder import HDCEncoder
from modules.web_filter.policy.holo_filter.vector_store import VectorStore

def hebbian_update(prototype: np.ndarray, sample_hv: np.ndarray, alpha: float = 0.1) -> np.ndarray:
    """
    Simulates a Hebbian-style iterative refinement to move the prototype closer
    to the sample in the bipolar (-1, 1) space.
    """
    disagree = np.bitwise_xor(prototype, sample_hv)
    uint64_dim = prototype.shape[0]
    rands = np.random.randint(0, 100, size=uint64_dim*64, dtype=np.uint8)
    flip_decision = (rands < int(alpha * 100)).astype(np.uint8)
    flip_mask_uint64 = np.packbits(flip_decision).view(np.uint64)[:uint64_dim]
    actual_flips = np.bitwise_and(disagree, flip_mask_uint64)
    return np.bitwise_xor(prototype, actual_flips)

def extract_domain(url_string):
    if url_string.startswith("http://") or url_string.startswith("https://"):
        parsed = urllib.parse.urlparse(url_string)
        return parsed.netloc.split(':')[0]
    return url_string.split('/')[0]

def build_academic_model(data_dir: str):
    print("=== HoloFilter v2 Central HDC Trainer ===")
    
    benign_list = []
    phish_list = []
    dga_families = defaultdict(list)
    
    # 1. Parse Tranco Top 1M (Benign)
    tranco_path = os.path.join(data_dir, "top-1m.csv")
    if os.path.exists(tranco_path):
        print(f"Reading Tranco Benign from {tranco_path}...")
        with open(tranco_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= 2000: break # Use top 2k for fast baseline
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    benign_list.append(parts[1].lower())

    # 2. Parse DGA Data with Subclass Prototypes
    dga_path = os.path.join(data_dir, "dga_data.csv")
    if os.path.exists(dga_path):
        print(f"Reading DGA Families from {dga_path}...")
        with open(dga_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dom = row.get("domain", "").strip().lower()
                subcls = row.get("subclass", "unknown").strip().lower()
                if dom:
                    if len(dga_families[subcls]) < 200:
                        dga_families[subcls].append(dom)
                        
    # 3. Parse PhishTank
    phish_path = os.path.join(data_dir, "verified_online.csv")
    if os.path.exists(phish_path):
        print(f"Reading Phishing from {phish_path}...")
        with open(phish_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                url = row.get("url", "").strip()
                dom = extract_domain(url)
                if dom:
                    phish_list.append(dom)
                    count += 1
                if count >= 1000: break
                
    num_dga = sum(len(v) for v in dga_families.values())
    print(f"[Stats] DGA: {num_dga} ({len(dga_families)} families) | Benign: {len(benign_list)} | Phish: {len(phish_list)}")

    print("\nInitializing High-Dimensional Space (10048-D)...")
    encoder = HDCEncoder(dimensions=10048)
    store = VectorStore(dimensions=10048)
    
    iterations = 2
    print(f"Iterating Central Bounds ({iterations} epochs)...")
    
    if benign_list:
        p_benign = encoder.encode_domain(benign_list[0])
        for ep in range(iterations):
            for d in benign_list:
                p_benign = hebbian_update(p_benign, encoder.encode_domain(d), alpha=0.1)
        store.add_prototype("benign", p_benign)

    if phish_list:
        p_phish = encoder.encode_domain(phish_list[0])
        for ep in range(iterations):
            for d in phish_list:
                p_phish = hebbian_update(p_phish, encoder.encode_domain(d), alpha=0.15)
        store.add_prototype("phish", p_phish)

    for family, domains in dga_families.items():
        if len(domains) < 10: continue
        print(f"  -> Building Prototype for DGA Family: {family} ({len(domains)} samples)")
        p_dga = encoder.encode_domain(domains[0])
        for ep in range(iterations):
            for d in domains:
                p_dga = hebbian_update(p_dga, encoder.encode_domain(d), alpha=0.2)
        store.add_prototype("dga", p_dga)
    
    out_file = os.path.join(os.path.dirname(__file__), "offline_hv.npz")
    store.save(out_file)
    print(f"Model successfully saved to {os.path.basename(out_file)}")

if __name__ == "__main__":
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "datasets"))
    build_academic_model(data_dir=data_dir)
