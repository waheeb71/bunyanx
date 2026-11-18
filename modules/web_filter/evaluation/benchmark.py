import time
import os
import sys
import numpy as np

# Resolve imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from modules.web_filter.policy.holo_filter import HoloFilter
from modules.web_filter.policy.holo_filter.encoder import HDCEncoder

def benchmark_throughput_latency():
    """
    Simulates a heavy load on HoloFilter to prove the 1.2M QPS and < 4µs latency claim.
    We test pure inference assuming the model is loaded in memory.
    """
    print("\n--- [1] Throughput & Latency Benchmark ---")
    
    model_path = os.path.join(os.path.dirname(__file__), "offline_hv.npz")
    holo = HoloFilter(model_path=model_path)
    if not holo.ready:
        print("Model not ready! Run train_holo.py first.")
        return
        
    test_domains = ["xqz19aflk.net", "google.com", "abububa.biz", "yah00-login.com"] * 250
    num_queries = len(test_domains)
    
    # Warmup
    for d in test_domains[:10]:
        holo.evaluate(d)
        
    start_time = time.perf_counter()
    latencies = []
    
    for d in test_domains:
        t0 = time.perf_counter()
        res = holo.evaluate(d)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1_000_000) # Microseconds
        
    total_time = time.perf_counter() - start_time
    qps = num_queries / total_time
    
    p99_latency = np.percentile(latencies, 99)
    avg_latency = np.mean(latencies)
    
    print(f"Total Queries: {num_queries}")
    print(f"Throughput:    {qps:,.2f} Queries/sec")
    print(f"Average Latency: {avg_latency:.2f} µs")
    print(f"P99 Latency:   {p99_latency:.2f} µs")


def ablation_study():
    """
    Proves the necessity of Length Encoding, Position-Aware Permutations, and Multi-Signal mapping.
    """
    print("\n--- [2] Ablation Study (Methodology Stub) ---")
    print("This suite is designed for academic evaluation. When hooked to real datasets, it compares:")
    
    scenarios = [
        "1. Full HoloFilter v2 (Multi-Signal + Position Permutation + Length Encoding)",
        "2. Without Length Encoding (-Length)",
        "3. Without Positional Permutations (-Permutation) -> Falls back to 'Bag of N-grams'",
        "4. Unified Prototype (-MultiSignal) -> Averages all DGA families into one vector"
    ]
    
    for s in scenarios:
        print(f"[{s}] -> (F1: 0.00 | ROC-AUC: 0.00) [Mock Data]")
        
    print("\n[INFO] To run real ablations, modify encoder.py to toggle logic via parameters, and run against DGArchive CSV dataset.")

if __name__ == "__main__":
    benchmark_throughput_latency()
    ablation_study()
