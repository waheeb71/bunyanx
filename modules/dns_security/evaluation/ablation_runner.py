"""
DART-DNS Full Ablation Study Runner (Fixed v2)
Fixes:
  - Unicode encoding for Windows terminals
  - Temporal priming uses consistent srcs_ip per domain
  - Graph priming decoupled from eval pass
  - DART fusion threshold tuning based on realistic signal distribution
"""
import sys
import os
import time
import random
import logging
import math
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from modules.dns_security.evaluation.dataset_manager import DatasetManager
from modules.dns_security.evaluation.metrics import EvaluatorMetrics
from modules.dns_security.engine.dart.lexical import LexicalAnalyzer
from modules.dns_security.engine.dart.temporal import TemporalResonanceDetector
from modules.dns_security.engine.dart.graph import GraphResonanceEngine
from modules.dns_security.engine.dart.fusion import DARTFusionEngine
from modules.dns_security.engine.legacy.dga_detector import DGADetector

logging.basicConfig(level=logging.WARNING)


# ─────────────────────────── MI Helper ───────────────────────────────────────

def mutual_information(a_list, b_list):
    """Approximate Mutual Information between two binary vectors."""
    n = len(a_list)
    if n == 0:
        return 0.0
    joint = defaultdict(int)
    for a, b in zip(a_list, b_list):
        joint[(a, b)] += 1
    ca = defaultdict(int)
    cb = defaultdict(int)
    for (a, b), v in joint.items():
        ca[a] += v
        cb[b] += v
    mi = 0.0
    for (a, b), cnt in joint.items():
        p_ab = cnt / n
        p_a  = ca[a] / n
        p_b  = cb[b] / n
        if p_ab > 0:
            mi += p_ab * math.log2(p_ab / (p_a * p_b + 1e-12))
    return round(mi, 4)


# ─────────────────────────── Simulation ───────────────────────────────────────

def prime_temporal(detector, domain, src_ip, is_malicious) -> float:
    """
    Inject realistic query history for a FIXED src_ip.
    Called once before the eval pass so Layer 2 has state.
    Returns the timestamp for the NEXT query to maintain cadence.
    """
    base = time.time() - 120
    next_time = base
    if is_malicious:
        # Beaconing: 20 queries every ~5s with tiny jitter
        for i in range(20):
            jitter = random.uniform(-0.08, 0.08)
            detector.analyze(src_ip, domain, current_time=base + i * 5 + jitter)
        next_time = base + 20 * 5 + random.uniform(-0.08, 0.08)
    else:
        # Bursty human: 1-4 queries at random times
        count = random.randint(1, 4)
        for _ in range(count):
            detector.analyze(src_ip, domain,
                             current_time=base + random.uniform(0, 90))
        next_time = base + random.uniform(90, 120)
    return next_time

def prime_graph(engine, domain, src_ip, is_malicious):
    """
    Inject realistic cross-host history.
    Called once before eval pass.
    """
    base_t = time.time() - 20
    if is_malicious:
        # 4-7 DIFFERENT hosts query the same domain in the window
        for i in range(random.randint(4, 7)):
            ip = f"10.10.{random.randint(1,5)}.{random.randint(1,254)}"
            engine.analyze(ip, domain, current_time=base_t + i * 1.5)
    else:
        # Only 0-2 hosts — should NOT trigger (threshold=3)
        for _ in range(random.randint(0, 2)):
            ip = f"10.10.1.{random.randint(1,254)}"
            engine.analyze(ip, domain, current_time=base_t + random.uniform(0, 20))


# ─────────────────────────── Main Ablation ─────────────────────────────────

def run_full_ablation(n_samples=3000):
    sep = "=" * 62
    thin = "-" * 62

    print("\n" + sep)
    print("  DART-DNS: Full Ablation Study (Fixed v2)")
    print(sep)

    # 1. Datasets
    print("\nLoading datasets ...")
    dga_domains, benign_domains = DatasetManager.prepare_datasets(max_samples=n_samples)
    print(f"  DGA:    {len(dga_domains)} | Benign: {len(benign_domains)}")

    dataset = [(d, True) for d in dga_domains] + [(d, False) for d in benign_domains]
    random.shuffle(dataset)

    # 2. Engines
    lexical  = LexicalAnalyzer()
    temporal = TemporalResonanceDetector(high_freq_window=120, min_queries=5)
    graph    = GraphResonanceEngine(window_size=30, min_hosts_for_alert=3)
    fusion   = DARTFusionEngine(
        w1=0.50, w2=0.30, w3=0.20,
        theta_fusion=0.55,
        theta_s1=0.60, theta_s2=0.45, theta_s3=0.45,
        min_layers_confirm=1,   # single strong layer can confirm for DGA
    )

    # 3. PRIME temporal & graph state with FIXED src_ip per domain
    print("Priming temporal and graph state ...")
    domain_src_map = {}   # domain -> (src_ip, next_temporal_time)
    for domain, is_malicious in dataset:
        src_ip = f"10.{random.randint(1,5)}.{random.randint(1,10)}.{random.randint(2,254)}"
        next_t = prime_temporal(temporal, domain, src_ip, is_malicious)
        domain_src_map[domain] = (src_ip, next_t)
        prime_graph(graph, domain, src_ip, is_malicious)

    # 4. Evaluation pass
    print("Running evaluation pass ...")

    S1_TH, S2_TH, S3_TH = 0.60, 0.45, 0.45

    exps = {
        "Baseline (Shannon Entropy)": EvaluatorMetrics(),
        "S1 only (Lexical)":          EvaluatorMetrics(),
        "S2 only (Temporal)":         EvaluatorMetrics(),
        "S3 only (Graph)":            EvaluatorMetrics(),
        "S1 + S2":                    EvaluatorMetrics(),
        "S1 + S3":                    EvaluatorMetrics(),
        "S2 + S3":                    EvaluatorMetrics(),
        "DART Full Fusion":           EvaluatorMetrics(),
    }

    bin_s1, bin_s2, bin_s3, true_labels = [], [], [], []

    for domain, label in dataset:
        src_ip, next_t = domain_src_map[domain]

        # S1
        t0 = time.perf_counter()
        s1, s1c = lexical.analyze(domain)
        l1 = (time.perf_counter() - t0) * 1000

        # S2 — one more query to get current score (using consistent cadence time)
        t0 = time.perf_counter()
        sig2 = temporal.analyze(src_ip, domain, current_time=next_t)
        s2 = sig2.score
        l2 = (time.perf_counter() - t0) * 1000

        # S3
        t0 = time.perf_counter()
        sig3 = graph.analyze(src_ip, domain)
        s3 = sig3.score
        l3 = (time.perf_counter() - t0) * 1000

        # Shannon baseline
        sh_norm = min(1.0, lexical.shannon_entropy(domain) / 4.0)
        exps["Baseline (Shannon Entropy)"].record(label, sh_norm > 0.85, l1)

        # Per-layer
        exps["S1 only (Lexical)"].record(label, s1 > S1_TH, l1)
        exps["S2 only (Temporal)"].record(label, s2 > S2_TH, l2)
        exps["S3 only (Graph)"].record(label, s3 > S3_TH, l3)

        # Pairwise OR
        exps["S1 + S2"].record(label, (s1 > S1_TH or s2 > S2_TH), l1 + l2)
        exps["S1 + S3"].record(label, (s1 > S1_TH or s3 > S3_TH), l1 + l3)
        exps["S2 + S3"].record(label, (s2 > S2_TH or s3 > S3_TH), l2 + l3)

        # DART Fusion
        t0 = time.perf_counter()
        dec = fusion.fuse(
            domain=domain,
            s1_score=s1, s1_components=s1c,
            s2_score=s2, s2_info={"variance": sig2.variance,
                                   "query_count": sig2.query_count},
            s3_score=s3, s3_info={"unique_hosts": sig3.unique_hosts},
        )
        lf = (time.perf_counter() - t0) * 1000 + l1 + l2 + l3
        exps["DART Full Fusion"].record(label, dec.is_malicious, lf)

        # Collect for MI
        bin_s1.append(int(s1 > S1_TH))
        bin_s2.append(int(s2 > S2_TH))
        bin_s3.append(int(s3 > S3_TH))
        true_labels.append(int(label))

    # 5. Print table
    print("\n")
    hdr = f"{'Experiment':<28} {'F1':>7} {'FPR':>7} {'Recall':>7} {'Prec':>7} {'Lat(ms)':>9}"
    print(hdr)
    print(thin)
    for name, m in exps.items():
        r = m.compute()
        marker = " <-- DART" if name == "DART Full Fusion" else ""
        print(f"{name:<28} {r['F1 Score']:>7.4f} "
              f"{r['False Positive Rate (FPR)']:>7.4f} "
              f"{r['Recall (TPR)']:>7.4f} "
              f"{r['Precision']:>7.4f} "
              f"{r['Avg Latency (ms)']:>9.4f}"
              f"{marker}")

    # 6. Mutual Information
    mi_12 = mutual_information(bin_s1, bin_s2)
    mi_13 = mutual_information(bin_s1, bin_s3)
    mi_23 = mutual_information(bin_s2, bin_s3)

    print("\n" + thin)
    print("  Mutual Information Analysis (Empirical Layer Correlation)")
    print(thin)
    print(f"  MI(S1-Lexical, S2-Temporal) = {mi_12:.4f} bits")
    print(f"  MI(S1-Lexical, S3-Graph)    = {mi_13:.4f} bits")
    print(f"  MI(S2-Temporal, S3-Graph)   = {mi_23:.4f} bits")
    print("  Lower MI => Weaker correlation => stronger fusion benefit")
    print(thin)

    # 7. XAI examples (3 DGA + 3 Benign)
    print("\n  XAI Evidence Examples:")
    print(thin)
    dga_ex    = [(d, l) for d, l in dataset if l][:3]
    benign_ex = [(d, l) for d, l in dataset if not l][:3]
    for domain, label in dga_ex + benign_ex:
        src_ip, _ = domain_src_map[domain]
        s1v, s1c = lexical.analyze(domain)
        s2v = temporal.analyze(src_ip, domain).score
        s3g = graph.analyze(src_ip, domain)
        d = fusion.fuse(domain, s1v, s1c, s2v,
                        s3_score=s3g.score,
                        s3_info={"unique_hosts": s3g.unique_hosts})
        tag  = "DGA" if label else "BENIGN"
        verdict = "MALICIOUS" if d.is_malicious else "CLEAN"
        print(f"\n  [{tag}] {domain[:40]}")
        print(f"    Verdict: {verdict}  R={d.resonance_score}  layers_fired={d.layers_triggered}")
        for lname, ev in d.evidence.items():
            sc = ev.get('score', 0)
            reason = ev.get('reason', '')
            print(f"    {lname:10s} S={sc:.3f}  | {reason}")

    # 8. Export results to JSON (AI-2)
    import json
    results_export = []
    for name, m in exps.items():
        r = m.compute()
        results_export.append({
            "experiment": name,
            "f1_score": r['F1 Score'],
            "fpr": r['False Positive Rate (FPR)'],
            "recall": r['Recall (TPR)'],
            "precision": r['Precision'],
            "avg_latency_ms": r['Avg Latency (ms)']
        })
    
    export_path = os.path.join(os.path.dirname(__file__), "ablation_results.json")
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(results_export, f, indent=2)
    print(f"\n  Results exported to: {export_path}")

    print("\n" + sep)
    print("  Ablation study complete.")
    print(sep + "\n")


if __name__ == "__main__":
    run_full_ablation(n_samples=3000)
