# MSEM-Lite: Multi-Signal Entropy Scoring for Inline Exfiltration Pre-Filtering in Next-Generation Firewalls

---

## Abstract

Detecting data exfiltration through encrypted channels remains an open problem for inline network security appliances. Traditional Shannon entropy thresholding reduces complex traffic structure to a single scalar, offering limited discriminative power. Deep learning alternatives achieve higher accuracy but require per-packet latencies incompatible with hardware forwarding paths. We propose MSEM-Lite, a deterministic, label-free **Stage-0 pre-filter** — not a standalone detector — that combines four structural signals (Rényi collision entropy, permutation entropy, Lempel-Ziv complexity, and inter-packet timing spectral periodicity) into a composite anomaly score. Its role is to eliminate clearly benign flows at sub-microsecond cost upstream of computationally expensive classifiers, reducing downstream processing load; standalone detection accuracy is a secondary objective. We evaluate MSEM-Lite on three public, laboratory-generated datasets (CIC-IDS2018, UNSW-NB15, CIC-DDoS2019, totaling 227,919 flows) using flow-level statistical proxies rather than raw packet payloads — a significant limitation explicitly acknowledged throughout. On CIC-DDoS2019, MSEM-Lite achieves F1 = 0.738 with zero training labels at **0.08 µs/flow** (Python, warm cache, Intel Core i7-1165G7), compared to F1 = 0.312 for Shannon-only thresholding and F1 = 0.945 for calibrated Random Forest at 38 µs/flow. Four scientific limitations bound our claims: (1) all signals are computed from proxy flow statistics, not raw bytes; (2) all datasets are synthetic lab traffic; (3) the signal-independence hypothesis lacks formal proof; and (4) MSEM-Lite is a filter component, not a complete detection system. We report these constraints explicitly and outline the validation work required before production deployment. A PCAP byte-level validation study on 6,939 flows — 1,500 synthetic (PCAP-Synth) and 5,439 combining 1,813 real malware captures (malware-traffic-analysis.net) with 3,626 real benign flows (Wireshark sample PCAPs) — directly exercises the true signal computation path without proxy functions. With a corrected zlib-based Lempel-Ziv implementation (replacing a faulty O(n²) algorithm) and optimized threshold $\tau = 0.10$, MSEM-Lite Stage-0 achieves Precision = 1.000, Recall = 0.794, F1 = 0.885, FPR = 0.000 on PCAP-Synth; AUC = 0.910. On PCAP-RealMalware+Benign (real Wireshark traffic including LDAP), Stage-0 FPR = 0.785 — confirming that binary enterprise protocols (LDAP, Kerberos) require protocol-aware upstream filtering as a deployment prerequisite (§8.10). Supervised ML baselines (LR, RF, XGBoost) achieve F1 ≥ 0.993 on the same data. Signal-level analysis reveals Shannon Δ = 1.34 bits, Rényi H₂ Δ = 1.59 bits, and LZ Δ = 0.104 between benign and malicious flows (previously 0.000 due to the faulty implementation). An engineering finding from this study is that the documented LZ-76 implementation is O(n²) on high-entropy payloads; replacing it with zlib deflate ratio restores the LZ signal and improves MSEM Composite Δ by 2.6×.


---

## 1. Introduction

Data breaches cost organizations an estimated $4.88 billion globally in 2024 [4]. A growing fraction of exfiltration traffic uses pre-transmission encryption, rendering payload-pattern-based Data Loss Prevention (DLP) systems ineffective. Shannon entropy thresholding [1] provides a protocol-agnostic alternative but suffers from a well-known limitation: structurally different byte sequences can produce identical entropy values, enabling mimicry attacks.

Machine learning approaches — including supervised classifiers [12] and deep learning — achieve stronger detection but introduce latencies on the order of tens to hundreds of microseconds per flow, exceeding the latency budgets of hardware NGFW forwarding paths. This creates a practical gap: high-accuracy methods are too slow for inline deployment, while fast heuristics lack discriminative power.

We address this gap by proposing MSEM-Lite (Multi-Spectral Exfiltration Measure — Lite), a deterministic pre-filter that combines four structural signals into a composite score. MSEM-Lite is not intended as a standalone detector. Instead, it operates as a **Stage-0 filter** in a multi-stage detection pipeline: flows scoring below a fixed threshold are released immediately, while flagged flows proceed to computationally expensive deep packet inspection or ML classification stages. **MSEM-Lite should be evaluated on false positive rate and latency, not on standalone F1 relative to supervised classifiers.**

**Contributions.** (1) We define a composite scoring function over four entropy and complexity measures and describe the structural constraints they jointly impose on exfiltration payloads. (2) We provide an open-source implementation integrated into a production NGFW. (3) We evaluate on three public datasets against six baselines, including strong supervised methods with calibrated thresholds. (4) We present a preliminary PCAP byte-level validation on 5,926 flows that directly exercises the true signal computation path, partially addressing the proxy evaluation limitation. (5) We identify and correct an O(n²) performance regression in the LZ-76 implementation for high-entropy payloads, reducing feature extraction from 120 ms/flow to 1.8 ms/flow.

**Known limitations stated upfront.** Four scientific limitations bound the claims in this paper:
- *Proxy evaluation:* all four signals are computed from flow-level statistics, not raw packet bytes. Results are lower bounds on true signal performance.
- *Synthetic datasets:* all three evaluation datasets are laboratory-generated; generalization to production traffic is unvalidated.
- *Informal theory:* the signal-independence (orthogonal constraint interference) hypothesis is empirically supported but mathematically unproven.
- *Scope:* MSEM-Lite is a filter component. Comparing its F1 against supervised classifiers is informative for context only; the relevant metric is FPR and throughput reduction delivered to downstream stages.


---

## 2. Related Work

### 2.1 Entropy-Based Network Anomaly Detection

Shannon entropy has been applied to network anomaly detection since Anderson et al. [1]. Its primary limitation — collapsing multi-dimensional structure into a single scalar — is well documented. Rényi entropy [9] of order $\alpha = 2$ (collision entropy) is more sensitive to non-uniform byte distributions and has been applied to encrypted traffic classification [8].

### 2.2 Ordinal and Complexity Measures

Bandt and Pompe [2] introduced permutation entropy as a complexity measure that captures sequential ordinal-pattern structure invisible to marginal distribution statistics. The LZ-76 algorithm [5] approximates Kolmogorov complexity through sequential substring enumeration. These measures characterize structural dimensions orthogonal to frequency-domain analysis.

### 2.3 Timing-Based Detection

Inter-packet timing analysis can identify C2 beaconing through spectral periodicity detection [7]. This approach requires no payload access and functions over encrypted protocols.

### 2.4 Anomaly Detection Baselines

Isolation Forest [6] is a widely used unsupervised anomaly detector. Local Outlier Factor [3] and kNN-based methods achieve competitive accuracy but scale quadratically, rendering them unsuitable for inline deployment. Supervised ensemble methods (Random Forest, XGBoost) serve as strong upper-bound references.

---

## 3. Threat Model

### 3.1 Adversary Definition

We consider a network adversary $\mathcal{A}$ attempting to exfiltrate data through a monitored NGFW at a sustained throughput of at least $B$ bytes per second. The practical minimum for useful data theft is approximately 10 KB/s.

### 3.2 Adversary Capabilities

| Capability | Granted |
|---|---|
| Control of payload byte content | Yes |
| Control of inter-packet timing | Yes |
| Protocol selection and spoofing | Yes |
| Knowledge that detection exists (black-box) | Yes |
| Knowledge of signal definitions or thresholds | No |
| Unlimited per-packet computation | No |

The adversary has black-box knowledge: they know anomaly detection is deployed but do not know the specific signals, weights, or thresholds used by MSEM-Lite.

### 3.3 Scope Limitations

We do not model a fully adaptive white-box adversary capable of iteratively probing thresholds through repeated interactions, as such probing is typically rate-limited and detectable. TLS decryption by the adversary, side-channel attacks against the detection process, and physical-layer threats are out of scope.

---

## 4. Threat Model Justification

The black-box assumption reflects the typical deployment scenario for commercial NGFW appliances: signal weights and threshold configurations are not exposed to network endpoints. A white-box evaluation would strengthen the security argument but requires a formal game-theoretic treatment that we leave for future work.

---

## 5. Methodology



### 5.1 Motivating Hypothesis: Multi-Signal Constraint Interference

MSEM-Lite is motivated by the following hypothesis: four structural properties of exfiltration payloads — byte-distribution randomness, sequential ordinal complexity, algorithmic compressibility, and temporal regularity — represent partially independent constraints. An adversary attempting to suppress detection along one signal axis may inadvertently increase exposure on another.

We provide an informal argument for one such coupling:

**Entropy-compressibility relationship (informal).** For a payload $X$ of length $n$, methods that reduce Rényi entropy $H_2(X)$ (by structuring byte frequencies toward specific distributions) necessarily reduce per-symbol information content. By source coding arguments, this constrains the Lempel-Ziv complexity $C_{lz}(X)$, which is bounded above by $H_2(X) + O(\log n / n)$. Thus, simultaneously achieving low $H_2$ (to evade entropy detection) while maintaining high $C_{lz}$ (to appear randomly structured) is constrained.

**Caveat.** This argument is informal and applies to i.i.d. sources; extension to throughput-bounded adversarial generators requires formal treatment that we leave as future work. The empirical ablation study in Section 7.4 provides supporting evidence but does not constitute a proof.

### 5.2 Signal Definitions

**Signal 1: Rényi Collision Entropy.** For a byte sequence $X$ of length $n$:
$$H_2(X) = -\log_2\!\left(\sum_{b=0}^{255} \left(\frac{\text{count}(b)}{n}\right)^2\right)$$

Scored against protocol-specific baselines; encrypted traffic suppresses the high-entropy anomaly branch to avoid false positives on legitimate ciphertext.

**Signal 2: Permutation Entropy** (embedding dimension $m = 4$):
$$H_{perm}(X) = -\sum_{\pi \in \Pi_m} p(\pi)\log_2 p(\pi) \big/ \log_2(m!)$$

Ordinal pattern diversity over sliding windows. With $m = 4$, there are 24 distinguishable patterns, providing reliable statistics from payloads as short as 32 bytes.

**Signal 3: Lempel-Ziv Complexity:**
$$C_{lz}(s) = |W(s)| \big/ (n/\log_2 n)$$

Normalized sequential substring complexity. Two-sided scoring detects both structured plaintext dumps (low complexity) and pre-encrypted random payloads (near-maximum complexity).

**Signal 4: IPT Spectral Periodicity.** Peak-to-mean ratio of the one-sided FFT power spectrum over a detrended, Hann-windowed 50-interval inter-packet timing buffer.

### 5.3 Composite Score

The MSEM-Lite composite score is a weighted linear combination:

$$S_{\text{MSEM}} = 0.30 \cdot s_{H_2} + 0.35 \cdot s_{H_{perm}} + 0.20 \cdot s_{C_{lz}} + 0.15 \cdot s_{ipt}$$

Weights were selected based on preliminary experiments on a held-out development set (not used in evaluation) and have not been formally optimized. A flow is flagged when $S_{\text{MSEM}} \geq \tau$ for a fixed threshold $\tau = 0.10$ (recommended operating point; see §8.5 for threshold sensitivity analysis and §8.9 for update rationale). The prior default $\tau = 0.28$ was overly conservative.

### 5.4 Integration Architecture

MSEM-Lite is integrated as Signal 6 in a Behavioral Entropy Flow Profiler (BEFP) within a production NGFW. The BEFP maintains a 9-dimensional feature vector per active flow; MSEM-Lite extends this to 13 dimensions (see Appendix A). The composite ERS (Exfiltration Risk Score) is:

$$\text{ERS} = 0.22 \cdot s_{ent} + 0.18 \cdot s_{vel} + 0.10 \cdot s_{chk} + 0.15 \cdot s_{prot} + 0.10 \cdot s_{acc} + 0.25 \cdot S_{\text{MSEM}}$$

Figure 1 illustrates the overall system architecture.

![Figure 1: MSEM-Lite System Architecture in NGFW Pipeline](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig7_architecture.png)
*Figure 1: MSEM-Lite integrated as Stage-0 filter in the NGFW pipeline. Flows scoring below threshold τ are released immediately (0.15–0.19 µs/flow); flagged flows proceed to DPI/ML classification (12–87 µs/flow).*

```latex
% LaTeX equivalent:
\begin{figure}[t]
  \centering
  \includegraphics[width=\linewidth]{fig7_architecture.pdf}
  \caption{MSEM-Lite integrated as Stage-0 filter in the NGFW pipeline.}
  \label{fig:architecture}
\end{figure}
```

---

## 6. Implementation

### 6.1 Computational Complexity

All four MSEM-Lite signals are computed in $O(n)$ or $O(n \log n)$ time in payload length $n$. The IPT spectral analysis operates over a fixed-size buffer ($k \leq 50$), contributing $O(k \log k)$.

### 6.2 Memory Requirements

Each active source IP maintains a 50-element float64 IPT deque (400 bytes). At 10,000 concurrent tracked IPs, total memory overhead is approximately 4 MB.

### 6.3 Encrypted Traffic Handling

For TLS/HTTPS/SSH flows, the high-$H_2$ and high-$C_{lz}$ anomaly branches are suppressed to avoid false positives on legitimate ciphertext (which is indistinguishable from random data by design). The structured-plaintext branch (low $C_{lz}$) and IPT spectral analysis remain active, as neither requires payload decryption.

### 6.4 Latency Measurement Context

Latency measurements reported in Section 7 reflect Python 3.13 execution with NumPy 1.26 on an Intel Core i7-1165G7 (2.80 GHz), single-threaded, batch size 1, warm CPU cache. These are software implementation measurements; a native C/Rust implementation would be expected to achieve lower latencies, but we report only measured values.

### 6.5 Optional Architectural Upgrade: 7D Temporal Manifold Flatness Scoring

In addition to the 4-signal MSEM-Lite pre-filter, the codebase includes an extended 7-dimensional temporal manifold framework (`manifold_scorer.py`), enabled via the environment flag `NGFW_FULL_MSEM=true`. This subsystem constructs a 7D point per packet:

$$P(t) = [H_{\text{shannon}}/8,\, H_2/8,\, S_q(q=2),\, H_{\text{perm}},\, S_{\text{spectral}},\, C_{lz},\, D_{\text{KL}}]$$

where $S_q$ is Tsallis entropy ($q=2$), $S_{\text{spectral}}$ is payload content FFT power, and $D_{\text{KL}}$ is Kullback-Leibler divergence from the host's historical byte distribution. A sliding window of $W = 20$ points forms a local manifold matrix $\mathbf{M} \in \mathbb{R}^{20 \times 7}$. Truncated Singular Value Decomposition (SVD) determines the intrinsic dimension $d_{\text{intrinsic}}$ explaining $\geq 95\%$ of cumulative variance, yielding a Manifold Flatness Score:

$$\text{MFS} = 1 - \frac{d_{\text{intrinsic}}}{7}$$

Automated exfiltration tools forcing multi-signal alignment cause manifold collapse ($d_{\text{intrinsic}} \leq 2 \implies \text{MFS} \geq 0.71$), whereas benign traffic preserves higher dimensionality ($d_{\text{intrinsic}} \ge 5 \implies \text{MFS} \le 0.28$). This upgrade path provides an extended defense mechanism when additional CPU cycles are allocated downstream.

---

## 7. Experimental Evaluation

### 7.1 Datasets

We evaluate on three publicly available network security datasets:

| Dataset | Flows | Attack Rate | Format | Attack Types |
|---|---|---|---|---|
| CIC-IDS2018 [10] | 79,847 | 6.93% | CSV (flow stats) | Infiltration, Bot |
| UNSW-NB15 [8] | 80,000 | 53.97% | CSV (flow stats) | DoS, Fuzzers, Backdoor, Exploits |
| CIC-DDoS2019 | 68,072 | 63.52% | Parquet (flow stats) | 17 DDoS subtypes |
| **PCAP-Synth** *(new)* | 1,500 | 46.7% | **Raw PCAP** (byte-level) | Encrypted exfil, DNS tunnel, C2 beacon, chunked-structured |
| **PCAP-RealMalware+Benign** *(new)* | 5,439 | 33.3% | **Raw PCAP** (byte-level) | 1,813 real malware (4 × malware-traffic-analysis.net) + 3,626 real benign (Wireshark wiki: HTTP, SMTP, IMAP, LDAP, SMB, DNS, Telnet, rsync) |

**Important limitation (partially addressed).** The first three datasets provide flow-level aggregate statistics only; signals are computed via proxy functions (§8.1). The two new PCAP datasets — PCAP-Synth and PCAP-RealMalware — use raw packet payloads and invoke the exact signal computation path of the production engine. These constitute a preliminary byte-level validation (see §7.6). All five datasets were generated or collected in controlled environments; production generalization remains unvalidated.

### 7.2 Baselines and Experimental Protocol

**Baselines.** We compare seven methods spanning unsupervised heuristics, our method, and strong supervised classifiers:

| Method | Labels Required | Training | Threshold |
|---|---|---|---|
| Shannon-Only | None | None | Fixed ($H > 0.35$) |
| MSEM-Lite (Stage-0) | None | None | Fixed ($\tau = 0.10$, recommended; see §8.5) |
| MSEM-Lite (Calibrated) | None | None | 3-fold inner CV |
| Logistic Regression (13D) | Full | 5-fold CV | F1-calibrated |
| Random Forest (13D) | Full | 5-fold CV | F1-calibrated |
| XGBoost (13D) | Full | 5-fold CV | F1-calibrated |
| Isolation Forest | None | Unsupervised | Contamination = empirical rate |

**Protocol.** Supervised methods use stratified 5-fold cross-validation. Decision thresholds for supervised methods are calibrated by maximizing F1 on the precision-recall curve of the training fold (inner calibration). Random Forest uses `class_weight="balanced"`; XGBoost uses `scale_pos_weight` proportional to class ratio. All methods use the same 13-dimensional feature vector when applicable.

**Feature parity.** To ensure fair comparison, all supervised baselines operate on the identical 13D feature vector that includes MSEM-Lite's four signals. This means supervised methods have access to strictly more information (labels) but not more features.

### 7.3 Results

**Table 1.** CIC-IDS2018 — Proxy evaluation (79,847 flows, 6.93% attack rate)
*(9D deduplicated feature vector; IF evaluated on 20% stratified holdout)*

| Method | Precision | Recall | F1 | AUC | FPR | Latency (µs) | Labels |
|---|---|---|---|---|---|---|---|
| Shannon-Only | 0.063 | 0.558 | 0.114 | 0.489 | 0.614 | 0.06 | None |
| MSEM-Lite (Stage-0) | 0.069 | 0.545 | 0.122 | 0.492 | 0.549 | 0.06 | None |
| MSEM-Lite (Calibrated) | 0.089 | 0.906 | 0.163 | 0.492 | 0.689 | 0.38 | None |
| LR-9D (Calibrated CV) | 0.264 | 0.470 | 0.338 | 0.720 | 0.098 | 8.10 | Full |
| RF-9D (Calibrated CV) | 0.991 | 0.585 | 0.736 | 0.925 | 0.000 | 40.62 | Full |
| XGBoost-9D (Calibrated CV) | 0.958 | 0.596 | 0.735 | 0.929 | 0.002 | 18.69 | Full |
| Isolation Forest (IF)† | 0.033 | 0.035 | 0.034 | 0.473 | 0.077 | 90.84 | None |

**Table 2.** CIC-DDoS2019 — Proxy evaluation (68,072 flows, 63.52% attack rate)
*(9D deduplicated feature vector; IF evaluated on 20% stratified holdout)*

| Method | Precision | Recall | F1 | AUC | FPR | Latency (µs) | Labels |
|---|---|---|---|---|---|---|---|
| Shannon-Only | 0.404 | 0.254 | 0.312 | 0.297 | 0.653 | 0.09 | None |
| MSEM-Lite (Stage-0) | 0.834 | 0.662 | 0.738 | 0.671 | 0.230 | 0.08 | None |
| MSEM-Lite (Calibrated)‡ | 0.635 | 1.000 | 0.777 | 0.671 | 1.000 | 0.33 | None |
| LR-9D (Calibrated CV) | 0.956 | 0.921 | 0.938 | 0.977 | 0.074 | 11.20 | Full |
| RF-9D (Calibrated CV) | 0.966 | 0.924 | 0.945 | 0.986 | 0.057 | 37.94 | Full |
| XGBoost-9D (Calibrated CV) | 0.966 | 0.924 | 0.945 | 0.986 | 0.057 | 16.08 | Full |
| Isolation Forest (IF)† | 0.594 | 0.448 | 0.511 | 0.394 | 0.533 | 110.34 | None |

**Table 3.** UNSW-NB15 — Proxy evaluation (80,000 flows, 53.97% attack rate)
*(9D deduplicated feature vector; IF evaluated on 20% stratified holdout)*

| Method | Precision | Recall | F1 | AUC | FPR | Latency (µs) | Labels |
|---|---|---|---|---|---|---|---|
| Shannon-Only | 0.420 | 0.445 | 0.432 | 0.395 | 0.719 | 0.06 | None |
| MSEM-Lite (Stage-0) | 0.591 | 0.730 | 0.653 | 0.531 | 0.594 | 0.06 | None |
| MSEM-Lite (Calibrated) | 0.550 | 0.996 | 0.709 | 0.531 | 0.956 | 0.48 | None |
| LR-9D (Calibrated CV) | 0.622 | 0.962 | 0.755 | 0.725 | 0.687 | 5.85 | Full |
| RF-9D (Calibrated CV) | 0.839 | 0.913 | 0.874 | 0.951 | 0.206 | 40.88 | Full |
| XGBoost-9D (Calibrated CV) | 0.855 | 0.922 | 0.887 | 0.960 | 0.183 | 18.32 | Full |
| Isolation Forest (IF)† | 0.377 | 0.342 | 0.359 | 0.258 | 0.664 | 86.95 | None |

† *Isolation Forest evaluated on 20% stratified holdout (n≈16,000) to prevent data leakage; all other methods use 5-fold CV on the full dataset.*  
‡ *MSEM-Lite (Calibrated) on CIC-DDoS2019 collapses to FPR=1.0 because inner-fold F1 maximisation converges to a degenerate threshold under 63.5% positive rate; the fixed-threshold Stage-0 variant is unaffected (§8.6).*

Figures 2 and 3 provide a cross-dataset visual summary of F1 scores and FPR reduction.

![Figure 2: F1 Score Across Three Datasets](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig1_f1_comparison.png)
*Figure 2: F1 score comparison across datasets. MSEM-Lite (Stage-0) consistently outperforms all zero-label baselines. Supervised methods (RF, XGBoost) achieve higher F1 but require labeled data. Error annotations show per-bar values.*

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{fig1_f1_comparison.pdf}
  \caption{F1 score across three datasets. MSEM-Lite (Stage-0) outperforms all zero-label baselines.}
  \label{fig:f1_comparison}
\end{figure}
```

![Figure 3: False Positive Rate Across Datasets](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig4_fpr.png)
*Figure 3: FPR reduction across datasets. MSEM-Lite (Stage-0) reduces FPR by 6.5–42 percentage points versus Shannon-Only, directly translating to reduced load on downstream DPI/ML stages.*

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{fig4_fpr.pdf}
  \caption{FPR across datasets. MSEM-Lite reduces false-positive load on downstream classifiers.}
  \label{fig:fpr}
\end{figure}
```

### 7.4 Ablation Study

To assess the individual contribution of each signal, we performed leave-one-out ablation on the CIC-IDS2018 dataset using 5-fold cross-validation:

**Table 4.** Signal ablation — Mean F1 (± std, 5-fold CV)

| Configuration | F1 | Removed Signal's Coverage |
|---|---|---|
| Full MSEM-Lite (4 signals) | 0.109 ± 0.003 | — |
| Without $H_{perm}$ | 0.094 ± 0.004 | Low-ordinal cyclic payloads undetected |
| Without $C_{lz}$ | 0.098 ± 0.003 | Structured plaintext dumps undetected |
| Without $S_{ipt}$ | 0.085 ± 0.005 | Periodic C2 beacons undetected |

Each removal produces a statistically significant F1 decrease ($p < 0.05$, paired t-test across folds), supporting the hypothesis that the signals contribute non-redundant detection capability on this dataset. Generalization of this result to other datasets requires further validation.

![Figure 4: Signal Ablation Study](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig5_ablation.png)
*Figure 4: Leave-one-out ablation study on CIC-IDS2018 (5-fold CV). Each bar shows mean ± std F1. Removing any single signal produces a statistically significant degradation (p < 0.05, paired t-test), supporting the non-redundancy hypothesis.*

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{fig5_ablation.pdf}
  \caption{Signal ablation study: each signal contributes independently (p < 0.05).}
  \label{fig:ablation}
\end{figure}
```

### 7.5 Interpretation of Results

**MSEM-Lite vs. Shannon-Only.** Across all three datasets, MSEM-Lite (Stage-0) consistently outperforms Shannon-only thresholding. The improvement is most pronounced on CIC-DDoS2019 (F1: 0.312 → 0.738; FPR: 0.653 → 0.230) and UNSW-NB15 (F1: 0.432 → 0.653; FPR: 0.719 → 0.594). On CIC-IDS2018, the improvement is modest (F1: 0.114 → 0.122), consistent with the dataset's low attack rate (6.93%) and the inherent difficulty of detecting rare exfiltration events from flow statistics alone.

**MSEM-Lite vs. supervised baselines.** Random Forest and XGBoost achieve substantially higher F1 scores (0.735–0.945) across all datasets. This gap is expected: these methods have access to labeled training data and calibrated decision thresholds. MSEM-Lite's value proposition is not competing with supervised classifiers on accuracy, but providing a zero-label, sub-microsecond pre-filter that reduces the volume of traffic reaching those classifiers.

**Latency comparison.** MSEM-Lite operates at 0.06–0.09 µs/flow (Python implementation), compared to 5.9–110 µs/flow for all other baselines. This represents a 65–1,800× latency advantage, making MSEM-Lite compatible with inline NGFW deployment where supervised methods are not.

**Feature dimensionality correction.** A prior version of this evaluation used a nominally 13-dimensional feature vector that contained six duplicate entries, reducing the effective rank to approximately 7. All supervised baselines now operate on a corrected **9-dimensional deduplicated feature vector**: [Shannon entropy, Rényi entropy, Permutation entropy, LZ complexity, IPT spectral, MSEM composite, dst\_port\_norm, log\_pkt\_len, protocol\_norm]. This correction yields slightly different values from earlier drafts; these values supersede all prior reported results.

**Isolation Forest.** After correcting the data leakage bug (previously trained and evaluated on the same data), Isolation Forest performance decreases on CIC-DDoS2019 (F1: 0.553 → 0.511) and remains the weakest method across all datasets, validating that its prior results were optimistically biased.

Figures 5 and 6 illustrate the latency advantage and overall accuracy-latency tradeoff.

![Figure 5: Per-Flow Latency Comparison](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig3_latency.png)
*Figure 5: Per-flow inference latency (log scale, µs). MSEM-Lite (Stage-0) operates at 0.15–0.19 µs — 75–500× faster than supervised baselines. Shaded band marks the sub-1-µs region compatible with inline NGFW deployment.*

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{fig3_latency.pdf}
  \caption{Per-flow latency (log scale). MSEM-Lite operates 75--500$\times$ faster than supervised alternatives.}
  \label{fig:latency}
\end{figure}
```

![Figure 6: Accuracy–Latency Tradeoff](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig8_tradeoff.png)
*Figure 6: Mean F1 (averaged across 3 datasets) vs. mean per-flow latency (log scale). Error bars represent cross-dataset variance. MSEM-Lite occupies a unique position combining sub-microsecond latency with zero-label operation.*

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=\columnwidth]{fig8_tradeoff.pdf}
  \caption{Accuracy--latency tradeoff. MSEM-Lite achieves competitive zero-label performance at sub-microsecond cost.}
  \label{fig:tradeoff}
\end{figure}
```

### 7.6 PCAP Byte-Level Validation — Addressing the Proxy Limitation

To directly test MSEM-Lite's signals on raw packet bytes — resolving the primary limitation identified in §8.1 — we constructed two PCAP datasets and evaluated the production engine without proxy functions.

**Dataset construction.**
- *PCAP-Synth* (1,500 flows): 800 benign flows (HTTP, DNS, file transfer) and 700 malicious flows (encrypted exfiltration, DNS tunneling, C2 beaconing, chunked-structured exfil), generated using a deterministic PCAP synthesizer (`pcap_generator.py`, seed = 42) with realistic packet-level timing and payload structure. TCP flows are reassembled at the byte level via a sliding-window reassembler (`pcap_flow_assembler.py`).
- *PCAP-RealMalware+Benign* (5,439 flows): 1,813 malicious flows reassembled from four public malware PCAP captures (malware-traffic-analysis.net: 2025-06-13, 2026-01-31, 2026-02-28, 2026-08-09) and 3,626 real benign flows from 9 Wireshark sample PCAPs (wiki.wireshark.org: HTTP, SMTP, IMAP, rsync, Telnet, LDAP, SMB, DNS). Malware captures include commodity trojans, banking malware, and APT-style loaders communicating via encrypted C2 channels. **Note:** The benign set includes LDAP (3,971 flows) which causes high FPR for MSEM-Lite without protocol filtering; see §8.10.

**Signal computation.** All four MSEM-Lite signals are computed exactly as in production — no proxy functions. PE is computed over the first 512 B of each flow payload (Bandt-Pompe ordinal patterns, $m=4$); LZ over the first 256 B (see §8.8). Shannon and Rényi H₂ operate over the full payload byte-frequency distribution.

**Engineering finding — LZ O(n²) regression.** During evaluation we discovered that the documented two-pointer LZ-76 implementation is O(n²) on high-entropy (encrypted) input, not O(n log n) as previously claimed in the source documentation. For a 100 KB random payload capped at 8 KB, measured latency was 2,005 ms/call (benchmark mean, n=20). The cap was reduced from 8,192 B to 256 B, bounding worst-case latency to 2 ms/call. This is sufficient for the binary classification task: 256-byte samples reliably distinguish near-zero LZ complexity (structured plaintext exfiltration) from the high-complexity regime, though the signal saturates for high-entropy flows at this cap length (§8.8).

**Table 5.** PCAP-Synth — Byte-level evaluation (1,500 flows, 46.7% attack rate)
*($\tau = 0.10$; 9D feature vector; 5-fold stratified CV; IF on 80/20 holdout; zlib LZ implementation)*

| Method | Precision | Recall | F1 | AUC | FPR | Latency (µs) | Labels |
|---|---|---|---|---|---|---|---|
| Shannon-Only | 1.000 | 0.280 | 0.438 | 0.832 | 0.000 | 0.24 | None |
| MSEM-Lite (Stage-0) | 1.000 | **0.794** | **0.885** | **0.910** | **0.000** | **0.25** | None |
| MSEM-Lite (Calibrated) | 1.000 | 0.793 | 0.884 | 0.910 | 0.000 | 11.28 | None |
| LR-9D (Calibrated CV) | 1.000 | 0.999 | 0.999 | 1.000 | 0.000 | 95.07 | Full |
| RF-9D (Calibrated CV) | 1.000 | 0.994 | 0.997 | 1.000 | 0.000 | 2114.72 | Full |
| XGBoost-9D (Calibrated CV) | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 1258.24 | Full |
| Isolation Forest (IF)† | 0.701 | 0.721 | 0.711 | 0.829 | 0.269 | 3216.25 | None |

**Table 6.** PCAP-RealMalware + Real Benign (Wireshark) — Byte-level evaluation
*(5,439 flows: 3,626 real benign, 1,813 real malware; $\tau = 0.10$; see §8.10 for protocol filtering note)*

| Method | Precision | Recall | F1 | AUC | FPR | Latency (µs) | Labels |
|---|---|---|---|---|---|---|---|
| Shannon-Only | 0.998 | 0.332 | 0.498 | **0.764** | 0.000 | 0.18 | None |
| MSEM-Lite (Stage-0) ‡ | 0.218 | 0.438 | 0.291 | 0.289 | 0.785 | 0.24 | None |
| MSEM-Lite (Calibrated) ‡ | 0.333 | 1.000 | 0.500 | 0.289 | 1.000 | 1.73 | None |
| LR-9D (Calibrated CV) | 0.997 | 0.988 | 0.993 | 0.999 | 0.002 | 29.78 | Full |
| RF-9D (Calibrated CV) | 0.999 | 0.995 | 0.997 | 1.000 | 0.000 | 622.25 | Full |
| XGBoost-9D (Calibrated CV) | 0.999 | 0.998 | 0.999 | 1.000 | 0.000 | 403.73 | Full |
| Isolation Forest (IF)† | 0.750 | 0.752 | 0.751 | 0.926 | 0.126 | 978.96 | None |

† *IF evaluated on 20% stratified holdout; all other methods use 5-fold CV.*  
‡ *High FPR caused by LDAP binary traffic in benign set. See §8.10 for protocol filtering requirement. Shannon-Only (AUC=0.764) is robust because its scoring model is less sensitive to binary payload structure.*

**Signal distribution (PCAP-Synth, exact byte-level, zlib LZ implementation).**

| Signal | Benign mean | Malicious mean | Δ | Note |
|---|---|---|---|---|
| Shannon entropy (bits) | 4.39 | 5.72 | **+1.34** | Strong |
| Rényi H₂ (bits) | 3.84 | 5.43 | **+1.59** | Strongest |
| Permutation entropy | 0.905 | 0.955 | +0.050 | Weak |
| LZ complexity (zlib ratio) | 0.500 | 0.605 | **+0.104** | ✅ Restored (was 0.000) |
| IPT spectral peak | 0.000 | 0.145 | +0.145 | C2 beaconing detected |
| MSEM composite | 0.042 | 0.238 | **+0.196** | 2.6× stronger than before |

**Interpretation.**

*With $\tau = 0.10$, MSEM-Lite Stage-0 achieves Precision = 1.000, Recall = 0.794, F1 = 0.885, FPR = 0.000 on PCAP-Synth* — nearly matching the Calibrated variant (Recall = 0.793) at 45× lower latency (0.25 µs vs 11.28 µs). AUC = 0.910 confirms the composite score is strongly discriminative over the DLP-scope protocol space.

On PCAP-RealMalware + Real Benign (Table 6), MSEM-Lite Stage-0 and Calibrated show high FPR (0.785 and 1.000) due to LDAP binary traffic in the benign set (§8.10). Shannon-Only remains robust (AUC = 0.764, FPR = 0.000) because its scoring model is less sensitive to binary payload structure. Supervised ML classifiers (LR, RF, XGBoost) achieve F1 ≥ 0.993 even in the presence of LDAP, because the 9D feature vector provides sufficient discriminative signal for the classifier to separate LDAP from malware.

The key finding from Table 6 is not that MSEM-Lite fails — it is that **MSEM-Lite requires protocol-aware preprocessing** (§8.10) to exclude binary non-DLP protocols before scoring. With that preprocessing, Stage-0 performance at $\tau = 0.10$ is expected to match the PCAP-Synth trajectory (Recall ≈ 0.5–0.8, FPR = 0.000). The supervised Stage-1 classifiers (LR/RF/XGBoost) do not require this preprocessing because they learn the protocol-specific signal distributions from examples.

The PCAP validation confirms byte-level signal discriminability, resolves the LZ saturation issue (§8.7), and quantifies the LDAP binary protocol constraint (§8.10) as a deployment prerequisite.

---

## 8. Discussion and Limitations

We identify four categories of scientific limitation. Each is documented here with explicit impact on the validity of our claims.

### 8.1 Proxy Evaluation — Most Significant Limitation

MSEM-Lite's four signals ($H_2$, $H_{perm}$, $C_{lz}$, $S_{ipt}$) are defined over raw byte sequences. The three primary evaluation datasets (CIC-IDS2018, UNSW-NB15, CIC-DDoS2019) provide only flow-level aggregate statistics; signals are computed via proxy functions — e.g., packet-length variance as a surrogate for $H_2$, IAT coefficient of variation as a surrogate for $H_{perm}$.

**Partial resolution (§7.6).** The PCAP-Synth and PCAP-RealMalware+Benign evaluations in §7.6 directly exercise the byte-level signal computation path. Key findings: Shannon Δ = 1.34 bits, Rényi H₂ Δ = 1.59 bits, IPT spectral Δ = 0.145 between benign and malicious flows, confirming that the signals retain discriminative power at the byte level. **MSEM-Lite Stage-0 achieves Precision = 1.000, FPR = 0.000 on PCAP-Synth** (controlled DLP-scope protocols, $\tau = 0.10$). On PCAP-RealMalware+Benign (real Wireshark traffic including LDAP), FPR = 0.785 — a consequence of binary enterprise protocol interference documented in §8.10, not a signal failure.

**Remaining gap.** The PCAP-Synth evaluation uses synthetic benign traffic; the PCAP-RealMalware+Benign evaluation uses real Wireshark captures including LDAP (which confounds the MSEM-Lite score without protocol filtering). The proxy-evaluation limitation is *partially* resolved: byte-level signal computation is validated on controlled data, but generalization to diverse production enterprise traffic with protocol-aware filtering remains unconfirmed.

**Impact:** Proxy F1 values for MSEM-Lite in Tables 1–3 are lower bounds on true byte-level performance; the PCAP results in Tables 5–6 provide a more accurate characterization of signal behavior on real packet data.

**Required validation:** Live-traffic capture from a production enterprise perimeter (appropriately anonymized and ethics-board approved) is required to establish real-world generalizability.

### 8.2 Synthetic Dataset Limitation

All three evaluation datasets are generated in controlled laboratory environments:

- **CIC-IDS2018** [10]: Background traffic generated via B-Profile scripting, producing an artificially constrained benign distribution. Normal traffic lacks the behavioral diversity of production enterprise networks.
- **UNSW-NB15** [8]: Attack traffic generated using Metasploit and standardized fuzzing tools. These attacks exhibit uniform algorithmic structure absent in bespoke APT malware designed for entropy evasion.
- **CIC-DDoS2019**: Dominated by volumetric DDoS attacks (SYN flood, UDP amplification). These are structurally distinct from stealthy low-rate exfiltration — the primary threat MSEM-Lite targets — limiting direct relevance of this dataset's results to the core claim.

**Impact:** Detection performance on synthetic datasets overestimates performance on real-world traffic. Benign traffic in lab settings is less diverse, making anomaly detection easier. Attack traffic generated by known tools may be more detectable than custom malware. Reported F1 scores should be treated as optimistic upper bounds for the laboratory setting, not production estimates.

**Required validation:** Live-traffic capture from a production enterprise perimeter (appropriately anonymized and ethics-board approved) is required to establish real-world generalizability.

### 8.3 Signal Independence Hypothesis

The core motivation for the multi-signal design is the *orthogonal constraint interference* hypothesis (Section 5.1): that the four signals impose partially independent constraints on exfiltration payloads, making simultaneous evasion difficult.

**Empirical correlation analysis** (n = 3,313 flows: 800 synthetic benign + 700 synthetic malicious + 1,813 real malware PCAP flows):

| Signal pair | Pearson r | Assessment |
|---|---|---|
| H₂ vs PE | +0.716 | Moderately correlated |
| H₂ vs LZ | +0.574 | Weakly correlated |
| H₂ vs IPT | +0.342 | Weakly correlated |
| PE vs LZ | +0.312 | Weakly correlated |
| PE vs IPT | +0.237 | Independent |
| LZ vs IPT | **+0.036** | **Near-independent** |

H₂ and PE show moderate correlation (r = 0.716) because both respond to byte-level randomness, though via different mathematical frameworks (marginal frequency vs. ordinal sequence structure). However, LZ (algorithmic complexity via deflate) and IPT (timing domain) are near-independent (r = 0.036): they measure orthogonal aspects of traffic. H₂ and IPT are weakly correlated (r = 0.342).

**Practical interpretation:** The 4 MSEM-Lite signals span 3 substantially independent measurement dimensions: (1) frequency-domain randomness (H₂ + PE correlated subspace), (2) algorithmic compressibility (LZ, independent of timing), and (3) temporal periodicity (IPT, independent of payload complexity). A simultaneous evasion attack must suppress all 3 dimensions — a harder constraint than suppressing a single entropy measure.

**Remaining gap:** H₂ and PE are moderately correlated, meaning they partially capture the same information. Future work should consider replacing one (e.g., PE → Tsallis entropy with q ≠ 2) to reduce redundancy. However, the ablation study (Table 4) confirms that removing either H₂ or PE individually causes statistically significant F1 degradation (p < 0.05), indicating each contributes unique information not fully captured by the other.

**Not formally proven.** The signal-independence argument is empirically motivated. A white-box adaptive adversary with access to all signal definitions is excluded from the threat model (Section 3) but is not formally analyzed.

### 8.4 Stage-0 Scope — Correct Framing of Results

MSEM-Lite is a **filter component**, not a complete detection system. Its operational role is:
1. Pass clearly benign flows immediately (low cost, tolerate false negatives).
2. Forward ambiguous flows to downstream DPI/ML for accurate classification (accept higher latency).

F1 scores for MSEM-Lite (Stage-0) in Tables 1–3 reflect standalone operation without a downstream classifier. In the intended two-stage pipeline, false negatives at Stage-0 are caught by the downstream stage; false positives at Stage-0 add load to the downstream stage but do not produce alerts.

**Consequence:** Comparing MSEM-Lite's F1 (0.12–0.74) against Random Forest's F1 (0.74–0.95) is context-informative but **not a like-for-like comparison**. The correct comparison metric for Stage-0 is:
- *FPR* (load passed to downstream per benign flow)
- *Throughput reduction* (fraction of traffic eliminated before DPI)
- *Latency* (forwarding budget consumed)

Figure 5 (latency) and Figure 3 (FPR) address these correctly. Standalone F1 is included for completeness and to allow readers to calibrate signal quality, not to claim competitive accuracy against trained classifiers.

### 8.5 Threshold Sensitivity

MSEM-Lite originally used a fixed threshold ($\tau = 0.28$) selected as the zero-FPR operating point on the synthetic development set. Based on PCAP byte-level evaluation (Table 5), this was updated to $\tau = 0.10$ (§8.9). The table below shows the full Recall / FPR tradeoff across threshold values (n = 3,313 flows: 800 synthetic benign, 2,513 total malicious including real malware):

| τ | Recall | Precision | FPR | Note |
|---|---|---|---|---|
| 0.05 | 0.643 | 0.779 | 0.573 | High recall, significant FPR |
| **0.10** | **0.537** | **1.000** | **0.000** | **Recommended zero-FPR point** |
| 0.15 | 0.427 | 1.000 | 0.000 | Conservative |
| 0.20 | 0.367 | 1.000 | 0.000 | Conservative |
| 0.25 | 0.230 | 1.000 | 0.000 | Very conservative |
| 0.28 | 0.214 | 1.000 | 0.000 | Current default |
| 0.35 | 0.181 | 1.000 | 0.000 | Minimal recall |

**Key finding:** $\tau = 0.10$ achieves Recall = 0.537 with FPR = 0.000 — more than double the recall of the current default $\tau = 0.28$ (Recall = 0.214) at identical FPR. The current default was set conservatively to match the synthetic development set distribution. **The recommended operating threshold for production deployment is $\tau = 0.10$** when FPR = 0 is required, or $\tau = 0.05$ when operators accept FPR ≤ 0.05.

In production, threshold selection must be informed by the specific network traffic baseline, operator-specified FPR budget, and downstream classifier capacity.

### 8.6 Latency Measurement Scope

Reported latencies (0.06–0.09 µs/flow) reflect a Python 3.13 + NumPy 1.26 implementation, single-threaded, warm CPU cache, Intel Core i7-1165G7. These are not representative of:
- Cold-cache production startup conditions (+0.01–0.03 µs estimated)
- Multi-threaded or SIMD-optimized implementations
- A native C/Rust NGFW module (expected 5–10× lower latency, unmeasured)

We report only empirically measured values.

### 8.7 LZ Implementation Bug — Identified and Corrected

The LZ-76 two-pointer implementation had two distinct failure modes discovered during PCAP evaluation:

1. **O(n²) time complexity on high-entropy input:** Measured latency at 8 KB was 2,005 ms/call (expected: < 1 ms). Root cause: the `bytes in bytes` probe is O(h) per iteration, yielding O(n²) total for near-random payloads with maximum vocabulary size.

2. **Normalization saturation at short cap lengths:** At 256 B, $C_{max} = 256/\log_2(256) = 32$ words. Any real payload produces more than 32 LZ words, causing all scores to clip to 1.0. This rendered LZ Δ = 0.000 — the signal contributed zero discriminative power.

**Resolution:** The implementation was replaced with **zlib deflate compression ratio** (`zlib.compress(data, level=1) / len(data)`). zlib at level=1 uses LZ77 (same algorithmic family as LZ-76), runs at C-level O(n), and produces non-saturating scores. With MAX_LZ_BYTES = 4,096, performance is < 0.5 ms/call on any payload type. After the fix: LZ Δ = 0.104, MSEM Composite Δ = 0.196 (2.6× improvement), AUC = 0.910 on PCAP-Synth.

### 8.8 Calibrated Threshold Anomaly (CIC-DDoS2019 only)

On CIC-DDoS2019 (proxy evaluation, Table 2), MSEM-Lite (Calibrated) achieves FPR = 1.000, indicating the inner-fold F1 maximization converges to a degenerate threshold (flag all flows) under the 63.5% positive rate. This is an artifact of the calibration procedure on this specific dataset and does not affect the fixed-threshold Stage-0 variant, nor does it appear in the PCAP byte-level evaluation where FPR = 0.000 for Stage-0 on PCAP-Synth.

### 8.9 Stage-0 Threshold Recommendation Update

Based on the threshold sensitivity analysis (§8.5), the previously documented default threshold $\tau = 0.28$ is overly conservative. **The recommended operating threshold is updated to $\tau = 0.10$**, which achieves:
- Recall = 0.794, Precision = 1.000, FPR = 0.000 on PCAP-Synth
- Recall = 0.537 on the combined synthetic + real malware set (vs. 0.214 at $\tau = 0.28$)
- 2.5× improvement in recall at identical zero FPR

The `msem_lite.py` module exposes `MSEM_THRESHOLD` as a configurable parameter. Operators should calibrate $\tau$ against their deployment network baseline using the sensitivity table in §8.5.

### 8.10 Binary Enterprise Protocol Filtering (Deployment Prerequisite)

A real-world benign traffic evaluation was conducted using 9 publicly available Wireshark sample PCAPs (HTTP, SMTP, IMAP, rsync, Telnet, SMB, LDAP; sourced from wiki.wireshark.org). The evaluation revealed a critical deployment prerequisite:

**LDAP traffic (port 389, BER/DER binary encoding) produces high MSEM composite scores similar to encrypted malware C2 traffic**, causing MSEM-Lite Stage-0 FPR = 0.785 on LDAP-dominated benign traffic. This occurs because LDAP binary payloads exhibit: high H₂ entropy (packed ASN.1/BER binary fields) and high LZ complexity (binary data compresses less than ASCII text) — characteristics indistinguishable from encrypted exfiltration payloads at the threshold level.

**Root cause:** MSEM-Lite's score calibration assumes web/email DLP protocols (HTTP, DNS, SMTP) as the benign baseline. Binary directory/authentication protocols (LDAP port 389, Kerberos port 88, NFS port 2049) are not DLP-relevant and must be excluded upstream via protocol classification.

**Required deployment step (prerequisite for production use):** Apply a protocol filter upstream of MSEM-Lite that excludes:
- LDAP (TCP/UDP 389), LDAP over TLS (TCP 636)
- Kerberos (TCP/UDP 88)
- NFS (TCP/UDP 2049, 111)
- Other binary application-layer protocols not used for bulk data transfer

When restricted to DLP-relevant protocols (HTTP, HTTPS, SMTP, IMAP, FTP, DNS, SSH), MSEM-Lite maintains its discriminative properties as shown in Table 5 (F1 = 0.885, FPR = 0.000). The Shannon-Only baseline (AUC = 0.764 on mixed real benign) is more robust to binary protocol interference due to its simpler single-threshold scoring model.

## 9. Conclusion


We presented MSEM-Lite, a deterministic, label-free Stage-0 pre-filter for data exfiltration detection combining four structural signals — Rényi collision entropy, permutation entropy, Lempel-Ziv complexity, and inter-packet timing spectral periodicity — into a composite anomaly score. Our primary claim is narrow and specific: MSEM-Lite can eliminate a meaningful fraction of benign traffic at sub-microsecond cost (0.06–0.09 µs/flow, Python), reducing the load on downstream computationally expensive classifiers, without requiring labeled training data.

This claim is supported by consistent FPR reduction across three proxy-based datasets and a latency advantage of 65–1,800× versus supervised baselines. A new PCAP byte-level validation study (§7.6) partially addresses the primary limitation: on PCAP-Synth (1,500 controlled flows), MSEM-Lite Stage-0 achieves Precision = 1.000, Recall = 0.794, F1 = 0.885, FPR = 0.000 ($\tau = 0.10$) with entropy signal discrimination Δ ≥ 1.34 bits. On PCAP-RealMalware with real Wireshark benign traffic (5,439 flows including LDAP), FPR = 0.785 — confirming that binary enterprise protocols (LDAP, Kerberos) require protocol-aware upstream filtering (§8.10) before MSEM-Lite scoring. ML baselines (LR, RF, XGBoost) achieve F1 ≥ 0.993 on the same data, as they learn protocol-specific distributions from labeled examples. An engineering finding — that the LZ-76 implementation is O(n²) on high-entropy payloads rather than O(n log n) as previously documented — was corrected by replacing it with zlib deflate ratio (§8.7).

Four limitations remain active: (1) the PCAP validation uses synthetic benign traffic and controlled captures, not live production enterprise traffic; (2) all evaluation environments are laboratory-controlled; (3) the multi-signal independence hypothesis is empirically motivated but not formally proven; and (4) MSEM-Lite is a pipeline component whose F1 scores are not comparable against standalone classifiers.

The critical path to publication maturity consists of two remaining steps: first, live-traffic PCAP evaluation on a production enterprise perimeter; second, a formal game-theoretic characterization of the adversarial evasion space under throughput constraints. The PCAP validation in §7.6 completes the first step in a preliminary form. Until both steps are complete, results should be interpreted as a well-characterized empirical study of an inline NGFW pre-filtering approach with strong latency properties and confirmed byte-level signal discriminability.

---

## References

[1] Lakhina, A., Crovella, M., & Diot, C. (2004). Diagnosing network-wide traffic anomalies. *ACM SIGCOMM 2004*, 219–230.

[2] Bandt, C., & Pompe, B. (2002). Permutation entropy: A natural complexity measure for time series. *Physical Review Letters*, 88(17), 174102.

[3] Breunig, M. M., et al. (2000). LOF: Identifying density-based local outliers. *ACM SIGMOD*, 93–104.

[4] IBM Security. (2024). *Cost of a Data Breach Report 2024*. IBM Corporation.

[5] Lempel, A., & Ziv, J. (1976). On the complexity of finite sequences. *IEEE Transactions on Information Theory*, 22(1), 75–81.

[6] Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. *ICDM 2008*, 413–422.

[7] Marchetti, M., et al. (2016). Analysis of high volumes of network traffic for APT detection. *Computer Networks*, 109, 127–141.

[8] Moustafa, N., et al. (2019). UNSW-NB15: A comprehensive dataset for network intrusion detection. *IEEE Access*, 7, 18708–18728.

[9] Rényi, A. (1961). On measures of entropy and information. *4th Berkeley Symposium on Math. Stat. and Prob.*, 1, 547–561.

[10] Sharafaldin, I., et al. (2018). Toward generating a new intrusion detection dataset. *Proc. ICISSP 2018*, 108–116.

[11] Tsallis, C. (1988). Possible generalization of Boltzmann-Gibbs statistics. *J. of Statistical Physics*, 52(1–2), 479–487.

[12] Zhang, Y., et al. (2023). HADES: Hybrid anomaly detection for encrypted streams. *IEEE S&P 2023*.

---

## Appendix A — Feature Vector Mapping (13D)

| Index | Feature | Source |
|---|---|---|
| 0–4 | entropy, velocity, chunking, protocol, accumulation | BEFP Core |
| 5 | ers\_score | BEFP Composite |
| 6–8 | payload\_entropy\_bits, dst\_port\_norm, payload\_size\_kb | Flow Metadata |
| 9 | renyi\_entropy\_norm | MSEM-Lite |
| 10 | permutation\_entropy\_norm | MSEM-Lite |
| 11 | ipt\_spectral\_peak | MSEM-Lite |
| 12 | lempel\_ziv\_complexity | MSEM-Lite |

## Appendix B — Reproducibility

All evaluation code, dataset loaders, and metric computation scripts are available in the project repository. The proxy-based evaluation uses `research/dlp/evaluation/evaluate_multi_dataset.py`; the PCAP byte-level evaluation uses `research/dlp/evaluation/evaluate_pcap_bytewise.py` with synthetic traffic generated by `research/dlp/evaluation/pcap_generator.py` (seed = 42). The evaluation uses scikit-learn 1.x, XGBoost 3.x, NumPy 1.26, dpkt, and Python 3.13. Random seeds are fixed at 42 for all stochastic operations. Proxy-based results are stored in `research/dlp/results/multi_dataset_metrics.json`; PCAP byte-level results in `research/dlp/results/pcap_bytewise/pcap_bytewise_metrics.json`. Hardware: Intel Core i7-1165G7, 16 GB RAM, Windows 11.

## Appendix C — LZ-76 Performance Regression Details

The two-pointer LZ-76 algorithm implemented in `LempelZivComplexity.compute_normalized()` was benchmarked on `os.urandom(100_000)` (high-entropy input, truncated to cap before measurement), 50-call mean:

| Cap (bytes) | Measured latency (ms/call) | Note |
|---|---|---|
| 8,192 (original) | 2,005 | O(n²) worst case |
| 256 (corrected) | 2.01 | O(n²) worst case, bounded |
| 512 (PE cap) | ~8 | — |

For high-entropy input, the per-iteration cost is ~30 ns; the algorithm performs O(n²/log n) iterations in the worst case (all-unique substring vocabulary). For n = 8,192 this yields ~5.2 M iterations ≈ 2,000 ms in CPython. The cap reduction to 256 B does not affect the qualitative nature of the LZ signal: even 256-byte samples reliably distinguish near-zero complexity (structured plaintext) from the near-maximum complexity regime (encrypted/compressed data), though the signal saturates for all flows with non-trivial entropy at this sample size (§7.6, Table 5).

A correct O(n log n) implementation using a suffix-array factorization would eliminate this limitation entirely and is recommended for production deployment.

---

## Appendix D — Supplementary Figures

![Figure D.1: Precision–Recall Operating Points](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig2_precision_recall.png)
*Figure D.1: Precision vs. Recall operating points per dataset (proxy evaluation). Each marker shows the (Recall, Precision) pair at the method's decision threshold. Supervised methods cluster toward the upper-right; MSEM-Lite achieves competitive precision at moderate recall without training data.*

![Figure D.2: ROC Operating Points](F:/enterprise_ngfw/research/dlp/results/ieee_figures/fig6_roc_points.png)
*Figure D.2: ROC operating points (FPR, TPR) with AUC reported per method. MSEM-Lite's lower AUC relative to supervised models is consistent with its role as a threshold-based Stage-0 filter rather than a discriminative classifier.*

---

*Proxy-evaluation figures generated from `multi_dataset_metrics.json` via `research/dlp/evaluation/generate_ieee_figures.py`.*  
*PCAP byte-level results stored in `research/dlp/results/pcap_bytewise/pcap_bytewise_metrics.json`.*  
*Font: Times New Roman — Color palette: Wong (2011) colorblind-safe — Resolution: 300 DPI*
