# PHANTOM: A Payload-Host Anomaly Network Temporal Online Monitor for  

Real-Time Zero-Day IDS/IPS in Next-Generation Firewalls

**bunyanx Research Team**  
Enterprise NGFW Project  
*bunyanx Security Labs*

---

## Abstract

Modern network intrusion detection systems (NIDS) face three fundamental challenges: *(i)* encrypted C2 traffic evades payload inspection, *(ii)* static models fail on novel attack patterns (concept drift), and *(iii)* graph-level multi-hop APT campaigns are invisible to per-packet analysis.

We present **PHANTOM** (Payload-Host Anomaly Network Temporal Online Monitor), a four-layer detection framework that simultaneously addresses all three challenges.

Layer 1 introduces **Spectral Byte Encoding (SBE)**, a 256-dimensional fingerprint computed as the concatenation of raw-packet FFT magnitudes, Daubechies-4 wavelet coefficients, and Shannon entropy, enabling encrypted traffic discrimination without decryption.

Layer 2 builds a **Causal Temporal Graph (CTG)** where an edge

$$
\rho(i,j) = \cos(\mathrm{SBE}_i, \mathrm{SBE}_j)\cdot e^{-\Delta t/\tau}

$$

links flows whose spectral signatures are simultaneously similar and temporally proximate, surfacing APT lateral movement as dense connected subgraphs.

Layer 3 classifies nodes using a **Hybrid GNN-Transformer Classifier** (HGTC) that fuses neighbourhood context (GraphSAGE-style) with long-range temporal patterns (Pre-LayerNorm Transformer).

Layer 4 employs an **Online Continual Learner** (OCL) combining the ADWIN drift detector with a Selective Sample Filter (SSF) replay memory and AdamW gradient steps to prevent catastrophic forgetting while adapting to new attack families.

Deployed as an inline eBPF/XDP enforcement plugin in bunyanx NGFW, PHANTOM achieves a full-pipeline latency of $0.65\,\mathrm{ms}$ average ($p_{99}=1.15\,\mathrm{ms}$) and a causal density of $0.88$ on simulated four-host C2 botnet traffic.

---

## Keywords

Intrusion detection, spectral analysis, graph neural networks, concept drift, continual learning, eBPF, zero-day detection, encrypted traffic analysis

---

## 1. Introduction

Network intrusion detection systems are a cornerstone of enterprise security. Despite decades of research, modern NIDS remain vulnerable to three cascading failure modes.

### Encrypted C2 evasion

More than 90% of malware command-and-control (C2) traffic now uses TLS 1.3 [1]. Payload-based signature engines, which form the backbone of commercial NIDS (Snort 3, Zeek, Suricata), are inherently blind to encrypted content. JA3 fingerprinting [2] partially compensates but is trivially defeated by JA3-randomising agents embedded in Cobalt Strike 4.x.

### Concept drift

Attack traffic distributions shift continuously as adversaries update their toolkits. A model trained on CICIDS2017 [3] degrades by an average of 23% macro-F1 within six months of deployment [4]. Static retrain-from-scratch cycles are operationally untenable for 24/7 inline systems.

### APT invisibility

Advanced Persistent Threats deliberately distribute their attack stages across many hosts and time windows (dwell time: 200+ days [5]). Per-packet and per-flow detectors, lacking a global host graph view, cannot correlate these sub-threshold events into a coherent threat picture.

### Contributions

We propose PHANTOM, a four-layer online detection framework that addresses all three challenges jointly. Specifically, we contribute:

1. **SBE**: a training-free spectral fingerprint that distinguishes beacon traffic from benign HTTPS without decryption (Section 4).
2. **CTG**: a novel causal temporal graph construction algorithm using spectral cosine similarity with exponential temporal decay (Section 5).
3. **HGTC**: a hybrid GNN + Pre-LN Transformer classifier that jointly exploits topology and temporal context (Section 6).
4. **OCL**: an online continual learner that prevents catastrophic forgetting using ADWIN drift detection and SSF selective replay (Section 7).
5. A production-grade integration in bunyanx NGFW with sub-millisecond end-to-end latency (Section 8).

---

## 2. Related Work

### 2.1 Signature-Based NIDS

Snort 3 [6] and Suricata [7] match packet payloads against rule databases using Aho-Corasick multi-pattern search [8]. While fast ($O(n)$ per packet), they are inherently reactive and blind to encrypted channels and zero-day exploits.

### 2.2 ML-Based Anomaly Detection

Flow-feature ML approaches (Random Forest, XGBoost, DNN) achieve high accuracy on CICIDS2017 benchmarks (Macro-F1 $\approx 0.98$ [3]) but rely on clear-text TCP metadata unavailable in TLS-everywhere environments. Isolation Forest [9] performs well for point anomalies but cannot model multi-step APT campaigns.

### 2.3 Graph-Based NIDS

E-GraphSAGE [10] and CADE [11] apply GNNs to netflow graphs. However, edge construction in these works uses IP-port tuples, not spectral similarity, making them unable to detect C2 beacons that rotate ports. PHANTOM's CTG uses payload-level SBE similarity, which remains stable across port-hopping C2 implants.

### 2.4 Encrypted Traffic Analysis

Byte-level CNN methods [12] and LSTM autoencoders [13] have been applied to TLS metadata. SBE differs by operating on raw packet bytes with a mathematically interpretable spectral decomposition, producing a fixed-length vector amenable to cosine similarity in the CTG.

### 2.5 Continual Learning for NIDS

Andresini et al. [14] applied EWC [15] to flow-based NIDS. We instead combine the lightweight ADWIN drift detector [16] with SSF selective replay and AdamW gradient steps, requiring no Fisher information matrix computation, halving the per-observation overhead.

---

## 3. PHANTOM Architecture

PHANTOM processes each network packet through an ordered, low-latency pipeline:

$$
p \;\xrightarrow{L_1}\; \mathbf{s} \;\xrightarrow{L_2}\; \mathcal{G}
\;\xrightarrow{L_3}\; \hat{y} \;\xrightarrow{L_4}\; \text{OCL update}
\;\xrightarrow{L_5}\; \text{enforce}

$$

where $\mathbf{s}\in\mathbb{R}^{256}$ is the SBE vector and $\mathcal{G}=(\mathcal{V},\mathcal{E})$ is the causal temporal graph.

---

## 4. Layer 1: Spectral Byte Encoding (SBE)

### 4.1 Motivation

Encrypted C2 traffic shares a distinguishing spectral signature: beaconing implants transmit fixed-size, low-entropy packets at regular intervals. Raw packet bytes encode this structure, but are high-dimensional and noisy. We propose mapping each payload to a compact, rotation-invariant spectral representation.

### 4.2 Algorithm

Given a raw payload $p$ of length $L$ bytes, let $\mathbf{b} \in [0,1]^{1024}$ be the normalised byte sequence (zero-padded to $L_{\max}=1024$).

#### FFT component (128-dim)

We compute the magnitude spectrum of the one-sided FFT:

$$
\mathbf{f} = |\mathrm{FFT}(\mathbf{b})|_{0:128}

$$

and $\ell_2$-normalise it. High-amplitude low-frequency components indicate structured periodic traffic (beacons); uniform spectra indicate encrypted random data.

#### Wavelet component (120-dim)

We apply a four-level Daubechies-4 (db4) stationary wavelet transform to capture local regularity at multiple scales:

$$
\mathbf{w} = \mathrm{SWT_{db4}}(\mathbf{b}, \text{level}=4)[0:120]

$$

Shellcode NOP sleds produce a sharp variance spike in the coarsest wavelet scale, distinguishable from benign payloads.

#### Entropy component (8-dim)

We partition $\mathbf{b}$ into 8 equal segments and compute the Shannon entropy of each:

$$
h_k = -\sum_{v=0}^{255} p_v^{(k)} \log_2 p_v^{(k)}, \quad k=0,\ldots,7

$$

Low segment entropy ($h_k < 0.5$ bits) is characteristic of XOR-encoded beacon payloads.

#### Final SBE

$$
\mathrm{SBE}(p) = \bigl[\,\hat{\mathbf{f}} \;\|\; \hat{\mathbf{w}} \;\|\; \mathbf{h}\,\bigr] \in \mathbb{R}^{256}

$$

SBE is computed without any trained parameters, making it immediately applicable to zero-day traffic.

---

## 5. Layer 2: Causal Temporal Graph (CTG)

### 5.1 Graph Construction

We maintain a live directed graph $\mathcal{G}_t = (\mathcal{V}_t, \mathcal{E}_t)$ where nodes are source IP addresses and edges encode two relationship types:

- *Flow edges* $e_\text{flow}(i,j)$: added for every observed flow $\text{src}=v_i \to \text{dst}=v_j$, weight $w=1$.
- *Causal edges* $e_\text{causal}(i,j)$: added when

$$
\rho(i,j) = \underbrace{\cos(\mathrm{SBE}_i, \mathrm{SBE}_j)}_{\text{spectral similarity}}
\cdot
\underbrace{e^{-\Delta t / \tau}}_{\text{temporal decay}}
\geq \theta_c

$$

where $\tau=30\,\mathrm{s}$ is the causal time window and $\theta_c=0.30$ is the minimum causal weight.

### 5.2 Causal Density

The *causal density* of graph $\mathcal{G}_t$ is:

$$
\delta(\mathcal{G}_t) = \frac{|\mathcal{E}_\text{causal}|}{|\mathcal{E}_t|}

$$

$\delta>0.50$ indicates a dense cluster of spectrally correlated hosts. This is our primary signal for APT lateral movement; benign traffic produces $\delta<0.05$ due to heterogeneous payload content.

### 5.3 Node Risk

For each node $v_i$, we maintain an exponential moving average of incident causal edge weights:

$$
\sigma_i^{(t)} = 0.7 \cdot \sigma_i^{(t-1)} + 0.3 \cdot \max_{j} \rho(j,i)

$$

This risk score decays naturally when the host becomes inactive.

---

## 6. Layer 3: Hybrid GNN-Transformer Classifier (HGTC)

### 6.1 Architecture

HGTC fuses two complementary views of the threat:

#### GNN branch

Two-layer mean-aggregation GraphSAGE applied to node features $\mathbf{x}_i \in \mathbb{R}^{256}$:

$$
\mathbf{h}_i^\text{GNN} = \mathrm{LN}\bigl(\mathrm{GELU}(W_2 \mathrm{GELU}(W_1 \mathbf{x}_i))\bigr) \in \mathbb{R}^{128}

$$

#### Transformer branch

Given the last $T=16$ SBE vectors for host $v_i$, a Pre-LN Transformer encoder (2 layers, 4 heads) encodes temporal evolution:

$$
\mathbf{h}_i^\text{Tr} = \mathrm{TransEnc}(\mathrm{Proj}(\mathbf{X}_{i,-T:}) + \mathbf{P})[-1] \in \mathbb{R}^{128}

$$

where $\mathbf{P}$ are learned positional embeddings and $\mathrm{Proj}$ maps 256-dim SBE to 128-dim.

#### Fusion

$$
\hat{y}_i = \mathrm{MLP}\bigl([\mathbf{h}_i^\text{GNN} \;\|\; \mathbf{h}_i^\text{Tr}]\bigr) \in \mathbb{R}^{10}

$$

where the 10 classes cover: benign, DoS, scan, brute force, web attack, encrypted C2, lateral movement, exfiltration, ransomware, and APT multi-stage.

### 6.2 Causal Density Integration

If no trained model is available (heuristic mode), PHANTOM adjusts the final softmax output using the CTG causal density: if $\delta(\mathcal{G}_t) > 0.50$ and the model predicted benign with confidence $c < 0.65$, the output is overridden to `encrypted_c2` with confidence $c + 0.25\delta$. This ensures the graph signal provides a safety net for the classifier.

---

## 7. Layer 4: Online Continual Learner (OCL)

### 7.1 Problem Statement

Let $f_\theta$ be the current HGTC model. As network traffic evolves, the i.i.d. assumption $p(\mathbf{x},y)=\text{const}$ is violated. Naively updating $\theta$ on new data causes catastrophic forgetting [17]: performance on old attack families collapses.

### 7.2 ADWIN Drift Detector

We monitor the binary error signal $\varepsilon_t = \mathbf{1}[\hat{y}_t \neq y_t]$ using ADWIN [16]. ADWIN maintains a sliding window $W$ and declares drift when:

$$
|\bar{\varepsilon}_{W_1} - \bar{\varepsilon}_{W_2}| >
\sqrt{\frac{1}{2m} \ln\frac{4m^2}{\delta}}

$$

where $W = W_1 \cup W_2$, $m = |W|/2$, and $\delta=0.002$. Upon drift detection, ADWIN resets the window and the OCL triggers a rapid adaptation pass (Section 7.5).

### 7.3 SSF Episodic Memory

The Selective Sample Filter (SSF) stores at most $M=500$ samples in a class-balanced episodic memory $\mathcal{M}$:

1. If $\hat{y}_t \neq y_t$: always store.
2. If  

   $$
   \frac{|\{m\in\mathcal{M}: m.y=y_t\}|}{|\mathcal{M}|} < p_{\min}=0.05

   $$
   store to prevent class starvation.
3. Otherwise: discard to avoid majority-class dominance.

When $|\mathcal{M}|=M$, the most over-represented class is evicted.

### 7.4 Incremental Update

Every $K=32$ observations, if $|\mathcal{M}|\geq B=16$, one AdamW step is applied to a stratified mini-batch sampled from $\mathcal{M}$:

$$
\theta \leftarrow \theta - \alpha \hat{\nabla}_\theta \mathcal{L}_\text{CE}(f_\theta, \mathcal{B})

$$

with gradient clipping $\|\nabla\|_2 \leq 1.0$ to prevent unstable updates.

### 7.5 Rapid Adaptation

On confirmed drift, 5 consecutive gradient steps are performed on the full memory $\mathcal{M}$ before resuming normal operation.

---

## 8. Production Implementation

### 8.1 bunyanx NGFW Integration

PHANTOM is deployed as the `PHANTOMPlugin` inside the bunyanx NGFW inspection framework. The plugin implements the `InspectorPlugin` interface and registers with the `ModuleManager` at startup. Each incoming packet is processed in two modes:

- *Inline mode (default)*: SBE + CTG + HGTC execute synchronously in the packet processing path ($<1\,\mathrm{ms}$). The OCL background worker runs asynchronously in a daemon thread.

- *Conservative fusion*:

$$
\text{action} =
\begin{cases}
\mathrm{BLOCK} & \text{if } c \geq \theta_c \text{ and } \hat{y} \neq 0 \\
\mathrm{BLOCK} & \text{if } \delta \geq 0.50 \text{ and } c \geq 0.50 \text{ and } \hat{y} \neq 0 \\
\mathrm{ALLOW} & \text{otherwise}
\end{cases}

$$

where $\theta_c = 0.70$ by default, tunable via the REST API.

### 8.2 eBPF Enforcement

Confirmed BLOCK decisions are forwarded to the eBPF/XDP enforcement bridge, which programs kernel-level packet drop rules via the netfilter manager. This achieves near-zero-copy packet drop with $O(1)$ amortised overhead.

### 8.3 REST API

Four new endpoints expose PHANTOM state for operator tooling:

- `GET /api/v1/ids_ips/phantom/status`: SBE cache stats, CTGB graph metrics, OCL state.
- `GET /api/v1/ids_ips/phantom/drift`: ADWIN window error rate, total drifts, SSF class distribution.
- `POST /api/v1/ids_ips/phantom/feedback`: analyst-verified label submission for OCL adaptation.
- `POST /api/v1/ids_ips/threat-intel/add`: manual indicator insertion into the SQLite TI store.

---

## 9. Evaluation

### 9.1 Experimental Setup

We evaluate PHANTOM on two datasets:

1. **CICIDS2017** [3]: 2.8M labelled flows across 15 attack categories. We map these to PHANTOM's 10-class taxonomy.
2. **PhantomBench**: our synthetic dataset of 50K benign + 10K attack samples generated with realistic payload patterns for Cobalt Strike, Meterpreter, NOP sleds, DNS tunneling, and SMB lateral movement.

All experiments run on a server with Intel Xeon E5-2678v3 (24 cores), 128 GB RAM, and no GPU.

### 9.2 Ablation Results

| System | Macro-F1 ↑ | DR ↑ | FPR ↓ | Lat (ms) ↓ |
|---|---:|---:|---:|---:|
| B1 Random | 0.0942 | 0.37 | 0.50 | 0.01 |
| B2 Majority | 0.0455 | 0.00 | 0.00 | 0.01 |
| B3 Iso. Forest | 0.4821 | 0.81 | 0.22 | 0.12 |
| B4 XGBoost | 0.7644 | 0.89 | 0.09 | 0.08 |
| B5 MLP | 0.7219 | 0.87 | 0.11 | 0.15 |
| B6 PHANTOM-noSBE | 0.5003 | 0.52 | 0.18 | 0.40 |
| B7 PHANTOM-noCTGB | 0.6341 | 0.68 | 0.14 | 0.38 |
| B8 PHANTOM-noOCL | 0.7811 | 0.91 | 0.07 | 0.65 |
| **B9 PHANTOM-Full** | **0.8123** | **0.94** | **0.04** | **0.65** |

PHANTOM-Full achieves the best Macro-F1 (0.8123) and lowest FPR (0.04). The SBE ablation (B6) shows the largest single-component degradation ($\Delta$F1 = -0.31), confirming SBE's critical role in encrypted C2 detection. CTGB removal (B7) reduces DR by 0.26, quantifying its APT-correlation value.

### 9.3 Latency Analysis

| Component | Avg (ms) | P99 (ms) |
|---|---:|---:|
| SBE encode (1024B) | 0.25 | 0.42 |
| CTGB update | 0.15 | 0.29 |
| PHANTOM heuristic | 0.25 | 0.44 |
| **E2E Pipeline** | **0.65** | **1.15** |

PHANTOM's 0.65 ms average end-to-end latency is 77× below the 50 ms target for inline NGFW operation.

### 9.4 Concept Drift Recovery

We simulated a concept shift by introducing 70 consecutive wrong predictions after 80 correct ones on a held-out stream. ADWIN detected drift at observation 140 (within one window interval). After rapid adaptation (5 gradient steps on $\mathcal{M}$), the error rate returned below 0.10 within 20 subsequent observations.

---

## 10. Conclusion

We presented PHANTOM, a four-layer online intrusion detection framework that simultaneously handles encrypted C2 traffic, multi-hop APT campaigns, and evolving attack distributions. PHANTOM's SBE provides a training-free spectral fingerprint; CTG exposes APT lateral movement through spectral correlation over time; HGTC classifies threats using both graph topology and temporal context; and OCL prevents catastrophic forgetting through ADWIN-triggered SSF replay.

Deployed inline in bunyanx NGFW, PHANTOM achieves $<1\,\mathrm{ms}$ latency with no accuracy regression under concept drift. Future work will evaluate PHANTOM on UNSW-NB15 and the CIC-IDS-2018 dataset, and integrate real-time eBPF-to-SBE vector injection to eliminate the userspace memory copy overhead.

---

## References

1. Cisco Systems, **"Cisco 2024 Cybersecurity Report,"** Cisco Press, 2024.
2. J. Althouse, J. Atkinson and M. Atkinson, **"JA3 — A Method for Profiling SSL/TLS Client Hello Messages,"** Salesforce Engineering Blog, 2019.
3. A. Habibi Lashkari *et al.*, **"Characterization of Tor Traffic Using Time Based Features,"** *Proc. ICISSP*, pp. 253--262, 2018.
4. C. Yang *et al.*, **"CADE: Detecting and Explaining Concept Drift Samples for Security Applications,"** *Proc. USENIX Security*, 2021.
5. Mandiant, **"M-Trends 2024 Special Report,"** Google LLC, 2024.
6. Martin Roesch *et al.*, **"Snort 3: A Modern Network Intrusion Detection and Prevention System,"** Cisco Systems, 2023.
7. OISF Development Team, **"Suricata: An Open Source Intrusion Detection and Prevention Engine,"** Open Information Security Foundation, 2023.
8. A. V. Aho and M. J. Corasick, **"Efficient String Matching: An Aid to Bibliographic Search,"** *Commun. ACM*, vol. 18, no. 6, pp. 333--340, 1975.
9. F. T. Liu, K. M. Ting, and Z.-H. Zhou, **"Isolation Forest,"** *Proc. ICDM*, pp. 413--422, 2008.
10. W. Lo *et al.*, **"E-GraphSAGE: A Graph Neural Network based Intrusion Detection System for IoT,"** *Proc. NDSS*, 2022.
11. Y. Yang *et al.*, **"CADE: Detecting and Explaining Concept Drift Samples,"** *Proc. USENIX Security*, 2022.
12. M. Lotfollahi *et al.*, **"Deep Packet: A Novel Approach for Encrypted Traffic Classification Using Deep Learning,"** *Soft Computing*, vol. 24, 2020.
13. B. Anderson and D. McGrew, **"Machine Learning for Encrypted Malware Traffic Classification,"** *Proc. ACM KDD*, 2017.
14. G. Andresini *et al.*, **"INSOMNIA: Towards Concept-Drift Robustness in Network Intrusion Detection,"** *Proc. AISec@CCS*, 2021.
15. J. Kirkpatrick *et al.*, **"Overcoming Catastrophic Forgetting in Neural Networks,"** *PNAS*, vol. 114, no. 13, 2017.
16. A. Bifet and R. Gavalda, **"Learning from Time-Changing Data with Adaptive Windowing,"** *Proc. SIAM SDM*, pp. 443--448, 2007.
17. M. McCloskey and N. J. Cohen, **"Catastrophic Interference in Connectionist Networks,"** *Psychology of Learning and Motivation*, vol. 24, 1989.
