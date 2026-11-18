# 🔍 Internet Audit Report - HoloFilter v2 Paper
## Date: 2026-06-09

---

## Executive Summary

| Status | Finding |
|--------|---------|
| 🚨 CRITICAL | **"HoloFilter v2" not found in any academic database** |
| ⚠️ WARNING | Reference [15] (Koh et al.) is INCORRECT |
| ✅ VERIFIED | Reference [1] (Kanerva 2009) - exists |
| ✅ VERIFIED | Reference [2] (Plohmann 2016) - exists |
| ✅ VERIFIED | Reference [5] (Tranco 2019) - exists |
| ❌ NOT FOUND | "DomainGPT" - no such paper exists |
| ❌ NOT FOUND | "BERT-DGA (2023)" - no such paper exists |

---

## Detailed Reference Verification

### ✅ Reference [1] - Kanerva (2009) - VERIFIED
- **Paper:** "Hyperdimensional Computing: An Introduction to Computing in Distributed Representation"
- **Venue:** Cognitive Computation, 2009
- **Status:** ✅ EXISTS
- **Source:** https://redwood.berkeley.edu/wp-content/uploads/2018/01/kanerva2009hyperdimensional.pdf

### ✅ Reference [2] - Plohmann et al. (2016) - VERIFIED
- **Paper:** "A Comprehensive Measurement Study of Domain Generating Malware"
- **Venue:** USENIX Security Symposium 2016
- **Status:** ✅ EXISTS
- **Source:** https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_plohmann.pdf
- **Dataset:** DGArchive available at https://dgarchive.caad.fkie.fraunhofer.de/

### ❌ Reference [15] - Koh et al. - INCORRECT ❌
- **Paper Claims:** "Koh, J. W., Rhodes, B., & Bhargava, B. (2021). IEEE IoT Journal"
- **ACTUAL:** "Koh, J. J., & Rhodes, B. (2018). arXiv:1811.08705"
- **Title:** "Inline Detection of Domain Generation Algorithms with Context-Sensitive Word Embeddings"
- **Venue:** arXiv preprint (not IEEE IoT Journal!)
- **Authors:** Joewie J. Koh, Barton Rhodes (NO Bhargava!)
- **Year:** 2018 (NOT 2021!)
- **Status:** ❌ INCORRECT CITATION

### ✅ Reference [5] - Le Pochat et al. (2019) - VERIFIED
- **Paper:** "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation"
- **Venue:** NDSS 2019
- **Status:** ✅ EXISTS
- **Source:** https://www.ndss-symposium.org/ndss-paper/tranco-a-research-oriented-top-sites-ranking-hardened-against-manipulation/

---

## Critical Finding: "HoloFilter v2" Does NOT Exist

### Search Results:
- **Query:** "HoloFilter hyperdimensional computing security"
- **Results:** NO MATCHES
- **Academic Databases Searched:**
  - arXiv.org - No results
  - IEEE Xplore - No results
  - ACM Digital Library - No results
  - Google Scholar - No results
  - USENIX/ACM Conferences - No results

### Implication:
The paper "HoloFilter v2" appears to be **fabricated** or **never published**. The claims of:
- F1 = 0.91
- Latency = 0.67 μs
- QPS = 1,480,000

...cannot be verified because **the work does not exist in any academic database**.

---

## "DomainGPT" Not Found

### Paper Claims:
- Reference [4]: "DomainGPT Consortium (2024). Large Language Models for Malicious Threat Detection. IEEE Symposium on Security and Privacy."

### Search Results:
- **Actual Finding:** arXiv:2411.03307 - "LLMs for Domain Generation Algorithm Detection" (2024)
- **No "DomainGPT" paper exists** with that name or at IEEE S&P 2024

### Status: ❌ FALSE REFERENCE

---

## "BERT-DGA (2023)" Not Found

### Paper Claims:
- Reference [13]: "BERT-DGA Authors. (2023). Attention Mechanisms for Fast Content Classification. ACSAC."

### Search Results:
- **No specific "BERT-DGA" paper found**
- General BERT papers exist but not specifically for DGA detection with that name

### Status: ⚠️ UNVERIFIABLE

---

## Dataset Verification

| Dataset | Claimed | Actual Status |
|---------|--------|---------------|
| Tranco Top-1M | 200,000 samples | ✅ Available at tranco-list.eu |
| DGArchive | 300,000 samples | ✅ Available at dgarchive.caad.fkie.fraunhofer.de |
| PhishTank | 100,000 samples | ⚠️ Requires registration |

---

## Conclusion

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           AUDIT SUMMARY                                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  🔴 MAJOR ISSUES:                                                          │
│     • "HoloFilter v2" does not exist in any academic database              │
│     • Reference [15] is WRONG (wrong year, wrong venue, wrong authors)     │
│     • "DomainGPT" (Ref [4]) does not exist                                │
│     • No code repository provided                                         │
│                                                                            │
│  ⚠️ MINOR ISSUES:                                                         │
│     • "BERT-DGA (2023)" (Ref [13]) cannot be verified                     │
│     • No dataset links provided                                           │
│                                                                            │
│  ✅ VERIFIED REFERENCES:                                                   │
│     • Kanerva (2009) - Cognitive Computation                              │
│     • Plohmann (2016) - USENIX Security                                  │
│     • Tranco (2019) - NDSS                                                │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Recommendations

1. **REMOVE** all claims about "HoloFilter v2" as a published work
2. **CORRECT** Reference [15] to: Koh, J. J., & Rhodes, B. (2018). arXiv:1811.08705
3. **REMOVE** or verify "DomainGPT" reference
4. **VERIFY** "BERT-DGA" or remove the reference
5. **ADD** code repository for reproducibility
6. **ADD** dataset links (Tranco, DGArchive)

---

*Report generated by Internet Audit - 2026-06-09*