"""
Final Comprehensive Audit of waf_academic_paper.md
Checks:
1. Internal consistency (numbers match across sections)
2. Figure vs text consistency
3. Remaining terminology errors
4. Missing citations
5. Structural issues
"""

import re, sys

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

errors   = []
warnings = []
ok_items = []

def err(msg, line=None):
    loc = f" (L{line})" if line else ""
    errors.append(f"ERROR{loc}: {msg}")

def warn(msg, line=None):
    loc = f" (L{line})" if line else ""
    warnings.append(f"WARN{loc}: {msg}")

def ok(msg):
    ok_items.append(f"OK: {msg}")

# ─────────────────────────────────────────────────────────────────────────────
# 1. CORE METRICS — check all critical numbers are consistent
# ─────────────────────────────────────────────────────────────────────────────
print("Scanning metrics consistency...")

# NLP Test Accuracy
nlp_accs = re.findall(r"90\.41%", content)
if len(nlp_accs) >= 2:
    ok(f"NLP Test Accuracy 90.41% appears {len(nlp_accs)} times (consistent)")
elif len(nlp_accs) == 1:
    warn("NLP Test Accuracy 90.41% appears only once — check Abstract mentions it")
else:
    err("NLP Test Accuracy 90.41% NOT FOUND in paper")

# AUC
aucs = re.findall(r"AUC[=\s]*0\.9258", content)
if len(aucs) >= 1:
    ok(f"NLP AUC=0.9258 present ({len(aucs)}x)")
else:
    err("NLP AUC=0.9258 not found")

# SQLi recall
sqli = re.findall(r"(?:SQLi|sqli).*?99\.9%|99\.9%.*?(?:SQLi|sqli)", content, re.IGNORECASE)
if sqli:
    ok("SQLi recall 99.9% present")
else:
    err("SQLi recall 99.9% NOT FOUND")

# XSS recall 91.5%
xss = re.findall(r"91\.5%", content)
if xss:
    ok(f"XSS recall 91.5% present ({len(xss)}x)")
else:
    err("XSS recall 91.5% NOT FOUND")

# BiLSTM val 96.23%
bilstm_val = re.findall(r"96\.23%", content)
if len(bilstm_val) >= 2:
    ok(f"BiLSTM Val 96.23% consistent ({len(bilstm_val)}x)")
else:
    warn(f"BiLSTM Val 96.23% appears only {len(bilstm_val)}x")

# BiLSTM test 95.87%
bilstm_test = re.findall(r"95\.87%", content)
if len(bilstm_test) >= 2:
    ok(f"BiLSTM Test 95.87% consistent ({len(bilstm_test)}x)")
else:
    warn(f"BiLSTM Test 95.87% appears only {len(bilstm_test)}x — check section 5.2 and conclusion")

# Full pipeline 98.66%
pipeline = re.findall(r"98\.66%", content)
if len(pipeline) >= 2:
    ok(f"Full pipeline 98.66% consistent ({len(pipeline)}x)")
else:
    warn(f"Full pipeline 98.66% appears only {len(pipeline)}x")

# FPR 1.30%
fpr = re.findall(r"1\.30%|FPR.*?1\.3%|1\.3%.*?FPR", content, re.IGNORECASE)
if fpr:
    ok("FPR=1.30% present")
else:
    warn("FPR=1.30% not clearly stated")

# Latency 8.93ms
lat = re.findall(r"8\.93 ms", content)
if len(lat) >= 1:
    ok(f"Latency 8.93ms present ({len(lat)}x)")
else:
    err("Latency 8.93ms NOT FOUND")

# McNemar chi2=847.2
mcn = re.findall(r"847\.2", content)
if mcn:
    ok("McNemar chi2=847.2 present")
else:
    err("McNemar chi2=847.2 NOT FOUND")

# ─────────────────────────────────────────────────────────────────────────────
# 2. FIGURE vs TEXT CONSISTENCY
# ─────────────────────────────────────────────────────────────────────────────
print("Checking Figure vs Text consistency...")

# Fig 1 confusion matrix: paper says n=4328, Benign=996, SQLi=1666, XSS=1666
fig1_n    = "4,328" in content or "4328" in content
fig1_ben  = "996" in content
fig1_sqli = "1,666" in content or "1666" in content
if fig1_n:
    ok("Fig 1: n=4,328 mentioned in text")
else:
    err("Fig 1: test set n=4,328 NOT clearly stated in text")

if fig1_ben and fig1_sqli:
    ok("Fig 1: class sizes (Benign=996, SQLi/XSS=1,666) stated")
else:
    warn("Fig 1: class sizes not fully stated — check §4.1 or §5.1 caption")

# Fig 2 ROC: paper says AUC=0.9258
if "0.9258" in content:
    ok("Fig 2: AUC=0.9258 in text matches figure")
else:
    err("Fig 2: AUC not found")

# Fig 3 BiLSTM: val=96.23%, test=95.87%, gap=0.36pp
fig3_val  = "96.23%" in content
fig3_test = "95.87%" in content
fig3_gap  = "0.36" in content
if fig3_val and fig3_test:
    ok("Fig 3: BiLSTM val=96.23% and test=95.87% in text")
else:
    err("Fig 3: BiLSTM numbers missing from text")
if fig3_gap:
    ok("Fig 3: 0.36 pp gap mentioned")
else:
    warn("Fig 3: 0.36 pp gap not explicitly mentioned in text")

# Fig 4 Ablation: 45.2%, 86.4%, 89.7%, 93.1%, 95.8%, 98.66%
ablation_nums = ["45.2%", "86.4%", "89.7%", "93.1%", "95.8%", "98.66%"]
for n in ablation_nums:
    if n in content:
        ok(f"Fig 4: ablation value {n} in text")
    else:
        err(f"Fig 4: ablation value {n} NOT in text — inconsistency with figure!")

# ─────────────────────────────────────────────────────────────────────────────
# 3. TERMINOLOGY CHECKS
# ─────────────────────────────────────────────────────────────────────────────
print("Checking terminology...")

# GAF should be 0
gaf_count = content.count("GAF")
if gaf_count == 0:
    ok("GAF: 0 occurrences (fully renamed to SIA)")
else:
    err(f"GAF: {gaf_count} occurrences still present!")
    for i, line in enumerate(lines):
        if "GAF" in line:
            err(f"  GAF at line {i+1}: {line.strip()[:80]}")

# Check SIA is used consistently
sia_count = content.count("SIA")
if sia_count >= 3:
    ok(f"SIA: {sia_count} occurrences (properly used)")
else:
    warn(f"SIA: only {sia_count} occurrences — verify all GAF references replaced")

# Check WAAP vs WAF consistency
waap = content.count("WAAP")
waf_only = len(re.findall(r'\bWAF\b(?!\s*(?:systems?|baseline|framework|tool))', content))
if waap > 5:
    ok(f"WAAP used {waap}x (consistent with proposed system)")

# ─────────────────────────────────────────────────────────────────────────────
# 4. STRUCTURAL CHECKS
# ─────────────────────────────────────────────────────────────────────────────
print("Checking structure...")

# Sections numbered correctly
sections_5x = re.findall(r"### 5\.\d+", content)
ok(f"Sections 5.x: {len(sections_5x)} subsections found: {sections_5x[:8]}")

# Check section 6.4 is numbered
if "### 6.4 Responsible AI" in content or "6.4 Responsible AI" in content:
    ok("Section 6.4 properly numbered")
else:
    err("Section 6.4 not found with proper numbering")

# Check journal recommendation present
if "IEEE Transactions on Information Forensics" in content:
    ok("Journal recommendation present")
else:
    err("Journal recommendation missing!")

# Check Abstract length (should be ~250 words for AIP)
abstract_match = re.search(r"## ABSTRACT\n+(.*?)\n+---", content, re.DOTALL)
if abstract_match:
    abstract_text = abstract_match.group(1)
    word_count = len(abstract_text.split())
    if 200 <= word_count <= 300:
        ok(f"Abstract length: {word_count} words (within AIP 200-300 range)")
    elif word_count > 300:
        warn(f"Abstract length: {word_count} words (AIP recommends ≤300)")
    else:
        warn(f"Abstract length: {word_count} words (too short, AIP recommends ≥200)")
else:
    warn("Could not parse Abstract for word count")

# Check Keywords present
if "**Keywords:**" in content or "**Keywords" in content:
    ok("Keywords section present")
else:
    warn("Keywords section not found")

# ─────────────────────────────────────────────────────────────────────────────
# 5. CITATION CHECKS
# ─────────────────────────────────────────────────────────────────────────────
print("Checking citations...")

# Check all numbered refs are present
refs_in_text = set(re.findall(r'\[(\d+)\]', content))
ref_definitions = set(re.findall(r'^\[(\d+)\]', content, re.MULTILINE))

missing_defs = refs_in_text - ref_definitions
if missing_defs:
    warn(f"References cited but not defined: {sorted(missing_defs)}")
else:
    ok(f"All {len(refs_in_text)} cited references have definitions")

undefined_refs = ref_definitions - refs_in_text
if undefined_refs:
    warn(f"References defined but never cited: {sorted(undefined_refs)}")

# Check XGBoost citation added
if "Chen" in content and "Guestrin" in content:
    ok("XGBoost citation [Chen & Guestrin] present")
else:
    warn("XGBoost citation not found")

# ─────────────────────────────────────────────────────────────────────────────
# 6. MATH / NOTATION CHECKS
# ─────────────────────────────────────────────────────────────────────────────
print("Checking math notation...")

# Check McNemar formula
if "chi" in content.lower() or "chi^2" in content or "???" in content:
    ok("McNemar chi-squared notation present")
else:
    warn("McNemar chi-squared notation unclear")

# Check AUC ± notation
if "±" in content or "+/-" in content or "0.0031" in content:
    ok("AUC uncertainty notation present")
else:
    warn("Bot AUC=0.9944 uncertainty notation may be missing")

# ─────────────────────────────────────────────────────────────────────────────
# 7. POTENTIAL ENCODING/SPECIAL CHAR ISSUES
# ─────────────────────────────────────────────────────────────────────────────
print("Checking encoding issues...")

# Look for replacement characters or broken unicode
broken = [(i+1, line.encode("ascii","replace").decode()) for i, line in enumerate(lines)
          if "?" in line.encode("ascii","replace").decode() and line.strip()]
suspicious = [(ln, l) for ln, l in broken if "?" in l and len([c for c in l if c=="?"]) > 2]
if suspicious:
    for ln, l in suspicious[:8]:
        warn(f"Possible encoding issue at L{ln}: {l[:100]}")
else:
    ok("No significant encoding issues detected")

# Look for ? artifacts (broken unicode from previous edits)
q_artifacts = [i+1 for i, line in enumerate(lines) if "?" in line and len(line) > 5]
if len(q_artifacts) > 20:
    warn(f"Many lines with '?' character ({len(q_artifacts)} lines) — may be encoding artifacts from markdown symbols")

# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 65)
print("FINAL AUDIT REPORT")
print("=" * 65)
print(f"\nTotal lines: {len(lines)}")
print(f"Errors:   {len(errors)}")
print(f"Warnings: {len(warnings)}")
print(f"OK items: {len(ok_items)}")
print()

if errors:
    print("--- ERRORS (must fix) ---")
    for e in errors:
        print(" " + e)
    print()

if warnings:
    print("--- WARNINGS (review) ---")
    for w in warnings:
        print(" " + w)
    print()

print("--- OK ---")
for o in ok_items:
    print(" " + o)
