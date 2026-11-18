import re, sys

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Extract key data needed for figures

# 1. NLP Confusion Matrix data
print("=== NLP METRICS (for Confusion Matrix & ROC) ===")
nlp_markers = [
    "SQLi recall=99.9%", "XSS recall=91.5%", "AUC=0.9258",
    "90.41%", "Benign recall", "72.0%"
]
for m in nlp_markers:
    if m in content:
        idx = content.find(m)
        line_num = content[:idx].count("\n") + 1
        ctx = content[max(0,idx-80):idx+120].replace("\n"," ")
        print(f"  [{m}] L{line_num}: ...{ctx.encode('ascii','replace').decode()}...")
    print()

# 2. Find confusion matrix table
print("=== CONFUSION MATRIX TABLE ===")
cm_patterns = ["| Benign |", "| SQLi |", "| XSS |", "True Label", "Predicted"]
for pat in cm_patterns:
    if pat in content:
        idx = content.find(pat)
        line_num = content[:idx].count("\n") + 1
        print(f"  Found '{pat}' at line {line_num}")
        chunk = content[idx:idx+500]
        print(chunk.encode("ascii","replace").decode()[:400])
        print()
        break

# 3. Ablation study data
print("=== ABLATION STUDY ===")
abl_markers = ["ablation", "Ablation", "Layer Removal", "w/o", "without"]
for m in abl_markers:
    if m in content:
        idx = content.find(m)
        line_num = content[:idx].count("\n") + 1
        chunk = content[idx:idx+800]
        print(f"  [{m}] L{line_num}:")
        print(chunk.encode("ascii","replace").decode()[:600])
        print()
        break
