with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

print("Total lines:", len(content.splitlines()))
print()

checks = [
    ("C1 - Test set footnote", "4,328-sample evaluation partition"),
    ("C1 - stratified sub-partition", "stratified sub-partition"),
    ("C2 - GNN Evaluation Note", "Evaluation Note"),
    ("C2 - GNN in Limitations 6.3", "GNN evaluation methodology"),
    ("C4 - Abstract AUC caveat", "interpretive caveat"),
    ("M1 - Sequential Latency label", "Sequential"),
    ("M2 - McNemar Contingency Table", "Contingency Table"),
    ("M3 - SIA rename done", "SIA (MiniLM"),
    ("M4 - Novel attack source OWASP", "OWASP Testing Guide"),
    ("M5 - JA3 RSA fix", "RSA Conference"),
    ("W2 - Section 6.4 numbered", "6.4 Responsible AI"),
    ("W3 - Terminology note", "Terminology:"),
    ("W4 - NW first application claim", "systematic search"),
    ("BiLSTM test in conclusion", "independent temporal test split"),
    ("R1 - arXiv preprint caveat", "arXiv preprint"),
    ("C5 - Journal recommendation", "IEEE Transactions on Information Forensics"),
    ("GAF replaced = 0 remaining", "GAF"),
]

all_ok = True
for label, pattern in checks:
    found = pattern in content
    if label == "GAF replaced = 0 remaining":
        status = "OK (0 GAF)" if not found else "STILL HAS GAF"
        ok = not found
    else:
        status = "OK" if found else "MISSING"
        ok = found
    if not ok:
        all_ok = False
    print(status + " <- " + label)

print()
if all_ok:
    print("ALL FIXES VERIFIED!")
else:
    print("Some fixes still pending")
