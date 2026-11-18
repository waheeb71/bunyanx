with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

checks = [
    ("C1 - Test set stratified note",        "stratified sub-partition"),
    ("C1 - Footnote in 5.1",                 "4,328-sample evaluation partition"),
    ("C2 - GNN Evaluation Note",             "Evaluation Note"),
    ("C2 - GNN limitation added to 6.3",     "GNN evaluation methodology"),
    ("C4 - Abstract AUC caveat",             "interpretive caveat"),
    ("M1 - Sequential latency clarified",    "Sequential"),
    ("M2 - McNemar table in 5.7",            "CRS Correct"),
    ("M3 - GAF renamed to SIA (0 remain)",   "GAF"),
    ("M4 - Novel attacks sourced OWASP",     "OWASP Testing Guide"),
    ("M5 - JA3 ref RSA 2019",               "RSA Conference"),
    ("W2 - Section 6.4 numbered",            "6.4 Responsible AI"),
    ("W3 - Terminology note in intro",       "Terminology:"),
    ("W4 - NW first application qualified",  "systematic search"),
    ("BiLSTM independent test in conclusion","independent temporal test split"),
    ("R1 - arXiv preprint caveat",           "arXiv preprint"),
    ("R2 - XGBoost citation added",          "Chen & Guestrin, 2016"),
    ("R3 - Pawlick 2021 deception survey",   "Pawlick"),
    ("R3 - Sarhan 2022 IDS survey",          "Sarhan"),
    ("C5 - Journal recommendation section",  "IEEE Transactions on Information Forensics"),
]

ok_count = 0
total = 0
for label, pattern in checks:
    found = pattern in content
    if label == "M3 - GAF renamed to SIA (0 remain)":
        status = "OK (0 GAF)" if not found else "FAIL - GAF still present"
        ok = not found
    else:
        status = "OK" if found else "MISSING"
        ok = found
    total += 1
    if ok:
        ok_count += 1
    print(status + " <- " + label)

print()
print("=" * 50)
print("Score: " + str(ok_count) + "/" + str(total) + " fixes verified")
if ok_count == total:
    print("ALL PAPER FIXES COMPLETE!")
else:
    print("Remaining: " + str(total - ok_count) + " items")
print("Total paper lines:", len(content.splitlines()))
