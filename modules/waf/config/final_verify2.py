import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

print("=== FINAL VERIFICATION (corrected) ===\n")

ok = 0; fail = 0

def check(label, found, expected_found=True):
    global ok, fail
    passed = (found == expected_found)
    status = "OK" if passed else "FAIL"
    if passed: ok += 1
    else: fail += 1
    print(f"  {status:6} | {label}")

# References
check("REF [8] = Liu et al. arXiv:2310.12815",        "arXiv:2310.12815" in content)
check("REF [8] Rodrigues REMOVED",                     "G. Rodrigues" in content, expected_found=False)
check("REF [10] proceedings in press note",             "proceedings in press" in content)
check("REF [25b] Pawlick corrected to 2019",           "2019. [doi: 10.1145/3354045]" in content)
check("REF [25b] vol.52 corrected",                    "vol. 52" in content)
check("REF [25c] La et al. renamed",                   "[25c] Q. D. La" in content)
check("REF [26] peer-reviewed note added",             "peer-reviewed treatment" in content)
check("In-text [8] -> [16,17]",                        "[16, 17]" in content)

# Content
check("GAF = 0 (fully replaced by SIA)",               "GAF" in content, expected_found=False)
check("SIA used correctly",                            "SIA" in content)
check("Terminology note in intro",                     "Terminology:" in content)
check("GNN Evaluation Note added",                     "Evaluation Note" in content)
check("McNemar contingency table",                     "CRS Correct" in content)
check("arXiv under peer review caveat",                "under peer review" in content)
check("Section 6.4 numbered",                          "6.4 Responsible AI" in content)
check("Journal recommendation",                        "IEEE Transactions on Information Forensics" in content)

# Metrics consistency
check("NLP accuracy 90.41% (multiple)",                content.count("90.41%") >= 2)
check("BiLSTM val 96.23%",                             "96.23%" in content)
check("BiLSTM test 95.87%",                            "95.87%" in content)
check("Full pipeline 98.66%",                          content.count("98.66%") >= 3)
check("McNemar chi2=847.2",                            "847.2" in content)
check("XGBoost Chen & Guestrin citation",              "Chen & Guestrin" in content)

# Abstract
abs_match = re.search(r"## ABSTRACT\n+(.*?)\n+---", content, re.DOTALL)
wc = len(abs_match.group(1).split()) if abs_match else 0
check(f"Abstract 200-300 words ({wc} words)",          200 <= wc <= 300)

print(f"\n{'='*52}")
print(f"Score: {ok}/{ok+fail} checks passed")
print(f"Paper lines: {len(lines)}")
if fail == 0:
    print("\n*** ALL CHECKS PASSED — PAPER READY FOR SUBMISSION ***")
else:
    print(f"\n{fail} item(s) still need attention")
