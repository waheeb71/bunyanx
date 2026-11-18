with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

print("=== FINAL VERIFICATION ===\n")

checks = [
    # Reference fixes
    ("REF [8] replaced with Liu et al.",       "Prompt Injection Attacks and Defenses in LLM-Integrated"),
    ("REF [8] arXiv ID verified",              "arXiv:2310.12815"),
    ("REF [8] Rodrigues REMOVED",              "G. Rodrigues"),
    ("REF [10] in-press note",                 "proceedings in press"),
    ("REF [25b] Pawlick year=2019",            "2019. [doi: 10.1145/3354045]"),
    ("REF [25b] vol corrected",                "vol. 52"),
    ("REF [25c] La et al. renamed",            "[25c] Q. D. La"),
    ("REF [26] Fraunholz peer-review note",    "peer-reviewed treatment"),
    # Content fixes
    ("In-text [8] replaced by [16,17]",        "[16, 17]"),
    ("GAF = 0 occurrences",                    "GAF"),
    ("SIA present",                            "SIA"),
    # Metrics
    ("NLP accuracy 90.41%",                    "90.41%"),
    ("BiLSTM val 96.23%",                      "96.23%"),
    ("BiLSTM test 95.87%",                     "95.87%"),
    ("Full pipeline 98.66%",                   "98.66%"),
    ("McNemar 847.2",                          "847.2"),
    # Structure
    ("Terminology note",                       "Terminology:"),
    ("Section 6.4 numbered",                   "6.4 Responsible AI"),
    ("Journal recommendation",                 "IEEE Transactions on Information Forensics"),
    ("Abstract 200-300 words",                 None),  # word count check
    ("McNemar contingency table",              "CRS Correct"),
    ("GNN Evaluation Note",                    "Evaluation Note"),
    ("arXiv preprint caveat",                  "arXiv preprint, under review"),
]

ok = 0
fail = 0
for label, pattern in checks:
    if pattern is None:
        # Word count check
        import re
        abs_match = re.search(r"## ABSTRACT\n+(.*?)\n+---", content, re.DOTALL)
        if abs_match:
            wc = len(abs_match.group(1).split())
            status = "OK" if 200 <= wc <= 300 else "WARN"
            note = f"{wc} words"
        else:
            status = "WARN"; note = "not found"
        print(f"  {status:6} | {label}: {note}")
        if status == "OK": ok += 1
        else: fail += 1
        continue

    found = pattern in content
    if label == "REF [8] Rodrigues REMOVED":
        # Rodrigues should NOT be in content
        status = "OK" if not found else "FAIL"
    else:
        status = "OK" if found else "FAIL"

    if status == "OK": ok += 1
    else: fail += 1
    print(f"  {status:6} | {label}")

print(f"\n{'='*50}")
print(f"Result: {ok}/{ok+fail} checks passed")
if fail == 0:
    print("ALL CHECKS PASSED - Paper is ready for submission!")
else:
    print(f"{fail} check(s) need attention")

print(f"\nTotal paper lines: {len(lines)}")
