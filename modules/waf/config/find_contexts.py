with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

sections = {
    "C1_5.1_test_confusion": ("5.1", "5,118", 30),
    "C2_5.4.1_GNN": ("5.4.1", "GNN", 20),
    "M2_5.7_mcnemar": ("McNemar", "chi", 20),
    "W2_6.4": ("Responsible AI", "Ethical", 5),
    "W3_intro_contributions": ("contributions:", "WAAP", 10),
}

print("=== Searching for fix targets ===\n")

for key, (search1, search2, ctx) in sections.items():
    print(f"--- {key} ---")
    for i, line in enumerate(lines):
        if search1 in line:
            start = max(0, i-2)
            end = min(len(lines), i+ctx)
            print(f"  Found '{search1}' at line {i+1}:")
            for j in range(start, end):
                print(f"    {j+1}: {lines[j].rstrip()}")
            print()
            break
