with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find in-text uses of [8], [10], [26]
targets = ["[8]", "[10]", "[26]"]
for t in targets:
    print(f"\n=== Usages of {t} ===")
    for i, line in enumerate(lines):
        if t in line:
            safe = line.encode("ascii","replace").decode().rstrip()
            print(f"  L{i+1}: {safe[:130]}")
