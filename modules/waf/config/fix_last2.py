import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Check 1: GAF count
gaf_count = content.count("GAF")
print(f"GAF occurrences: {gaf_count}")
if gaf_count > 0:
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "GAF" in line:
            print(f"  L{i+1}: {line.encode('ascii','replace').decode()[:120]}")

# Check 2: arXiv preprint caveat — what exact text exists?
arxiv_patterns = [
    "arXiv preprint, under review",
    "arXiv preprint (under review",
    "under review",
    "under peer review",
]
for p in arxiv_patterns:
    if p in content:
        idx = content.find(p)
        ln = content[:idx].count("\n") + 1
        ctx = content[max(0,idx-50):idx+80]
        print(f"Found '{p}' at L{ln}: {ctx.encode('ascii','replace').decode()[:120]}")
