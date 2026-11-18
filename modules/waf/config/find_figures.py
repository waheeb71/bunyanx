import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

# Find all image references
imgs = re.findall(r'!\[([^\]]*)\]\(([^\)]+)\)', content)
print("=== Images referenced in paper ===")
for alt, path in imgs:
    print(f"  ALT: {alt[:60]}")
    print(f"  PATH: {path}")
    print()

# Find all Figure mentions
print("=== Figure mentions ===")
for i, line in enumerate(lines):
    try:
        l = line.encode("ascii","replace").decode()
        if "Fig." in l or "Figure" in l or "fig_" in l:
            print(f"  L{i+1}: {l[:120]}")
    except:
        pass
