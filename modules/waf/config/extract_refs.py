import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Extract all reference definitions [N] Author...
ref_pattern = re.compile(r'^\[(\d+[ab]?)\]\s+(.+?)(?=\n\[|\Z)', re.MULTILINE | re.DOTALL)
refs = ref_pattern.findall(content)

print(f"=== REFERENCES FOUND: {len(refs)} ===\n")
for num, body in refs:
    body_clean = body.strip().replace("\n", " ")[:160]
    print(f"[{num}] {body_clean}")
    print()
