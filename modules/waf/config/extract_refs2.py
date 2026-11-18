import re, json

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

ref_pattern = re.compile(r'^\[(\d+[ab]?)\]\s+(.+?)(?=\n\[|\Z)', re.MULTILINE | re.DOTALL)
refs = ref_pattern.findall(content)

data = []
for num, body in refs:
    body_clean = body.strip().replace("\n", " ")
    data.append({"num": num, "text": body_clean})

with open(r"F:\enterprise_ngfw\modules\waf\config\refs_list.json", "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f"Extracted {len(data)} references -> refs_list.json")
