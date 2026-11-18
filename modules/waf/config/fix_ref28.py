with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Fix R3b: Add Sarhan after [28] H. Liu (correct author initial)
sarhan_addition = "\n[28b] M. Sarhan, S. Layeghy, and M. Portmann, \"Towards a Standard Feature Set for Network Intrusion Detection System Datasets,\" *Mobile Netw. Appl.*, vol. 27, pp. 357-370, 2022. [doi: 10.1007/s11036-021-01843-0]"

target = "[28] H. Liu and B. Lang"
if target in content and "Standard Feature Set for Network" not in content:
    idx = content.find(target)
    eol = content.find("\n", idx)
    content = content[:eol] + sarhan_addition + content[eol:]
    print("R3b: Sarhan 2022 survey ADDED")
else:
    print("R3b: already present or not found")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Lines:", len(content.splitlines()))
