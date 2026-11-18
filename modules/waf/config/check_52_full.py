with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find 5.2 section and print it fully
in_52 = False
count = 0
for i, line in enumerate(lines):
    l = line.encode("ascii","replace").decode().rstrip()
    if "### 5.2" in l:
        in_52 = True
    if in_52:
        print(str(i+1) + ": " + l[:120])
        count += 1
    if in_52 and count > 5 and "### 5." in l and "5.2" not in l:
        break
    if count > 60:
        break
