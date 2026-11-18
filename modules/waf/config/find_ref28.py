with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

print("Lines containing [28] or Liu:")
for i, line in enumerate(lines):
    try:
        l = line.encode("ascii", "replace").decode()
        if "[28]" in l or "Liu" in l or "Lang" in l:
            print(str(i+1) + ": " + l.rstrip()[:120])
    except:
        pass
