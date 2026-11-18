# encoding: utf-8
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find where Contingency table is
print("Lines containing Contingency:")
for i, line in enumerate(lines):
    try:
        if "Contingency" in line or "CRS Correct" in line or "McNemar" in line:
            print(str(i+1) + ": " + line.rstrip()[:120].encode("ascii","replace").decode())
    except:
        pass

# Also find where 5.7 is
print("\nLines with 5.7:")
for i, line in enumerate(lines):
    try:
        if "5.7" in line:
            print(str(i+1) + ": " + line.rstrip()[:120].encode("ascii","replace").decode())
    except:
        pass
