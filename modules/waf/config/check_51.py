with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find where "90.41% test accuracy" is
for i, line in enumerate(lines):
    try:
        l = line.encode("ascii","replace").decode()
        if "90.41% test accuracy" in l or "Test Accuracy" in l and "90.41" in l:
            print("Found at line", i+1, ":", l.rstrip()[:100])
            for j in range(max(0,i-2), min(len(lines),i+10)):
                print(str(j+1)+":", lines[j].encode("ascii","replace").decode().rstrip()[:110])
            print()
    except: pass

# Find section 5.1 heading
for i, line in enumerate(lines):
    try:
        l = line.encode("ascii","replace").decode()
        if "5.1" in l and ("#" in l or "NLP" in l):
            print("5.1 heading at line", i+1, ":", l.rstrip()[:80])
    except: pass
