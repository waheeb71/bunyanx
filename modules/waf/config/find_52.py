with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find section 5.2
for i, line in enumerate(lines):
    try:
        l = line.encode("ascii", "replace").decode().rstrip()
        if ("5.2" in l and ("BiLSTM" in l or "Temporal" in l or "Session" in l or "Tracker" in l)):
            # Print 30 lines from here
            print("Found at line", i+1, ":", l[:80])
            for j in range(i, min(i+35, len(lines))):
                try:
                    print(str(j+1) + ": " + lines[j].encode("ascii","replace").decode().rstrip()[:120])
                except:
                    print(str(j+1) + ": [encode error]")
            break
    except:
        pass
