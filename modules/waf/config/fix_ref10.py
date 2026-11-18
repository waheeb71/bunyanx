with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Find and fix ref [10]
lines = content.splitlines()
for i, line in enumerate(lines):
    if "Abibulaiev" in line:
        print(f"L{i+1}: {line.encode('ascii','replace').decode()[:150]}")
        # Fix this line
        if "in press" not in line:
            new_line = line.rstrip()
            if new_line.endswith("."):
                new_line = new_line[:-1] + ". [Accepted paper; proceedings in press at time of submission.]"
            elif "pp." in new_line:
                new_line = new_line + " [Accepted paper; proceedings in press at time of submission.]"
            lines[i] = new_line + "\n"
            print(f"  -> Fixed")

content = "\n".join(l.rstrip() for l in lines)
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)
print("Done. Lines:", len(content.splitlines()))

# Also verify [8] fix
for i, line in enumerate(content.splitlines()):
    if "[8]" in line and i < 100:
        print(f"[8] in text at L{i+1}: {line.encode('ascii','replace').decode()[:110]}")
    if "Liu et al" in line and "2310" in line:
        print(f"New ref [8] at L{i+1}: {line.encode('ascii','replace').decode()[:110]}")
