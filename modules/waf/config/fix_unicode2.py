import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Show all lines with ? character (potential broken unicode)
lines = content.splitlines()
problem_lines = []
for i, line in enumerate(lines):
    if "\ufffd" in line or "?" in line:
        # Filter out markdown question marks that are legitimate
        clean = line.replace("?", "")
        # Check if ? is a suspicious artifact
        if any(c == "?" for c in line):
            problem_lines.append((i+1, line[:120]))

print(f"Lines with ? character ({len(problem_lines)} total):")
shown = set()
for ln, l in problem_lines[:30]:
    encoded = l.encode("ascii", "replace").decode()
    if encoded not in shown:
        shown.add(encoded)
        print(f"  L{ln}: {encoded[:120]}")
