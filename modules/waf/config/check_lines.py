import unicodedata

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

check_lines = [17, 62, 314, 486, 543, 544, 545, 546]

for ln in check_lines:
    line = lines[ln-1]
    # Find all non-ASCII characters
    non_ascii = [(i, c, unicodedata.name(c, "UNKNOWN")) for i, c in enumerate(line) if ord(c) > 127]
    problem = [(i, c, name) for i, c in enumerate(line) for name in [unicodedata.name(c, "UNKNOWN")]
               if ord(c) > 127 and ("REPLACEMENT" in name or "UNKNOWN" in name)]
    
    safe = line.rstrip().encode("ascii","replace").decode()[:100]
    print(f"L{ln}: {safe}")
    if problem:
        print(f"  PROBLEM chars: {[(i, hex(ord(c)), name) for i, c, name in problem[:5]]}")
    elif non_ascii:
        chars_info = [(hex(ord(c)), unicodedata.name(c,"?")) for _, c, _ in non_ascii[:5]]
        print(f"  Non-ASCII chars (OK): {chars_info}")
    print()
