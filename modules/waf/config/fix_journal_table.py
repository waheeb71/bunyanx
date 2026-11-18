with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# The journal table still has "| ??" before rank labels and ranges without dash
# Direct targeted replacement of the entire journal table

OLD_TABLE = """| Rank | Journal | Impact Factor (approx.) | Review Time |
|---|---|---|---|
| ?? Best fit | **IEEE Transactions on Information Forensics and Security** | ~8.0 | 36 months |
| ?? Good | **Computers & Security (Elsevier)** | ~5.6 | 24 months |
| ?? Faster | **IEEE Access (Security section)** | ~3.9 | 68 weeks |
| ?? Alternative | **Journal of Network and Computer Applications** | ~7.7 | 35 months |"""

NEW_TABLE = """| Rank | Journal | Impact Factor (approx.) | Review Time |
|---|---|---|---|
| **Primary** | **IEEE Transactions on Information Forensics and Security** | ~8.0 | 3-6 months |
| **2nd Choice** | **Computers & Security (Elsevier)** | ~5.6 | 2-4 months |
| **Fast Track** | **IEEE Access (Security section)** | ~3.9 | 6-8 weeks |
| **Alternative** | **Journal of Network and Computer Applications** | ~7.7 | 3-5 months |"""

if OLD_TABLE in content:
    content = content.replace(OLD_TABLE, NEW_TABLE)
    print("Journal table fixed (exact match)")
else:
    # Try flexible match - find the table lines and replace them
    import re
    # Replace any line with "??" prefix in the journal table area
    idx = content.find("IEEE Transactions on Information Forensics and Security")
    if idx > 0:
        # Get the surrounding 500 chars
        start = content.rfind("\n| Rank", 0, idx)
        end = content.find("\n\n", idx)
        if start > 0 and end > 0:
            old_chunk = content[start:end]
            new_chunk = old_chunk
            replacements = [
                (r'\| .*?Best fit \|', '| **Primary** |'),
                (r'\| .*?Good \|', '| **2nd Choice** |'),
                (r'\| .*?Faster \|', '| **Fast Track** |'),
                (r'\| .*?Alternative \|', '| **Alternative** |'),
                (r'(\d)(\d) months', r'\1-\2 months'),
                (r'(\d)(\d) weeks', r'\1-\2 weeks'),
            ]
            for pattern, repl in replacements:
                new_chunk = re.sub(pattern, repl, new_chunk)
            content = content[:start] + new_chunk + content[end:]
            print("Journal table fixed (flexible match)")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Lines:", len(content.splitlines()))

# Verify
idx = content.find("IEEE Transactions on Information Forensics")
chunk = content[max(0,idx-300):idx+300]
for l in chunk.splitlines():
    if "|" in l:
        print(" ", l.encode("ascii","replace").decode()[:120])
