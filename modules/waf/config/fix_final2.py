import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Fix broken emoji medal chars (U+FFFD replacement chars and emoji variants)
# Journal recommendation table lines
content = re.sub(r'\|\s*[\ufffd\U0001F947\U0001F948\U0001F949\U0001F504\U0001F1FA\U0001F947\U0001F3C5\U0001F948\U0001F949][\ufffd]?\s*Best fit', '| **Primary**', content)
content = re.sub(r'\|\s*[\ufffd\U0001F947\U0001F948\U0001F949\U0001F504\U0001F1FA\U0001F947\U0001F3C5\U0001F948\U0001F949][\ufffd]?\s*Good', '| **2nd Choice**', content)
content = re.sub(r'\|\s*[\ufffd\U0001F947\U0001F948\U0001F949\U0001F504\U0001F1FA\U0001F947\U0001F3C5\U0001F948\U0001F949][\ufffd]?\s*Faster', '| **Fast Track**', content)
content = re.sub(r'\|\s*[\ufffd\U0001F947\U0001F948\U0001F949\U0001F504\U0001F1FA\U0001F947\U0001F3C5\U0001F948\U0001F949][\ufffd]?\s*Alternative', '| **Alternative**', content)

# Also catch raw U+FFFD sequences at line starts in the journal table
lines = content.splitlines()
new_lines = []
for line in lines:
    if "\ufffd" in line:
        # Replace all replacement chars
        if "Best fit" in line:
            line = re.sub(r'^\|\s*[\ufffd]+\s*', '| **Primary** ', line)
        elif "Good" in line and "IEEE" not in line:
            line = re.sub(r'^\|\s*[\ufffd]+\s*', '| **2nd Choice** ', line)
        elif "Faster" in line:
            line = re.sub(r'^\|\s*[\ufffd]+\s*', '| **Fast Track** ', line)
        elif "Alternative" in line:
            line = re.sub(r'^\|\s*[\ufffd]+\s*', '| **Alternative** ', line)
        # Clean up remaining replacement chars
        line = line.replace("\ufffd", "")
    # Fix range notation "3-6" that may still show as "3?6"
    line = re.sub(r"(\d)\?(\d)", r"\1-\2", line)
    new_lines.append(line)

content = "\n".join(new_lines)

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

# Verify no more replacement chars
remaining_fffd = content.count("\ufffd")
print("Remaining U+FFFD chars:", remaining_fffd)
print("Lines:", len(new_lines))

# Check the journal table looks right
idx = content.find("IEEE Transactions on Information Forensics")
if idx > 0:
    chunk = content[max(0,idx-200):idx+400]
    print("\nJournal table preview:")
    for l in chunk.splitlines():
        safe = l.encode("ascii","replace").decode()
        if "|" in safe or "Journal" in safe or "Rank" in safe:
            print(" ", safe[:120])
