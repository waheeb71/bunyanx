import re

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

changes = 0

new_lines = []
for i, line in enumerate(lines):
    ln = i + 1
    orig = line

    # Lines 656-659: Journal table — fix medal emojis and dashes
    if ln in (656, 657, 658, 659):
        # "??" medal emojis broken -> use text labels
        line = line.replace("| ??", "| **1st**")  # gold
        line = line.replace("| ??", "| **2nd**")  # silver
        line = line.replace("| ??", "| **3rd**")  # bronze
        line = line.replace("| ??", "| **Alt**")  # Alternative
        # "3?6 months" -> "3-6 months"
        line = re.sub(r"(\d)\?(\d)", r"\1-\2", line)
        if line != orig:
            changes += 1
            print(f"  Fixed L{ln}: {line.rstrip()[:100]}")

    # Line 737: CAPTCHA paper — "CAPTCHAs? A la" — this ? is legitimate (question mark in title)
    # Leave as-is (it's a real question mark in the paper title)

    new_lines.append(line)

# Also do a global pass for any remaining broken section refs
content = "".join(new_lines)

# Fix "??" medal emojis that may remain (different encoding)
content = re.sub(r'\| \?{1,2} Best fit \|', '| **1st** |', content)
content = re.sub(r'\| \?{1,2} Good \|',     '| **2nd** |', content)
content = re.sub(r'\| \?{1,2} Faster \|',   '| **3rd** |', content)
content = re.sub(r'\| \?{1,2} Alternative \|','| **Alt** |', content)

# Fix "3?6 months" style ranges in the journal table
content = re.sub(r'(\d)\?(\d)', r'\1-\2', content)

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print(f"Total changes: {changes}")
print("Lines:", len(content.splitlines()))

# Verify
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    final = f.readlines()
remaining = [(i+1, l.rstrip()[:100]) for i, l in enumerate(final) if "?" in l and "CAPTCHA" not in l and "?" not in l]
print(f"\nRemaining ? issues: {len(remaining)}")
for ln, l in remaining[:10]:
    print(f"  L{ln}: {l.encode('ascii','replace').decode()}")
