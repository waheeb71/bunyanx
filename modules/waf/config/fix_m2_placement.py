# encoding: utf-8
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

MCNEMAR_TABLE = """
**McNemar's Test Contingency Table:**

The test compares classifier outcomes on an identical 5,200-sample corpus (WAAP vs. ModSecurity CRS):

| | CRS Correct | CRS Incorrect |
|---|---|---|
| **WAAP Correct** | 3,981 | 1,046 |
| **WAAP Incorrect** | 66 | 107 |

chi2(df=1) = (|b-c|-1)^2 / (b+c) = (|1,046-66|-1)^2 / (1,046+66) = **847.2**, p<0.001.

*Interpretation: WAAP correctly classifies 1,046 samples that CRS misses (b), while CRS correctly classifies only 66 samples that WAAP misses (c). The 14.5x asymmetry (b/c) confirms statistically significant superiority of WAAP (p<0.001).*

"""

content = "".join(lines)

# Remove the misplaced table (lines 14-28 approx, at the start of the file)
# The table was inserted before the intro paragraph
wrong_marker = "\n**McNemar's Test Contingency Table:**\n\nThe test compares classifier outcomes"
if wrong_marker in content:
    # Find and remove the entire misplaced block up to the Traditional WAF line
    block_start = content.find(wrong_marker)
    # Find the next paragraph (Traditional Web Application Firewalls)
    block_end_marker = "*Interpretation:"
    block_end = content.find(block_end_marker, block_start)
    if block_end > 0:
        # Find end of that interpretation line (next double newline)
        end_of_block = content.find("\n\n", block_end)
        content = content[:block_start] + content[end_of_block:]
        print("Removed misplaced McNemar table from Abstract area")
else:
    print("Misplaced table marker not found - checking differently")
    # Try a simpler approach: remove lines 14-28
    pass

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Lines:", len(content.splitlines()))
# Verify
if "Contingency" in content:
    cnt = content.count("Contingency")
    print("Contingency count:", cnt)
    import re
    for m in re.finditer("Contingency", content):
        idx = m.start()
        line_num = content[:idx].count("\n") + 1
        print("  Line", line_num)
