with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# The footnote is at line 18 (index 17), right after the abstract paragraph
# We need to move it to section 5.1
# First: find and remove it from line 18
FOOTNOTE_TEXT = "*Note on test set size: The 4,328-sample evaluation partition"
footnote_line_idx = -1
for i, line in enumerate(lines):
    if FOOTNOTE_TEXT in line:
        footnote_line_idx = i
        break

if footnote_line_idx < 0:
    print("Footnote not found")
    exit()

print("Footnote found at line:", footnote_line_idx + 1)
footnote_content = lines[footnote_line_idx]

# Remove from current position
lines.pop(footnote_line_idx)
# Also remove the blank line that was after it if needed
# Re-find section 5.1
content = "".join(lines)

# Find where 5.1 NLP results are (the confusion matrix table or accuracy table)
# Look for the specific accuracy table in 5.1
sec51_markers = [
    "**Test Accuracy: 90.41%",
    "Test Accuracy: 90.41",
    "90.41% test accuracy",
    "| SQLi | 99.9%",
    "**NLP Classification Report",
    "5.1 NLP",
    "### 5.1",
]
placed = False
for marker in sec51_markers:
    if marker in content:
        idx = content.find(marker)
        # Find next double newline (end of block)
        next_break = content.find("\n\n", idx)
        if 0 < next_break < idx + 5000:
            content = content[:next_break] + "\n\n" + footnote_content.rstrip() + "\n" + content[next_break:]
            print("Footnote placed after:", marker[:50])
            placed = True
            break

if not placed:
    print("Could not find 5.1 marker - searching for NLP accuracy values")
    # Try broader search for the accuracy table
    for marker in ["AUC=0.9258", "SQLi recall=99.9%", "XSS recall=91.5%"]:
        if marker in content:
            idx = content.find(marker)
            next_break = content.find("\n\n", idx)
            if 0 < next_break < idx + 3000:
                content = content[:next_break] + "\n\n" + footnote_content.rstrip() + "\n" + content[next_break:]
                print("Footnote placed after:", marker[:50])
                placed = True
                break

if not placed:
    print("ERROR: Could not place footnote - appending at end of 5.1 area")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Total lines:", len(content.splitlines()))

# Verify new location
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    final_lines = f.readlines()
for i, line in enumerate(final_lines):
    if "4,328-sample evaluation partition" in line:
        print("Footnote now at line:", i+1)
        for j in range(max(0,i-2), min(len(final_lines), i+3)):
            print("  " + str(j+1) + ":", final_lines[j].encode("ascii","replace").decode().rstrip()[:100])
