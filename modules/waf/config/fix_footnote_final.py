with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

FOOTNOTE_TEXT = "*Note on test set size: The 4,328-sample evaluation partition"
FOOTNOTE_LINE = None
footnote_idx = -1

for i, line in enumerate(lines):
    if FOOTNOTE_TEXT in line:
        footnote_idx = i
        FOOTNOTE_LINE = line
        break

if footnote_idx < 0:
    print("Footnote not found"); exit()

print("Footnote currently at line:", footnote_idx + 1)

# Remove from current position (it is in conclusion at line 638)
lines.pop(footnote_idx)
# Remove extra blank line if needed
if footnote_idx < len(lines) and lines[footnote_idx].strip() == "":
    lines.pop(footnote_idx)

# Now find the correct insertion point: after the confusion matrix in 5.1
# Section 5.1 is at line 297. Find the first table/result block after it.
content = "".join(lines)

# Find 5.1 heading
idx_51 = content.find("### 5.1 Layer 4a")
if idx_51 < 0:
    idx_51 = content.find("### 5.1")

print("5.1 heading at char:", idx_51)

# Find the accuracy table in 5.1 - look for the test metrics
# The paper says "Test Accuracy: 90.41%" - find this
markers = [
    "| Test | 4,328 |",
    "| Test  | 4,328",
    "4,328 |",
    "AUC=0.9258",
    "AUC = 0.9258",
    "**Test Accuracy:",
    "**Best Test Accuracy",
]

placed = False
for marker in markers:
    if marker in content and content.find(marker) > idx_51:
        idx = content.find(marker, idx_51)
        # Find next double newline
        next_blank = content.find("\n\n", idx)
        if 0 < next_blank < idx + 2000:
            content = content[:next_blank] + "\n\n" + FOOTNOTE_LINE.rstrip() + "\n" + content[next_blank:]
            print("Footnote placed after:", marker[:50], "at char", idx)
            placed = True
            break

if not placed:
    # Just find the first table end after 5.1
    idx = idx_51
    for _ in range(30):
        next_break = content.find("\n\n", idx + 100)
        if next_break < 0: break
        # Check if there is a table before this break
        segment = content[idx:next_break]
        if "|" in segment and "---" in segment:
            content = content[:next_break] + "\n\n" + FOOTNOTE_LINE.rstrip() + "\n" + content[next_break:]
            print("Footnote placed after first result table in 5.1")
            placed = True
            break
        idx = next_break

if not placed:
    print("ERROR - could not place; adding manually after 5.1 heading line")
    content = content.replace("### 5.1 Layer 4a: Unified NLP Model (1D-CNN + BiLSTM)\n",
                               "### 5.1 Layer 4a: Unified NLP Model (1D-CNN + BiLSTM)\n\n" + FOOTNOTE_LINE.rstrip() + "\n")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Total lines:", len(content.splitlines()))
# verify
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    fl = f.readlines()
for i, line in enumerate(fl):
    if FOOTNOTE_TEXT in line:
        print("Footnote now at line:", i+1)
        for j in range(max(0,i-3), min(len(fl),i+4)):
            print("  "+str(j+1)+": "+fl[j].encode("ascii","replace").decode().rstrip()[:100])
