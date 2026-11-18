with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

WRONG_FOOTNOTE = "\n*Note on test set size: The 4,328-sample evaluation partition is a stratified subset of the full 13,671-sample held-out split defined in §4.1 (Data Splits). See §4.1 for complete partitioning details.*\n"

if WRONG_FOOTNOTE in content:
    # Remove misplaced footnote
    content = content.replace(WRONG_FOOTNOTE, "\n", 1)
    print("Removed misplaced C1 footnote from Abstract area")

    # Now place it in the correct location: after the confusion matrix or test accuracy in section 5.1
    # Look for the confusion matrix table end or accuracy mention in 5.1
    markers_51 = [
        "| **F1-Score** |",
        "| F1 |",
        "test set (n=4,328)",
        "4,328 samples",
        "AUC=0.9258",
    ]
    placed = False
    for marker in markers_51:
        if marker in content:
            idx = content.find(marker)
            # find next blank line
            next_blank = content.find("\n\n", idx)
            if 0 < next_blank < idx + 3000:
                content = content[:next_blank] + WRONG_FOOTNOTE.rstrip() + "\n" + content[next_blank:]
                print("C1 footnote placed after:", marker[:50])
                placed = True
                break
    if not placed:
        # Find 5.1 heading and add footnote after its first result table
        idx_51 = content.find("### 5.1")
        if idx_51 < 0:
            idx_51 = content.find("## 5.1")
        if idx_51 > 0:
            # Find the next table end (line starting with |) + blank line
            idx_table = content.find("\n\n", idx_51 + 100)
            count = 0
            while idx_table > 0 and count < 20:
                # Find next table after this blank
                next_content = content[idx_table:idx_table+200]
                if "|" in next_content:
                    # Find end of this table
                    table_end = content.find("\n\n", idx_table + 10)
                    if table_end > 0:
                        content = content[:table_end] + WRONG_FOOTNOTE.rstrip() + "\n" + content[table_end:]
                        print("C1 footnote placed after first table in §5.1")
                        placed = True
                        break
                idx_table = content.find("\n\n", idx_table + 10)
                count += 1
        if not placed:
            print("WARNING: Could not place footnote in 5.1 - marking for manual review")
else:
    print("Misplaced footnote not found (may already be fixed)")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Done. Lines:", len(content.splitlines()))

# Quick verify
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    try:
        if "4,328-sample evaluation partition" in line:
            print("Footnote now at line:", i+1)
            print("Context lines around it:")
            for j in range(max(0,i-3), min(len(lines),i+4)):
                print("  " + str(j+1) + ": " + lines[j].encode("ascii","replace").decode().rstrip()[:100])
    except:
        pass
