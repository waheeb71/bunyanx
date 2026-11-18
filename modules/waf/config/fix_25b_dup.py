with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# Fix duplicate [25b] — rename La et al. to [25c]
old_25c = '[25b] Q. D. La, T. Q. S. Quek, J. Lee, S. Jin, and H. Zhu'
new_25c = '[25c] Q. D. La, T. Q. S. Quek, J. Lee, S. Jin, and H. Zhu'
if old_25c in content:
    content = content.replace(old_25c, new_25c)
    print("Fixed: La et al. renamed from [25b] to [25c]")
else:
    print("La et al. [25b] not found")
    # Count [25b] occurrences
    count = content.count("[25b]")
    print(f"[25b] appears {count} times in document")

with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)
print("Done. Lines:", len(content.splitlines()))
