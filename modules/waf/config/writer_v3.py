import os

# Read v2 script
with open(r"F:\enterprise_ngfw\modules\waf\config\fix_c3_bilstm_v2.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix: in preprocess(), add row-filtering to remove duplicate header rows  
# Insert after the line: df = df[available + [LABEL_COL]].copy()
old_line = "    df = df[available + [LABEL_COL]].copy()"
new_lines = """    df = df[available + [LABEL_COL]].copy()
    # Remove duplicate header rows (CIC-IDS2018 CSVs often contain repeated header lines)
    for col in available:
        df = df[df[col] != col]
    for col in available:
        df[col] = pd.to_numeric(df[col], errors='coerce')"""

content = content.replace(old_line, new_lines)

dst = r"F:\enterprise_ngfw\modules\waf\config\fix_c3_bilstm_v3.py"
with open(dst, "w", encoding="utf-8") as f:
    f.write(content)

print("v3 written to:", dst)
print("Lines:", content.count("\n"))
