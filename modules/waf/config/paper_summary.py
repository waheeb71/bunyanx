with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

print("=== PAPER STATUS SUMMARY ===")
print("Total lines:", len(lines))

# Count sections
sections = [l for l in lines if l.startswith("## ") or l.startswith("### ")]
print("Sections:", len(sections))

# Key metrics present
metrics = [
    "90.41%",   # NLP accuracy
    "96.23%",   # BiLSTM val
    "95.87%",   # BiLSTM independent test
    "98.66%",   # Full pipeline
    "0.9258",   # NLP AUC
    "0.8969",   # Bot Kaggle AUC
    "8.93 ms",  # Latency
]

print("\nKey metrics in paper:")
for m in metrics:
    found = m in content
    print(("  OK: " if found else "  MISSING: ") + m)

# Verify section 5.2 has both val and test numbers
print("\nSection 5.2 - BiLSTM:")
in_52 = False
for i, line in enumerate(lines):
    if "5.2" in line and "BiLSTM" in line or "5.2" in line and "Temporal" in line:
        in_52 = True
    if in_52:
        try:
            l = line.encode("ascii", "replace").decode()
            if l.strip():
                print("  L" + str(i+1) + ": " + l[:100])
        except:
            pass
    if in_52 and i > 0 and "###" in line and "5.2" not in line:
        break

