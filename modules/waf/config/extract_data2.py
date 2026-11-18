with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find the NLP confusion matrix data and class report
print("=== Lines around Fig.1 (Confusion Matrix) ===")
for i, line in enumerate(lines):
    l = line.encode("ascii","replace").decode().rstrip()
    if "Fig. 1" in l or "Confusion Matrix" in l or "fig_confusion" in l:
        for j in range(max(0,i-5), min(len(lines),i+30)):
            print(str(j+1)+":", lines[j].encode("ascii","replace").decode().rstrip()[:130])
        print()
        break

print("=== Ablation Study table ===")
for i, line in enumerate(lines):
    l = line.encode("ascii","replace").decode().rstrip()
    if "5.6" in l and "Ablation" in l:
        for j in range(max(0,i), min(len(lines),i+50)):
            print(str(j+1)+":", lines[j].encode("ascii","replace").decode().rstrip()[:130])
        break

print("=== NLP classification report / per-class metrics ===")
for i, line in enumerate(lines):
    l = line.encode("ascii","replace").decode().rstrip()
    if "| Benign |" in l or "Benign |" in l and "Precision" in lines[max(0,i-2)].decode("ascii","replace") if isinstance(lines[max(0,i-2)], bytes) else True:
        for j in range(max(0,i-3), min(len(lines),i+15)):
            print(str(j+1)+":", lines[j].encode("ascii","replace").decode().rstrip()[:130])
        print()
        break
