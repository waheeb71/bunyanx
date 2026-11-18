import sys, re
sys.stdout.reconfigure(encoding='utf-8')

with open(r'f:\enterprise_ngfw\modules\predictive_ai\ORACLE_paper_final.md', 'r', encoding='utf-8') as f:
    text = f.read()

bib_text = text.split('## References')[1].split('## Appendix')[0]
bib_map = {}
for m in re.finditer(r'(\d+)\.\s+([^\n]+)', bib_text):
    bib_map[int(m.group(1))] = m.group(2).strip()

body = text.split('## References')[0]

# Find all citations and verify semantic match
lines = body.split('\n')
for line_idx, line in enumerate(lines):
    cits = re.findall(r'\[(\d+(?:[–\-,\s]+\d+)*)\]', line)
    for c in cits:
        # Check numbers
        nums = []
        for item in re.split(r'[,;\s]+', c):
            if '–' in item or '-' in item:
                parts = re.split(r'[–\-]', item)
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    nums.extend(range(int(parts[0]), int(parts[1])+1))
            elif item.isdigit():
                nums.append(int(item))
        for n in nums:
            if n in bib_map:
                print(f"L{line_idx+1} cite [{n}] -> {bib_map[n][:60]}")
                print(f"   Context: {line.strip()[:100]}\n")
            else:
                print(f"L{line_idx+1} cite [{n}] -> MISSING IN BIBLIOGRAPHY!\n")
