import sys, re
sys.stdout.reconfigure(encoding='utf-8')

with open(r'f:\enterprise_ngfw\modules\predictive_ai\ORACLE_paper_final.md', 'r', encoding='utf-8') as f:
    text = f.read()

parts = text.split('## References')
body = parts[0]
bib = parts[1].split('## Appendix')[0] if len(parts) > 1 else ''

# Extract all [X] in body
raw_cits = re.findall(r'\[(\d+(?:[–\-,\s]+\d+)*)\]', body)
cited = set()
for c in raw_cits:
    for item in re.split(r'[,;\s]+', c):
        if '–' in item or '-' in item:
            sub = re.split(r'[–\-]', item)
            if len(sub) == 2 and sub[0].isdigit() and sub[1].isdigit():
                for n in range(int(sub[0]), int(sub[1])+1):
                    cited.add(n)
        elif item.isdigit():
            cited.add(int(item))

# Filter out interval [0]
cited.discard(0)

print('Citations cited in body:', sorted(list(cited)))

# Extract bib entries
bib_entries = re.findall(r'(\d+)\.\s+([^\n]+)', bib)
print('Bib entries count:', len(bib_entries))
bib_nums = {int(b[0]) for b in bib_entries}

missing_in_body = bib_nums - cited
print('Bib entries NEVER cited in body:', sorted(list(missing_in_body)))
print('Citations in body exceeding bib entries:', sorted([x for x in cited if x not in bib_nums]))

# Check table sequence in body
tables = re.findall(r'\*\*Table\s+([IVXLCDM\d]+):', body)
print('\nTables sequence found in markdown:')
for i, t in enumerate(tables):
    print(f'  {i+1}: Table {t}')

# Check figures in body
figs = re.findall(r'Fig(?:ure|\.)?\s*(\d+)', body)
print(f'\nFigures mentioned in body: {sorted(list(set(figs)))}')
fig_imgs = re.findall(r'!\[.*?\]\((figures/.*?)\)', body)
print(f'Figure images embedded in body: {len(fig_imgs)}')
for img in fig_imgs:
    print('  ', img)
