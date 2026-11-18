import sys, re
sys.stdout.reconfigure(encoding='utf-8')
text = open('AEGIS_paper_final.md', encoding='utf-8').read()
lines = text.splitlines()
print(f'Lines: {len(lines)}  |  Size: {len(text):,} bytes')
print()

# Check for internal sections still in paper
internal = ['PEER REVIEW', 'SCIENTIFIC AUDIT', 'Recommended Corrections', 'Critical Issues', 'Unsupported Claims']
print('--- Internal sections (must be ABSENT) ---')
for term in internal:
    found = [i+1 for i,l in enumerate(lines) if term.upper() in l.upper()]
    print(f'  {"FOUND" if found else "CLEAN"}  "{term}"  {found if found else ""}')

print()
print('--- Last 5 lines of paper ---')
for i, l in enumerate(lines[-5:]):
    print(f'  {len(lines)-4+i}: {l}')

print()
sections = ['## Abstract', '## I. Introduction', '## II. Background', 
            '## III. Threat Model', '## IV. The Framework', '## V. Experimental',
            '## VI. Discussion', '## VII. Conclusion', '## References',
            '## Appendix']
print('--- Required sections ---')
for sec in sections:
    found = any(sec in l for l in lines)
    print(f'  {"OK" if found else "MISSING"}  {sec}')

print()
print('--- Banned patterns ---')
bad = [r'\(Fact\)', r'\(Assumption\)', r'\(Future Work\)', r'\[Verification Required\]', r'0\.907', r'98\.8%']
for pat in bad:
    found = [i+1 for i,l in enumerate(lines) if re.search(pat, l)]
    print(f'  {"FOUND at "+str(found) if found else "CLEAN"}  pattern={pat}')
