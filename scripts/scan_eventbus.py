import os, re, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

MODULES_DIR = 'modules'
BROKEN_PATTERNS = [
    r'asyncio\.run\(',
    r'new_event_loop\(\)',
    r'get_event_loop\(\)\.is_running',
    r'get_running_loop\(\)\.create_task',
]
GOOD = 'publish_from_thread'

needs_fix = []
already_fixed = []
has_bus_only = []

for root, dirs, files in os.walk(MODULES_DIR):
    dirs[:] = [d for d in dirs if d not in ('__pycache__', 'tests', 'benchmarks')]
    for fn in files:
        if not fn.endswith('.py'):
            continue
        path = os.path.join(root, fn)
        try:
            txt = open(path, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        if 'EventBus' not in txt:
            continue
        if 'publish' not in txt:
            continue

        broken = []
        for pat in BROKEN_PATTERNS:
            if re.search(pat, txt):
                broken.append(pat)

        if GOOD in txt:
            already_fixed.append(path)
        elif broken:
            needs_fix.append((path, broken))
        else:
            has_bus_only.append(path)

print("=" * 65)
print("  NEEDS FIX — broken thread pattern detected")
print("=" * 65)
for path, issues in needs_fix:
    print(f"  {path}")
    for i in issues:
        print(f"    - {i}")

print()
print("=" * 65)
print("  ALREADY FIXED — uses publish_from_thread")
print("=" * 65)
for path in already_fixed:
    print(f"  {path}")

print()
print("=" * 65)
print("  HAS EventBus publish but no broken pattern")
print("=" * 65)
for path in has_bus_only:
    print(f"  {path}")

print()
print(f"Summary: {len(needs_fix)} need fix, {len(already_fixed)} fixed, {len(has_bus_only)} other")
