import os, re, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

FILES = [
    'modules/dns_security/engine/plugin.py',
    'modules/email_security/engine/core/email_inspector.py',
    'modules/firewall/engine/firewall_plugin.py',
    'modules/predictive_ai/engine/AEGIS/core/AEGIS_engine.py',
    'modules/uba/engine/core/uba_plugin.py',
    'modules/vpn/module.py',
    'modules/vpn/policy/vpn/portal.py',
    'modules/web_filter/engine/plugin.py',
]

for path in FILES:
    try:
        txt = open(path, encoding='utf-8', errors='replace').read()
    except Exception as e:
        print(f"\n[{path}] ERROR: {e}")
        continue

    # Find EventBus publish lines
    lines = txt.splitlines()
    pub_lines = []
    for i, line in enumerate(lines):
        if ('publish' in line or 'EventBus' in line or 'Topics.' in line) and 'def ' not in line:
            pub_lines.append((i+1, line.strip()))

    print(f"\n{'='*60}")
    print(f"  {path}")
    print(f"{'='*60}")
    if pub_lines:
        for lineno, content in pub_lines[:20]:
            print(f"  L{lineno:4d}: {content[:110]}")
    else:
        print("  (no relevant lines found)")
