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
    txt = open(path, encoding='utf-8', errors='replace').read()
    lines = txt.splitlines()

    # Find the block around loop.create_task
    for i, line in enumerate(lines):
        if 'loop.create_task' in line and 'publish' in lines[max(0,i-8):i+1][-1] or \
           ('loop.create_task' in line and any('publish' in l for l in lines[max(0,i-10):i])):
            start = max(0, i-12)
            end = min(len(lines), i+3)
            print(f"\n=== {path} L{start+1}-{end} ===")
            for j in range(start, end):
                marker = '>>>' if j == i else '   '
                print(f"  {marker} L{j+1:4d}: {lines[j][:110]}")
            break
