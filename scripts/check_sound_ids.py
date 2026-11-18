import json, re, sys

with open('var/audio/alerts/manifest.json', encoding='utf-8') as f:
    manifest = json.load(f)

with open('system/audio/profiles/default.py', encoding='utf-8') as f:
    code = f.read()

profile_ids = re.findall(r'sound_id="([^"]+)"', code)
manifest_keys = set(manifest.keys())

print('=== sound_id vs manifest.json ===')
ok, miss = 0, 0
for sid in sorted(set(profile_ids)):
    if sid in manifest_keys:
        print(f'  OK   {sid}')
        ok += 1
    else:
        print(f'  MISS {sid}')
        miss += 1

print(f'\nManifest keys: {sorted(manifest_keys)}')
print(f'\nResult: {ok} matched, {miss} missing from manifest')
print('\nFiles on disk:')
import os
for f in sorted(os.listdir('var/audio/alerts')):
    print(f'  {f}')
