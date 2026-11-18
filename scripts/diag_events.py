import json, collections, sqlite3, os, re, sys

# Fix Windows encoding
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SEP = "=" * 65

# ─── 1. Events JSON ───────────────────────────────────────────────────
print(SEP)
print("  EVENTS JSON")
print(SEP)

with open('logs/events/events_20260706.json', encoding='utf-8', errors='replace') as f:
    content = f.read()

lines = [l.strip() for l in content.strip().splitlines() if l.strip()]
events = []
for l in lines:
    try: events.append(json.loads(l))
    except: pass

print(f"Total flow events: {len(events)}")

verdicts = collections.Counter(e.get('verdict','?') for e in events)
print("\n[Verdicts]")
for v,c in verdicts.most_common():
    print(f"  {c:4d}  {v}")

reasons = collections.Counter()
for e in events:
    r = str(e.get('reason',''))[:110]
    reasons[r] += 1
print("\n[Top Reasons — what the proxy decided]")
for r,c in list(reasons.most_common(15)):
    print(f"  {c:3d}  {r}")

# Which modules are firing?
print("\n[Modules mentioned in reasons]")
module_hits = collections.Counter()
for e in events:
    r = str(e.get('reason',''))
    for tag in re.findall(r'\[([a-z_]+)\]', r):
        module_hits[tag] += 1
for m,c in module_hits.most_common():
    print(f"  {c:4d}  {m}")

# ─── 2. Log: EventBus publishes ────────────────────────────────────────
print(f"\n{SEP}")
print("  BUNYANX.LOG — EventBus Publishes & Audio")
print(SEP)

log_path = 'data/logs/bunyanx.log'
audio_lines, pub_topics = [], collections.Counter()
if os.path.exists(log_path):
    with open(log_path, encoding='utf-8', errors='replace') as f:
        log_lines = f.readlines()

    print(f"Total log lines: {len(log_lines)}")

    AUDIO_KW = [
        'NativePlayer','AudioManager','sound_id','dlp.incident',
        'threat.detected','malware','waf.block','ids.port',
        'anomaly','STORM','COOLDOWN','suppressed','[EventBus',
        'publish','subscribe','EventSubscriber'
    ]
    audio_lines = [l.strip() for l in log_lines
                   if any(k in l for k in AUDIO_KW)]

    print(f"Audio/EventBus log lines found: {len(audio_lines)}")

    print("\n[EventBus-related lines (last 50)]")
    for l in audio_lines[-50:]:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', l)
        print(f"  {clean[:150]}")

    # Count published topics
    print("\n[Topics published to EventBus]")
    for l in log_lines:
        for m in re.finditer(r"publish.*?['\"]([a-z][a-z_.]+[a-z])['\"]", l):
            pub_topics[m.group(1)] += 1
        for m in re.finditer(r"topic=['\"]([a-z][a-z_.]+[a-z])['\"]", l):
            pub_topics[m.group(1)] += 1

    if pub_topics:
        for t,c in pub_topics.most_common(25):
            print(f"  {c:4d}  {t}")
    else:
        print("  *** NONE FOUND — modules are NOT publishing to EventBus! ***")

    # WAF-specific: did WAF publish anything?
    print("\n[WAF-related log lines]")
    waf_lines = [l.strip() for l in log_lines
                 if 'waf' in l.lower() and any(k in l.lower() for k in
                    ['block','alert','publish','event','topic','detected','score'])]
    for l in waf_lines[-20:]:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', l)
        print(f"  {clean[:160]}")
    if not waf_lines:
        print("  (none)")

    # IDS-specific
    print("\n[IDS/Threat-related log lines]")
    ids_lines = [l.strip() for l in log_lines
                 if any(k in l.lower() for k in
                    ['ids','threat.detected','malware','brute','port.scan',
                     'anomaly.scored','correlation'])]
    for l in ids_lines[-20:]:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', l)
        print(f"  {clean[:160]}")
    if not ids_lines:
        print("  (none — IDS/Threat modules may not be publishing events!)")

else:
    print("  Log file not found!")

# ─── 3. Events DB ──────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  EVENTS.DB")
print(SEP)

db_path = 'data/events.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print(f"Tables: {tables}")

    for tbl in tables[:6]:
        cur.execute(f"SELECT COUNT(*) FROM [{tbl}]")
        count = cur.fetchone()[0]
        cur.execute(f"PRAGMA table_info([{tbl}])")
        cols = [r[1] for r in cur.fetchall()]
        print(f"\n  [{tbl}] rows={count}")
        print(f"  cols: {cols}")
        if count > 0:
            cur.execute(f"SELECT * FROM [{tbl}] ORDER BY rowid DESC LIMIT 3")
            rows = cur.fetchall()
            for row in rows:
                print(f"    {str(row)[:200]}")
    conn.close()
else:
    print(f"  Not found: {db_path}")

# ─── 4. DIAGNOSIS ──────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  ROOT CAUSE DIAGNOSIS")
print(SEP)

# Check key sources
waf_publishes  = sum(v for k,v in pub_topics.items() if 'waf' in k)
ids_publishes  = sum(v for k,v in pub_topics.items() if 'ids' in k or 'threat' in k or 'malware' in k)
dlp_publishes  = sum(v for k,v in pub_topics.items() if 'dlp' in k)
total_publishes = sum(pub_topics.values())

print(f"  EventBus publishes total : {total_publishes}")
print(f"  DLP publishes            : {dlp_publishes}")
print(f"  WAF publishes            : {waf_publishes}")
print(f"  IDS/Threat publishes     : {ids_publishes}")
print()

waf_drops = sum(1 for e in events if 'waf' in str(e.get('reason','')).lower())
ids_drops = sum(1 for e in events if any(k in str(e.get('reason','')).lower()
               for k in ['ids','scan','port']))
print(f"  WAF blocks in events.json: {waf_drops}")
print(f"  IDS events in events.json: {ids_drops}")
print()

if waf_publishes == 0 and waf_drops > 0:
    print("  [CONFIRMED] WAF is BLOCKING attacks but NOT publishing to EventBus!")
    print("  => waf.block / waf.alert events are never sent => no audio!")
if ids_publishes == 0:
    print("  [CONFIRMED] IDS/Threat modules NOT publishing to EventBus!")
    print("  => threat.detected / ids.port_scan never fire => no audio!")
if dlp_publishes > 0:
    print(f"  [OK] DLP publishes {dlp_publishes} events => dlp_incident.mp3 plays correctly")
