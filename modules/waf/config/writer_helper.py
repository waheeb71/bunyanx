import os, shutil, gc

src = r'C:\Users\acer\.gemini\antigravity-ide\brain\71413fa4-6651-48eb-84cf-bcd72db350d5\scratch\fix_c3_bilstm_test.py'
dst = r'F:\enterprise_ngfw\modules\waf\config\fix_c3_bilstm_v2.py'

with open(src, 'r', encoding='utf-8') as f:
    content = f.read()

# Add chunked config after GRAD_CLIP
content = content.replace(
    'GRAD_CLIP   = 1.0\n',
    'GRAD_CLIP   = 1.0\nMAX_ROWS_PER_FILE = 600_000  # cap per day file to avoid OOM\nCHUNK_SIZE = 200_000        # rows per CSV chunk\n'
)

# Replace load_days with a chunked version
old_start = 'def load_days(day_files, data_dir):'
old_end = '    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()\n'

# Find and replace
idx_s = content.find(old_start)
idx_e = content.find(old_end, idx_s) + len(old_end)
new_fn = '''def load_days(day_files, data_dir):
    dfs = []
    for f in day_files:
        path = os.path.join(data_dir, f)
        if not os.path.exists(path):
            print("  [SKIP] " + f + " not found")
            continue
        chunks_list = []
        row_count = 0
        try:
            for chunk in pd.read_csv(path, encoding="latin-1", low_memory=False, chunksize=CHUNK_SIZE):
                chunk.columns = chunk.columns.str.strip()
                chunks_list.append(chunk)
                row_count += len(chunk)
                if row_count >= MAX_ROWS_PER_FILE:
                    break
            df_f = pd.concat(chunks_list, ignore_index=True)
            del chunks_list
            dfs.append(df_f)
            print("  Loaded " + f + ": " + str(row_count) + " rows")
        except Exception as e:
            print("  [WARN] Could not load " + f + ": " + str(e))
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
'''
content = content[:idx_s] + new_fn + content[idx_e:]
with open(dst, 'w', encoding='utf-8') as f:
    f.write(content)
print("Done. Lines:", content.count("\n"))
