with open(r"F:\enterprise_ngfw\modules\waf\config\fix_c3_bilstm_v3.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix 1: Remove LabelEncoder entirely - use direct binary labeling from string
# Replace the preprocess function to do binary labeling before encoding

old_preprocess = """def preprocess(df, scaler=None, le=None, fit=False):
    available = [c for c in FEATURE_COLS if c in df.columns]
    for m in set(FEATURE_COLS) - set(available):
        df[m] = 0.0
    available = FEATURE_COLS
    df = df[available + [LABEL_COL]].copy()
    # Remove duplicate header rows (CIC-IDS2018 CSVs often contain repeated header lines)
    for col in available:
        df = df[df[col] != col]
    for col in available:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    if fit:
        le = LabelEncoder()
        df[LABEL_COL] = le.fit_transform(df[LABEL_COL].astype(str))
        scaler = StandardScaler()
        df[available] = scaler.fit_transform(df[available])
    else:
        df[LABEL_COL] = le.transform(
            df[LABEL_COL].astype(str).apply(
                lambda x: x if x in le.classes_ else le.classes_[0]))
        df[available] = scaler.transform(df[available])
    benign_label = le.transform(["BENIGN"])[0] if "BENIGN" in le.classes_ else 0
    y = (df[LABEL_COL] != benign_label).astype(int).values
    X = df[available].values.astype(np.float32)
    return X, y, scaler, le"""

new_preprocess = """def preprocess(df, scaler=None, le=None, fit=False):
    available = [c for c in FEATURE_COLS if c in df.columns]
    for m in set(FEATURE_COLS) - set(available):
        df[m] = 0.0
    available = FEATURE_COLS
    df = df[available + [LABEL_COL]].copy()
    # Remove duplicate header rows (CIC-IDS2018 CSVs often contain repeated header lines)
    for col in available:
        df = df[df[col] != col]
    for col in available:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    # Binary labeling: BENIGN=0, anything else=1 (robust across all days & attack types)
    raw_labels = df[LABEL_COL].astype(str).str.strip()
    y = (raw_labels != "BENIGN").astype(int).values
    if fit:
        scaler = StandardScaler()
        df[available] = scaler.fit_transform(df[available])
        le = None  # not needed for binary classification
    else:
        df[available] = scaler.transform(df[available])
    X = df[available].values.astype(np.float32)
    return X, y, scaler, le"""

if old_preprocess in content:
    content = content.replace(old_preprocess, new_preprocess)
    print("preprocess function REPLACED with binary labeling fix")
else:
    print("ERROR: old_preprocess pattern not found")
    # Fallback: show what the function looks like
    idx = content.find("def preprocess(")
    print("Current preprocess start:", content[idx:idx+300])

# Fix 2: Remove emoji from final print (encoding issue)
content = content.replace('print("\\u2705 Fix C3 COMPLETE")', 'print("Fix C3 COMPLETE")')
content = content.replace("print('\\u2705 Fix C3 COMPLETE')", "print('Fix C3 COMPLETE')")
content = content.replace("print(f\"\\nResults saved to: {RESULTS_OUT}\")", 'print("Results saved")')

dst = r"F:\enterprise_ngfw\modules\waf\config\fix_c3_bilstm_v4.py"
with open(dst, "w", encoding="utf-8") as f:
    f.write(content)
print("v4 written:", dst, "lines:", content.count("\n"))
