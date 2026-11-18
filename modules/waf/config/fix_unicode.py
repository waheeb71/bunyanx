with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

changes = []

# Fix McNemar formula line (line 486)
# ??? -> chi^2 and broken chars
old_mcn = "??(df=1) = (|b?c|?1)? / (b+c) = (|1,046?66|?1)? / (1,046+66) = **847.2**"
new_mcn = "χ²(df=1) = (|b−c|−1)² / (b+c) = (|1,046−66|−1)² / (1,046+66) = **847.2**"
if old_mcn in content:
    content = content.replace(old_mcn, new_mcn)
    changes.append("Fixed McNemar formula")

# Fix comparison table symbols (? -> check/cross symbols)
# Lines 543-546: ? in table = checkmark Unicode issue
# Replace "| ?" with "| ✓" and "? |" with "✓ |" in comparison table context
# Only in the comparison table section
comp_table_start = content.find("| ModSecurity CRS v3.3.5 |")
comp_table_end   = content.find("\n\n", comp_table_start) if comp_table_start > 0 else -1

if comp_table_start > 0 and comp_table_end > 0:
    table_chunk = content[comp_table_start:comp_table_end]
    # Fix broken checkmarks: "? " in table cells -> "✓"
    # Look for the pattern: | ? | or | ?? | 
    fixed_chunk = table_chunk
    # The ? chars appear to be broken unicode
    # Replace patterns like "| ? |" -> "| ✓ |" but only where it makes sense
    import re
    # In comparison table, standalone ? in a cell = checkmark
    fixed_chunk = re.sub(r'\|\s*\?\s*\|', '| ✓ |', fixed_chunk)
    fixed_chunk = re.sub(r'\|\s*\?\s*(Limited)', r'| Limited', fixed_chunk)
    fixed_chunk = re.sub(r'\|\s*\?+\s*Certified', '| ✓ Certified', fixed_chunk)
    fixed_chunk = re.sub(r'\|\s*\?+\s*GCN', '| ✓ GCN', fixed_chunk)
    if fixed_chunk != table_chunk:
        content = content[:comp_table_start] + fixed_chunk + content[comp_table_end:]
        changes.append("Fixed checkmarks in comparison table")

# Fix training improvements box (line 314)
# "Benign?1.04" -> "Benign×1.04" (class weights)
old_weights = "Benign?1.04, XSS?2.57, SQLi?0.61"
new_weights = "Benign×1.04, XSS×2.57, SQLi×0.61"
if old_weights in content:
    content = content.replace(old_weights, new_weights)
    changes.append("Fixed class weight notation (×)")

# Fix abstract/intro broken chars
# "AUC=0.9944?0.0031" -> "AUC=0.9944±0.0031"
old_auc = "AUC=0.9944?0.0031"
new_auc = "AUC=0.9944±0.0031"
if old_auc in content:
    content = content.replace(old_auc, new_auc)
    changes.append("Fixed ± in AUC notation")

# "0.9944\u00b10.0031" alternative
content = content.replace("AUC=0.9944\u00b10.0031", "AUC=0.9944±0.0031")

# Fix arrow symbols: "?" used as "→"
# Common patterns in comparison table like "?" for performance indicator
content = content.replace("~90%?", "~90%*")
content = content.replace("~85%?", "~85%*")
content = content.replace("~3%?", "~3%*")
content = content.replace("~5%?", "~5%*")

# Fix "?" checkpoint symbol in BiLSTM section
content = content.replace("**Best Validation Accuracy: 96.23%** ? Best model", 
                           "**Best Validation Accuracy: 96.23%** — Best model")
content = content.replace("**Best Validation Accuracy: 94.15%** ? Best model",
                           "**Best Validation Accuracy: 94.15%** — Best model")
changes.append("Fixed arrow/dash symbols")

# Fix "?" used as section references (§ symbol)
# Pattern: "?4.1" -> "§4.1"
def fix_section_refs(text):
    import re
    # Fix patterns like "?4.1", "?5.2", "?6" etc.
    fixed = re.sub(r'\?(\d+(?:\.\d+)?(?:\.\d+)?)', r'§\1', text)
    return fixed

new_content = fix_section_refs(content)
if new_content != content:
    ref_count = len(re.findall(r'\?(\d+(?:\.\d+)?)', content))
    content = new_content
    changes.append(f"Fixed {ref_count} section references (?X.X -> §X.X)")

# Fix "Fig. X ?" -> "Fig. X —"
content = re.sub(r'(Fig\. \d+) ?', r'\1 —', content)
changes.append("Fixed Fig. references")

# Write back
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Changes made:")
for c in changes:
    print(" -", c)
print("Done. Lines:", len(content.splitlines()))
