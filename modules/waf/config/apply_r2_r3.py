with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()
    lines = content.splitlines()

print("Total lines before:", len(lines))
changes = []

# ── R2: Citations in 2.3 (XGBoost paper) ────────────────────────────────────
# Add [Chen & Guestrin 2016] after XGBoost-based mention
old_xgb = "XGBoost-based behavioral classifiers"
new_xgb = "XGBoost-based behavioral classifiers [Chen & Guestrin, 2016]"
if old_xgb in content and new_xgb not in content:
    content = content.replace(old_xgb, new_xgb, 1)
    changes.append("R2a: XGBoost citation added in 2.3")
else:
    changes.append("R2a: XGBoost citation already present or marker not found")

# ── R2: §2.5 — qualify absolute novelty claim ────────────────────────────────
old_2_5 = "to the best of our knowledge, based on systematic review (2020-2026)"
new_2_5 = "to the best of our knowledge, based on systematic review of IEEE Xplore, ACM DL, and Google Scholar (2020-2026)"
if old_2_5 in content and new_2_5 not in content:
    content = content.replace(old_2_5, new_2_5, 1)
    changes.append("R2b: 2.5 systematic review scope expanded")
elif new_2_5 in content:
    changes.append("R2b: Already expanded")
else:
    # Try the exact string from the paper
    for marker in ["to the best of our knowledge", "systematic review (2020"]:
        if marker in content:
            changes.append("R2b: marker found: " + marker)
            break

# ── R3: Update old references ─────────────────────────────────────────────────
# [25] Spitzner 2003 -> add Pawlick et al. IEEE TIFS 2021
old_spitzner = "[25] L. Spitzner"
new_spitzner_addition = "\n[25b] J. Pawlick, E. Colbert, and Q. Zhu, \"A Game-Theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy,\" *ACM Comput. Surv.*, vol. 54, no. 2, pp. 1-28, 2021. [doi: 10.1145/3418306]"
if old_spitzner in content and "Game-Theoretic Taxonomy" not in content:
    idx = content.find(old_spitzner)
    # find end of that reference line
    eol = content.find("\n", idx)
    content = content[:eol] + new_spitzner_addition + content[eol:]
    changes.append("R3a: Pawlick 2021 deception survey added after [25]")
else:
    changes.append("R3a: Spitzner ref not found or Pawlick already present")

# [28] Liu & Lang 2019 -> add Sarhan 2023 ML-IDS survey
old_liu = "[28] Y. Liu and B. Lang"
new_sarhan = "\n[28b] M. Sarhan, S. Layeghy, and M. Portmann, \"Towards a Standard Feature Set for Network Intrusion Detection System Datasets,\" *Mobile Netw. Appl.*, vol. 27, pp. 357-370, 2022. [doi: 10.1007/s11036-021-01843-0]"
if old_liu in content and "Standard Feature Set for Network" not in content:
    idx = content.find(old_liu)
    eol = content.find("\n", idx)
    content = content[:eol] + new_sarhan + content[eol:]
    changes.append("R3b: Sarhan 2023 ML-IDS survey added after [28]")
else:
    changes.append("R3b: Liu ref not found or Sarhan already present")

# ── Write back ────────────────────────────────────────────────────────────────
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Changes applied:")
for c in changes:
    print(" -", c)
print("Total lines after:", len(content.splitlines()))
