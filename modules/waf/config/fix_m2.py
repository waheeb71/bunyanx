# encoding: utf-8
with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# M2 was placed but the marker check uses "Contingency" - let us check
if "Contingency" in content:
    print("Contingency IS in file")
else:
    print("Contingency NOT in file - adding it now")
    # find where McNemar is mentioned (chi2 result)
    markers = ["McNemar", "chi^2=", "847.2"]
    for m in markers:
        if m in content:
            idx = content.find(m)
            ctx = content[max(0,idx-200):idx+500]
            print("Found at context:", ctx[:300])
            break

# Let us search for what was added:
if "CRS Correct" in content:
    print("CRS Correct table IS present")
    idx = content.find("CRS Correct")
    print("Context:", content[max(0,idx-100):idx+400])
else:
    print("CRS Correct table NOT found")
