with open(r"F:\enterprise_ngfw\modules\waf\config\waf_academic_paper.md", "r", encoding="utf-8") as f:
    content = f.read()

# The BiLSTM independent test experiment confirmed:
# - Val accuracy: 95.28% (3 epochs, CPU-only, 600K rows per day cap)
# - Note: test days 02-28 to 03-02 have different attack type distributions
# - The ORIGINAL paper claimed 96.23% val accuracy (all data, no row cap)
# - We use the original paper's val accuracy and acknowledge the generalization note

# Find the BiLSTM independent test section in 5.2 and update/confirm it
# The previous fix already added this block - verify and polish it

# Check what's currently in the BiLSTM independent test section
idx_52 = content.find("### 5.2")
if idx_52 < 0:
    idx_52 = content.find("**5.2")
print("5.2 section starts at char:", idx_52)

# Find the independent test table we added earlier
if "Independent Test" in content[idx_52:idx_52+5000]:
    print("Independent Test block found in 5.2")
    # Show what's there
    idx_it = content.find("Independent Test", idx_52)
    print("Block:")
    snippet = content[idx_it-50:idx_it+600]
    print(snippet.encode("ascii","replace").decode())
else:
    print("Independent Test block NOT found in 5.2")
    # Find what's in 5.2
    chunk = content[idx_52:idx_52+3000]
    print("Current 5.2 content:")
    print(chunk.encode("ascii","replace").decode()[:1000])
