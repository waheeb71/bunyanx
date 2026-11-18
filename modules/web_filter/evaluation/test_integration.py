import sys
import os

# Add root folder to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

try:
    from modules.web_filter.policy.engine import WebFilterEngine
except Exception as e:
    print(f"Error loading WebFilterEngine: {e}")
    sys.exit(1)

print("\n" + "="*80)
print("bunyanx NGFW - Web Filter Integrated Test")
print("="*80)

print("[+] Loading Database schemas and Offline HDC Matrices...")
try:
    engine = WebFilterEngine()
except Exception as e:
    # Handle DB not initialized in test scripts gracefully
    print("DatabaseManager not initialized. Stubbing database requirements for AI test...")
    from modules.web_filter.policy.category import CategoryEngine
    class MockCategoryEngine(CategoryEngine):
        def reload(self):
            pass # Skip querying DB
    
    # Manually attach mock
    ce = MockCategoryEngine()
    
    # We still need a shell engine
    class MockWebFilterEngine:
        def __init__(self):
            self.category_engine = ce
    engine = MockWebFilterEngine()


test_domains = [
    "google.com", 
    "wikipedia.org", 
    "lskdfjlskdfj234.net", 
    "paypal-security-check.com", 
    "abububa.biz",
    "xsderfvbgtyhnm.ru"
]

print("\n Testing Real-Time Classification Pipeline:\n")
header = f"{'Domain':<30} | {'Action':<10} | {'AI Confidence':<15} | {'Category Assigned':<20}"
print(header)
print("-" * len(header))

for d in test_domains:
    res = engine.category_engine.categorize(d)
    
    action = res.ai_action if res.ai_action else "ALLOW"
    confidence = f"{res.risk_score:.2f}" if res.risk_score > 0 else "N/A"
    cat = res.categories[0]
    
    print(f"{d:<30} | {action:<10} | {confidence:<15} | {cat:<20}")

print("\n" + "="*80)
print("Architecture Verification Complete")
