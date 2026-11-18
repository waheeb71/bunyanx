import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from modules.web_filter.policy.holo_filter import HoloFilter

model_path = os.path.join(os.path.dirname(__file__), "offline_hv.npz")
print(f"Loading Model: {model_path}")

holo = HoloFilter(model_path=model_path)
print(f"Model Ready: {holo.ready}")

test_domains = [
    "google.com", 
    "paypal-login-secure.com", 
    "qweqweasdzxczxc.net",
    "bksdkfjwerer.com",
    "microsoft.com"
]

print("\n--- Diagnostic Array ---")
for d in test_domains:
    res = holo.evaluate(d)
    print(f"Domain: {d:25} | Risk: {res['risk']:.4f} | Action: {res['action']} | Reason: {res['reason']}")
