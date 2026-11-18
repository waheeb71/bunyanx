"""
Understand how input_sequence maps to the model's 14-dim one-hot input,
then generate ALL paper figures from real model inference on real data.
"""
import sys, json, pathlib, re
sys.stdout.reconfigure(encoding='utf-8')

# ── Read the actual predictor source ───────────────────────────────────
src = open(r'F:/enterprise_ngfw/modules/predictive_ai/engine/AEGIS/intent/attention_predictor.py',
           encoding='utf-8').read()

# Print the _to_onehot and _build_windows methods
start = src.find('def _to_onehot')
end   = src.find('\n    def ', start + 10)
print("=== _to_onehot ===")
print(src[start:end])

start2 = src.find('def _build_windows')
end2   = src.find('\n    def ', start2 + 10)
print("=== _build_windows ===")
print(src[start2:end2])

# Also find predict() to see how input_sequence is parsed
start3 = src.find('def predict(')
end3   = src.find('\n    def ', start3 + 10)
print("=== predict ===")
print(src[start3:end3])
