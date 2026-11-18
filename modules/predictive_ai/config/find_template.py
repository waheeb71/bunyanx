import os, sys
sys.stdout.reconfigure(encoding='utf-8')
d = r'F:\enterprise_ngfw\modules\predictive_ai\paper'
for f in os.listdir(d):
    if 'Conference' in f:
        print(repr(f))
        print(f)
