"""Debug: What does the model actually predict?"""
import sys, torch, torch.nn as nn, numpy as np
sys.path.insert(0, '.')

N_FEATURES,N_TTPS,WINDOW = 14, 9, 10
TTP_NAMES = ['SCAN','WAF_EXPLOIT','MALWARE','DGA_C2','DLP_EXFIL',
             'LATERAL','PRIV_ESC','PERSISTENCE','RANSOMWARE']
TTP_INDEX = {t:i for i,t in enumerate(TTP_NAMES)}
EP_INDEX  = {'PROC_CREATE':0,'FILE_MOD':1,'REG_EDIT':2,'NET_CONN':3,'MEM_INJECT':4}

d_model,n_heads,n_layers,d_ff,dropout = 64,4,2,256,0.1

class _PE(nn.Module):
    def __init__(self):
        super().__init__()
        pe = torch.zeros(512,d_model)
        pos = torch.arange(0,512,dtype=torch.float).unsqueeze(1)
        div = torch.exp(torch.arange(0,d_model,2,dtype=torch.float)*(-np.log(10000.)/d_model))
        pe[:,0::2]=torch.sin(pos*div); pe[:,1::2]=torch.cos(pos*div)
        self.register_buffer('pe', pe.unsqueeze(0))
    def forward(self,x): return x + self.pe[:,:x.size(1)]

class M(nn.Module):
    def __init__(self):
        super().__init__()
        self.input_projection = nn.Linear(N_FEATURES, d_model)
        self.pos_encoder = _PE()
        enc = nn.TransformerEncoderLayer(d_model=d_model, nhead=n_heads,
              dim_feedforward=d_ff, dropout=dropout, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(enc, num_layers=n_layers)
        self.head = nn.Sequential(nn.Linear(d_model,32), nn.ReLU(),
                                  nn.Dropout(dropout), nn.Linear(32,N_TTPS))
    def forward(self,x):
        x=self.input_projection(x); x=self.pos_encoder(x)
        x=self.transformer_encoder(x); return self.head(x[:,-1,:])

m = M()
state = torch.load('models/ttp_transformer.pt', map_location='cpu', weights_only=False)
m.load_state_dict(state); m.eval()

def make_input(ttps, eps=None):
    eps = eps or []
    t = np.zeros((1,WINDOW,N_FEATURES), dtype=np.float32)
    for i, ttp in enumerate(ttps[-WINDOW:]):
        t[0, i, TTP_INDEX.get(ttp, 0)] = 1.0
    for i, ep in enumerate(eps[-WINDOW:]):
        t[0, i, 9+EP_INDEX.get(ep,0)] = 1.0
    return torch.tensor(t)

print("=== Model Prediction Debug ===\n")

tests = [
    ("All zeros",                  [],                   []),
    ("SCAN x10",                   ['SCAN']*10,          []),
    ("SCAN->WAF_EXPLOIT (end)",    ['SCAN']*9+['WAF_EXPLOIT'], []),
    ("WAF->MALWARE (end)",         ['WAF_EXPLOIT']*9+['MALWARE'], []),
    ("MALWARE->DGA_C2 (end)",      ['MALWARE']*9+['DGA_C2'], ['NET_CONN']*10),
    ("DGA->DLP_EXFIL (end)",       ['DGA_C2']*9+['DLP_EXFIL'], []),
    ("MALWARE->LATERAL (end)",     ['MALWARE']*9+['LATERAL'], []),
    ("LATERAL->PRIV_ESC (end)",    ['LATERAL']*9+['PRIV_ESC'], ['MEM_INJECT']*10),
    ("PRIV->PERSISTENCE (end)",    ['PRIV_ESC']*9+['PERSISTENCE'], ['REG_EDIT']*10),
    ("PERSIST->RANSOMWARE (end)",  ['PERSISTENCE']*9+['RANSOMWARE'], ['FILE_MOD']*10),
]

for name, ttps, eps in tests:
    x = make_input(ttps, eps)
    with torch.no_grad():
        probs = torch.softmax(m(x), dim=-1).squeeze().numpy()
    pred = int(np.argmax(probs))
    top3 = sorted(enumerate(probs), key=lambda x: -x[1])[:3]
    top3_str = ", ".join(f"{TTP_NAMES[i]}={v:.3f}" for i,v in top3)
    print(f"  {name:35s} -> {TTP_NAMES[pred]:12s}  top3: [{top3_str}]")

print()
print("=== Per-class dominant prediction (50 per class) ===")
for cls_name in TTP_NAMES:
    ci = TTP_INDEX[cls_name]
    preds = []
    for _ in range(50):
        seq = [cls_name]*WINDOW
        x = make_input(seq)
        with torch.no_grad():
            probs = torch.softmax(m(x), dim=-1).squeeze().numpy()
        preds.append(int(np.argmax(probs)))
    from collections import Counter
    most = Counter(preds).most_common(1)[0]
    print(f"  Input={cls_name:12s} -> always predicts {TTP_NAMES[most[0]]:12s} ({most[1]}/50)")
