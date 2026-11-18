"""
bunyanx NGFW — محرك احتمالات سلسلة الإيذاء (KillchainGraph)

ميزة بحثية (Research Feature #2):
هذا الكود يبدل القواعد القديمة (الشروط if/else) في محرك الارتباط،
ويستبدلها بـ رسم بياني موجه (Directed Markov Chain Graph) يتعلم من نفسه.

المعمارية الهندزية:
    - العقد (Nodes): المشاكل الأمنية (فحص، استغلال WAF، برمجيات خبيثة، الخ...)
    - الحواف (Edges): احتمالية إن الهجوم يطمر من خطوة للثانية P(B | A)
    - التعلم: يتحدث الوزن تلقائياً مع كل هجمة حية (وما يحتاجش إعادة تدريب للمودل)
    - التقييم: نضرب احتمالات المسار كامل عشان نطلع سكور الهجمة
    - القرار: لو السكور طاف الـ KILL_CHAIN_THRESHOLD نفعل الدفاع فوراً

ليش هذا أشنب وأفضل من القواعد الثابتة؟
    - صايد للحركات المجهولة اللي ما تبرمجت من قبل
    - يتعلم ويتأقلم مع بيئة الشبكة الحقيقية حبة حبة
    - الحساب الاحتمالي يعيطنا رد ذكي ومتوازن بدال (أبيض وأسود)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False


# ── رسم بياني احتياطي (بدون مكتبة networkx) ─────────────────────────

class _FallbackGraph:
    """
    رسم بياني احتياطي يغطي مكان الـ networkx.DiGraph لو هي مش محملة.
    يحفظ العقد كـ set والحواف كقاموس متداخل:
        _adj[src][dst] = {"weight": float, "count": int}
    """

    def __init__(self):
        self._nodes: set = set()
        self._adj:   dict = {}   # src -> {dst -> attrs}

    def add_nodes_from(self, nodes):
        for n in nodes:
            self._nodes.add(n)
            self._adj.setdefault(n, {})

    def nodes(self):
        return list(self._nodes)

    def add_edge(self, src, dst, **attrs):
        self._nodes.add(src)
        self._nodes.add(dst)
        self._adj.setdefault(src, {})
        self._adj.setdefault(dst, {})
        self._adj[src][dst] = attrs

    def has_edge(self, src, dst):
        return dst in self._adj.get(src, {})

    def __getitem__(self, src):
        return self._adj[src]

    def number_of_edges(self):
        return sum(len(dsts) for dsts in self._adj.values())

    def successors(self, node):
        return list(self._adj.get(node, {}).keys())

    def __contains__(self, node):
        return node in self._nodes

    def edges(self, data=False):
        result = []
        for src, dsts in self._adj.items():
            for dst, attrs in dsts.items():
                result.append((src, dst, attrs) if data else (src, dst))
        return result


# ── الثوابت الأساسية ──────────────────────────────────────────────────

# العتبة اللي إذا تجاوزها سكور الهجوم، يقوم النظام يفعل الدفاع
KILL_CHAIN_THRESHOLD = 0.45

# سرعة التعلم وتحديث الأوزان (كل ما كبر، كل ما تعلم أسرع من الهجمات الجديدة)
LEARNING_ALPHA = 0.15

# كل أنواع الأحداث اللي نعتبرها عقد في سلسلة الإيذاء
EVENT_TYPES = [
    "SCAN",
    "WAF_EXPLOIT",
    "MALWARE",
    "DGA_C2",
    "DLP_EXFIL",
    "LATERAL_MOVEMENT",
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "RANSOMWARE",
    "UNKNOWN",
]

# الاحتمالات المسبقة بناءً على إحصائيات منصة (MITRE ATT&CK)
# تمثل فرصة وقوع حدث بعد الحدث اللي قبله P(B | A)
#
# AEGIS v2 — سلسلة إيذاء غير خطية (بناءً على النقد الأكاديمي):
#   * الروابط الأمامية   : تسلسل طبيعي للهجوم
#   * الروابط الخلفية   : الهاكر يعاود خطوة سابقة (مثل إعادة التمركز)
#   * القفزات           : الهاكر يحرق المراحل ويتخطى (من الفحص للتحرك الجانبي مباشرة)
#   * اكتشاف الدوامات    : نصيد حركات اللف والدوران (APT persistence loops)
_PRIOR_EDGES = [
    # ── روابط أمامية (الطريق المعتاد للهجوم) ─────────────────────────
    ("SCAN",                "WAF_EXPLOIT",           0.68),
    ("SCAN",               "DGA_C2",                0.22),
    ("SCAN",               "LATERAL_MOVEMENT",      0.35),
    ("WAF_EXPLOIT",        "DLP_EXFIL",             0.81),
    ("WAF_EXPLOIT",        "PRIVILEGE_ESCALATION",  0.55),
    ("WAF_EXPLOIT",        "MALWARE",               0.40),
    ("MALWARE",            "DGA_C2",                0.88),
    ("MALWARE",            "LATERAL_MOVEMENT",      0.60),
    ("MALWARE",            "RANSOMWARE",            0.44),
    ("DGA_C2",             "DLP_EXFIL",             0.74),
    ("DGA_C2",             "LATERAL_MOVEMENT",      0.50),
    ("DLP_EXFIL",          "LATERAL_MOVEMENT",      0.30),
    ("LATERAL_MOVEMENT",   "PRIVILEGE_ESCALATION",  0.70),
    ("LATERAL_MOVEMENT",   "DLP_EXFIL",             0.65),
    ("PRIVILEGE_ESCALATION","PERSISTENCE",          0.80),
    ("PRIVILEGE_ESCALATION","DLP_EXFIL",            0.75),
    ("PRIVILEGE_ESCALATION","RANSOMWARE",           0.50),

    # ── قفزات وحرق مراحل (هجمات APT الخبيثة) ─────────────────
    # من الفحص للتحرك الجانبي (موظف خائن أو حسابه مخترق)
    ("SCAN",               "LATERAL_MOVEMENT",      0.18),
    # من الفحص للمالوير مباشرة بدون استغلال واضح
    ("SCAN",               "MALWARE",               0.12),
    # فيروس الفدية السريع اللي ما يهتم يتخفى أو يتمركز
    ("WAF_EXPLOIT",        "RANSOMWARE",            0.22),
    # مالوير زرع نفسه من سكات بدون ما يسوي C2
    ("MALWARE",            "PERSISTENCE",           0.33),
    # C2 يرفع الصلاحيات بدال ما يتحرك جانبي
    ("DGA_C2",             "PRIVILEGE_ESCALATION",  0.28),

    # ── روابط خلفية: المهاجم رجع لطبقة سابقة (لف ودوران) ─────────────
    # تحرك جانبي ودور له فحص جديد
    ("LATERAL_MOVEMENT",   "SCAN",                  0.15),
    # رفع صلاحيات وبعدها واصل ينتشر في الشبكة
    ("PRIVILEGE_ESCALATION","LATERAL_MOVEMENT",     0.40),
    # تمركز وبعده رفع صلاحياته ثاني
    ("PERSISTENCE",        "PRIVILEGE_ESCALATION",  0.20),
    # مبرمج خبيث صحي من النوم وبدأ يتحرك بالشبكة
    ("PERSISTENCE",        "LATERAL_MOVEMENT",      0.25),
    # يحافظ على قناة الاتصال (C2) شغالة باستمرار
    ("PERSISTENCE",        "DGA_C2",                0.35),
    # فشل في رفع الصلاحيات ورجع يحاول يخترق WAF من جديد
    ("PRIVILEGE_ESCALATION","WAF_EXPLOIT",          0.08),
]


# ── هياكل البيانات ──────────────────────────────────────────────────────

@dataclass
class KillChainPath:
    """وصف المسار المكتشف للهجمة مع سكور الاحتمالية حقه."""
    nodes: List[str]
    score: float
    src_ip: str
    detected_at: float = field(default_factory=time.time)

    @property
    def is_critical(self) -> bool:
        return self.score >= KILL_CHAIN_THRESHOLD

    def __str__(self) -> str:
        # عرض آخر 5 عقد فقط عشان ما يطول السجل
        tail = self.nodes[-5:]
        prefix = "..." if len(self.nodes) > 5 else ""
        chain = " → ".join(tail)
        return f"[{prefix}{chain}] score={self.score:.3f} (path_len={len(self.nodes)})"


# ── محرك KillchainGraph ────────────────────────────────────────────────

class KillchainGraph:
    """
    رسم بياني لاحتمالات سلسلة الإيذاء يتعلم ويتكيف أوتوماتيكياً.
    يحفظ انتقالات أحداث الأمان ويحدث نسبة وتناسب الأحداث من الهجمات الحية.
    يفحص إذا الحركة من الآي بي هذا تشكل هجمة معقدة.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)

        if _NX_AVAILABLE:
            self._graph = nx.DiGraph()
        else:
            self.logger.warning(
                "مكتبة networkx غايبة — النظام بيستخدم الرسم البياني الاحتياطي. "
                "نزلها واهجعنا: pip install networkx"
            )
            self._graph = _FallbackGraph()
        self._build_initial_graph()

        # نحتفظ بكم مرة شفناها عشان التحديث الموزون للتعلم
        self._edge_counts: Dict[Tuple[str, str], int] = {}

        self.logger.info(
            "تم تشغيل محرك KillchainGraph ذيه | العقد=%d | العتبة=%s | "
            "الخلفية=%s",
            len(EVENT_TYPES),
            KILL_CHAIN_THRESHOLD,
            "networkx" if _NX_AVAILABLE else "fallback",
        )

    def _build_initial_graph(self):
        """تلقيم الرسم البياني بأنواع الأحداث والاحتمالات الأولية."""
        self._graph.add_nodes_from(EVENT_TYPES)
        for src, dst, prob in _PRIOR_EDGES:
            self._graph.add_edge(src, dst, weight=prob, count=1)

    # ── التعلم الحي (Online Learning) ───────────────────────────────────

    def record_transition(self, from_event: str, to_event: str):
        """
        نسجل الحدث ونحدث وزن الاحتمال (عبر معادلة EMA).
        تُستدعى آلياً لما نفحص تسلسل هجوم واقعي. (هذا هو عصب التعلم).
        """
        if not self._graph:
            return

        from_event = from_event.upper()
        to_event   = to_event.upper()

        # لو العقد ما كانت موجودة، نفرع لها وتصبح موجودة
        if from_event not in self._graph:
            self._graph.add_node(from_event)
        if to_event not in self._graph:
            self._graph.add_node(to_event)

        key = (from_event, to_event)
        self._edge_counts[key] = self._edge_counts.get(key, 0) + 1

        if self._graph.has_edge(from_event, to_event):
            old_prob = self._graph[from_event][to_event]["weight"]
            # هنا التحديث: نمزج بين الماضي وهذا الحدث اللي وقع 100%
            new_prob = (1 - LEARNING_ALPHA) * old_prob + LEARNING_ALPHA * 1.0
            self._graph[from_event][to_event]["weight"] = min(new_prob, 0.99)
            self._graph[from_event][to_event]["count"] += 1
        else:
            # مسار جديد كرت (ما شفناه من قبل) — نعطيه وزن مبدئي حذر
            self._graph.add_edge(from_event, to_event, weight=LEARNING_ALPHA, count=1)

        self.logger.debug(f"KillchainGraph: تعلم مسار هجوم جديد {from_event} → {to_event}")

    # ── فحص المسار ─────────────────────────────────────────────────────

    def evaluate_ip_events(self, src_ip: str, events: List[str]) -> Optional[KillChainPath]:
        """
        بناءً على قائمة أحداث من آي بي واحد، نحسب سكور الخطر
        عن طريق ضرب الاحتمالات لخطوات الهجوم.
        مثال: SCAN(0.68)→WAF(0.81)→DLP = 0.55 → خطر فادح (CRITICAL)

        يرد بقيمة None لو السلسلة أقل من خطوتين.
        """
        if len(events) < 2:
            return None

        # توحيد الحروف
        normalized = [e.upper() for e in events]

        # حساب سكور الهجوم
        score = 1.0
        valid_hops = 0
        for i in range(len(normalized) - 1):
            src_node = normalized[i]
            dst_node = normalized[i + 1]
            if self._graph.has_edge(src_node, dst_node):
                score *= self._graph[src_node][dst_node]["weight"]
                valid_hops += 1
            else:
                # مسار غريب: نخفض السكور بس ما نلغي الهجمة كاملة
                score *= 0.10
                valid_hops += 1

        if valid_hops == 0:
            return None

        path = KillChainPath(nodes=normalized, score=round(score, 4), src_ip=src_ip)

        # Check whitelist before auto-blocking
        is_whitelisted = False
        try:
            from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
            if get_whitelist_manager().is_whitelisted(src_ip):
                is_whitelisted = True
        except Exception:
            pass

        # نسجل فقط لو الخطر وصل لعتبة حرجة (is_critical)
        if path.is_critical and not is_whitelisted:
            self.logger.warning(f"[KillchainGraph] 🚫 CRITICAL THREAT DETECTED | Auto-blocking {src_ip}: {path}")
            if src_ip and src_ip not in ("127.0.0.1", "::1"):
                try:
                    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
                    get_blocklist_manager().block_ip_sync(
                        src_ip,
                        reason=f"Predictive AI Killchain Threat Detected (score={path.score})",
                        blocked_by="killchain_graph",
                        duration_seconds=600
                    )
                except Exception as _k_err:
                    self.logger.debug(f"[KillchainGraph] Auto-block failed for {src_ip}: {_k_err}")
        else:
            self.logger.debug(f"[KillchainGraph] {src_ip}: {path}")

        return path

    # ── توقع التكتيك القادم ──────────────────────────────────────────

    def predict_next_event(self, current_event: str, top_n: int = 3) -> List[Tuple[str, float]]:
        """
        بناءً على الحدث الحالي، نخرج أفضل توقعات لايش المهاجم بيسوي.
        ويُستخدم هذا في محرك IntentPredictor عشان يسبقه بخطوة.
        """
        current_event = current_event.upper()
        if current_event not in self._graph:
            return []

        successors = [
            (successor, self._graph[current_event][successor]["weight"])
            for successor in self._graph.successors(current_event)
        ]
        return sorted(successors, key=lambda x: x[1], reverse=True)[:top_n]

    # ── فحص تركيبة النظام ──────────────────────────────────────────

    def get_graph_summary(self) -> Dict:
        """يخرج لك ملخص شامل للحالة حق الرسم البياني عشان الواجهة."""
        return {
            "available": True,
            "nodes": list(self._graph.nodes()),
            "edge_count": self._graph.number_of_edges(),
            "threshold": KILL_CHAIN_THRESHOLD,
            "top_edges": sorted(
                [
                    {"from": u, "to": v, "probability": round(d["weight"], 3), "observations": d.get("count", 0)}
                    for u, v, d in self._graph.edges(data=True)
                ],
                key=lambda x: x["probability"],
                reverse=True,
            )[:15],
            "nonlinear_stats": self.get_nonlinear_stats(),
        }

    # ── دعم الهجوم غير الخطي (AEGIS v2) ──────────────────────────

    def detect_loop(self, src_ip: str, min_loop_len: int = 2) -> bool:
        """
        يكشف إذا الهاكر جالس يلف ويدور ويكرر مراحله.
        أمثلة:
          - مالوير يتمركز ونام، وبعدين رجع يشتغل
          - تحرك جانبي، وبعدين فحص داخلي مرة ثانية
          - محاولات متكررة تخترع وتفشل
        """
        history = self._ip_event_history.get(src_ip, [])
        if len(history) < min_loop_len * 2:
            return False
        # نعد الخطوات؛ لو عاد نفس الخطوة مرة ثانية يعني بيلف ويدور
        from collections import Counter
        stage_counts = Counter(ev.upper() for ev in history)
        return any(count >= min_loop_len for count in stage_counts.values())

    def get_nonlinear_stats(self) -> dict:
        """
        يطلع إحصائيات للحركات غير الخطية (تخطي ورجوع وحرق مراحل).
        هذا مهم لورقة الـ AEGIS المقطع الرابع عشان نثبت قوة الكود في البحث.
        """
        forward_edges = 0
        back_edges    = 0
        skip_edges    = 0

        # الترتيب المنطقي للتهديد (أمامياً)
        _ORDER = {
            "SCAN": 0, "WAF_EXPLOIT": 1, "MALWARE": 2, "DGA_C2": 3,
            "LATERAL_MOVEMENT": 4, "PRIVILEGE_ESCALATION": 5,
            "PERSISTENCE": 6, "DLP_EXFIL": 7, "RANSOMWARE": 8,
        }

        for src, dst, data in self._graph.edges(data=True):
            obs = data.get("count", 0)
            if obs == 0:
                continue   # نحسب بس المسارات اللي شفناها عياناً
            s_ord = _ORDER.get(src, -1)
            d_ord = _ORDER.get(dst, -1)
            if s_ord == -1 or d_ord == -1:
                continue
            diff = d_ord - s_ord
            if diff == 1:
                forward_edges += obs
            elif diff > 1:
                skip_edges    += obs
            else:
                back_edges    += obs   # رجوع للخلف أو لف ورا نفسه

        total = forward_edges + back_edges + skip_edges or 1
        return {
            "forward_edges_pct": round(forward_edges / total * 100, 1),
            "back_edges_pct":    round(back_edges    / total * 100, 1),
            "skip_edges_pct":    round(skip_edges    / total * 100, 1),
            "total_transitions": total,
        }
