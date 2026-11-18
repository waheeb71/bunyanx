"""
bunyanx NGFW — AEGIS Engine: المنسق الرئيسي (Main Orchestrator)
==================================================

كلاس AEGISEngine هو نقطة الدخول الوحيدة لكل استنتاجات نظام AEGIS.
يجمع الأربعة المكونات الأساسية في دائرة دفاع مغلقة (Closed-Loop Pipeline):

    حدث أمني (Security Event)
         │
         ▼
    [1] مقدر الحالة العدائية (ASE)
         تحديث الاعتقاد البايزي لخطوات المهاجم في سلسلة الإيذاء (MITRE).
         المخرجات: الحالة الاعتقادية (توزيع احتمالي لكل آي بي)
         │
         ▼
    [2] محاكي النية العدائية (AIS)
         يحسب التوزيع الاحتمالي للخطوة الجاية للمهاجم (بناءً على عقلانية بولتزمان).
         المخرجات: قائمة بتوقعات أساليب الهجوم (TTPPrediction)
         │
         ▼
    [3] محسن الاستراتيجية المضادة (CSO)
         يختبر كل السيناريوهات (Minimax) ويخصم عقوبة التصعيد قبل ما يقرر أفضل دفاع.
         المخرجات: الاستراتيجية المضادة (القرار + التبرير العلمي)
         │
         ▼
    [4] حلقة التغذية المستمرة (Feedback Loop)
         دالة `record_actual_ttp` تحدث جدول التعلم (Q-table) وفلتر بايز 
         مباشرة في الذاكرة مع كل هفوة للهاكر.

كيفية الاستخدام:
-----
    from modules.predictive_ai.engine.AEGIS import AEGISEngine

    AEGIS = AEGISEngine()

    # يتم استدعاءها مع كل حدث أمني (كل طارقة):
    result = AEGIS.process_event(src_ip="10.0.0.5", event_type="WAF_EXPLOIT")

    print(result.counter_strategy.action)          # مثلاً "HONEYPOT_REDIRECT"
    print(result.counter_strategy.explanation)
    print(result.belief_state.most_likely_stage)   # مثلاً "INITIAL_ACCESS"
"""

from __future__ import annotations

import time
import logging
import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Dict

from system.events.bus import EventBus
from system.events.topics import Topics

from modules.predictive_ai.engine.AEGIS.state.estimator import (
    AdversarialStateEstimator,
)
from modules.predictive_ai.engine.AEGIS.intent.simulator import (
    AdversarialIntentSimulator,
    TTPPrediction,
)

from modules.predictive_ai.engine.AEGIS.state.belief import BeliefState
from modules.predictive_ai.engine.AEGIS.strategy.optimizer import (
    CounterStrategy,
    CounterStrategyOptimizer,
)
from modules.predictive_ai.engine.AEGIS.deception.injector import (
    DeceptionInjectionEngine,
    DecoyDirective,
)
from modules.predictive_ai.engine.AEGIS.ueba.verifier import (
    UEBAVerifier,
    UEBADecision,
    UEBAVerdict,
)
from modules.predictive_ai.engine.AEGIS.topology.gnn import (
    GNNLateralPredictor,
)
from modules.predictive_ai.engine.AEGIS.topology.graph import (
    NetworkTopology,
)
from modules.predictive_ai.engine.AEGIS.core.constants import (
    CSO_ALPHA, CSO_BETA, CSO_GAMMA, CSO_LAMBDA,
    NUM_TTPS, NUM_STAGES,
    DEFENDER_ACTIONS,
)
from modules.predictive_ai.engine.AEGIS.intent.ciapg import (
    CausalAntiPoisoningGate,
)
from modules.predictive_ai.engine.AEGIS.intent.dmaa import (
    DualModelAdaptiveAdversary,
)
from modules.predictive_ai.engine.AEGIS.intent.cpci import (
    CalibratedPredictionConfidenceIndex,
    AuthorizationTier,
)
from modules.predictive_ai.engine.AEGIS.strategy.ddts import (
    DefensiveDigitalTwinSimulator,
)


# ---------------------------------------------------------------------------
# مسجل الأحداث حق الوحدة (Logger)
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# هياكل المخرجات (Output type)
# ---------------------------------------------------------------------------

@dataclass
class AEGISResult:
    """
    النتيجة الكاملة لدورة استنتاج واحدة في محرك AEGIS.

    الخصائص:
    ----------
    src_ip : str
        عنوان الآي بي حق الهاكر المشتبه فيه.
    event_type : str
        الحدث الأمني اللي خلى النظام يصحصح.
    belief_state : BeliefState
        تحديث الاعتقاد البايزي بعد ما رصدنا الحدث.
    ttp_distribution : list[TTPPrediction]
        التكتيكات المتوقعة اللي ناوي يسويها הهاكر.
    counter_strategy : CounterStrategy
        القرار الدفاعي الأشنب (حسب توازن ناش).
    ueba_decision : UEBADecision | None
        قرار بوابة السلوكيات (عشان نقلل الإنذارات الكاذبة).
    decoy_directive : DecoyDirective | None
        تعليمات توجيه الهاكر لشبكة وهمية لو قرر النظام يخدعه.
    inference_time_ms : float
        الوقت بالملي ثانية اللي استغرقه النظام عشان يقرر.
    timestamp : float
        التوقيت حق الحدث (UNIX).
    """

    src_ip:            str
    event_type:        str
    belief_state:      BeliefState
    ttp_distribution:  list[TTPPrediction]
    counter_strategy:  CounterStrategy
    ueba_decision:     Optional[UEBADecision]
    decoy_directive:   Optional[DecoyDirective]
    inference_time_ms: float
    # C11 — CPCI outputs
    prediction_set:    list[str] = field(default_factory=list)
    cpci_score:        float = 0.0
    authorization:     str = "HUMAN_REVIEW"
    # C10 — DDTS validation report
    ddts_report:       Optional[dict] = None
    timestamp:         float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_ip":            self.src_ip,
            "event_type":        self.event_type,
            "belief_state":      self.belief_state.to_dict(),
            "ttp_distribution":  [
                {"ttp": p.ttp, "probability": round(p.probability, 4)}
                for p in self.ttp_distribution[:5]
            ],
            "counter_strategy":  self.counter_strategy.to_dict(),
            "ueba_decision":     self.ueba_decision.to_dict() if self.ueba_decision else None,
            "decoy_directive":   self.decoy_directive.to_dict() if self.decoy_directive else None,
            "inference_time_ms": round(self.inference_time_ms, 3),
            "prediction_set":    self.prediction_set,
            "cpci_score":        round(self.cpci_score, 4),
            "authorization":     self.authorization,
            "ddts_report":       self.ddts_report,
            "timestamp":         self.timestamp,
        }


# ---------------------------------------------------------------------------
# AEGISEngine
# ---------------------------------------------------------------------------

class AEGISEngine:
    """
    المنسق الرئيسي والمحرك العقلاني حق AEGIS.

    كل المكونات (ASE, AIS, CSO) نصلحها مرة واحدة وقت إقلاع النظام
    ونشاركها في كل الاستدعاءات (عشان الأداء وسرعة المعالجة).
    """

    def __init__(
        self,
        *,
        ase_max_tracked_ips: int   = 4_096,
        ase_decay_alpha:     float = 0.15,
        cso_alpha:           float = CSO_ALPHA,
        cso_beta:            float = CSO_BETA,
        cso_gamma:           float = CSO_GAMMA,
        cso_lam:             float = CSO_LAMBDA,
        die_decoy_subnet:    str   = "10.99.88.",
        die_max_decoys:      int   = 256,
        die_default_ttl:     int   = 1_800,
        die_min_certainty:   float = 0.35,
        enable_ueba:         bool  = True,
        ueba_base_risk_threshold: float = 0.35,
        enable_gnn:          bool  = False,
        gnn_blend_weight:    float = 0.40,
        # C7 — Dual-Model Adaptive Adversary
        enable_dmaa:         bool  = True,
        # C8 — Causal Anti-Poisoning Gate
        enable_ciapg:        bool  = True,
        # C11 — Calibrated Prediction Confidence Index
        enable_cpci:         bool  = True,
        prevent_cpci_override_on_threats: bool = True,
        # C10 — Defensive Digital Twin Simulator
        enable_ddts:         bool  = True,
    ) -> None:
        self._prevent_cpci_override_on_threats = prevent_cpci_override_on_threats
        self._ase = AdversarialStateEstimator(
            max_tracked_ips=ase_max_tracked_ips,
            decay_alpha=ase_decay_alpha,
        )
        self._ais = AdversarialIntentSimulator()
        self._cso = CounterStrategyOptimizer(
            alpha=cso_alpha,
            beta=cso_beta,
            gamma=cso_gamma,
            lam=cso_lam,
        )

        self._gnn: Optional[GNNLateralPredictor] = None
        self._topology: Optional[NetworkTopology] = None
        self._gnn_blend = gnn_blend_weight
        self._enable_gnn = enable_gnn
        if enable_gnn:
            self._gnn = GNNLateralPredictor()

        # Layer 4.5: بوابة السلوكيات UEBA Verification Gate
        self._ueba: Optional[UEBAVerifier] = None
        self._enable_ueba = enable_ueba
        if enable_ueba:
            self._ueba = UEBAVerifier(
                base_risk_threshold=ueba_base_risk_threshold,
            )
        self._die = DeceptionInjectionEngine(
            decoy_subnet=die_decoy_subnet,
            max_active_decoys=die_max_decoys,
            default_ttl=die_default_ttl,
            min_belief_certainty=die_min_certainty,
        )

        # C8 — Causal Anti-Poisoning Gate
        self._ciapg: Optional[CausalAntiPoisoningGate] = (
            CausalAntiPoisoningGate() if enable_ciapg else None
        )

        # C7 — Dual-Model Adaptive Adversary
        self._dmaa: Optional[DualModelAdaptiveAdversary] = (
            DualModelAdaptiveAdversary() if enable_dmaa else None
        )

        # C11 — Calibrated Prediction Confidence Index
        self._cpci: Optional[CalibratedPredictionConfidenceIndex] = (
            CalibratedPredictionConfidenceIndex() if enable_cpci else None
        )

        # C10 — Defensive Digital Twin Simulator
        self._ddts: Optional[DefensiveDigitalTwinSimulator] = (
            DefensiveDigitalTwinSimulator() if enable_ddts else None
        )

        # سجل القرارات الحي (in-memory rolling buffer)
        self._decision_history: deque = deque(maxlen=200)

        components = "ASE + AIS + CSO"
        if enable_gnn:
            components = "ASE + GNN + AIS + CSO"
        if enable_ueba:
            components += " + UEBA"
        if enable_ciapg:
            components += " + CIAPG"
        if enable_dmaa:
            components += " + DMAA"
        if enable_cpci:
            components += " + CPCI"
        if enable_ddts:
            components += " + DDTS"
        components += " + DIE"
        _log.info("AEGIS  ready — %s", components)

    @property
    def prevent_cpci_override_on_threats(self) -> bool:
        return getattr(self, "_prevent_cpci_override_on_threats", True)

    @prevent_cpci_override_on_threats.setter
    def prevent_cpci_override_on_threats(self, value: bool) -> None:
        self._prevent_cpci_override_on_threats = bool(value)

    # ------------------------------------------------------------------
    # النخاع الشوكي لمعالجة الأحداث (Main inference path)
    # ------------------------------------------------------------------

    def process_event(
        self,
        src_ip:             str,
        event_type:         str,
        *,
        is_endpoint_signal: bool  = False,
        is_critical_asset:  bool  = False,
        operational_budget: float = 1.0,
        max_escalation:     float = 1.0,
        tpe_score:          float = 0.0,
        bytes_transferred:  int   = 0,
        dst_ip:             str   = "",
        protocol:           str   = "",
    ) -> AEGISResult:
        """
        نشغل دورة الذكاء كاملة لحدث أمني واحد.
        """
        t0 = time.perf_counter()

        # -- C8: CIAPG — Causal Anti-Poisoning Gate (filter before AIS update)
        ciapg_decision = "PASS"
        ciapg_gamma    = 0.0
        if self._ciapg is not None:
            belief_pre = self._ase.get_belief(src_ip)
            stage_from = belief_pre.most_likely_stage if belief_pre else "RECONNAISSANCE"
            # Predict what stage_to will be after Bayesian update
            # Use current most-likely stage as stage_to approximation
            stage_to = stage_from  # conservative: same stage until proven otherwise
            ciapg_decision, ciapg_gamma = self._ciapg.check(
                ttp=event_type, stage_from=stage_from, stage_to=stage_to
            )

        # -- Layer 0: Record Event into AIS History (Multi-Modal) ---------
        # Only update if CIAPG did not detect poisoning
        if ciapg_decision == "PASS":
            self._ais.observe_real_ttp(
                ttp_name=event_type,
                src_ip=src_ip,
                is_endpoint_signal=is_endpoint_signal,
            )
            if self._ciapg is not None:
                self._ciapg.observe(event_type, stage_from, stage_to)
        else:
            _log.warning(
                "AEGIS: CIAPG quarantined event ip=%s ttp=%s γ=%.3f",
                src_ip, event_type, ciapg_gamma,
            )

        # -- Layer 2: ASE — Bayesian belief update -------------------------
        belief = self._ase.observe(src_ip, event_type)

        # -- Layer 3: AIS — TTP distribution prediction -------------------
        ttp_distribution = self._ais.predict_ttp_distribution(src_ip)
        attention_exp    = self._ais.get_attention_explanation(src_ip)

        # -- C7: DMAA — Evasion-adjusted TTP distribution -----------------
        if self._dmaa is not None:
            base_probs = {p.ttp: p.probability for p in ttp_distribution}
            adjusted   = self._dmaa.get_evasion_adjusted_probs(
                base_probs, belief.most_likely_stage_idx
            )
            # Rebuild ttp_distribution with evasion-adjusted probabilities
            from modules.predictive_ai.engine.AEGIS.intent.simulator import TTPPrediction
            ttp_distribution = [
                TTPPrediction(ttp=ttp, probability=prob)
                for ttp, prob in sorted(adjusted.items(), key=lambda x: -x[1])
            ]

        # -- C11: CPCI — Conformal prediction set + authorization tier ------
        prediction_set = list()
        cpci_score     = 0.0
        authorization: str = "HUMAN_REVIEW"
        if self._cpci is not None:
            probs_dict = {p.ttp: p.probability for p in ttp_distribution}
            cpci_result    = self._cpci.full_assessment(probs_dict, belief.entropy)
            prediction_set = cpci_result["prediction_set"]
            cpci_score     = cpci_result["cpci"]
            authorization  = cpci_result["authorization"]

        # -- Layer 4: CSO — Nash-optimal strategy -------------------------
        counter_strategy = self._cso.optimize(
            ttp_distribution,
            is_critical_asset=is_critical_asset,
            operational_budget=operational_budget,
            max_escalation=max_escalation,
            tpe_score=tpe_score,
            attention_explanation=attention_exp,
        )

        # -- C10: DDTS — k-step Monte Carlo validation --------------------
        ddts_report = None
        if self._ddts is not None:
            import numpy as _np
            from modules.predictive_ai.engine.AEGIS.core.constants import TTP_INDEX
            ttp_probs_vec = _np.zeros(len(TTP_INDEX), dtype=_np.float64)
            for p in ttp_distribution:
                idx = TTP_INDEX.get(p.ttp.upper())
                if idx is not None:
                    ttp_probs_vec[idx] = p.probability
            if ttp_probs_vec.sum() > 0:
                ttp_probs_vec /= ttp_probs_vec.sum()
            committed_idx, ddts_report = self._ddts.evaluate(
                nash_best_idx=counter_strategy.action_idx,
                ttp_probs=ttp_probs_vec,
                current_stage_idx=belief.most_likely_stage_idx,
            )
            if committed_idx != counter_strategy.action_idx:
                counter_strategy = self._rebuild_strategy_for_action(
                    DEFENDER_ACTIONS[committed_idx], counter_strategy
                )

        # -- C11: CPCI EMERGENCY_OVERRIDE — revert to safest action -------
        if authorization == "EMERGENCY_OVERRIDE":
            if self._prevent_cpci_override_on_threats:
                if counter_strategy.action not in ("ALLOW", "MONITOR"):
                    _log.info(
                        "AEGIS: CPCI EMERGENCY_OVERRIDE active (cpci=%.3f), but threat protection is ENABLED → Preserving defensive action %s for ip=%s",
                        cpci_score, counter_strategy.action, src_ip,
                    )
                else:
                    # If high threat score is present, force BLOCK instead of MONITOR
                    if (self._ase is not None and self._ase.get_threat_score(src_ip) > 0.65):
                        counter_strategy = self._rebuild_strategy_for_action("BLOCK", counter_strategy)
                        _log.warning(
                            "AEGIS: CPCI EMERGENCY_OVERRIDE with high threat score (%.2f) → Enforcing BLOCK for ip=%s",
                            self._ase.get_threat_score(src_ip), src_ip,
                        )
                    else:
                        counter_strategy = self._rebuild_strategy_for_action("MONITOR", counter_strategy)
                        _log.warning(
                            "AEGIS: CPCI EMERGENCY_OVERRIDE ip=%s cpci=%.3f → MONITOR",
                            src_ip, cpci_score,
                        )
            else:
                counter_strategy = self._rebuild_strategy_for_action("MONITOR", counter_strategy)
                _log.warning(
                    "AEGIS: CPCI EMERGENCY_OVERRIDE ip=%s cpci=%.3f → MONITOR",
                    src_ip, cpci_score,
                )

        # -- C7: DMAA — Update belief about defender (from our own action) -
        if self._dmaa is not None:
            self._dmaa.update_belief(counter_strategy.action)

        # -- Layer 4.5: UEBA — بوابة فحص السلوك (عشان ما نظلم الموظفين) ---
        ueba_decision: Optional[UEBADecision] = None
        if self._ueba is not None:
            ueba_decision = self._ueba.verify(
                counter_strategy=counter_strategy,
                src_ip=src_ip,
                bytes_transferred=bytes_transferred,
                dst_ip=dst_ip,
                protocol=protocol,
            )
            # تطبيق قرار بوابة السلوكيات: تجاوز (براءة) أو تصعيد الكرت الأحمر
            if ueba_decision.verdict == UEBAVerdict.OVERRIDE:
                # نعدل الاستراتيجية بناءً على براءة المتهم
                counter_strategy = self._rebuild_strategy_for_action(
                    ueba_decision.final_action,
                    counter_strategy,
                )
            elif ueba_decision.verdict == UEBAVerdict.ESCALATE:
                counter_strategy = self._rebuild_strategy_for_action(
                    ueba_decision.final_action,
                    counter_strategy,
                )

        # -- Layer 5: DIE — حقن فخاخ الخداع في الوقت والمكان المناسب ------
        decoy_directive = self._die.maybe_inject(
            attacker_ip=src_ip,
            belief=belief,
            counter_strategy=counter_strategy,
        )

        elapsed_ms = (time.perf_counter() - t0) * 1_000.0

        result = AEGISResult(
            src_ip=src_ip,
            event_type=event_type.upper(),
            belief_state=belief,
            ttp_distribution=ttp_distribution,
            counter_strategy=counter_strategy,
            ueba_decision=ueba_decision,
            decoy_directive=decoy_directive,
            inference_time_ms=elapsed_ms,
            prediction_set=prediction_set,
            cpci_score=cpci_score,
            authorization=authorization,
            ddts_report=ddts_report,
        )

        # نحفظ القرار في السجل الحي
        self._decision_history.append(result.to_dict())

        ueba_tag = ""
        if ueba_decision and ueba_decision.verdict != UEBAVerdict.CONFIRM:
            ueba_tag = f" → UEBA:{ueba_decision.verdict.value}"

        _log.info(
            "AEGIS [%.2f ms] ip=%s event=%s → stage=%s → action=%s auth=%s%s%s",
            elapsed_ms,
            src_ip,
            event_type.upper(),
            belief.most_likely_stage,
            counter_strategy.action,
            authorization,
            ueba_tag,
            f" → DECOY:{decoy_directive.redirect_to}" if decoy_directive else "",
        )

        try:
            EventBus.publish_from_thread(Topics.AI_SCORE_GENERATED, result.to_dict())
        except Exception as e:
            _log.debug("Failed to dispatch AI AEGIS event: %s", e)

        return result

    # ------------------------------------------------------------------
    # حلقة التغذية المتصلة المستقلة (Closed-loop feedback)
    # ------------------------------------------------------------------

    def record_actual_ttp(
        self,
        src_ip:      str,
        stage_name:  str,
        actual_ttp:  str,
        predicted_top_ttp: Optional[str] = None,
    ) -> None:
        """
        هنا نعلم النظام أيش اللي وقع بالواقع، عشان يقارنه بتوقعاته.
        """
        self._ais.observe_real_ttp(actual_ttp, src_ip)

        if predicted_top_ttp:
            self._ais.record_prediction_accuracy(predicted_top_ttp, actual_ttp)

        # نلقم محرك بايز بالحدث اللي تم تأكيده
        self._ase.observe(src_ip, actual_ttp)

        _log.debug(
            "تغذية راجعة حية لـ AEGIS: ip=%s stage=%s actual_ttp=%s",
            src_ip, stage_name, actual_ttp,
        )

    def reset_attacker(self, src_ip: str) -> None:
        """
        تصفير عداد الهاكر بعد ما نعطيه قاضية ونطيره من الشبكة.
        """
        self._ase.reset_ip(src_ip)
        _log.info("AEGIS: تم تنظيف الذاكرة وتصفير الآي بي=%s.", src_ip)

    # ------------------------------------------------------------------
    # منافذ الشفافية والعرض (Direct sub-component accessors)
    # ------------------------------------------------------------------

    def get_belief(self, src_ip: str) -> Optional[dict]:
        """يرد لك قناعات النظام البايزية الحالية تجاه ذا الآي بي."""
        belief = self._ase.get_belief(src_ip)
        return belief.to_dict() if belief else None

    def get_counter_strategy(
        self,
        src_ip: str,
        *,
        is_critical_asset: bool = False,
        tpe_score: float = 0.0,
    ) -> Optional[dict]:
        """
        يرد لك الخطة الدفاعية الحالية اللي ناوي يعتزي بها النظام ضد ذا الآي بي.
        """
        belief = self._ase.get_belief(src_ip)
        if belief is None:
            return None
            
        ttp_distribution = self._ais.predict_ttp_distribution(src_ip)
        attention_exp = self._ais.get_attention_explanation(src_ip)
        
        strategy = self._cso.optimize(
            ttp_distribution, 
            is_critical_asset=is_critical_asset,
            tpe_score=tpe_score,
            attention_explanation=attention_exp
        )
        return strategy.to_dict()

    def health_check(self) -> dict:
        """فحص طبي شامل لأعضاء محرك AEGIS، تُرسل لواجهة الـ API."""
        result = {
            "ase": self._ase.summary(),
            "ais": self._ais.get_accuracy_report(),
            "cso": {
                "alpha": self._cso.alpha,
                "beta":  self._cso.beta,
                "gamma": self._cso.gamma,
                "lam":   self._cso.lam,
            },
            "gnn": self._gnn.summary() if self._gnn else {"enabled": False},
            "ueba": self._ueba.summary() if self._ueba else {"enabled": False},
            "die": self._die.summary(),
        }
        return result

    def get_active_decoys(self) -> list[dict]:
        """يجيب لك كل الفخاخ اللي منشورة وشغالة ذي الحين."""
        return self._die.get_active_decoys()

    def get_recent_decisions(self, n: int = 20) -> list[dict]:
        """
        يرد لك آخر N قرارات أخذها محرك AEGIS من سجل الذاكرة الحي.
        كل قرار يحتوي على: src_ip, event_type, belief_state,
        ttp_distribution, counter_strategy, ueba_decision, decoy_directive.
        """
        decisions = list(self._decision_history)
        return decisions[-n:] if len(decisions) >= n else decisions

    @property
    def ueba(self) -> Optional[UEBAVerifier]:
        """يسمح لباب التسجيل (baseline registration) للموظفين."""
        return self._ueba

    @property
    def gnn(self) -> Optional[GNNLateralPredictor]:
        """يسمح للوصول لمحرك التوقع الجانبي."""
        return self._gnn

    def set_topology(self, topology: NetworkTopology) -> None:
        """
        يزود النظام بمخطط الشبكة عشان الـ GNN يفهم الخريطة.
        استدعيها كلما اتغير شكل الشبكة.
        """
        self._topology = topology
        if self._gnn:
            _log.info(
                "AEGISEngine: تم تحديث الخريطة (%d عقدة, %d رابط)",
                topology.num_nodes, topology.num_edges,
            )

    # ------------------------------------------------------------------
    # دوال مساعدة مخفية (Private helpers)
    # ------------------------------------------------------------------

    @staticmethod
    def _rebuild_strategy_for_action(
        new_action: str,
        original: CounterStrategy,
    ) -> CounterStrategy:
        """
        يصلح خطة جديدة (CounterStrategy) بالإجراء المعدل من الـ UEBA،
        مع الحفاظ على باقي الحسبة (عشان التبرير يكون مضبوط).
        """
        from modules.predictive_ai.engine.AEGIS.core.constants import DEFENDER_ACTIONS
        try:
            new_idx = DEFENDER_ACTIONS.index(new_action)
        except ValueError:
            new_idx = original.action_idx
            new_action = original.action

        return CounterStrategy(
            action=new_action,
            action_idx=new_idx,
            net_value=original.net_value,
            expected_disruption=original.expected_disruption,
            operational_cost=original.operational_cost,
            escalation_risk=original.escalation_risk,
            deception_value=original.deception_value,
            ttp_distribution=original.ttp_distribution,
            explanation=(
                f"[UEBA تدخُّل → {new_action}] {original.explanation}"
            ),
        )


OracleEngine = AEGISEngine
OracleResult = AEGISResult
