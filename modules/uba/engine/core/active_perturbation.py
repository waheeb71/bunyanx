"""
Enterprise bunyanx — Active Perturbation Engine (Research)

Injects micro-faults (e.g., TCP delays or drops) into suspect streams
to measure the application/user reaction time, differentiating automated scripts
from human operators based on Causal Perturbation testing.

MITRE ATT&CK Coverage:
  - T1046: Network Service Discovery (Active Detection)
  - T1595: Active Scanning (Countermeasure via Perturbation)
"""

import time
import logging
import threading
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

# Maximum number of active faults to track (prevents memory exhaustion under DDoS)
_MAX_ACTIVE_FAULTS = 10_000
# TTL for active faults in seconds (auto-cleanup if no response)
_FAULT_TTL_SECONDS = 120.0


@dataclass
class PerturbationResult:
    flow_id: str
    fault_type: str
    injected_at: float
    response_delay_ms: float
    bot_probability: float  # 0.0 (Human) to 1.0 (Bot)


class MicroFaultInjector:
    """
    Manages state for active micro-interventions on suspicious flows.
    Includes TTL-based cleanup to prevent unbounded memory growth.
    """
    
    def __init__(self, max_faults: int = _MAX_ACTIVE_FAULTS, ttl_seconds: float = _FAULT_TTL_SECONDS):
        # Maps flow_id -> (fault_type, timestamp_injected)
        self._active_faults: Dict[str, Tuple[str, float]] = {}
        self._max_faults = max_faults
        self._ttl_seconds = ttl_seconds
        self._last_prune: float = 0.0
        self._lock = threading.RLock()
        
    def evaluate_risk_for_perturbation(self, risk_score: float) -> str:
        """Decide what kind of fault to inject based on risk (0-100)."""
        # Between 40 and 70, inject a slight TCP jitter.
        if 40 <= risk_score < 70:
            return "TCP_JITTER_500MS"
        # Between 70 and 85, drop a packet to force retransmission logic.
        elif 70 <= risk_score < 85:
            return "TCP_WINDOW_ZERO"
        return "NONE"

    def mark_flow_for_fault(self, flow_id: str, fault_type: str) -> None:
        """Mark a flow for perturbation injection. Actual injection is done by pipeline/eBPF."""
        with self._lock:
            self._prune_expired()
            if len(self._active_faults) >= self._max_faults:
                logger.warning(
                    "[AP-Engine] Active faults at capacity (%d), dropping oldest",
                    self._max_faults,
                )
                # Remove oldest entry
                oldest_key = min(self._active_faults, key=lambda k: self._active_faults[k][1])
                del self._active_faults[oldest_key]

            if flow_id not in self._active_faults:
                self._active_faults[flow_id] = (fault_type, time.time())
                logger.info(
                    "[AP-Engine] Active Perturbation scheduled on flow %s: %s",
                    flow_id, fault_type,
                )
        
    def measure_reaction(self, flow_id: str, current_timestamp: float) -> Optional[PerturbationResult]:
        """
        When the next packet arrives for a perturbed flow, measure the delta.
        Automated scanners/bots typically proceed instantly (<100ms) or crash.
        Humans encounter the jitter, wait, and retry manually (>300ms).
        """
        with self._lock:
            if flow_id not in self._active_faults:
                return None
                
            fault_type, injected_time = self._active_faults.pop(flow_id)
        
        # Delta between the time we injected the fault and the user reaction
        delay_ms = (current_timestamp - injected_time) * 1000.0
        
        # Causal inference heuristic:
        # Instant retry < 100ms indicates programmatic loop -> bot.
        # > 300ms indicates human interface or timeout based.
        if delay_ms < 100:
            bot_prob = 1.0
        elif 100 <= delay_ms <= 300:
            # Linear decay from 100ms to 300ms
            bot_prob = 1.0 - ((delay_ms - 100) / 200)
        else:
            bot_prob = 0.0  # Human-like delay
            
        result = PerturbationResult(
            flow_id=flow_id,
            fault_type=fault_type,
            injected_at=injected_time,
            response_delay_ms=delay_ms,
            bot_probability=bot_prob
        )
        
        logger.info(
            "[AP-Engine] Flow %s reacted in %.1fms -> Bot Probability: %.0f%%",
            flow_id, delay_ms, bot_prob * 100,
        )
        return result

    def _prune_expired(self) -> None:
        """Remove expired faults to prevent memory bloat. Runs at most once per second."""
        with self._lock:
            now = time.time()
            if now - self._last_prune < 1.0:
                return
            self._last_prune = now
            expired = [
                k for k, (_, ts) in self._active_faults.items()
                if now - ts > self._ttl_seconds
            ]
            for k in expired:
                del self._active_faults[k]
            if expired:
                logger.debug("[AP-Engine] Pruned %d expired fault entries", len(expired))

    @property
    def active_count(self) -> int:
        """Number of currently tracked perturbation flows."""
        with self._lock:
            return len(self._active_faults)
