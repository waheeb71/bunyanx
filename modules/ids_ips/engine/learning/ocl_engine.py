"""
PHANTOM — Online Continual Learner (OCL)
=========================================
Layer 4 of the PHANTOM IDS/IPS framework.

Solves the catastrophic forgetting problem in real-time NIDS/IPS:
  * New attack types appear → model must learn them WITHOUT forgetting old ones.
  * Concept drift occurs   → model must detect and adapt automatically.

Architecture
------------

  ┌─────────────────────────────────────────────────────────────────────┐
  │  observe(sample, label, is_correct)                                 │
  │       │                                                             │
  │       ├─→ ADWIN Drift Detector ──── drift? ──→ _adapt()           │
  │       │                                                             │
  │       ├─→ SSF Memory Store ──────── informative? ──→ store()       │
  │       │                                                             │
  │       └─→ every 32 steps ──────────────────────→ _incremental_upd()│
  └─────────────────────────────────────────────────────────────────────┘

Key algorithms
--------------
  ADWIN (Bifet & Gavalda, 2007):
    Adaptive Windowing drift detector. Maintains a sliding window of error
    rates and detects when the mean error in the first half significantly
    differs from the second half.  Declared drift triggers _adapt().

  SSF — Selective Sample Filter (from PHANTOM paper):
    Decides which samples are worth storing in the episodic memory.
    A sample is "informative" if:
      (a) model got it WRONG (high uncertainty)  OR
      (b) it belongs to an under-represented class in memory.
    This maintains class balance and prevents the BENIGN class from
    dominating the replay buffer.

  Incremental Update:
    After accumulating `update_interval` new observations, runs one
    AdamW gradient step on a small batch sampled from the SSF memory.
    This is done in a background thread to not block the inference path.

Graceful degradation
--------------------
  If PyTorch is not installed, all gradient updates are silently skipped.
  The drift detector and memory store still operate, and the engine
  surfaces drift alerts via get_drift_status() for operator awareness.

Thread safety
-------------
  All state mutations are protected by threading.RLock.
  Incremental updates run in a background daemon thread.

Usage
-----
    ocl = OnlineContinualLearner(model=phantom_classifier_instance)
    ocl.observe(sbe_vector, label=5, is_correct=False)
    status = ocl.get_drift_status()
    # status["drift_detected"] == True  →  model has been adapted
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UPDATE_INTERVAL: int   = 32        # gradient steps every N observations
_MEMORY_SIZE:     int   = 500       # max episodic memory entries
_BATCH_SIZE:      int   = 16        # replay batch size per update
_LR:              float = 1e-4      # AdamW learning rate
_ADWIN_WINDOW:    int   = 100       # error rate window for ADWIN
_ADWIN_DELTA:     float = 0.002     # ADWIN significance level (smaller = more sensitive)
_MIN_CLASS_RATIO: float = 0.05      # min fraction for any threat class in memory


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MemoryEntry:
    """One episodic memory record stored by the SSF filter."""
    sbe:       np.ndarray     # 256-dim spectral vector
    label:     int            # ground-truth class index
    timestamp: float = field(default_factory=time.time)
    was_wrong: bool  = False  # model was incorrect when this was observed


@dataclass
class DriftStatus:
    """Snapshot of the ADWIN drift detector state."""
    drift_detected:     bool
    window_error_rate:  float       # mean error rate in the current window
    drift_timestamp:    Optional[float]  # when last drift was detected (None if never)
    total_drifts:       int
    memory_size:        int
    total_observations: int
    last_update_ts:     Optional[float]

    def to_dict(self) -> dict:
        return {
            "drift_detected":     self.drift_detected,
            "window_error_rate":  round(self.window_error_rate, 4),
            "drift_timestamp":    self.drift_timestamp,
            "total_drifts":       self.total_drifts,
            "memory_size":        self.memory_size,
            "total_observations": self.total_observations,
            "last_update_ts":     self.last_update_ts,
        }


# ---------------------------------------------------------------------------
# ADWIN Drift Detector (lightweight, no external dependencies)
# ---------------------------------------------------------------------------

class _ADWINDetector:
    """
    Simplified ADWIN drift detector.

    Maintains a circular buffer of binary error signals (1=wrong, 0=correct).
    Drift is declared when the mean error of the first half of the window
    differs significantly from the second half.

        |error_first_half - error_second_half| > threshold

    where threshold = sqrt( (1 / (2 * n)) * ln(4 * n² / delta) )
    and n = window size / 2.

    Reference: Bifet & Gavalda (SDM 2007), Equation 4.
    """

    def __init__(
        self,
        window: int   = _ADWIN_WINDOW,
        delta:  float = _ADWIN_DELTA,
    ) -> None:
        self._window = window
        self._delta  = delta
        self._errors: Deque[int] = deque(maxlen=window)
        self._drift_count = 0
        self._last_drift_ts: Optional[float] = None

    def update(self, is_error: bool) -> bool:
        """
        Add a new error observation.

        Returns True if drift is detected in this step.
        """
        self._errors.append(1 if is_error else 0)

        n = len(self._errors)
        if n < 20:
            return False  # not enough data

        # Split into two halves
        mid = n // 2
        errors_list = list(self._errors)
        mean_first  = sum(errors_list[:mid]) / mid
        mean_second = sum(errors_list[mid:]) / (n - mid)

        # ADWIN threshold (Hoeffding-based bound)
        threshold = (1.0 / (2.0 * mid)) * np.log(4.0 * mid ** 2 / self._delta)
        threshold = np.sqrt(threshold)

        if abs(mean_first - mean_second) > threshold:
            self._drift_count   += 1
            self._last_drift_ts  = time.time()
            self._errors.clear()   # reset window after drift
            logger.warning(
                "ADWIN drift detected #%d  |  "
                "first_half=%.3f  second_half=%.3f  threshold=%.3f",
                self._drift_count, mean_first, mean_second, threshold,
            )
            return True

        return False

    @property
    def is_drifting(self) -> bool:
        return self._last_drift_ts is not None and (
            time.time() - self._last_drift_ts < 60.0  # flag for 60 s after detection
        )

    @property
    def window_error_rate(self) -> float:
        if not self._errors:
            return 0.0
        return sum(self._errors) / len(self._errors)

    @property
    def drift_count(self) -> int:
        return self._drift_count

    @property
    def last_drift_ts(self) -> Optional[float]:
        return self._last_drift_ts


# ---------------------------------------------------------------------------
# SSF Memory (Selective Sample Filter)
# ---------------------------------------------------------------------------

class _SSFMemory:
    """
    Episodic replay memory with class-balanced storage.

    Selection criterion (SSF):
      Store if:
        (a) model prediction was WRONG  → high information content
        (b) label is under-represented  → maintains class balance
      Eviction: randomly evict the OVER-represented class when full.
    """

    def __init__(self, maxsize: int = _MEMORY_SIZE) -> None:
        self._maxsize = maxsize
        self._entries: List[MemoryEntry] = []
        self._class_counts: Dict[int, int] = defaultdict(int)

    def is_informative(self, label: int, was_wrong: bool) -> bool:
        """Decide whether to store this sample."""
        if was_wrong:
            return True   # always store errors

        # Store if this class is under-represented
        total = len(self._entries)
        if total == 0:
            return True

        class_frac = self._class_counts[label] / total
        return class_frac < _MIN_CLASS_RATIO

    def store(self, entry: MemoryEntry) -> None:
        """Store *entry*, evicting if memory is full."""
        if len(self._entries) >= self._maxsize:
            self._evict()
        self._entries.append(entry)
        self._class_counts[entry.label] += 1

    def _evict(self) -> None:
        """Remove one sample from the most over-represented class."""
        if not self._entries:
            return
        total    = len(self._entries)
        majority = max(self._class_counts, key=lambda c: self._class_counts[c])
        # Find and remove earliest majority-class entry
        for i, e in enumerate(self._entries):
            if e.label == majority:
                self._entries.pop(i)
                self._class_counts[majority] = max(0, self._class_counts[majority] - 1)
                return

    def sample_batch(self, batch_size: int) -> List[MemoryEntry]:
        """Stratified random sample of *batch_size* entries."""
        if len(self._entries) <= batch_size:
            return list(self._entries)
        indices = np.random.choice(len(self._entries), size=batch_size, replace=False)
        return [self._entries[i] for i in indices]

    def class_distribution(self) -> Dict[int, int]:
        return dict(self._class_counts)

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Online Continual Learner
# ---------------------------------------------------------------------------

class OnlineContinualLearner:
    """
    Online Continual Learner — Layer 4 of the PHANTOM framework.

    Parameters
    ----------
    model             : PHANTOMClassifier instance (or None for drift-only mode)
    update_interval   : perform one gradient step every N observations
    memory_size       : maximum episodic memory entries
    batch_size        : replay batch size per gradient step
    learning_rate     : AdamW learning rate
    device            : torch device string ("cpu" or "cuda")
    """

    def __init__(
        self,
        model:            Optional[Any]  = None,   # PHANTOMClassifier
        update_interval:  int   = _UPDATE_INTERVAL,
        memory_size:      int   = _MEMORY_SIZE,
        batch_size:       int   = _BATCH_SIZE,
        learning_rate:    float = _LR,
        device:           str   = "cpu",
    ) -> None:
        self._model          = model
        self._update_interval = update_interval
        self._batch_size     = batch_size
        self._lr             = learning_rate
        self._device         = device

        self._lock = threading.RLock()

        # Sub-components
        self._adwin  = _ADWINDetector()
        self._memory = _SSFMemory(maxsize=memory_size)

        # Counters
        self._total_observations = 0
        self._step_counter       = 0
        self._total_updates      = 0
        self._last_update_ts: Optional[float] = None

        # AdamW optimiser (initialised lazily when first update runs)
        self._optimizer = None

        # Background update thread — uses queue.Queue so the worker
        # blocks on get() instead of busy-polling at 20 Hz.
        self._update_queue: queue.Queue = queue.Queue()
        self._bg_thread = threading.Thread(
            target=self._background_worker,
            daemon=True,
            name="OCL-Update",
        )
        self._bg_thread.start()

        logger.info(
            "OnlineContinualLearner ready  |  model=%s  interval=%d  memory=%d",
            type(model).__name__ if model else "None",
            update_interval, memory_size,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(
        self,
        sbe:        np.ndarray,
        label:      int,
        is_correct: bool,
    ) -> bool:
        """
        Register one observation from the inference pipeline.

        Parameters
        ----------
        sbe        : 256-dim SBE vector of the observed packet
        label      : ground-truth class index (from analyst feedback or
                     high-confidence PHANTOM prediction)
        is_correct : whether the model's prediction was correct
                     (False = model made an error → high priority for storage)

        Returns
        -------
        True if drift was detected in this step.
        """
        with self._lock:
            self._total_observations += 1
            self._step_counter       += 1

            # ── ADWIN drift detection ──────────────────────────────────
            drift_now = self._adwin.update(is_error=not is_correct)
            if drift_now:
                # FIX: Push 5 rapid-adaptation batches to the background
                # queue instead of running them inline (blocked the inspection
                # path for the duration of 5 gradient steps).
                if self._model is not None and len(self._memory) >= self._batch_size:
                    logger.info("OCL: queuing rapid adaptation (5 steps) after drift detection.")
                    for _ in range(5):
                        batch = self._memory.sample_batch(self._batch_size)
                        self._update_queue.put(batch)  # non-blocking enqueue

            # ── SSF memory storage ─────────────────────────────────────
            if self._memory.is_informative(label, was_wrong=not is_correct):
                entry = MemoryEntry(
                    sbe=sbe.astype(np.float32),
                    label=label,
                    was_wrong=not is_correct,
                )
                self._memory.store(entry)

            # ── Schedule background update ─────────────────────────────
            if self._step_counter >= self._update_interval:
                self._step_counter = 0
                if len(self._memory) >= self._batch_size:
                    batch = self._memory.sample_batch(self._batch_size)
                    self._update_queue.put(batch)   # non-blocking enqueue

            return drift_now

    def get_drift_status(self) -> DriftStatus:
        """Return a snapshot of the drift detector and memory state."""
        with self._lock:
            return DriftStatus(
                drift_detected=self._adwin.is_drifting,
                window_error_rate=self._adwin.window_error_rate,
                drift_timestamp=self._adwin.last_drift_ts,
                total_drifts=self._adwin.drift_count,
                memory_size=len(self._memory),
                total_observations=self._total_observations,
                last_update_ts=self._last_update_ts,
            )

    def set_model(self, model: Any) -> None:
        """Hot-swap the underlying model (e.g. after retraining)."""
        with self._lock:
            self._model     = model
            self._optimizer = None   # reset optimiser state
            logger.info("OCL: model swapped → %s", type(model).__name__)

    def get_class_distribution(self) -> Dict[int, int]:
        """Return current class distribution in episodic memory."""
        with self._lock:
            return self._memory.class_distribution()

    # ------------------------------------------------------------------
    # Background update worker
    # ------------------------------------------------------------------

    def _background_worker(self) -> None:
        """
        Runs in a daemon thread.
        Blocks on queue.Queue.get() instead of busy-polling at 20 Hz,
        eliminating millions of unnecessary wakeups during idle periods.
        """
        while True:
            try:
                # Blocks indefinitely until work arrives — zero CPU waste.
                batch = self._update_queue.get(block=True, timeout=None)
                self._apply_gradient_step(batch)
                self._update_queue.task_done()
            except Exception as exc:
                logger.error("OCL background worker error: %s", exc)

    def _apply_gradient_step(self, batch: List[MemoryEntry]) -> None:
        """
        Perform one AdamW gradient step on *batch*.

        Uses cross-entropy loss on a simple linear probe (SBE → classes)
        when the full PHANTOMClassifier model is not available.
        """
        if self._model is None:
            return   # drift-only mode

        try:
            import torch
            import torch.nn as nn
            import torch.nn.functional as F

            # ── Build tensors ──────────────────────────────────────────
            sbe_list   = [torch.tensor(e.sbe,  dtype=torch.float32) for e in batch]
            label_list = [torch.tensor(e.label, dtype=torch.long)    for e in batch]

            sbe_batch   = torch.stack(sbe_list)          # [B, 256]
            label_batch = torch.stack(label_list)         # [B]

            # Build seq input (single-step for online updates — no temporal context)
            T          = 17   # seq_len + 1
            seq_batch  = sbe_batch.unsqueeze(1).expand(-1, T, -1)   # [B, T, 256]
            pos_batch  = torch.arange(T).unsqueeze(0).expand(len(batch), -1)

            # ── Initialise optimiser on first call ─────────────────────
            if self._optimizer is None:
                self._optimizer = torch.optim.AdamW(
                    self._model.parameters(),
                    lr=self._lr,
                    weight_decay=1e-4,
                )

            # ── Forward + loss ─────────────────────────────────────────
            self._model.train()
            self._optimizer.zero_grad()

            logits = self._model(sbe_batch, seq_batch, pos_batch)   # [B, classes]
            loss   = F.cross_entropy(logits, label_batch)

            loss.backward()

            # Gradient clipping prevents catastrophic weight updates
            torch.nn.utils.clip_grad_norm_(self._model.parameters(), max_norm=1.0)

            self._optimizer.step()
            self._model.eval()

            with self._lock:
                self._total_updates  += 1
                self._last_update_ts  = time.time()

            logger.debug(
                "OCL update #%d  |  batch=%d  loss=%.4f",
                self._total_updates, len(batch), loss.item(),
            )

        except ImportError:
            pass   # PyTorch not available — skip silently
        except Exception as exc:
            logger.error("OCL gradient step failed: %s", exc)

    # ------------------------------------------------------------------
    # Adaptation after drift
    # ------------------------------------------------------------------

    def _adapt(self) -> None:
        """
        Kept for backward compatibility — adaptation is now enqueued
        directly in observe() so gradient steps run in the background
        without blocking the inspection path.
        """
        pass  # logic moved to observe() → _update_queue.put()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_observations": self._total_observations,
                "total_updates":      self._total_updates,
                "memory_size":        len(self._memory),
                "drift_count":        self._adwin.drift_count,
                "is_drifting":        self._adwin.is_drifting,
                "window_error_rate":  round(self._adwin.window_error_rate, 4),
                "last_update_ts":     self._last_update_ts,
                "class_distribution": self._memory.class_distribution(),
            }
