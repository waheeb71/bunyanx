"""
bunyanx NGFW — AEGIS Engine: UEBA User/Entity Baseline Module
=================================================================

Implements User and Entity Behavior Analytics (UEBA) baseline profiling
for reducing false positive rates in the AEGIS defensive pipeline.

Purpose
-------
The AEGIS framework's 20% FPR (1/5 benign scenarios misclassified)
is caused by semantic ambiguity: large data transfers from backup
servers look identical to exfiltration at the network metadata level.

This module builds behavioral baselines per user/entity so that the
UEBAVerifier can distinguish:
  - "This 500GB transfer happens every Sunday at 2 AM from the backup
     server" → NORMAL (benign scheduled backup)
  - "This 500GB transfer at 3 PM on Tuesday from a developer laptop
     to a foreign IP" → ANOMALOUS (likely exfiltration)

Components
----------
  UserBaseline     — Per-user/entity behavioral profile dataclass
  BaselineBuilder  — Constructs baselines from historical session data
  AnomalyScorer    — Z-score based deviation detection

Research Reference
------------------
  AEGIS Paper — §IV.B Layer 4.5 (UEBA Verification Gate)
  Gartner, "Market Guide for UEBA," 2024.
  E. Bertino et al., "Data-Driven Insider Threat Detection," IEEE, 2020.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EntityType(Enum):
    """Classification of the network entity generating traffic."""
    USER_WORKSTATION = "user_workstation"
    SERVER_BACKUP    = "server_backup"
    SERVER_DB        = "server_db"
    SERVER_WEB       = "server_web"
    IOT_DEVICE       = "iot_device"
    ADMIN_CONSOLE    = "admin_console"
    UNKNOWN          = "unknown"


class DayOfWeek(Enum):
    MONDAY    = 0
    TUESDAY   = 1
    WEDNESDAY = 2
    THURSDAY  = 3
    FRIDAY    = 4
    SATURDAY  = 5
    SUNDAY    = 6


# ---------------------------------------------------------------------------
# Session Record (input to BaselineBuilder)
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    """
    A single historical network session used to build baselines.

    Attributes
    ----------
    src_ip : str
        Source IP of the session.
    dst_ip : str
        Destination IP.
    bytes_transferred : int
        Total bytes transferred in this session.
    timestamp : float
        UNIX timestamp when the session started.
    protocol : str
        Protocol used (e.g. "SMB", "HTTPS", "FTP").
    duration_seconds : float
        Session duration in seconds.
    day_of_week : int
        Day of week (0=Monday, 6=Sunday).
    hour_of_day : int
        Hour of day (0–23).
    entity_type : EntityType
        Classification of the source entity.
    """
    src_ip:             str
    dst_ip:             str
    bytes_transferred:  int
    timestamp:          float
    protocol:           str          = "UNKNOWN"
    duration_seconds:   float        = 0.0
    day_of_week:        int          = 0
    hour_of_day:        int          = 0
    entity_type:        EntityType   = EntityType.UNKNOWN


# ---------------------------------------------------------------------------
# UserBaseline — Per-entity behavioral profile
# ---------------------------------------------------------------------------

@dataclass
class UserBaseline:
    """
    Behavioral baseline profile for a network entity (user/server/device).

    This profile captures the "normal" behavior of an entity across
    multiple dimensions, enabling Z-score anomaly detection.

    Attributes
    ----------
    entity_ip : str
        IP address of the entity this baseline describes.
    entity_type : EntityType
        Classification of the entity.
    avg_bytes_per_session : float
        Mean bytes transferred per session (historical).
    std_bytes_per_session : float
        Standard deviation of bytes per session.
    avg_sessions_per_day : float
        Mean number of sessions per day.
    std_sessions_per_day : float
        Standard deviation of sessions per day.
    typical_hours : set[int]
        Set of hours (0–23) when this entity is normally active.
    typical_days : set[int]
        Set of days (0=Mon, 6=Sun) when this entity is normally active.
    typical_destinations : set[str]
        Set of destination IPs this entity normally communicates with.
    typical_protocols : set[str]
        Set of protocols this entity normally uses.
    max_observed_bytes : int
        Maximum single-session bytes ever observed from this entity.
    session_count : int
        Total number of sessions in the baseline training window.
    baseline_created_at : float
        UNIX timestamp when the baseline was last computed.
    is_scheduled_job : bool
        True if the entity exhibits highly periodic behavior (e.g. backup).
    schedule_pattern : str
        Human-readable schedule description (e.g. "Sundays 02:00-04:00").
    """

    entity_ip:              str
    entity_type:            EntityType       = EntityType.UNKNOWN
    avg_bytes_per_session:  float            = 0.0
    std_bytes_per_session:  float            = 0.0
    avg_sessions_per_day:   float            = 0.0
    std_sessions_per_day:   float            = 0.0
    typical_hours:          set[int]         = field(default_factory=set)
    typical_days:           set[int]         = field(default_factory=set)
    typical_destinations:   set[str]         = field(default_factory=set)
    typical_protocols:      set[str]         = field(default_factory=set)
    max_observed_bytes:     int              = 0
    session_count:          int              = 0
    baseline_created_at:    float            = field(default_factory=time.time)
    is_scheduled_job:       bool             = False
    schedule_pattern:       str              = ""

    def to_dict(self) -> dict:
        return {
            "entity_ip":              self.entity_ip,
            "entity_type":            self.entity_type.value,
            "avg_bytes_per_session":  round(self.avg_bytes_per_session, 2),
            "std_bytes_per_session":  round(self.std_bytes_per_session, 2),
            "avg_sessions_per_day":   round(self.avg_sessions_per_day, 2),
            "typical_hours":          sorted(self.typical_hours),
            "typical_days":           sorted(self.typical_days),
            "typical_destinations":   sorted(self.typical_destinations),
            "typical_protocols":      sorted(self.typical_protocols),
            "max_observed_bytes":     self.max_observed_bytes,
            "session_count":          self.session_count,
            "is_scheduled_job":       self.is_scheduled_job,
            "schedule_pattern":       self.schedule_pattern,
        }


# ---------------------------------------------------------------------------
# BaselineBuilder — Constructs baselines from historical session data
# ---------------------------------------------------------------------------

class BaselineBuilder:
    """
    Constructs UserBaseline profiles from historical session records.

    Design
    ------
    Operates in batch mode: feed it all historical sessions for a time
    window (e.g. 30 days), then call ``build()`` to generate baselines.

    The builder detects scheduled jobs by looking for high periodicity
    in session timestamps (e.g. weekly Sunday backups).
    """

    # Minimum sessions required to build a meaningful baseline
    MIN_SESSIONS_FOR_BASELINE: int = 5

    # Periodicity detection: if >60% of sessions fall on the same day/hour
    PERIODICITY_THRESHOLD: float = 0.60

    def __init__(self) -> None:
        # ip → list[SessionRecord]
        self._sessions: dict[str, list[SessionRecord]] = defaultdict(list)

    def add_session(self, session: SessionRecord) -> None:
        """Add a historical session record for baseline building."""
        self._sessions[session.src_ip].append(session)

    def add_sessions(self, sessions: list[SessionRecord]) -> None:
        """Add multiple session records at once."""
        for s in sessions:
            self._sessions[s.src_ip].append(s)

    def build(self, entity_ip: str) -> Optional[UserBaseline]:
        """
        Build a UserBaseline for the given entity IP.

        Returns None if insufficient historical data is available.
        """
        records = self._sessions.get(entity_ip, [])
        if len(records) < self.MIN_SESSIONS_FOR_BASELINE:
            _log.debug(
                "BaselineBuilder: insufficient data for ip=%s (%d sessions)",
                entity_ip, len(records),
            )
            return None

        bytes_list = [r.bytes_transferred for r in records]
        hours      = [r.hour_of_day for r in records]
        days       = [r.day_of_week for r in records]
        dests      = {r.dst_ip for r in records}
        protocols  = {r.protocol for r in records}

        # Statistics
        avg_bytes = sum(bytes_list) / len(bytes_list)
        std_bytes = _std_dev(bytes_list, avg_bytes)
        max_bytes = max(bytes_list)

        # Sessions per day estimation (from timestamps)
        sessions_per_day = self._estimate_sessions_per_day(records)
        avg_spd = sum(sessions_per_day) / len(sessions_per_day) if sessions_per_day else 0
        std_spd = _std_dev(sessions_per_day, avg_spd) if sessions_per_day else 0

        # Typical hours (hours covering >10% of sessions each)
        hour_counts = _count_occurrences(hours, 24)
        typical_hours = {
            h for h, count in enumerate(hour_counts)
            if count / len(records) > 0.10
        }

        # Typical days
        day_counts = _count_occurrences(days, 7)
        typical_days = {
            d for d, count in enumerate(day_counts)
            if count / len(records) > 0.10
        }

        # Entity type detection
        entity_type = self._detect_entity_type(records)

        # Periodicity / scheduled job detection
        is_scheduled, pattern = self._detect_periodicity(
            records, day_counts, hour_counts,
        )

        baseline = UserBaseline(
            entity_ip=entity_ip,
            entity_type=entity_type,
            avg_bytes_per_session=avg_bytes,
            std_bytes_per_session=std_bytes,
            avg_sessions_per_day=avg_spd,
            std_sessions_per_day=std_spd,
            typical_hours=typical_hours,
            typical_days=typical_days,
            typical_destinations=dests,
            typical_protocols=protocols,
            max_observed_bytes=max_bytes,
            session_count=len(records),
            is_scheduled_job=is_scheduled,
            schedule_pattern=pattern,
        )

        _log.info(
            "BaselineBuilder: built baseline for ip=%s (type=%s, sessions=%d, "
            "scheduled=%s)",
            entity_ip, entity_type.value, len(records), is_scheduled,
        )
        return baseline

    def build_all(self) -> dict[str, UserBaseline]:
        """Build baselines for all known entity IPs."""
        baselines: dict[str, UserBaseline] = {}
        for ip in self._sessions:
            baseline = self.build(ip)
            if baseline:
                baselines[ip] = baseline
        return baselines

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_sessions_per_day(
        records: list[SessionRecord],
    ) -> list[float]:
        """Group sessions by calendar day and count per-day totals."""
        day_buckets: dict[int, int] = defaultdict(int)
        for r in records:
            # Bucket by day number (approximate — timestamp / 86400)
            day_key = int(r.timestamp // 86400)
            day_buckets[day_key] += 1
        return list(day_buckets.values()) if day_buckets else [0]

    @staticmethod
    def _detect_entity_type(records: list[SessionRecord]) -> EntityType:
        """Heuristic entity type detection from session patterns."""
        # If any record has explicit entity type, use majority vote
        type_votes: dict[EntityType, int] = defaultdict(int)
        for r in records:
            type_votes[r.entity_type] += 1

        if EntityType.UNKNOWN in type_votes and len(type_votes) == 1:
            # All unknown — try heuristic detection
            protocols = {r.protocol.upper() for r in records}
            avg_bytes = sum(r.bytes_transferred for r in records) / len(records)

            if "SMB" in protocols and avg_bytes > 100_000_000:  # >100MB avg
                return EntityType.SERVER_BACKUP
            if "MYSQL" in protocols or "POSTGRES" in protocols:
                return EntityType.SERVER_DB
            if "HTTP" in protocols or "HTTPS" in protocols:
                return EntityType.SERVER_WEB
            return EntityType.USER_WORKSTATION

        # Return most common non-UNKNOWN type
        for etype, count in sorted(
            type_votes.items(), key=lambda x: x[1], reverse=True,
        ):
            if etype != EntityType.UNKNOWN:
                return etype
        return EntityType.UNKNOWN

    def _detect_periodicity(
        self,
        records: list[SessionRecord],
        day_counts: list[int],
        hour_counts: list[int],
    ) -> tuple[bool, str]:
        """
        Detect if the entity's sessions follow a periodic schedule.

        Returns (is_scheduled, description).
        """
        n = len(records)
        if n < self.MIN_SESSIONS_FOR_BASELINE:
            return False, ""

        # Check if >60% of sessions concentrate on 1–2 days
        sorted_days = sorted(enumerate(day_counts), key=lambda x: x[1], reverse=True)
        top_day_frac = sorted_days[0][1] / n

        # Check if >60% of sessions concentrate on 1–2 hours
        sorted_hours = sorted(enumerate(hour_counts), key=lambda x: x[1], reverse=True)
        top_hour_frac = sorted_hours[0][1] / n

        if top_day_frac >= self.PERIODICITY_THRESHOLD and top_hour_frac >= self.PERIODICITY_THRESHOLD:
            day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            primary_day  = day_names[sorted_days[0][0]]
            primary_hour = sorted_hours[0][0]
            pattern = f"{primary_day}s {primary_hour:02d}:00-{(primary_hour+2)%24:02d}:00"
            return True, pattern

        return False, ""


# ---------------------------------------------------------------------------
# AnomalyScorer — Z-score based deviation detection
# ---------------------------------------------------------------------------

class AnomalyScorer:
    """
    Computes multi-dimensional anomaly scores for a network event
    against a known UserBaseline using modified Z-scores.

    Anomaly Dimensions
    ------------------
    1. Volume anomaly:  bytes_transferred vs baseline mean/std
    2. Temporal anomaly: event hour/day vs typical schedule
    3. Destination anomaly: target IP in known destinations?
    4. Protocol anomaly: protocol in known protocol set?

    Overall anomaly score ∈ [0, 1]:
        0.0 = perfectly normal behavior
        1.0 = extreme deviation from baseline

    The UEBAVerifier uses this score to decide CONFIRM/OVERRIDE/ESCALATE.
    """

    # Weights for each anomaly dimension
    W_VOLUME:      float = 0.35
    W_TEMPORAL:    float = 0.25
    W_DESTINATION: float = 0.20
    W_PROTOCOL:    float = 0.10
    W_SCHEDULE:    float = 0.10

    # Z-score thresholds
    Z_NORMAL:   float = 1.5   # below this → normal
    Z_WARNING:  float = 3.0   # above this → highly anomalous
    Z_MAX_CLIP: float = 5.0   # clip Z-scores to prevent extreme values

    def score(
        self,
        baseline:           UserBaseline,
        bytes_transferred:  int,
        hour_of_day:        int,
        day_of_week:        int,
        dst_ip:             str,
        protocol:           str,
    ) -> AnomalyResult:
        """
        Compute a composite anomaly score for a single event.

        Parameters
        ----------
        baseline : UserBaseline
            The entity's behavioral baseline.
        bytes_transferred : int
            Bytes in the current event.
        hour_of_day : int
            Current hour (0–23).
        day_of_week : int
            Current day (0=Mon, 6=Sun).
        dst_ip : str
            Destination IP of the current event.
        protocol : str
            Protocol of the current event.

        Returns
        -------
        AnomalyResult
            Composite anomaly score with per-dimension breakdown.
        """
        # ── 1. Volume anomaly ─────────────────────────────────────────
        vol_z = self._z_score(
            bytes_transferred,
            baseline.avg_bytes_per_session,
            baseline.std_bytes_per_session,
        )
        vol_norm = self._z_to_score(vol_z)

        # ── 2. Temporal anomaly ───────────────────────────────────────
        hour_anomaly = 0.0 if hour_of_day in baseline.typical_hours else 1.0
        day_anomaly  = 0.0 if day_of_week in baseline.typical_days else 1.0
        temporal_norm = (hour_anomaly + day_anomaly) / 2.0

        # ── 3. Destination anomaly ────────────────────────────────────
        dst_anomaly = 0.0 if dst_ip in baseline.typical_destinations else 1.0

        # ── 4. Protocol anomaly ───────────────────────────────────────
        proto_anomaly = 0.0 if protocol.upper() in {
            p.upper() for p in baseline.typical_protocols
        } else 1.0

        # ── 5. Schedule violation ─────────────────────────────────────
        schedule_anomaly = 0.0
        if baseline.is_scheduled_job:
            # If it's a scheduled job and this event matches the schedule,
            # it's almost certainly normal — strong signal
            if day_of_week in baseline.typical_days and hour_of_day in baseline.typical_hours:
                schedule_anomaly = 0.0
            else:
                schedule_anomaly = 0.5   # off-schedule but known entity

        # ── Composite score ───────────────────────────────────────────
        composite = (
            self.W_VOLUME      * vol_norm
            + self.W_TEMPORAL  * temporal_norm
            + self.W_DESTINATION * dst_anomaly
            + self.W_PROTOCOL  * proto_anomaly
            + self.W_SCHEDULE  * schedule_anomaly
        )
        composite = max(0.0, min(1.0, composite))

        result = AnomalyResult(
            composite_score=round(composite, 4),
            volume_z_score=round(vol_z, 4),
            volume_anomaly=round(vol_norm, 4),
            temporal_anomaly=round(temporal_norm, 4),
            destination_anomaly=round(dst_anomaly, 4),
            protocol_anomaly=round(proto_anomaly, 4),
            schedule_anomaly=round(schedule_anomaly, 4),
            is_scheduled_match=(
                baseline.is_scheduled_job
                and day_of_week in baseline.typical_days
                and hour_of_day in baseline.typical_hours
            ),
        )

        _log.debug(
            "AnomalyScorer: ip=%s composite=%.3f vol_z=%.2f "
            "temporal=%.2f dst=%.2f proto=%.2f sched=%.2f",
            baseline.entity_ip,
            composite, vol_z,
            temporal_norm, dst_anomaly, proto_anomaly, schedule_anomaly,
        )

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        """Compute Z-score, handling zero std (constant baseline)."""
        if std < 1e-6:
            # If std is ~0, any deviation from mean is significant
            if abs(value - mean) < 1e-6:
                return 0.0
            return 5.0   # max anomaly signal
        return abs(value - mean) / std

    def _z_to_score(self, z: float) -> float:
        """Map Z-score to [0, 1] anomaly score using sigmoid-like curve."""
        z = min(z, self.Z_MAX_CLIP)
        if z <= self.Z_NORMAL:
            return 0.0
        if z >= self.Z_WARNING:
            return 1.0
        # Linear interpolation between thresholds
        return (z - self.Z_NORMAL) / (self.Z_WARNING - self.Z_NORMAL)


# ---------------------------------------------------------------------------
# AnomalyResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnomalyResult:
    """
    Result of a single UEBA anomaly scoring operation.

    Attributes
    ----------
    composite_score : float
        Overall anomaly score ∈ [0, 1]. Higher = more anomalous.
    volume_z_score : float
        Raw Z-score for data volume.
    volume_anomaly : float
        Normalized volume anomaly ∈ [0, 1].
    temporal_anomaly : float
        Temporal deviation score ∈ [0, 1].
    destination_anomaly : float
        Destination novelty score (0 = known, 1 = unknown destination).
    protocol_anomaly : float
        Protocol novelty score (0 = known, 1 = unknown protocol).
    schedule_anomaly : float
        Schedule violation score ∈ [0, 1].
    is_scheduled_match : bool
        True if the event matches a known periodic schedule.
    """

    composite_score:     float
    volume_z_score:      float
    volume_anomaly:      float
    temporal_anomaly:    float
    destination_anomaly: float
    protocol_anomaly:    float
    schedule_anomaly:    float
    is_scheduled_match:  bool

    def to_dict(self) -> dict:
        return {
            "composite_score":     self.composite_score,
            "volume_z_score":      self.volume_z_score,
            "volume_anomaly":      self.volume_anomaly,
            "temporal_anomaly":    self.temporal_anomaly,
            "destination_anomaly": self.destination_anomaly,
            "protocol_anomaly":    self.protocol_anomaly,
            "schedule_anomaly":    self.schedule_anomaly,
            "is_scheduled_match":  self.is_scheduled_match,
        }


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _std_dev(values: list[float], mean: float) -> float:
    """Compute population standard deviation."""
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _count_occurrences(values: list[int], n_bins: int) -> list[int]:
    """Count occurrences of each integer in [0, n_bins)."""
    counts = [0] * n_bins
    for v in values:
        if 0 <= v < n_bins:
            counts[v] += 1
    return counts
