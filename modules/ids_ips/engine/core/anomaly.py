"""
IPS Anomaly Detection Bridge
============================
Bridges the IPS Policy Engine to the ML-based AnomalyDetector.

Previously a no-op stub — now wired to the real AnomalyDetector from
engine/anomaly_detector.py.  Falls back gracefully if the ML stack is
unavailable (numpy / sklearn / xgboost not installed).
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AnomalyBridge:
    """Bridge from IPSEngine to the ML AnomalyDetector."""

    def __init__(self) -> None:
        self._detector = None
        try:
            from modules.ids_ips.engine.anomaly_detector import AnomalyDetector
            self._detector = AnomalyDetector()
            logger.info("AnomalyBridge: wired to AnomalyDetector (ML active).")
        except Exception as exc:
            logger.warning(
                "AnomalyBridge: AnomalyDetector unavailable (%s) — "
                "anomaly scoring disabled (heuristic fallback).", exc
            )

    def check(self, flow_stats: dict) -> bool:
        """
        Return True if the flow is anomalous.

        Parameters
        ----------
        flow_stats : dict
            Must contain the same keys as TrafficFeatures fields.
            Missing keys are filled with safe defaults (0.0 / 0).

        Returns
        -------
        bool — True if anomalous.
        """
        if self._detector is None:
            return False

        try:
            from modules.ids_ips.engine.anomaly_detector import TrafficFeatures
            features = TrafficFeatures(
                packets_per_second       = float(flow_stats.get("packets_per_second", 0)),
                bytes_per_second         = float(flow_stats.get("bytes_per_second", 0)),
                avg_packet_size          = float(flow_stats.get("avg_packet_size", 0)),
                packet_size_variance     = float(flow_stats.get("packet_size_variance", 0)),
                tcp_ratio                = float(flow_stats.get("tcp_ratio", 0)),
                udp_ratio                = float(flow_stats.get("udp_ratio", 0)),
                syn_ratio                = float(flow_stats.get("syn_ratio", 0)),
                unique_dst_ports         = int(flow_stats.get("unique_dst_ports", 0)),
                unique_src_ports         = int(flow_stats.get("unique_src_ports", 0)),
                inter_arrival_time_mean  = float(flow_stats.get("inter_arrival_time_mean", 0)),
                inter_arrival_time_variance = float(flow_stats.get("inter_arrival_time_variance", 0)),
                failed_connections       = int(flow_stats.get("failed_connections", 0)),
                connection_attempts      = int(flow_stats.get("connection_attempts", 0)),
                reputation_score         = float(flow_stats.get("reputation_score", 100)),
                flow_duration            = float(flow_stats.get("flow_duration", 0)),
                payload_entropy          = float(flow_stats.get("payload_entropy", 0.5)),
                upload_download_ratio    = float(flow_stats.get("upload_download_ratio", 1.0)),
                fin_rst_ratio            = float(flow_stats.get("fin_rst_ratio", 0)),
                max_packet_size          = int(flow_stats.get("max_packet_size", 0)),
                small_packet_ratio       = float(flow_stats.get("small_packet_ratio", 0)),
                ack_ratio                = float(flow_stats.get("ack_ratio", 0)),
            )
            result = self._detector.detect(features)
            return result.is_anomaly
        except Exception as exc:
            logger.error("AnomalyBridge.check() failed: %s", exc)
            return False

    @property
    def is_available(self) -> bool:
        """True when a real ML model (not heuristic fallback) is loaded."""
        return self._detector is not None and self._detector.model is not None
