"""
Enterprise bunyanx — Email Risk Scoring Engine

Aggregates scores from all email detection modules into a
single risk score and maps it to a policy decision.

Weights (default — configurable via waf.yaml):
  phishing       : 35%
  url_scanner    : 25%
  attachment_guard: 20%
  sender_reputation: 15%
  spam_filter    : 5%
  smtp_commands  : (bonus penalty, not weighted)

Policy decisions:
  ALLOW      : < threshold.allow
  QUARANTINE : threshold.allow - threshold.block  (move to spam folder)
  BLOCK      : >= threshold.block                 (SMTP REJECT)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class EmailPolicyDecision(str, Enum):
    ALLOW      = "allow"
    QUARANTINE = "quarantine"    # Deliver to Spam / Junk folder
    BLOCK      = "block"         # SMTP 550 REJECT — do not deliver


@dataclass
class EmailRiskBreakdown:
    phishing_score:    float = 0.0
    url_score:         float = 0.0
    attachment_score:  float = 0.0
    sender_score:      float = 0.0
    spam_score:        float = 0.0
    plsf_score:        float = 0.0
    vsde_score:        float = 0.0
    command_penalty:   float = 0.0
    final_score:       float = 0.0
    decision:          EmailPolicyDecision = EmailPolicyDecision.ALLOW

    def to_dict(self) -> dict:
        return {
            "phishing_score":   round(self.phishing_score, 3),
            "url_score":        round(self.url_score, 3),
            "attachment_score": round(self.attachment_score, 3),
            "sender_score":     round(self.sender_score, 3),
            "spam_score":       round(self.spam_score, 3),
            "plsf_score":       round(self.plsf_score, 3),
            "vsde_score":       round(self.vsde_score, 3),
            "command_penalty":  round(self.command_penalty, 3),
            "final_score":      round(self.final_score, 3),
            "decision":         self.decision.value,
        }


class EmailRiskEngine:
    """
    Calculate final email risk score from all detection layers.

    Weights should sum to 1.0.

    Args:
        w_phishing:    Weight for phishing detection score
        w_url:         Weight for URL scan score
        w_attachment:  Weight for attachment guard score
        w_sender:      Weight for sender reputation score
        w_spam:        Weight for spam filter score
        threshold_allow:      Score below this → ALLOW
        threshold_block:      Score at or above this → BLOCK
    """

    def __init__(
        self,
        w_phishing:       float = 0.25,
        w_url:            float = 0.15,
        w_attachment:     float = 0.15,
        w_sender:         float = 0.15,
        w_spam:           float = 0.05,
        w_plsf:           float = 0.10,
        w_vsde:           float = 0.15,
        threshold_allow:  float = 0.25,
        threshold_quarantine: float = 0.55,
        threshold_block:  float = 0.80,
        thresholds=None,   # Optional: full RiskThresholds object from email.yaml
    ):
        # Normalize weights so they always sum to 1.0
        total = w_phishing + w_url + w_attachment + w_sender + w_spam + w_plsf + w_vsde
        if total > 0:
            self.w_phishing   = w_phishing   / total
            self.w_url        = w_url        / total
            self.w_attachment = w_attachment / total
            self.w_sender     = w_sender     / total
            self.w_spam       = w_spam       / total
            self.w_plsf       = w_plsf       / total
            self.w_vsde       = w_vsde       / total
        else:
            self.w_phishing = self.w_url = self.w_attachment = self.w_sender = self.w_spam = self.w_plsf = self.w_vsde = 1.0 / 7.0

        self.threshold_allow      = threshold_allow
        self.threshold_quarantine = threshold_quarantine
        self.threshold_block      = threshold_block

        # Full thresholds object (from email.yaml) — used for per-scanner override thresholds
        if thresholds is not None:
            self.thresholds = thresholds
        else:
            # Build a minimal RiskThresholds using the individual floats passed
            from modules.email_security.engine.core.settings import RiskThresholds
            self.thresholds = RiskThresholds(
                allow=threshold_allow,
                quarantine=threshold_quarantine,
                block=threshold_block,
            )

    def calculate(
        self,
        phishing_score:    float = 0.0,
        url_score:         float = 0.0,
        attachment_score:  float = 0.0,
        sender_score:      float = 0.0,
        spam_score:        float = 0.0,
        plsf_score:        float = 0.0,
        vsde_score:        float = 0.0,
        command_penalty:   float = 0.0,
        force_block:       bool  = False,
    ) -> EmailRiskBreakdown:
        """
        Calculate the final risk score.

        Args:
            phishing_score:   From PhishingDetector.detect()
            url_score:        From URLScanner.scan()
            attachment_score: From AttachmentGuard.scan()
            sender_score:     From SenderReputation.check()
            spam_score:       From SpamFilter.score()
            plsf_score:       From PsychoLinguisticProfiler.analyze()
            vsde_score:       From VisualDesyncScanner.scan()
            command_penalty:  Extra penalty for suspicious SMTP commands
            force_block:      Force BLOCK regardless of score (e.g., dangerous attachment)

        Returns:
            EmailRiskBreakdown with final_score and decision
        """
        breakdown = EmailRiskBreakdown(
            phishing_score   = phishing_score,
            url_score        = url_score,
            attachment_score = attachment_score,
            sender_score     = sender_score,
            spam_score       = spam_score,
            plsf_score       = plsf_score,
            vsde_score       = vsde_score,
            command_penalty  = command_penalty,
        )

        # Weighted sum
        raw = (
            (phishing_score   * self.w_phishing) +
            (url_score        * self.w_url) +
            (attachment_score * self.w_attachment) +
            (sender_score     * self.w_sender) +
            (spam_score       * self.w_spam) +
            (plsf_score       * self.w_plsf) +
            (vsde_score       * self.w_vsde) +
            command_penalty
        )

        # 🚨 Single High-Confidence Threat Overrides
        if phishing_score >= self.thresholds.phishing_block_threshold:
            force_block = True
            logger.warning("High-confidence Phishing (score=%.3f) — forcing BLOCK.", phishing_score)
        elif phishing_score >= self.thresholds.phishing_quarantine_threshold:
            raw = max(raw, self.threshold_quarantine)
            logger.warning("Suspicious Phishing (score=%.3f) — escalating to QUARANTINE.", phishing_score)

        if url_score >= self.thresholds.url_block_threshold:
            force_block = True
            logger.warning("High-confidence Malicious URL (score=%.3f) — forcing BLOCK.", url_score)
        elif url_score >= self.thresholds.url_quarantine_threshold:
            raw = max(raw, self.threshold_quarantine)
            logger.warning("Suspicious URL (score=%.3f) — escalating to QUARANTINE.", url_score)

        if attachment_score >= self.thresholds.attachment_quarantine_threshold:
            raw = max(raw, self.threshold_quarantine)
            logger.warning("Suspicious Attachment (score=%.3f) — escalating to QUARANTINE.", attachment_score)

        # 🚨 AI Evasion / Mimicry Overrides
        # VSDE: Jaccard desync ratio R > threshold → visual evasion confirmed → BLOCK
        if vsde_score > self.thresholds.vsde_block_threshold:
            force_block = True
            logger.warning(
                "Visual-Semantic Desync detected (R=%.3f > %.3f)! Forcing BLOCK.",
                vsde_score, self.thresholds.vsde_block_threshold
            )

        # PLSF: λ_opt from email.yaml (Youden's J calibrated threshold, Dataset v3.0)
        # Score_composite = w_semantic × Dc + w_lexical × L_BEC  [paper §IV-A Eq.3]
        if plsf_score > self.thresholds.plsf_quarantine_threshold:
            logger.warning(
                "Psycho-Linguistic Mimicry detected (score=%.3f > λ_opt=%.3f)! Bumping risk to QUARANTINE.",
                plsf_score, self.thresholds.plsf_quarantine_threshold,
            )
            raw = max(raw, self.threshold_quarantine)
            if plsf_score > self.thresholds.plsf_block_threshold:
                force_block = True
                logger.warning(
                    "PLSF score %.3f > %.3f — forcing BLOCK (high-confidence BEC).",
                    plsf_score, self.thresholds.plsf_block_threshold
                )

        breakdown.final_score = min(raw, 1.0)

        # Determine decision
        if force_block:
            breakdown.decision = EmailPolicyDecision.BLOCK
        elif breakdown.final_score >= self.threshold_block:
            breakdown.decision = EmailPolicyDecision.BLOCK
        elif breakdown.final_score >= self.threshold_quarantine:
            breakdown.decision = EmailPolicyDecision.QUARANTINE
        else:
            breakdown.decision = EmailPolicyDecision.ALLOW

        logger.debug(
            "EmailRisk score=%.3f → %s (phish=%.2f url=%.2f attach=%.2f sender=%.2f spam=%.2f plsf=%.2f vsde=%.2f)",
            breakdown.final_score, breakdown.decision.value,
            phishing_score, url_score, attachment_score, sender_score, spam_score, plsf_score, vsde_score
        )

        return breakdown
