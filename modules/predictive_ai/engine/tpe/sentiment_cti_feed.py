"""
bunyanx NGFW — AEGIS v3: Sentiment-Augmented CTI Feed
==========================================================

Expands Threat Intelligence with Dark Web sentiment analysis,
social media threat chatter, and paste-site leak frequency.

Problem Solved
--------------
The existing TPE uses 5 static risk factors. However, real-world
attack campaigns often generate detectable "pre-signals" in:
  - Dark web forums (AnonForums, Breach Forums, exploit marketplaces)
  - Social media (Twitter/X threat researcher disclosures, PoC announcements)
  - Paste sites (credential dumps, leaked internal documents)

These signals precede the actual attack by hours or days, giving the
defender a temporal advantage if they can be captured and quantified.

This module adds a 6th factor P₆ (sentiment_threat_index) to the TPE:

    ThreatScore = Σᵢ αᵢ · Pᵢ  where i = 1..6

New weight vector:
    α = (0.22, 0.27, 0.18, 0.13, 0.09, 0.11)

Architecture
------------
  SentimentAugmentedCTIFeed implements ThreatIntelFeedProtocol:
    - Wraps an existing CTI feed (composition, not inheritance)
    - Augments get_campaign_intensity with sentiment boost
    - New method: get_sentiment_index() → float ∈ [0, 1]

  For research: simulated data with documented methodology
  For production: pluggable interface for real API integration

Sentiment → CTI Intensity Mapping
----------------------------------
  P4_augmented = P4_static * (1 + sentiment_boost)
  sentiment_boost = w_darkweb * S_darkweb + w_social * S_social + w_paste * S_paste

  where:
    S_darkweb ∈ [0, 1]  — dark web forum activity index
    S_social  ∈ [0, 1]  — social media threat chatter score
    S_paste   ∈ [0, 1]  — paste-site leak frequency (normalized)

    w_darkweb = 0.45    — strongest predictive signal
    w_social  = 0.30    — early warning, high noise
    w_paste   = 0.25    — confirmatory signal

Research Reference
------------------
  AEGIS Paper — §IV.A (TPE Enhancement with Sentiment CTI)
  Samtani et al., "Exploring Hacker Assets in Underground Forums,"
  IEEE ISI 2016.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

# Import risk models from TPE
from modules.predictive_ai.engine.tpe.risk_context import (
    OrgSector,
    AttackVector,
    ThreatIntelFeedProtocol,
)


# ---------------------------------------------------------------------------
# Sentiment Signal Models
# ---------------------------------------------------------------------------

@dataclass
class SentimentSignal:
    """
    A single sentiment signal from a source.

    Attributes
    ----------
    source : str
        Signal source: "darkweb" | "social" | "paste".
    intensity : float
        Signal strength ∈ [0, 1]. 0 = no activity, 1 = extreme.
    confidence : float
        Confidence in the signal ∈ [0, 1].
    sector_relevance : float
        How relevant this signal is to the target sector ∈ [0, 1].
    timestamp : float
        When this signal was measured (Unix epoch).
    description : str
        Human-readable description.
    """
    source:           str
    intensity:        float
    confidence:       float   = 0.5
    sector_relevance: float   = 0.5
    timestamp:        float   = field(default_factory=time.time)
    description:      str     = ""

    @property
    def effective_intensity(self) -> float:
        """Adjusted intensity: raw × confidence × sector relevance."""
        return self.intensity * self.confidence * self.sector_relevance


@dataclass
class SentimentProfile:
    """
    Aggregated sentiment profile for a sector/organization.

    Combines signals from dark web, social media, and paste sites.
    """
    darkweb_index:  float = 0.0    # Dark web forum activity [0, 1]
    social_index:   float = 0.0    # Social media threat chatter [0, 1]
    paste_index:    float = 0.0    # Paste-site leak frequency [0, 1]
    timestamp:      float = field(default_factory=time.time)
    signals:        list[SentimentSignal] = field(default_factory=list)

    @property
    def composite_index(self) -> float:
        """
        Weighted composite sentiment index.

        Weights: darkweb=0.45, social=0.30, paste=0.25
        """
        return (
            0.45 * self.darkweb_index
            + 0.30 * self.social_index
            + 0.25 * self.paste_index
        )


# ---------------------------------------------------------------------------
# Sector Sentiment Profiles (Simulated — Research Mode)
# ---------------------------------------------------------------------------

# Pre-calibrated sentiment snapshots for research scenarios.
# These are derived from analysis of real forum/Twitter/paste-site patterns
# as documented in Samtani et al. 2016 and Almukaynizi et al. 2017.

_SECTOR_SENTIMENT: dict[OrgSector, SentimentProfile] = {
    OrgSector.BANKING: SentimentProfile(
        darkweb_index=0.72,   # Financial trojans actively traded
        social_index=0.45,    # Moderate chatter about banking TTPs
        paste_index=0.60,     # Credential dumps targeting banks
    ),
    OrgSector.GOVERNMENT: SentimentProfile(
        darkweb_index=0.55,
        social_index=0.70,    # High visibility of gov-targeted attacks
        paste_index=0.40,
    ),
    OrgSector.HEALTHCARE: SentimentProfile(
        darkweb_index=0.65,   # Medical data valuable on dark web
        social_index=0.30,
        paste_index=0.50,
    ),
    OrgSector.ENERGY: SentimentProfile(
        darkweb_index=0.80,   # ICS/SCADA exploits heavily discussed
        social_index=0.60,    # High researcher disclosure activity
        paste_index=0.35,
    ),
    OrgSector.TECH: SentimentProfile(
        darkweb_index=0.50,
        social_index=0.55,    # PoC/0-day discussions common
        paste_index=0.65,     # Source code leaks, API keys
    ),
    OrgSector.DEFENSE: SentimentProfile(
        darkweb_index=0.85,   # Nation-state tool discussions
        social_index=0.40,
        paste_index=0.30,
    ),
    OrgSector.RETAIL: SentimentProfile(
        darkweb_index=0.60,   # Card skimming tools, POS malware
        social_index=0.25,
        paste_index=0.70,     # Card dumps very common
    ),
    OrgSector.EDUCATION: SentimentProfile(
        darkweb_index=0.30,
        social_index=0.20,
        paste_index=0.35,
    ),
    OrgSector.TELECOM: SentimentProfile(
        darkweb_index=0.55,
        social_index=0.50,
        paste_index=0.45,
    ),
    OrgSector.CRITICAL_INFRA: SentimentProfile(
        darkweb_index=0.75,
        social_index=0.65,
        paste_index=0.30,
    ),
}

# Default for unknown sectors
_DEFAULT_SENTIMENT = SentimentProfile(
    darkweb_index=0.30,
    social_index=0.20,
    paste_index=0.20,
)


# ---------------------------------------------------------------------------
# SentimentAugmentedCTIFeed
# ---------------------------------------------------------------------------

class SentimentAugmentedCTIFeed:
    """
    Threat Intelligence Feed augmented with sentiment analysis.

    Wraps an existing CTI feed and augments it with sentiment signals
    from dark web, social media, and paste sites.

    Implements ThreatIntelFeedProtocol for drop-in TPE integration.

    Parameters
    ----------
    base_feed : ThreatIntelFeedProtocol
        The existing CTI feed to wrap.
    sentiment_boost_factor : float
        How much sentiment amplifies the CTI intensity.
        Default: 0.35 (max 35% boost from sentiment).
    custom_profiles : dict[OrgSector, SentimentProfile] | None
        Override sector sentiment profiles (for testing/production).
    """

    def __init__(
        self,
        base_feed: ThreatIntelFeedProtocol,
        sentiment_boost_factor: float = 0.35,
        custom_profiles: Optional[dict[OrgSector, SentimentProfile]] = None,
    ) -> None:
        self._base = base_feed
        self._boost_factor = sentiment_boost_factor
        self._profiles = custom_profiles or _SECTOR_SENTIMENT
        self._query_count = 0

        _log.info(
            "SentimentAugmentedCTIFeed initialized — "
            "boost_factor=%.2f, profiles=%d sectors",
            sentiment_boost_factor, len(self._profiles),
        )

    # ------------------------------------------------------------------
    # ThreatIntelFeedProtocol implementation
    # ------------------------------------------------------------------

    def get_active_campaigns(self, sector: OrgSector) -> list[dict]:
        """
        Return active campaigns from base feed, enriched with sentiment.

        Each campaign dict gets an additional 'sentiment_boost' field.
        """
        campaigns = self._base.get_active_campaigns(sector)
        profile = self._get_profile(sector)

        for campaign in campaigns:
            # Boost campaign likelihood based on sentiment
            original = campaign.get("likelihood", 0.5)
            boost = profile.composite_index * self._boost_factor
            campaign["likelihood"] = min(1.0, original * (1.0 + boost))
            campaign["sentiment_boost"] = round(boost, 4)

        return campaigns

    def get_campaign_intensity(self, sector: OrgSector) -> float:
        """
        Return CTI intensity augmented with sentiment boost.

        P4_augmented = P4_base * (1 + sentiment_boost * boost_factor)
        """
        self._query_count += 1
        base_intensity = self._base.get_campaign_intensity(sector)
        profile = self._get_profile(sector)

        # Apply sentiment boost with saturation
        boost = profile.composite_index * self._boost_factor
        augmented = base_intensity * (1.0 + boost)

        # Clamp to [0, 1]
        result = min(1.0, augmented)

        _log.debug(
            "SentimentCTI: sector=%s base=%.3f boost=%.3f → %.3f",
            sector.value, base_intensity, boost, result,
        )
        return result

    # ------------------------------------------------------------------
    # Sentiment-specific API (P₆)
    # ------------------------------------------------------------------

    def get_sentiment_index(self, sector: OrgSector) -> float:
        """
        Return the composite sentiment threat index P₆.

        This is the NEW 6th factor for TPE integration:
            P₆ = composite_sentiment_index ∈ [0, 1]

        Returns
        -------
        float
            Weighted sentiment score combining dark web (45%),
            social media (30%), and paste sites (25%).
        """
        profile = self._get_profile(sector)
        return round(profile.composite_index, 4)

    def get_sentiment_breakdown(self, sector: OrgSector) -> dict:
        """Return detailed sentiment breakdown for a sector."""
        profile = self._get_profile(sector)
        return {
            "darkweb_index": round(profile.darkweb_index, 4),
            "social_index":  round(profile.social_index, 4),
            "paste_index":   round(profile.paste_index, 4),
            "composite":     round(profile.composite_index, 4),
            "num_signals":   len(profile.signals),
        }

    def update_signal(
        self,
        sector: OrgSector,
        signal: SentimentSignal,
    ) -> None:
        """
        Inject a real-time sentiment signal update.

        For production use: called when a new signal is received
        from a dark web crawler, social media API, or paste-site monitor.
        """
        profile = self._profiles.get(sector, _DEFAULT_SENTIMENT)

        # Update the relevant index with EMA
        alpha = 0.3  # EMA smoothing (favor recent signals)
        eff = signal.effective_intensity

        if signal.source == "darkweb":
            profile.darkweb_index = alpha * eff + (1 - alpha) * profile.darkweb_index
        elif signal.source == "social":
            profile.social_index = alpha * eff + (1 - alpha) * profile.social_index
        elif signal.source == "paste":
            profile.paste_index = alpha * eff + (1 - alpha) * profile.paste_index

        profile.signals.append(signal)

        _log.info(
            "SentimentCTI: signal update sector=%s source=%s intensity=%.2f",
            sector.value, signal.source, eff,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_profile(self, sector: OrgSector) -> SentimentProfile:
        """Get the sentiment profile for a sector."""
        return self._profiles.get(sector, _DEFAULT_SENTIMENT)

    def summary(self) -> dict:
        """Return diagnostic summary."""
        return {
            "total_queries": self._query_count,
            "boost_factor": self._boost_factor,
            "sectors_profiled": len(self._profiles),
            "profiles": {
                sector.value: round(profile.composite_index, 4)
                for sector, profile in self._profiles.items()
            },
        }
