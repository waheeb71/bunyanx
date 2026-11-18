"""
bunyanx NGFW — AEGIS Engine: Deception Injection Engine (DIE)
=================================================================

Dynamically generates stage-aware honeypot assets and redirect policies
to shape the attacker's behaviour rather than alert them.

Core Principle
--------------
    "Rather than blocking (which reveals detection), we redirect the
     attacker into a controlled decoy space where their activity is
     fully observable and their impact is zero."

How it works
------------
Given the attacker's current Kill-Chain belief and the CSO's chosen
action, DIE decides:

  1. Should a decoy asset be spawned for this attack path?
  2. What type of decoy is appropriate for this stage?
     (e.g., LATERAL-stage → fake file server in the lateral path)
  3. What redirect policy should be applied at the network layer?

Decoy asset lifetime management
--------------------------------
* Each DecoyAsset has a TTL (default 30 min).
* Assets are evicted automatically on the next ``cleanup()`` call.
* A maximum of ``max_active_decoys`` prevents resource exhaustion.
* Each decoy emits realistic-looking fake service banners to keep
  the attacker engaged while the SOC is alerted.

Integration point
-----------------
AEGISEngine calls ``maybe_inject()`` right after CSO decision.
The returned ``DecoyDirective`` (or None) is passed to PAEB for
network-layer application.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from modules.predictive_ai.engine.AEGIS.core.constants import (
    KILL_CHAIN_STAGES,
)
from modules.predictive_ai.engine.AEGIS.state.belief import BeliefState
from modules.predictive_ai.engine.AEGIS.strategy.optimizer import (
    CounterStrategy,
)


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decoy configuration by Kill-Chain stage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _StageDecoyTemplate:
    """
    Configuration template for a decoy asset appropriate for a
    given Kill-Chain stage.
    """
    decoy_type:      str   # Logical type: "file_server", "db_server", etc.
    fake_service:    str   # e.g. "SMB", "MySQL"
    fake_port:       int
    fake_banner:     str
    realism_score:   float  # 0.0 = trivially fake, 1.0 = indistinguishable


_STAGE_DECOY_TEMPLATES: dict[str, _StageDecoyTemplate] = {
    "RECONNAISSANCE": _StageDecoyTemplate(
        decoy_type="open_port_trap",
        fake_service="SSH",
        fake_port=22,
        fake_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        realism_score=0.90,
    ),
    "INITIAL_ACCESS": _StageDecoyTemplate(
        decoy_type="web_login_trap",
        fake_service="HTTPS",
        fake_port=443,
        fake_banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        realism_score=0.85,
    ),
    "EXECUTION": _StageDecoyTemplate(
        decoy_type="endpoint_honeypot",
        fake_service="WinRM",
        fake_port=5985,
        fake_banner="Microsoft-HTTPAPI/2.0",
        realism_score=0.80,
    ),
    "PERSISTENCE": _StageDecoyTemplate(
        decoy_type="config_store_trap",
        fake_service="Registry/Cron",
        fake_port=111,
        fake_banner="portmapper v2 ready",
        realism_score=0.75,
    ),
    "PRIVILEGE_ESCALATION": _StageDecoyTemplate(
        decoy_type="admin_credential_trap",
        fake_service="LDAP",
        fake_port=389,
        fake_banner="LDAP server ready — Acme Corp AD",
        realism_score=0.88,
    ),
    "LATERAL_MOVEMENT": _StageDecoyTemplate(
        decoy_type="fake_file_server",
        fake_service="SMB",
        fake_port=445,
        fake_banner="Windows Server 2019 (SMBv3)",
        realism_score=0.92,
    ),
    "COLLECTION": _StageDecoyTemplate(
        decoy_type="data_treasure_trap",
        fake_service="FTP",
        fake_port=21,
        fake_banner="220 ProFTPD 1.3.8 Server ready",
        realism_score=0.87,
    ),
    "EXFILTRATION": _StageDecoyTemplate(
        decoy_type="egress_intercept",
        fake_service="DNS-tunnel-sink",
        fake_port=53,
        fake_banner="",   # DNS has no banner
        realism_score=0.70,
    ),
}

# Defender actions for which decoy injection is meaningful
_DECEPTION_ACTIONS: frozenset[str] = frozenset({
    "HONEYPOT_REDIRECT",
    "DECOY_TRAP",
    "FAKE_PATCH",
    "MONITOR",   # low-impact monitor + observe via decoy
})


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

@dataclass
class DecoyAsset:
    """
    A single active decoy asset.

    Attributes
    ----------
    asset_id : str
        Unique identifier (UUID4) for this decoy instance.
    target_ip : str
        The attacker IP this decoy is deployed to intercept.
    stage : str
        Kill-Chain stage this decoy is tailored for.
    decoy_ip : str
        Fake IP address of the decoy host (within the internal range).
    decoy_type : str
        Logical type of the decoy (file_server, web_login_trap, etc.).
    fake_service : str
        Service name being emulated.
    fake_port : int
        Port the decoy listens on.
    fake_banner : str
        Service banner string to send on connection.
    deployed_at : float
        UNIX timestamp when the decoy was deployed.
    ttl_seconds : int
        Time-to-live in seconds. Default: 1 800 (30 min).
    is_active : bool
        True if the decoy is currently live.
    interaction_count : int
        Number of times the attacker has interacted with this decoy.
    """

    asset_id:          str
    target_ip:         str
    stage:             str
    decoy_ip:          str
    decoy_type:        str
    fake_service:      str
    fake_port:         int
    fake_banner:       str
    deployed_at:       float = field(default_factory=time.time)
    ttl_seconds:       int = 1_800
    is_active:         bool = True
    interaction_count: int = 0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.deployed_at) > self.ttl_seconds

    def record_interaction(self) -> None:
        self.interaction_count += 1
        _log.info(
            "DIE: attacker ip=%s interacted with decoy asset_id=%s "
            "(type=%s interaction#%d)",
            self.target_ip,
            self.asset_id,
            self.decoy_type,
            self.interaction_count,
        )

    def to_dict(self) -> dict:
        return {
            "asset_id":          self.asset_id,
            "target_ip":         self.target_ip,
            "stage":             self.stage,
            "decoy_ip":          self.decoy_ip,
            "decoy_type":        self.decoy_type,
            "fake_service":      self.fake_service,
            "fake_port":         self.fake_port,
            "deployed_at":       self.deployed_at,
            "ttl_seconds":       self.ttl_seconds,
            "is_active":         self.is_active,
            "is_expired":        self.is_expired,
            "interaction_count": self.interaction_count,
        }


@dataclass
class DecoyDirective:
    """
    Instruction set sent to the network enforcement layer (PAEB)
    to redirect the attacker to a decoy asset.
    """
    attacker_ip:  str
    decoy_asset:  DecoyAsset
    redirect_to:  str   # "decoy_ip:port" string for eBPF/XDP redirect rule
    reason:       str

    def to_dict(self) -> dict:
        return {
            "attacker_ip": self.attacker_ip,
            "redirect_to": self.redirect_to,
            "decoy_asset": self.decoy_asset.to_dict(),
            "reason":      self.reason,
        }


# ---------------------------------------------------------------------------
# DeceptionInjectionEngine
# ---------------------------------------------------------------------------

class DeceptionInjectionEngine:
    """
    Stage-aware dynamic honeypot generator and redirect policy manager.

    Parameters
    ----------
    decoy_subnet : str
        IP subnet prefix for generating fake decoy IPs.
        e.g. "10.99.88." → decoy IPs will be 10.99.88.1 – 10.99.88.254.
    max_active_decoys : int
        Maximum number of simultaneously active decoy assets.
        Prevents resource exhaustion. Default: 256.
    default_ttl : int
        Default decoy TTL in seconds. Default: 1 800 (30 min).
    min_belief_certainty : float
        Minimum belief certainty required before creating a decoy.
        Below this threshold we don't waste resources on uncertain threats.
        Default: 0.35.
    """

    def __init__(
        self,
        decoy_subnet:       str   = "10.99.88.",
        max_active_decoys:  int   = 256,
        default_ttl:        int   = 1_800,
        min_belief_certainty: float = 0.35,
    ) -> None:
        self._decoy_subnet = decoy_subnet
        self._max_active_decoys = max_active_decoys
        self._default_ttl = default_ttl
        self._min_certainty = min_belief_certainty

        # ip → DecoyAsset (one active decoy per attacker IP)
        self._active_decoys: dict[str, DecoyAsset] = {}
        self._decoy_counter: int = 1   # rolling counter for decoy IPs
        self._total_deployed: int = 0

        _log.info(
            "DeceptionInjectionEngine ready — subnet=%s max=%d ttl=%ds",
            decoy_subnet,
            max_active_decoys,
            default_ttl,
        )

    # ------------------------------------------------------------------
    # Main API
    # ------------------------------------------------------------------

    def maybe_inject(
        self,
        attacker_ip:     str,
        belief:          BeliefState,
        counter_strategy: CounterStrategy,
    ) -> Optional[DecoyDirective]:
        """
        Decide whether to inject a decoy for this attacker event.

        Returns a DecoyDirective (network redirect instruction) if a
        decoy should be deployed, or None if intervention is not warranted.

        Decision logic
        --------------
        1. action must be a deception-class action.
        2. belief certainty must exceed ``min_belief_certainty``.
        3. No existing active decoy for this IP (or existing one expired).
        4. Active decoy count must be below ``max_active_decoys``.
        """
        # -- Gate 1: action must justify deception ----------------------
        if counter_strategy.action not in _DECEPTION_ACTIONS:
            return None

        # -- Gate 2: belief certainty must be meaningful ----------------
        if belief.normalised_certainty < self._min_certainty:
            _log.debug(
                "DIE: skipping decoy for ip=%s — certainty %.2f < threshold %.2f",
                attacker_ip,
                belief.normalised_certainty,
                self._min_certainty,
            )
            return None

        # -- Gate 3: cleanup expired decoys & check capacity -----------
        self.cleanup()
        if len(self._active_decoys) >= self._max_active_decoys:
            _log.warning(
                "DIE: max_active_decoys=%d reached — cannot deploy new decoy",
                self._max_active_decoys,
            )
            return None

        # -- Gate 4: reuse existing active decoy if still valid --------
        if attacker_ip in self._active_decoys:
            existing = self._active_decoys[attacker_ip]
            if not existing.is_expired:
                _log.debug(
                    "DIE: reusing active decoy asset_id=%s for ip=%s",
                    existing.asset_id,
                    attacker_ip,
                )
                return self._build_directive(attacker_ip, existing, "reuse")

        # -- Deploy new decoy ------------------------------------------
        stage = belief.most_likely_stage
        template = _STAGE_DECOY_TEMPLATES.get(
            stage,
            _STAGE_DECOY_TEMPLATES["LATERAL_MOVEMENT"],  # safe default
        )

        decoy_ip = self._allocate_decoy_ip()
        asset = DecoyAsset(
            asset_id=str(uuid.uuid4()),
            target_ip=attacker_ip,
            stage=stage,
            decoy_ip=decoy_ip,
            decoy_type=template.decoy_type,
            fake_service=template.fake_service,
            fake_port=template.fake_port,
            fake_banner=template.fake_banner,
            ttl_seconds=self._default_ttl,
        )

        self._active_decoys[attacker_ip] = asset
        self._total_deployed += 1

        _log.warning(
            "DIE: DEPLOYED decoy asset_id=%s | attacker_ip=%s | stage=%s | "
            "type=%s | redirect_to=%s:%d",
            asset.asset_id,
            attacker_ip,
            stage,
            template.decoy_type,
            decoy_ip,
            template.fake_port,
        )

        return self._build_directive(attacker_ip, asset, "new_deployment")

    def record_decoy_interaction(self, attacker_ip: str) -> None:
        """
        Call when the attacker is observed interacting with the decoy.
        Increments interaction counter and triggers analyst alert.
        """
        asset = self._active_decoys.get(attacker_ip)
        if asset:
            asset.record_interaction()

    def cleanup(self) -> int:
        """
        Evict all expired decoy assets.
        Returns the number of decoys removed.
        """
        expired = [ip for ip, a in self._active_decoys.items() if a.is_expired]
        for ip in expired:
            asset = self._active_decoys.pop(ip)
            _log.info(
                "DIE: expired decoy asset_id=%s for ip=%s (interactions=%d)",
                asset.asset_id,
                ip,
                asset.interaction_count,
            )
        return len(expired)

    # ------------------------------------------------------------------
    # State access
    # ------------------------------------------------------------------

    def get_active_decoys(self) -> list[dict]:
        """Return all currently active (non-expired) decoy assets."""
        self.cleanup()
        return [a.to_dict() for a in self._active_decoys.values()]

    def summary(self) -> dict:
        """Return diagnostic summary."""
        self.cleanup()
        return {
            "active_decoys":    len(self._active_decoys),
            "max_capacity":     self._max_active_decoys,
            "total_deployed":   self._total_deployed,
            "utilisation_pct":  round(
                100.0 * len(self._active_decoys) / self._max_active_decoys, 1
            ),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _allocate_decoy_ip(self) -> str:
        """Rotate through the decoy subnet to assign a fake IP."""
        octet = (self._decoy_counter % 254) + 1   # 1 – 254
        self._decoy_counter += 1
        return f"{self._decoy_subnet}{octet}"

    @staticmethod
    def _build_directive(
        attacker_ip: str,
        asset: DecoyAsset,
        reason: str,
    ) -> DecoyDirective:
        return DecoyDirective(
            attacker_ip=attacker_ip,
            decoy_asset=asset,
            redirect_to=f"{asset.decoy_ip}:{asset.fake_port}",
            reason=reason,
        )
