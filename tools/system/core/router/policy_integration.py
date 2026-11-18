"""
Policy Integration
Handles interaction with the global Policy Engine.
"""

import logging
import asyncio
from typing import Optional
from system.policy.manager import PolicyManager
from system.policy.schema import PolicyContext, Action
from system.response.orchestrator import ThreatContext, MitigationAction
from .types import RoutingDecision

logger = logging.getLogger(__name__)

class PolicyIntegrator:
    """Wrapper around PolicyManager for Router"""

    def __init__(self, config: dict, policy_manager=None):
        # Accept a pre-built PolicyManager (from ServiceContainer) to avoid
        # importing module-specific engines directly in system/.
        # Fallback: create a bare manager if none provided (no engines registered).
        if policy_manager is None:
            from system.policy.manager import PolicyManager
            self.policy_manager = PolicyManager(config)
        else:
            self.policy_manager = policy_manager
        self.orchestrator = None

        # DDoS Protection: Bounded queue for mitigation tasks
        self.mitigation_queue = asyncio.Queue(maxsize=10000)
        self.dropped_mitigations = 0
        self._worker_task = asyncio.create_task(self._mitigation_worker())


    async def _mitigation_worker(self):
        """Background worker to process mitigations safely without OOM"""
        while True:
            try:
                threat_context = await self.mitigation_queue.get()
                if self.orchestrator:
                    await self.orchestrator.execute_mitigation(threat_context)
                self.mitigation_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Mitigation worker error: {e}")

        
    def enforce_policy(self, 
                      decision: RoutingDecision, 
                      client_ip: str, 
                      client_port: int, 
                      local_port: int,
                      protocol: str = "TCP",
                      interface: str = "eth0") -> bool:
        """
        Enforce policy on the routing decision.
        Returns True if allowed, False if blocked.
        Modifies 'decision' in-place if blocked.
        """
        ctx = PolicyContext(
            src_ip=client_ip,
            dst_ip=decision.target_host or "0.0.0.0",
            src_port=client_port,
            dst_port=decision.target_port or 0,
            protocol=protocol,
            interface=interface,
            domain=decision.target_host,
            app_id=None # Engine will try to resolve
        )
        
        action = self.policy_manager.evaluate(ctx)
        
        if action == Action.BLOCK:
            logger.warning(f"POLICY BLOCK: {client_ip} -> {decision.target_host}")
            
            # Trigger Autonomous Response if Orchestrator is hooked up
            if self.orchestrator:
                threat_context = ThreatContext(
                    target=client_ip,
                    action=MitigationAction.BLOCK_IP,
                    confidence=0.9,
                    reason=f"Blocked by Policy Engine: tried to access {decision.target_host}",
                    metadata={
                        "src_port": client_port,
                        "dst_ip": decision.target_host,
                        "dst_port": decision.target_port
                    }
                )
                try:
                    self.mitigation_queue.put_nowait(threat_context)
                except asyncio.QueueFull:
                    self.dropped_mitigations += 1
                    if self.dropped_mitigations % 1000 == 1:
                        logger.critical(f"DDoS WARNING: Mitigation queue full! Dropped {self.dropped_mitigations} mitigation actions.")
                
            decision.target_host = "0.0.0.0"
            decision.target_port = 0
            decision.metadata['blocked'] = True
            return False
            
        return True
