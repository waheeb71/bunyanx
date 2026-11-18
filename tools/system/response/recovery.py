"""
Enterprise bunyanx - Recovery Manager

Handles automated rollback and recovery from mitigation actions
once a threat has passed or a false positive is identified.
"""

import asyncio
import logging
import time
from enum import Enum
from typing import Optional, Dict

from system.telemetry.health import HealthStatus

class RecoveryManager:
    """Manages system health and recovers isolated/blocked entities (Event-Driven)."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.entity_health: Dict[str, HealthStatus] = {}
        self.recovery_queue: Dict[str, float] = {}  # target -> timestamp
        
        self._loop_task: Optional[asyncio.Task] = None
        self._wakeup_event = asyncio.Event()

    async def start(self):
        """Start the event-driven background loop."""
        if not self._loop_task:
            self._loop_task = asyncio.create_task(self._event_loop())
            self.logger.info("RecoveryManager event loop started.")

    async def stop(self):
        """Stop the background loop."""
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
            self._loop_task = None
            self.logger.info("RecoveryManager event loop stopped.")

    def mark_isolated(self, target: str, duration_sec: int = 3600):
        """Mark an entity as isolated and schedule recovery."""
        self.entity_health[target] = HealthStatus.ISOLATED
        self.recovery_queue[target] = time.time() + duration_sec
        self.logger.info(f"Target {target} marked isolated. Recovery scheduled in {duration_sec}s.")
        
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(self._wakeup_event.set)
        except RuntimeError:
            pass # Not in an event loop

    async def _event_loop(self):
        """Event-driven recovery loop."""
        while True:
            try:
                now = time.time()
                next_wakeup = None
                to_recover = []
                
                for target, recover_time in list(self.recovery_queue.items()):
                    if now >= recover_time:
                        to_recover.append(target)
                    else:
                        if next_wakeup is None or recover_time < next_wakeup:
                            next_wakeup = recover_time
                
                for target in to_recover:
                    await self._execute_recovery(target)
                
                self._wakeup_event.clear()
                if next_wakeup is None:
                    # Sleep until woken up by new isolation
                    await self._wakeup_event.wait()
                else:
                    sleep_duration = next_wakeup - time.time()
                    if sleep_duration > 0:
                        try:
                            await asyncio.wait_for(self._wakeup_event.wait(), timeout=sleep_duration)
                        except asyncio.TimeoutError:
                            pass # Timeout means it's time to recover!
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in RecoveryManager loop: {e}")
                await asyncio.sleep(5)
                
    async def _execute_recovery(self, target: str):
        """Execute the actual recovery process."""
        self.logger.info(f"🔄 Executing automated recovery for {target}...")
        
        self.entity_health[target] = HealthStatus.HEALTHY
        if target in self.recovery_queue:
            del self.recovery_queue[target]
            
        self.logger.info(f"✅ Target {target} restored to HEALTHY state.")
