"""
Enterprise bunyanx v2.0 - Inspector Plugin Base

Abstract base class for all inspection plugins.

Author: Enterprise bunyanx Team
License: Proprietary
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import IntEnum


class InspectionAction(IntEnum):
    """Action to take after inspection"""
    ALLOW = 0
    LOG_ONLY = 1
    PERTURB = 2
    REDIRECT = 3
    REDIRECT_DECOY = 4
    QUARANTINE = 5
    BLOCK = 6
    DROP = 7


class PluginPriority(IntEnum):
    """Plugin execution priority (lower = earlier)"""
    HIGHEST = 0
    HIGH = 25
    NORMAL = 50
    LOW = 75
    LOWEST = 100



@dataclass
class IdentityContext:
    user_id: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None

@dataclass
class RiskContext:
    score: float = 0.0
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None: self.tags = []

@dataclass
class SessionContext:
    session_id: Optional[str] = None
    is_authenticated: bool = False


@dataclass
class InspectionContext:
    """Context information for inspection (The Context Bus)"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # 'TCP', 'UDP', 'ICMP'
    direction: str  # 'inbound', 'outbound'
    flow_id: str  # Unique flow identifier
    timestamp: float
    
    # Optional nested contexts for advanced NGFW correlation
    identity: Optional[IdentityContext] = None
    risk: Optional[RiskContext] = None
    session: Optional[SessionContext] = None
    
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.identity is None:
            self.identity = IdentityContext()
        if self.risk is None:
            self.risk = RiskContext()
        if self.session is None:
            self.session = SessionContext()


@dataclass
class InspectionFinding:
    """A single finding produced by an inspection plugin"""
    plugin_name: str
    severity: str           # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 
    category: str           # e.g. "DLP", "SQL Injection", "XSS"
    description: str
    confidence: float = 1.0  # 0.0 – 1.0
    recommends_block: bool = False
    metadata: Dict[str, Any] = None
    evidence: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.evidence is None:
            self.evidence = {}


@dataclass
class InspectionResult:
    """Aggregated result returned by an inspection"""
    action: InspectionAction = InspectionAction.ALLOW
    findings: List[InspectionFinding] = None
    metadata: Dict[str, Any] = None
    processing_time_ms: float = 0.0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.metadata is None:
            self.metadata = {}
            
    @property
    def is_blocked(self) -> bool:
        """Check if traffic should be blocked"""
        return self.action in (InspectionAction.BLOCK, InspectionAction.DROP)




class AbstractEnricher(ABC):
    """
    Base class for Context Enrichers.
    Enrichers run BEFORE any inspection plugins to populate Identity, Risk, and Session contexts.
    """
    
    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        self.name = name
        self.logger = logger or logging.getLogger(f"{self.__class__.__name__}")

    @abstractmethod
    def enrich(self, context: InspectionContext) -> None:
        """Populate the InspectionContext in-place."""
        pass
        
    async def enrich_async(self, context: InspectionContext) -> None:
        """Asynchronously populate the InspectionContext."""
        import asyncio
        await asyncio.to_thread(self.enrich, context)

class InspectorPlugin(ABC):
    """
    Abstract base class for inspection plugins.
    
    All protocol inspectors must inherit from this class and implement
    the required methods.
    """
    
    def __init__(
        self,
        name: str,
        priority: PluginPriority = PluginPriority.NORMAL,
        logger: Optional[logging.Logger] = None
    ):
        self.name = name
        self.priority = priority
        self.logger = logger or logging.getLogger(f"{self.__class__.__name__}")
        self.enabled = True
        
        # Statistics
        self._inspected_count = 0
        self._detected_count = 0
        self._blocked_count = 0
        
    @abstractmethod
    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Check if this plugin can inspect the given traffic.
        
        Args:
            context: Inspection context
            
        Returns:
            True if plugin can handle this traffic
        """
        pass
        
    @abstractmethod
    def inspect(
        self,
        context: InspectionContext,
        data: bytes
    ) -> 'InspectionResult':
        """
        Inspect the traffic data.
        
        Args:
            context: Inspection context
            data: Raw packet/stream data
            
        Returns:
            InspectionResult with findings
        """
        pass

    async def inspect_async(
        self,
        context: InspectionContext,
        data: bytes
    ) -> 'InspectionResult':
        """
        Asynchronously inspect the traffic data.
        Defaults to running the synchronous inspect() method in a background thread 
        to ensure 100% backwards compatibility for legacy modules.
        Native async modules should override this method directly.
        """
        import asyncio
        return await asyncio.to_thread(self.inspect, context, data)
        
    def enable(self) -> None:
        """Enable this plugin"""
        self.enabled = True
        self.logger.info(f"Plugin {self.name} enabled")
        
    def disable(self) -> None:
        """Disable this plugin"""
        self.enabled = False
        self.logger.info(f"Plugin {self.name} disabled")
        
    def get_statistics(self) -> Dict:
        """Get plugin statistics"""
        return {
            'name': self.name,
            'enabled': self.enabled,
            'priority': self.priority,
            'inspected': self._inspected_count,
            'detected': self._detected_count,
            'blocked': self._blocked_count,
            'detection_rate': (
                self._detected_count / max(self._inspected_count, 1) * 100
            )
        }
        
    def reset_statistics(self) -> None:
        """Reset statistics counters"""
        self._inspected_count = 0
        self._detected_count = 0
        self._blocked_count = 0
    def get_netfilter_rules(self) -> Dict[str, List[str]]:
        """
        Return a dictionary of OS-level nftables rules required by this plugin.
        Expected keys: 'prerouting', 'input', 'forward', 'postrouting'.
        Values: List of nftables rule strings.
        Override this method to dynamically inject rules into the NetworkRuleOrchestrator.
        """
        return {}

    def __str__(self) -> str:
        return f"{self.name} (priority={self.priority}, enabled={self.enabled})"
