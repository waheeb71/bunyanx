"""
bunyanx NGFW — Service Container (Dependency Injection)
==========================================================
Lightweight DI container that registers system-wide services
and provides them to modules on demand.

Usage:
    container = ServiceContainer()
    container.register('db', DatabaseManager(...))
    container.register('event_bus', event_bus_instance)

    # In any module:
    db = container.get('db')

Thread-safe. Singleton-friendly.
"""

import logging
import threading
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)


class ServiceNotFoundError(KeyError):
    """Raised when a requested service is not registered."""
    pass


class ServiceContainer:
    """
    Lightweight Dependency Injection container.
    
    Registers named services and provides them to modules.
    Thread-safe for concurrent access from inspection threads.
    """

    _instance: Optional['ServiceContainer'] = None
    _lock = threading.Lock()

    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._rw_lock = threading.RLock()

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> 'ServiceContainer':
        """Return the global ServiceContainer singleton."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._lock:
            cls._instance = None

    # ── Public API ─────────────────────────────────────────────────

    def register(self, name: str, instance: Any) -> None:
        """
        Register a service by name.
        
        Args:
            name: Service identifier (e.g. 'db', 'event_bus', 'config')
            instance: The service instance
        """
        with self._rw_lock:
            if name in self._services:
                logger.warning(f"[ServiceContainer] Overwriting service: {name}")
            self._services[name] = instance
            logger.debug(f"[ServiceContainer] Registered service: {name}")

    def get(self, name: str) -> Any:
        """
        Retrieve a service by name.
        
        Args:
            name: Service identifier
            
        Returns:
            The service instance
            
        Raises:
            ServiceNotFoundError: If service is not registered
        """
        with self._rw_lock:
            if name not in self._services:
                raise ServiceNotFoundError(
                    f"Service '{name}' not found. "
                    f"Available: {list(self._services.keys())}"
                )
            return self._services[name]

    def get_optional(self, name: str) -> Optional[Any]:
        """
        Retrieve a service by name, returning None if not found.
        
        Args:
            name: Service identifier
            
        Returns:
            The service instance or None
        """
        with self._rw_lock:
            return self._services.get(name)

    def has(self, name: str) -> bool:
        """Check if a service is registered."""
        with self._rw_lock:
            return name in self._services

    def list_services(self) -> List[str]:
        """List all registered service names."""
        with self._rw_lock:
            return list(self._services.keys())

    def unregister(self, name: str) -> bool:
        """
        Remove a service from the container.
        
        Args:
            name: Service identifier
            
        Returns:
            True if the service was removed
        """
        with self._rw_lock:
            if name in self._services:
                del self._services[name]
                logger.debug(f"[ServiceContainer] Unregistered service: {name}")
                return True
            return False

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def __repr__(self) -> str:
        return f"ServiceContainer(services={self.list_services()})"
