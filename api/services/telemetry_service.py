"""
Enterprise bunyanx - Telemetry Service Layer
===================================================
Contains business logic for fetching system logs and telemetry data.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

async def get_recent_system_logs(limit: int = 500) -> List[Dict[str, Any]]:
    """Fetch the last N lines of terminal stdout logs emitted by the Python root logger."""
    try:
        from modules.log_manager.engine.log_controller import global_memory_handler
        return global_memory_handler.get_recent_logs(limit=limit)
    except Exception as e:
        logger.error(f"Failed to fetch recent logs: {e}")
        return []

async def subscribe_to_live_logs():
    """Returns an async generator to stream live system events globally."""
    try:
        from modules.log_manager.engine.log_controller import global_memory_handler
        async for log_entry in global_memory_handler.subscribe():
            yield log_entry
    except Exception as e:
        logger.error(f"Failed to subscribe to live logs: {e}")
