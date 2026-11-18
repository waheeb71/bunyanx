"""
bunyanx NGFW — Audio Alert System (AAS)
==========================================
Centralized event-driven audio notification service.

Usage:
    from system.audio import AudioManager

    manager = await AudioManager.instance()
    await manager.start()
"""

from system.audio.audio_manager import AudioManager

__all__ = ["AudioManager"]
