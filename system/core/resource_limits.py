"""
Resource Limits Manager — bunyanx NGFW
Automatically tunes OS file descriptor limits (RLIMIT_NOFILE) and handles emergency FD cleanup.
"""
import os
import sys
import gc
import time
import errno
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

_LAST_EMFILE_WARNING = 0.0
_EMFILE_WARNING_INTERVAL = 5.0  # Throttle log spam to once every 5 seconds


def setup_system_resource_limits(target_nofile: int = 65536) -> Tuple[int, int]:
    """
    Attempt to raise system open file descriptor limits (RLIMIT_NOFILE) on POSIX/Linux.
    Returns tuple of (current_soft_limit, current_hard_limit).
    """
    if sys.platform == "win32":
        # Windows uses C runtime file handle limits (_setmaxstdio)
        try:
            import win32file
            # Windows default CRT max is 512 / 2048
            logger.debug("[ResourceLimits] Windows OS detected — file handles managed via CRT.")
        except Exception:
            pass
        return (8192, 8192)

    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        logger.info("[ResourceLimits] Current OS file limits: soft=%d, hard=%d", soft, hard)

        if soft < target_nofile:
            # Determine maximum soft limit we can set without root privileges
            new_soft = min(target_nofile, hard) if hard > 0 else target_nofile
            if new_soft > soft:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
                    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                    logger.info("✅ [ResourceLimits] Successfully raised soft open file limit to %d", soft)
                except (ValueError, OSError) as exc:
                    logger.warning(
                        "[ResourceLimits] Could not raise RLIMIT_NOFILE to %d: %s. "
                        "Admin tip: Run 'ulimit -n 65536' or update /etc/security/limits.conf.",
                        new_soft, exc
                    )
        return (soft, hard)
    except ImportError:
        logger.debug("[ResourceLimits] 'resource' module unavailable on this platform.")
        return (1024, 1024)
    except Exception as exc:
        logger.error("[ResourceLimits] Error checking resource limits: %s", exc)
        return (1024, 1024)


def handle_emfile_resource_exhaustion(exc: Exception, context_msg: str = "") -> None:
    """
    Emergency handler for EMFILE / ENFILE (Errno 24: Too many open files).
    Prevents tight loop spin, runs garbage collection, and throttles log spam.
    """
    global _LAST_EMFILE_WARNING
    now = time.time()

    # Determine if error is EMFILE (24) or ENFILE (23) or contains text match
    is_emfile = False
    if isinstance(exc, OSError):
        if exc.errno in (errno.EMFILE, errno.ENFILE):
            is_emfile = True
    if not is_emfile and any(msg in str(exc) for msg in ("Too many open files", "out of system resource", "Errno 24")):
        is_emfile = True

    if is_emfile:
        if now - _LAST_EMFILE_WARNING > _EMFILE_WARNING_INTERVAL:
            _LAST_EMFILE_WARNING = now
            logger.critical(
                "🚨 [ResourceLimits] EMFILE/Errno 24: Too many open files! %s. "
                "Triggering emergency GC and connection throttling.",
                context_msg or str(exc)
            )

        # 1. Force emergency garbage collection to reclaim unreferenced sockets/files
        gc.collect()

        # 2. Brief sleep (50ms) to throttle accept spin loop and let TIME_WAIT sockets drain
        time.sleep(0.05)
