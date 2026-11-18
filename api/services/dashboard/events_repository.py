import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import aiosqlite

logger = logging.getLogger(__name__)


def get_events_db_path() -> str:
    """Resolves the absolute path to events.db."""
    project_root = Path(__file__).parent.parent.parent.parent
    db_path = str(project_root / "data" / "events.db")

    try:
        from modules.log_manager.engine.log_controller import LogControllerManager
        controller = LogControllerManager.get_instance()
        if controller and controller.event_db_path:
            db_path = controller.event_db_path
    except Exception:
        pass

    return os.path.abspath(db_path)


class EventsRepository:
    """Repository helper for querying security events database."""

    @staticmethod
    async def fetch_recent_events(limit: int = 100) -> List[Tuple]:
        """Fetches recent security events from events.db."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return []

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    "SELECT event_id, timestamp, src_ip, dst_ip, verdict, reason, ml_score "
                    "FROM events ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ) as cursor:
                    return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to query recent events: {e}")
            return []

    @staticmethod
    async def fetch_all_event_stats_rows() -> List[Tuple]:
        """Fetches raw rows required for globe stats calculations."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return []

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    "SELECT src_ip, verdict, reason, ml_score, timestamp FROM events"
                ) as cursor:
                    return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to query event stats rows: {e}")
            return []

    @staticmethod
    async def fetch_traffic_interval(start_iso: str, end_iso: str) -> Tuple[int, int]:
        """Fetches event counts for a given time window (reqs=all events, blocks=blocked verdicts)."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return 0, 0

        try:
            async with aiosqlite.connect(db_path) as db:
                # Total events in window → used as requests/s proxy
                async with db.execute(
                    "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?",
                    (start_iso, end_iso),
                ) as cursor:
                    row = await cursor.fetchone()
                    total = int(row[0]) if row and row[0] is not None else 0

                # Blocked/dropped events → used as blocks proxy
                async with db.execute(
                    "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? "
                    "AND verdict IN ('drop', 'block', 'quarantine', 'deny')",
                    (start_iso, end_iso),
                ) as cursor:
                    row = await cursor.fetchone()
                    blocked = int(row[0]) if row and row[0] is not None else 0

                return total, blocked
        except Exception:
            pass
        return 0, 0

    @staticmethod
    async def fetch_kpi_counts() -> Dict[str, int]:
        """Queries events.db for KPI alert counts and unique network assets/endpoints."""
        db_path = get_events_db_path()
        counts = {
            "total_alerts": 0,
            "critical_alerts": 0,
            "assets_monitored": 0,
            "endpoints_connected": 0,
        }

        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return counts

        try:
            async with aiosqlite.connect(db_path) as db:
                # Total alerts
                async with db.execute("SELECT COUNT(*) FROM events") as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        counts["total_alerts"] = row[0]

                # Critical alerts
                async with db.execute(
                    "SELECT COUNT(*) FROM events WHERE verdict IN ('drop', 'block', 'quarantine') "
                    "OR reason LIKE '%SQL%' OR reason LIKE '%score=0.8%' OR reason LIKE '%score=0.9%' "
                    "OR reason LIKE '%anomaly%'"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        counts["critical_alerts"] = row[0]

                # Assets monitored (unique destination IPs)
                async with db.execute(
                    "SELECT COUNT(DISTINCT dst_ip) FROM events WHERE dst_ip IS NOT NULL AND dst_ip != ''"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        counts["assets_monitored"] = row[0]

                # Endpoints connected (unique source IPs)
                async with db.execute(
                    "SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip IS NOT NULL AND src_ip != ''"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        counts["endpoints_connected"] = row[0]

        except Exception as e:
            logger.error(f"Failed to fetch KPI counts from events.db: {e}")

        return counts

    @staticmethod
    async def fetch_map_stats() -> Dict[str, Any]:
        """Queries events.db for map stats overlay metrics."""
        db_path = get_events_db_path()
        res = {
            "attacks_today": 0,
            "targeted_countries": 0,
            "active_attacks": 0,
            "data_exfil_tb": 0.0,
        }

        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return res

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute("SELECT COUNT(*) FROM events") as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        res["attacks_today"] = row[0]

                try:
                    async with db.execute(
                        "SELECT COUNT(DISTINCT country) FROM events WHERE country IS NOT NULL AND country != ''"
                    ) as cursor:
                        row = await cursor.fetchone()
                        if row and row[0]:
                            res["targeted_countries"] = row[0]
                except Exception:
                    pass

                try:
                    async with db.execute(
                        "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-5 minutes')"
                    ) as cursor:
                        row = await cursor.fetchone()
                        if row and row[0]:
                            res["active_attacks"] = row[0]
                except Exception:
                    pass

                async with db.execute(
                    "SELECT SUM(bytes) FROM events WHERE verdict IN ('drop', 'block')"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        res["data_exfil_tb"] = round(row[0] / (1024 ** 3), 2)

        except Exception as e:
            logger.error(f"Failed to fetch map stats from events.db: {e}")

        return res

    @staticmethod
    async def fetch_severity_rows() -> List[Tuple]:
        """Fetches verdict, reason, and ml_score columns for severity breakdown."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return []

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute("SELECT verdict, reason, ml_score FROM events") as cursor:
                    return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch severity rows: {e}")
            return []

    @staticmethod
    async def fetch_hourly_trends() -> List[Tuple]:
        """Fetches hourly alert counts from events.db."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return []

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    "SELECT strftime('%H', timestamp) as hr, COUNT(*) as cnt "
                    "FROM events "
                    "GROUP BY hr "
                    "ORDER BY hr"
                ) as cursor:
                    return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch hourly trends: {e}")
            return []

    @staticmethod
    async def fetch_top_services() -> List[Tuple]:
        """Fetches top targeted destination ports."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return []

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    "SELECT dst_port, COUNT(*) as cnt "
                    "FROM events "
                    "WHERE dst_port IS NOT NULL "
                    "GROUP BY dst_port "
                    "ORDER BY cnt DESC"
                ) as cursor:
                    return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to fetch top services: {e}")
            return []
