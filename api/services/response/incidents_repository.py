import os
import logging
import datetime as dt
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import aiosqlite
from sqlalchemy.future import select
from sqlalchemy import func

from system.database.database import Incident, AuditLog, SecurityEvent

logger = logging.getLogger(__name__)


def get_events_db_path() -> str:
    """Resolves absolute path to events.db."""
    project_root = Path(__file__).parent.parent.parent.parent
    return str(project_root / "data" / "events.db")


class IncidentsRepository:
    """Async repository for security incidents, audit logs, and events telemetry."""

    @staticmethod
    async def fetch_all_incidents(session) -> List[Incident]:
        """Fetches all logged security incidents ordered by timestamp descending."""
        result = await session.execute(
            select(Incident).order_by(Incident.timestamp.desc())
        )
        incidents = result.scalars().all()

        if not incidents:
            await IncidentsRepository.sync_incidents_from_events(session)
            result = await session.execute(
                select(Incident).order_by(Incident.timestamp.desc())
            )
            incidents = result.scalars().all()

        return incidents

    @staticmethod
    async def sync_incidents_from_events(session):
        """Generates authentic Incident records from real events.db security logs if Incident table is empty."""
        db_path = get_events_db_path()
        if not (os.path.exists(db_path) and os.path.getsize(db_path) > 0):
            return

        try:
            async with aiosqlite.connect(db_path) as db:
                async with db.execute(
                    "SELECT event_id, timestamp, src_ip, dst_ip, verdict, reason, ml_score "
                    "FROM events WHERE verdict IN ('drop', 'block', 'quarantine') "
                    "OR reason LIKE '%SQL%' OR reason LIKE '%RCE%' OR reason LIKE '%anomaly%' "
                    "OR ml_score >= 0.5 ORDER BY timestamp DESC LIMIT 30"
                ) as cursor:
                    rows = await cursor.fetchall()
                    if not rows:
                        return

                    grouped = {}
                    for r in rows:
                        ev_id, ts, src_ip, dst_ip, verdict, reason, ml_score = r
                        src_ip = src_ip or "0.0.0.0"
                        dst_ip = dst_ip or "10.0.0.1"
                        reason_str = (reason or "Security Violation").strip()
                        verdict = (verdict or "block").lower()

                        mod = "ids_ips"
                        r_lower = reason_str.lower()
                        if "waf" in r_lower or "sql" in r_lower or "xss" in r_lower or "rce" in r_lower:
                            mod = "waf"
                        elif "malware" in r_lower or "virus" in r_lower:
                            mod = "malware_av"
                        elif "dlp" in r_lower:
                            mod = "dlp"
                        elif "dns" in r_lower:
                            mod = "dns"
                        elif "uba" in r_lower or "user" in r_lower:
                            mod = "uba"

                        sev = "medium"
                        if ml_score is not None:
                            sev = "critical" if ml_score >= 0.8 else "high" if ml_score >= 0.5 else "medium"
                        elif verdict in ["drop", "block"] or "sql" in r_lower or "rce" in r_lower:
                            sev = "critical"

                        key = f"{src_ip}_{mod}"
                        if key not in grouped:
                            grouped[key] = {
                                "timestamp": ts,
                                "title": f"{mod.upper()}: {reason_str}",
                                "severity": sev,
                                "status": "open" if verdict in ["drop", "block"] else "investigating",
                                "source_ip": src_ip,
                                "destination_ip": dst_ip,
                                "module": mod,
                                "events_count": 1,
                                "description": f"Real threat event flagged from {src_ip} targeting {dst_ip} ({reason_str}).",
                            }
                        else:
                            grouped[key]["events_count"] += 1

                    for inc_data in grouped.values():
                        dt_obj = None
                        if inc_data["timestamp"]:
                            try:
                                dt_obj = dt.datetime.fromisoformat(inc_data["timestamp"].replace("Z", ""))
                            except Exception:
                                pass
                        if not dt_obj:
                            dt_obj = dt.datetime.utcnow()

                        session.add(
                            Incident(
                                timestamp=dt_obj,
                                title=inc_data["title"],
                                severity=inc_data["severity"],
                                status=inc_data["status"],
                                source_ip=inc_data["source_ip"],
                                destination_ip=inc_data["destination_ip"],
                                module=inc_data["module"],
                                events_count=inc_data["events_count"],
                                description=inc_data["description"],
                            )
                        )

                    await session.commit()
        except Exception as e:
            logger.error(f"Failed to sync real incidents from events.db: {e}")

    @staticmethod
    async def get_incident_by_id(session, inc_id: int) -> Optional[Incident]:
        """Fetches a single incident by integer ID."""
        result = await session.execute(
            select(Incident).filter(Incident.id == inc_id)
        )
        return result.scalars().first()

    @staticmethod
    async def fetch_audit_close_times(session, incident_ids: List[str]) -> Dict[str, str]:
        """Batch fetches audit logs for closed incidents to calculate closed_at timestamps."""
        close_times = {}
        if not incident_ids:
            return close_times

        try:
            audit_result = await session.execute(
                select(AuditLog).filter(
                    AuditLog.resource.in_([f"incident/{iid}" for iid in incident_ids]),
                    AuditLog.action == "update_incident_status",
                )
            )
            audits = audit_result.scalars().all()
            for audit in audits:
                if audit.details and audit.details.get("status") == "closed":
                    iid = audit.resource.split("/")[-1]
                    close_times[iid] = audit.timestamp.isoformat() + "Z"
        except Exception as e:
            logger.debug(f"Failed to fetch audit close times: {e}")

        return close_times

    @staticmethod
    async def fetch_associated_security_events(session, source_ip: str, limit: int = 10) -> List[SecurityEvent]:
        """Fetches associated SecurityEvents for a given source IP."""
        if not source_ip:
            return []
        try:
            evt_result = await session.execute(
                select(SecurityEvent)
                .filter(SecurityEvent.source_ip == source_ip)
                .order_by(SecurityEvent.timestamp.desc())
                .limit(limit)
            )
            return evt_result.scalars().all()
        except Exception as e:
            logger.debug(f"Failed to fetch associated security events: {e}")
            return []

    @staticmethod
    async def fetch_incident_audits(session, incident_id: str) -> List[AuditLog]:
        """Fetches AuditLogs associated with a specific incident ID."""
        try:
            audit_result = await session.execute(
                select(AuditLog)
                .filter(AuditLog.resource == f"incident/{incident_id}")
                .order_by(AuditLog.timestamp.desc())
            )
            return audit_result.scalars().all()
        except Exception as e:
            logger.debug(f"Failed to fetch incident audit logs: {e}")
            return []

    @staticmethod
    async def record_audit_log(session, username: str, action: str, resource: str, details: dict, ip_address: str = "127.0.0.1"):
        """Records an audit log entry."""
        try:
            session.add(
                AuditLog(
                    username=username,
                    action=action,
                    resource=resource,
                    details=details,
                    ip_address=ip_address,
                )
            )
            await session.commit()
        except Exception as e:
            logger.debug(f"AuditLog insertion skipped: {e}")
