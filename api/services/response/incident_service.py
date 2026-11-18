import logging
import datetime as dt
from typing import List, Dict, Any, Optional
from fastapi import Request, HTTPException
from sqlalchemy.future import select

from api.services.response.incidents_repository import IncidentsRepository

logger = logging.getLogger(__name__)

VALID_STATUSES = {"open", "investigating", "contained", "closed"}


def _parse_incident_id(incident_id: str) -> int:
    try:
        return int(str(incident_id).replace("INC-", "").strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")


def _get_sync_session():
    """Direct sync SQLAlchemy session as fallback when async engine is unavailable."""
    from system.database.database import SessionLocal
    return SessionLocal()


class IncidentService:
    """Service layer for security incident lifecycle management and timeline analysis."""

    @staticmethod
    def get_app(request: Request):
        """Returns bunyanx app instance, or None if not running."""
        if hasattr(request.app.state, "bunyanx") and request.app.state.bunyanx:
            return request.app.state.bunyanx
        return None

    # ------------------------------------------------------------------
    # list_incidents: tries async app.db.session(), falls back to sync DB
    # ------------------------------------------------------------------
    @classmethod
    async def list_incidents(cls, request: Request, token: dict) -> List[Dict[str, Any]]:
        app = cls.get_app(request)

        # ── Async path (engine running) ────────────────────────────────
        if app and hasattr(app, 'db') and hasattr(app.db, 'session'):
            try:
                async with app.db.session() as session:
                    incidents = await IncidentsRepository.fetch_all_incidents(session)
                    incident_ids = [f"INC-{inc.id:04d}" for inc in incidents if inc.status == "closed"]
                    close_times = await IncidentsRepository.fetch_audit_close_times(session, incident_ids)
                    return cls._build_list(incidents, close_times)
            except Exception as e:
                logger.warning(f"Async incidents fetch failed, using sync fallback: {e}")

        # ── Sync fallback path ─────────────────────────────────────────
        try:
            return await cls._list_incidents_sync()
        except Exception as e:
            logger.error(f"Sync incidents fallback also failed: {e}")
            return []

    @staticmethod
    def _build_list(incidents, close_times) -> List[Dict]:
        list_data = []
        for inc in incidents:
            d = inc.to_dict()
            if inc.status == "closed":
                iid = f"INC-{inc.id:04d}"
                if iid in close_times:
                    d["closed_at"] = close_times[iid]
                else:
                    fallback_time = (inc.timestamp or dt.datetime.utcnow()) + dt.timedelta(minutes=5)
                    d["closed_at"] = fallback_time.isoformat() + "Z"
            list_data.append(d)
        return list_data

    @staticmethod
    async def _list_incidents_sync() -> List[Dict]:
        """Sync DB fallback: reads Incident table, generates from SecurityEvent if empty."""
        from system.database.database import Incident, SecurityEvent
        import asyncio

        def _read():
            db = _get_sync_session()
            try:
                incidents = db.query(Incident).order_by(Incident.timestamp.desc()).limit(200).all()

                # If no Incident rows, synthesize from SecurityEvent
                if not incidents:
                    sev_events = (
                        db.query(SecurityEvent)
                        .filter(SecurityEvent.severity.in_(["critical", "high"]))
                        .order_by(SecurityEvent.timestamp.desc())
                        .limit(50)
                        .all()
                    )
                    # Fallback 2: just grab any recent events
                    if not sev_events:
                        sev_events = (
                            db.query(SecurityEvent)
                            .order_by(SecurityEvent.timestamp.desc())
                            .limit(30)
                            .all()
                        )

                    grouped = {}
                    for evt in sev_events:
                        key = f"{evt.source_ip}_{evt.event_type}"
                        if key not in grouped:
                            desc = evt.description or evt.event_type or "Security Event"
                            r_lower = desc.lower()
                            mod = "ids_ips"
                            if "waf" in r_lower or "sql" in r_lower or "xss" in r_lower:
                                mod = "waf"
                            elif "malware" in r_lower or "virus" in r_lower:
                                mod = "malware_av"
                            elif "dns" in r_lower:
                                mod = "dns"
                            elif "uba" in r_lower or "user" in r_lower:
                                mod = "uba"
                            is_blocked = evt.action in ["BLOCK", "DROP", "block", "drop"]
                            status_str = "contained" if is_blocked else "open"
                            close_time = (evt.timestamp + dt.timedelta(minutes=2)).isoformat() + "Z" if (is_blocked and evt.timestamp) else None
                            grouped[key] = {
                                "id": f"SE-{evt.id}",
                                "title": f"{mod.upper()}: {desc[:80]}",
                                "severity": evt.severity or "medium",
                                "status": status_str,
                                "src_ip": evt.source_ip or "0.0.0.0",
                                "dst_ip": evt.destination_ip or "10.0.0.1",
                                "module": mod,
                                "ts": evt.timestamp.isoformat() + "Z" if evt.timestamp else None,
                                "closed_at": close_time,
                                "events_count": 1,
                                "description": desc,
                            }
                        else:
                            grouped[key]["events_count"] += 1
                    return list(grouped.values())

                # Map ORM Incident → dict
                result = []
                for inc in incidents:
                    d = inc.to_dict()
                    result.append(d)
                return result
            finally:
                db.close()

        return await asyncio.get_event_loop().run_in_executor(None, _read)

    # ------------------------------------------------------------------
    # get_incident_detail
    # ------------------------------------------------------------------
    @classmethod
    async def get_incident_detail(cls, request: Request, incident_id: str, token: dict) -> Dict[str, Any]:
        inc_id = _parse_incident_id(incident_id)
        app = cls.get_app(request)

        if app and hasattr(app, 'db') and hasattr(app.db, 'session'):
            try:
                async with app.db.session() as session:
                    return await cls._build_detail(session, inc_id, incident_id)
            except Exception as e:
                logger.warning(f"Async detail fetch failed, using sync fallback: {e}")

        # Sync fallback
        import asyncio
        from system.database.database import Incident as IncModel
        def _read_sync():
            db = _get_sync_session()
            try:
                inc = db.query(IncModel).filter(IncModel.id == inc_id).first()
                if not inc:
                    return None
                d = inc.to_dict()
                d["timeline"] = [{
                    "msg": f"تم الكشف عن حادثة بواسطة وحدة {inc.module}",
                    "t": inc.timestamp.isoformat() + "Z" if inc.timestamp else None,
                    "color": "#ff5f5f" if inc.severity == "critical" else "#ffc107",
                }]
                return d
            finally:
                db.close()

        detail = await asyncio.get_event_loop().run_in_executor(None, _read_sync)
        if not detail:
            raise HTTPException(status_code=404, detail="Incident not found")
        return detail

    @classmethod
    async def _build_detail(cls, session, inc_id: int, incident_id: str) -> Dict[str, Any]:
        incident = await IncidentsRepository.get_incident_by_id(session, inc_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        timeline = []
        timeline.append({
            "msg": f"تم الكشف عن حادثة بواسطة وحدة {incident.module}",
            "t": incident.timestamp.isoformat() + "Z" if incident.timestamp else None,
            "color": "#ff5f5f" if incident.severity == "critical" else "#ffc107" if incident.severity == "high" else "#00d4ff",
        })
        if incident.source_ip:
            sec_events = await IncidentsRepository.fetch_associated_security_events(session, incident.source_ip, limit=10)
            for evt in sec_events:
                timeline.append({
                    "msg": f"تنبيه: {evt.description or 'نشاط مشبوه'} ({evt.event_type})",
                    "t": evt.timestamp.isoformat() + "Z" if evt.timestamp else None,
                    "color": "#00d4ff",
                })
        audits = await IncidentsRepository.fetch_incident_audits(session, incident_id)
        for audit in audits:
            if audit.action == "update_incident_status":
                status_label = {"open": "مفتوح", "investigating": "قيد التحقيق", "contained": "محدود", "closed": "مغلق"}.get(
                    (audit.details or {}).get("status"), (audit.details or {}).get("status"))
                timeline.append({
                    "msg": f"قام المستخدم {audit.username} بتحديث الحالة إلى '{status_label}'",
                    "t": audit.timestamp.isoformat() + "Z" if audit.timestamp else None,
                    "color": "#28c76f",
                })
            elif audit.action == "incident_mitigation":
                timeline.append({
                    "msg": f"تم تنفيذ إجراء: {(audit.details or {}).get('label', (audit.details or {}).get('action'))} بواسطة {audit.username}",
                    "t": audit.timestamp.isoformat() + "Z" if audit.timestamp else None,
                    "color": "#e0e0e0",
                })
        timeline.sort(key=lambda x: x["t"] or "")
        inc_dict = incident.to_dict()
        inc_dict["timeline"] = timeline
        if incident.status == "closed":
            close_audit = next(
                (a for a in audits if a.action == "update_incident_status" and a.details and a.details.get("status") == "closed"), None)
            if close_audit:
                inc_dict["closed_at"] = close_audit.timestamp.isoformat() + "Z"
            else:
                inc_dict["closed_at"] = ((incident.timestamp or dt.datetime.utcnow()) + dt.timedelta(minutes=5)).isoformat() + "Z"
        return inc_dict

    # ------------------------------------------------------------------
    # update_incident_status
    # ------------------------------------------------------------------
    @classmethod
    async def update_incident_status(cls, request: Request, incident_id: str, status_val: str, token: dict) -> Dict[str, Any]:
        inc_id = _parse_incident_id(incident_id)
        if status_val not in VALID_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_val}")

        app = cls.get_app(request)
        username = token.get("sub", "unknown")
        client_host = getattr(getattr(request, "client", None), "host", None)
        ip_addr = client_host if isinstance(client_host, str) else "127.0.0.1"

        if app and hasattr(app, 'db') and hasattr(app.db, 'session'):
            try:
                async with app.db.session() as session:
                    incident = await IncidentsRepository.get_incident_by_id(session, inc_id)
                    if not incident:
                        raise HTTPException(status_code=404, detail="Incident not found")
                    incident.status = status_val
                    await IncidentsRepository.record_audit_log(
                        session=session, username=username,
                        action="update_incident_status",
                        resource=f"incident/{incident_id}",
                        details={"status": status_val, "title": incident.title},
                        ip_address=ip_addr,
                    )
                    await session.commit()
                    return {"status": "success", "incident": incident.to_dict()}
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(f"Async status update failed: {e}")

        # Sync fallback
        import asyncio
        from system.database.database import Incident as IncModel
        def _update_sync():
            db = _get_sync_session()
            try:
                inc = db.query(IncModel).filter(IncModel.id == inc_id).first()
                if not inc:
                    return None
                inc.status = status_val
                db.commit()
                db.refresh(inc)
                return inc.to_dict()
            finally:
                db.close()
        result = await asyncio.get_event_loop().run_in_executor(None, _update_sync)
        if not result:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {"status": "success", "incident": result}
