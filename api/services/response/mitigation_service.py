import logging
import inspect
from typing import Dict, Any, List, Optional
from fastapi import Request, HTTPException

from api.services.response.incidents_repository import IncidentsRepository

logger = logging.getLogger(__name__)


def _parse_duration(duration_str: Optional[str]) -> Optional[int]:
    """Parse human duration like '1h', '24h', '30m', 'permanent' to seconds."""
    if not duration_str:
        return None
    d = str(duration_str).lower().strip()
    if d in ("permanent", "perm", "none", "0", "infinity"):
        return None
    if d.endswith("h"):
        try:
            return int(float(d[:-1]) * 3600)
        except Exception:
            pass
    if d.endswith("m"):
        try:
            return int(float(d[:-1]) * 60)
        except Exception:
            pass
    if d.endswith("d"):
        try:
            return int(float(d[:-1]) * 86400)
        except Exception:
            pass
    try:
        return int(float(d))
    except Exception:
        return None


class MitigationService:
    """Service layer for response orchestrator, eBPF hardware mitigations, and incident actions."""

    @staticmethod
    def get_app(request: Request):
        if hasattr(request.app.state, "bunyanx") and request.app.state.bunyanx:
            return request.app.state.bunyanx
        import system.core.engine as _eng
        app_inst = getattr(_eng, '_app_instance', None) or getattr(_eng, '_app_singleton', None)
        if app_inst:
            return app_inst
        return None

    @classmethod
    async def list_blocks(cls, request: Request, token: dict) -> Dict[str, Any]:
        from modules.firewall.engine.ip_blocklist import get_blocklist_manager

        mgr = get_blocklist_manager()
        blocked_entries = mgr.get_all()

        app = cls.get_app(request)
        orch_ips = []
        if app and hasattr(app, "orchestrator") and hasattr(app.orchestrator, "active_mitigations"):
            orch_ips = list(app.orchestrator.active_mitigations.keys())

        entries_by_ip = {item["ip"]: item for item in blocked_entries if isinstance(item, dict) and "ip" in item}
        for ip in orch_ips:
            if ip not in entries_by_ip:
                entries_by_ip[ip] = {
                    "ip": ip,
                    "reason": "حظر فوري عبر تسريع النواة (eBPF XDP Hardware Block)",
                    "blocked_by": "ebpf_engine",
                    "source": "ebpf",
                    "expires_at": None,
                }

        active_blocks_list = list(entries_by_ip.values())

        return {
            "active_blocks": active_blocks_list,
            "blocked_ips": blocked_entries,
            "count": len(active_blocks_list),
            "stats": mgr.get_stats(),
        }

    @classmethod
    async def remove_block(cls, request: Request, ip: str, token: dict) -> Dict[str, Any]:
        from modules.firewall.engine.ip_blocklist import get_blocklist_manager

        mgr = get_blocklist_manager()
        try:
            mgr.unblock_ip_sync(ip)
        except Exception as e:
            logger.debug(f"[ResponseApi] unblock_ip fallback: {e}")

        app = cls.get_app(request)
        if app and hasattr(app, "orchestrator") and app.orchestrator:
            try:
                if hasattr(app.orchestrator, "active_mitigations") and ip in app.orchestrator.active_mitigations:
                    del app.orchestrator.active_mitigations[ip]
            except Exception:
                pass
            engine = getattr(app.orchestrator, "ebpf_engine", None)
            if engine and hasattr(engine, "remove_blocked_ip"):
                try:
                    await engine.remove_blocked_ip(ip)
                except Exception:
                    pass

        if app and hasattr(app, "db") and app.db:
            try:
                username = token.get("sub", "unknown")
                client_host = getattr(getattr(request, "client", None), "host", None)
                ip_addr = client_host if isinstance(client_host, str) else "127.0.0.1"

                async with app.db.session() as session:
                    await IncidentsRepository.record_audit_log(
                        session=session,
                        username=username,
                        action="remove_block",
                        resource=f"firewall/block/{ip}",
                        details={"ip": ip},
                        ip_address=ip_addr,
                    )
            except Exception as ae:
                logger.debug(f"[ResponseApi] Audit log error: {ae}")

        return {"status": "success", "message": f"IP {ip} unblocked successfully"}

    @classmethod
    async def trigger_incident_action(
        cls,
        request: Request,
        incident_id: str,
        action: str,
        label: str,
        token: dict,
        ip: Optional[str] = None,
        reason: Optional[str] = None,
        duration: Optional[str] = None,
    ) -> Dict[str, Any]:
        from modules.firewall.engine.ip_blocklist import get_blocklist_manager

        target_ip = ip
        app = cls.get_app(request)
        incident = None

        # 1. Try to load incident from DB if numeric and no explicit IP
        if not target_ip:
            try:
                inc_num_str = incident_id.upper().replace("INC-", "").replace("INC_", "").strip()
                if inc_num_str.isdigit():
                    inc_id = int(inc_num_str)
                    if app and hasattr(app, "db") and app.db:
                        async with app.db.session() as session:
                            incident = await IncidentsRepository.get_incident_by_id(session, inc_id)
                            if incident:
                                target_ip = incident.source_ip or incident.destination_ip
            except Exception as e:
                logger.debug(f"[MitigationService] Incident lookup error for {incident_id}: {e}")

        # 2. Check if target_ip is determined
        if not target_ip and action in ("block_ip", "isolate"):
            raise HTTPException(
                status_code=400,
                detail=f"Target IP address not specified and could not be determined from incident '{incident_id}'.",
            )

        duration_sec = _parse_duration(duration)
        reason_text = reason or label or f"Incident {incident_id} Mitigation: {action}"

        # 3. Block in IPBlocklistManager (nftables/iptables/eBPF/memory)
        if action == "block_ip" and target_ip:
            mgr = get_blocklist_manager()
            mgr.block_ip_sync(
                ip=target_ip,
                reason=reason_text,
                blocked_by="response_center",
                duration_seconds=duration_sec,
            )

        # 4. Trigger Response Orchestrator if available
        if app:
            orchestrator = getattr(app, "orchestrator", None)
            if orchestrator and hasattr(orchestrator, "execute_mitigation") and target_ip:
                try:
                    from system.response.orchestrator import ThreatContext, MitigationAction
                    mit_action = MitigationAction.BLOCK_IP if action == "block_ip" else MitigationAction.ISOLATE_HOST
                    context = ThreatContext(
                        target=target_ip,
                        action=mit_action,
                        confidence=1.0,
                        reason=reason_text,
                        metadata={"incident_id": incident_id, "duration": duration},
                    )
                    res = orchestrator.execute_mitigation(context)
                    if inspect.isawaitable(res):
                        await res
                except Exception as oe:
                    logger.warning(f"[MitigationService] Orchestrator execution error: {oe}")

        # 5. Record Audit Log if DB is accessible
        if app and hasattr(app, "db") and app.db:
            try:
                username = token.get("sub", "unknown")
                client_host = getattr(getattr(request, "client", None), "host", None)
                ip_addr = client_host if isinstance(client_host, str) else "127.0.0.1"

                async with app.db.session() as session:
                    await IncidentsRepository.record_audit_log(
                        session=session,
                        username=username,
                        action="incident_mitigation",
                        resource=f"incident/{incident_id}",
                        details={
                            "action": action,
                            "label": label,
                            "ip": target_ip,
                            "reason": reason_text,
                            "duration": duration,
                        },
                        ip_address=ip_addr,
                    )
            except Exception as ae:
                logger.debug(f"[MitigationService] Audit log skipped: {ae}")

        return {
            "status": "success",
            "message": f"Action '{label}' executed successfully on {target_ip or incident_id}.",
            "ip": target_ip,
            "incident_id": incident_id,
        }
