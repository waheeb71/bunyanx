"""
Enterprise bunyanx — Network Operations Terminal API
======================================================
Provides real-time system and network telemetry for the SOC-grade
Network Operations Terminal (NOps) dashboard page.

Endpoints:
  GET  /api/v1/netops/connections   — Live TCP/UDP connections (psutil)
  GET  /api/v1/netops/ports         — Listening ports
  GET  /api/v1/netops/sockets       — Socket status summary
  GET  /api/v1/netops/eventbus      — Event bus topic statistics
  GET  /api/v1/netops/modules       — Per-module circuit breaker health
  GET  /api/v1/netops/websockets    — Active WebSocket session count
"""
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Request, HTTPException

from api.core.auth import require_operator

router = APIRouter(prefix="/api/v1/netops", tags=["Network Operations Terminal"])
logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

from collections import namedtuple

Addr = namedtuple("Addr", ["ip", "port"])

class DummyEnum:
    def __init__(self, name):
        self.name = name
    def __str__(self):
        return self.name

class FakeConnection:
    def __init__(self, fd, family, type, laddr, raddr, status, pid):
        self.fd = fd
        self.family = family
        self.type = type
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid

def _parse_netstat_fallback() -> list:
    import subprocess
    import platform
    import re
    
    conns = []
    try:
        system = platform.system().lower()
        if system == "windows":
            # Run netstat -ano
            # Hide command window
            startupinfo = None
            if hasattr(subprocess, "STARTUPINFO"):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                check=True,
                startupinfo=startupinfo
            )
            lines = proc.stdout.splitlines()
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4 or parts[0].upper() not in ["TCP", "UDP"]:
                    continue
                
                proto = parts[0].upper()
                local_addr_str = parts[1]
                remote_addr_str = parts[2]
                
                if proto == "TCP":
                    state = parts[3]
                    pid_str = parts[4] if len(parts) > 4 else "0"
                else:
                    state = "NONE"
                    pid_str = parts[3] if len(parts) > 3 else "0"
                
                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0
                
                def parse_ip_port(addr_str):
                    if addr_str == "*:*" or addr_str == "0.0.0.0:0" or addr_str == "[::]:0":
                        return Addr("", 0)
                    
                    ipv6_match = re.match(r"^\[(.*)\]:(\d+)$", addr_str)
                    if ipv6_match:
                        return Addr(ipv6_match.group(1), int(ipv6_match.group(2)))
                    
                    if ":" in addr_str:
                        ip, port = addr_str.rsplit(":", 1)
                        try:
                            return Addr(ip, int(port))
                        except ValueError:
                            return Addr(ip, 0)
                    return Addr(addr_str, 0)
                
                laddr = parse_ip_port(local_addr_str)
                raddr = parse_ip_port(remote_addr_str)
                
                family = DummyEnum("AF_INET6") if (":" in laddr.ip or "[" in local_addr_str) else DummyEnum("AF_INET")
                sock_type = DummyEnum("SOCK_STREAM") if proto == "TCP" else DummyEnum("SOCK_DGRAM")
                
                status_map = {
                    "LISTENING": "LISTEN",
                    "ESTABLISHED": "ESTABLISHED",
                    "TIME_WAIT": "TIME_WAIT",
                    "CLOSE_WAIT": "CLOSE_WAIT",
                    "SYN_SENT": "SYN_SENT",
                    "SYN_RECEIVED": "SYN_RECV",
                    "FIN_WAIT_1": "FIN_WAIT1",
                    "FIN_WAIT_2": "FIN_WAIT2",
                    "CLOSED": "CLOSED",
                }
                mapped_state = status_map.get(state.upper(), state.upper())
                
                conns.append(FakeConnection(
                    fd=-1,
                    family=family,
                    type=sock_type,
                    laddr=laddr,
                    raddr=raddr,
                    status=mapped_state,
                    pid=pid
                ))
        elif system == "linux":
            proc = subprocess.run(["ss", "-tun"], capture_output=True, text=True)
            if proc.returncode == 0:
                lines = proc.stdout.splitlines()
                for line in lines[1:]:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue
                    proto = "TCP" if "tcp" in parts[0].lower() else "UDP"
                    state = parts[1].upper()
                    status_map = {
                        "LISTEN": "LISTEN",
                        "ESTAB": "ESTABLISHED",
                        "UNCONN": "NONE",
                        "TIME-WAIT": "TIME_WAIT",
                        "CLOSE-WAIT": "CLOSE_WAIT",
                    }
                    mapped_state = status_map.get(state, state)
                    
                    local_str = parts[4]
                    remote_str = parts[5]
                    
                    def parse_linux_ip_port(addr_str):
                        if ":" in addr_str:
                            ip, port = addr_str.rsplit(":", 1)
                            ip = ip.replace("[", "").replace("]", "")
                            try:
                                return Addr(ip, int(port))
                            except ValueError:
                                return Addr(ip, 0)
                        return Addr(addr_str, 0)
                    
                    laddr = parse_linux_ip_port(local_str)
                    raddr = parse_linux_ip_port(remote_str)
                    
                    family = DummyEnum("AF_INET6") if (":" in laddr.ip) else DummyEnum("AF_INET")
                    sock_type = DummyEnum("SOCK_STREAM") if proto == "TCP" else DummyEnum("SOCK_DGRAM")
                    
                    conns.append(FakeConnection(
                        fd=-1,
                        family=family,
                        type=sock_type,
                        laddr=laddr,
                        raddr=raddr,
                        status=mapped_state,
                        pid=0
                    ))
    except Exception as e:
        logger.warning(f"[NetOps] Fallback parsing error: {e}")
    return conns

def _safe_psutil_conns(kind: str = "inet") -> list:
    try:
        import psutil
        conns = psutil.net_connections(kind=kind)
        if not conns:
            return _parse_netstat_fallback()
        return conns
    except Exception as e:
        logger.info(f"[NetOps] psutil.net_connections failed: {e}. Trying fallback.")
        return _parse_netstat_fallback()


def _addr_str(addr) -> str:
    if not addr or not addr.ip:
        return ""
    return f"{addr.ip}:{addr.port}" if addr.port else addr.ip


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/connections")
async def live_connections(
    token: dict = Depends(require_operator),
    limit: int = 200,
):
    """
    Return live TCP/UDP connections from the OS network stack.
    Requires operator+ role.
    """
    conns = _safe_psutil_conns("inet")
    results = []
    for c in conns[:limit]:
        results.append({
            "fd":       c.fd,
            "family":   c.family.name if hasattr(c.family, "name") else str(c.family),
            "type":     c.type.name if hasattr(c.type, "name") else str(c.type),
            "local":    _addr_str(c.laddr),
            "remote":   _addr_str(c.raddr),
            "status":   c.status or "NONE",
            "pid":      c.pid,
        })
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total": len(conns),
        "shown": len(results),
        "connections": results,
    }


@router.get("/ports")
async def listening_ports(token: dict = Depends(require_operator)):
    """Return all listening (server) sockets on this host."""
    conns = _safe_psutil_conns("inet")
    ports = [
        {
            "local":  _addr_str(c.laddr),
            "family": c.family.name if hasattr(c.family, "name") else str(c.family),
            "type":   c.type.name if hasattr(c.type, "name") else str(c.type),
            "pid":    c.pid,
        }
        for c in conns
        if c.status == "LISTEN" or not c.raddr
    ]
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "listening_count": len(ports),
        "ports": ports,
    }


@router.get("/sockets")
async def socket_summary(token: dict = Depends(require_operator)):
    """Return aggregated socket status counts."""
    conns = _safe_psutil_conns("inet")
    summary: dict[str, int] = {}
    for c in conns:
        s = c.status or "NONE"
        summary[s] = summary.get(s, 0) + 1

    import psutil
    net_io = psutil.net_io_counters()
    return {
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "total_sockets":    len(conns),
        "by_status":        summary,
        "bytes_sent":       net_io.bytes_sent,
        "bytes_recv":       net_io.bytes_recv,
        "packets_sent":     net_io.packets_sent,
        "packets_recv":     net_io.packets_recv,
        "errin":            net_io.errin,
        "errout":           net_io.errout,
        "dropin":           net_io.dropin,
        "dropout":          net_io.dropout,
    }


@router.get("/eventbus")
async def eventbus_stats(token: dict = Depends(require_operator)):
    """Return event bus topic publish/subscribe statistics."""
    try:
        from system.events.bus import EventBus
        bus = EventBus._instance
        if not bus:
            return {"available": False, "reason": "EventBus not started"}

        backend = getattr(bus, "_backend", None)
        stats = {}
        if backend and hasattr(backend, "_stats"):
            stats = backend._stats
        elif backend and hasattr(backend, "_subscriptions"):
            # Memory backend: report subscriber counts per topic
            subs = getattr(backend, "_subscriptions", {})
            stats = {
                topic: {"subscriber_count": len(handlers)}
                for topic, handlers in subs.items()
            }

        return {
            "available":  True,
            "backend":    type(backend).__name__ if backend else "unknown",
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "topics":     stats,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.get("/modules")
async def modules_health(
    request: Request,
    token: dict = Depends(require_operator),
):
    """Return per-module circuit breaker state and statistics."""
    bunyanx = getattr(request.app.state, "bunyanx", None)
    if not bunyanx:
        return {"available": False, "modules": []}

    pipeline = getattr(bunyanx, "inspection_pipeline", None)
    if not pipeline:
        return {"available": False, "modules": [], "reason": "Pipeline not initialized"}

    modules = []
    try:
        for plugin in pipeline.plugins:
            cb_state = "UNKNOWN"
            cb = getattr(plugin, "circuit_breaker", None)
            if cb:
                cb_state = getattr(cb, "state", "UNKNOWN")
                if hasattr(cb_state, "name"):
                    cb_state = cb_state.name

            modules.append({
                "name":            plugin.name,
                "enabled":         plugin.enabled,
                "priority":        getattr(plugin, "priority", 50),
                "circuit_breaker": cb_state,
                "statistics":      plugin.get_statistics() if hasattr(plugin, "get_statistics") else {},
            })
    except Exception as e:
        logger.warning(f"[NetOps] Module health error: {e}")

    return {
        "available":  True,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "count":      len(modules),
        "modules":    modules,
    }


@router.get("/websockets")
async def websocket_sessions(token: dict = Depends(require_operator)):
    """Return the count and metadata of active WebSocket connections."""
    try:
        from api.websocket.manager import manager
        stats = manager.get_stats()
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **stats,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}
