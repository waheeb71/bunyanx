import asyncio
import time
import logging
import threading
import ipaddress
from typing import Dict, Optional

logger = logging.getLogger(__name__)

import enum

class TCPState(str, enum.Enum):
    NEW = "NEW"                 # First SYN seen
    SYN_RECV = "SYN_RECV"       # SYN-ACK seen (Server replied)
    ESTABLISHED = "ESTABLISHED" # ACK seen, full duplex
    FIN_WAIT = "FIN_WAIT"       # One side sent FIN
    TIME_WAIT = "TIME_WAIT"     # Both sides sent FIN
    CLOSE = "CLOSE"             # RST or Timeout

class StateTracker:
    """
    Hardware-Grade State Tracker
    Uses integer tuple hashing for ultra-low latency connection lookups.
    Implements a formal TCP state machine lifecycle.

    Thread Safety: All state_table access is protected by an RLock
    to prevent corruption under concurrent inspection workers.
    """
    def __init__(self, timeout_seconds: int = 300, tcp_timeout: int = 3600, max_capacity: int = 100000):
        self.udp_timeout = timeout_seconds
        self.tcp_timeout = tcp_timeout
        self.short_timeout = 5 # For RST or TIME_WAIT
        self.max_capacity = max_capacity
        
        # In-memory fast state table: int_key -> {state, last_seen, is_tcp}
        self.state_table: Dict[int, dict] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        # Thread safety: protects all state_table reads and writes
        self._lock = threading.RLock()

    def get_or_update_state(
        self, src_ip: str, src_port: int,
        dst_ip: str, dst_port: int, proto: str,
        tcp_flags: str = ""
    ) -> str:
        """
        Retrieves or advances connection state based on TCP flags if provided.
        tcp_flags expects simple string: 'S' (SYN), 'SA' (SYN-ACK), 'F' (FIN), 'R' (RST), 'A' (ACK)
        """
        is_tcp = (proto.upper() == "TCP")
        key = self._fast_hash_key(src_ip, src_port, dst_ip, dst_port, proto)
        now = time.time()

        with self._lock:
            if key in self.state_table:
                conn = self.state_table.pop(key)  # Pop and reinsert for LRU order
                self.state_table[key] = conn
                
                # 1. Handle timeouts
                timeout = self._get_timeout_for_state(conn)
                if now - conn["last_seen"] > timeout:
                    return self._init_new_state_locked(key, now, is_tcp, tcp_flags)
                
                # 2. Advance TCP Data Machine
                conn["last_seen"] = now
                if is_tcp and tcp_flags:
                    self._advance_tcp_state(conn, tcp_flags)
                    return conn["state"]
                    
                # Generic advancement (UDP/ICMP or unknown TCP defaults to ESTABLISHED once seen twice)
                if conn["state"] == TCPState.NEW:
                    conn["state"] = TCPState.ESTABLISHED
                    
                return conn["state"]

            # New Connection
            return self._init_new_state_locked(key, now, is_tcp, tcp_flags)

    def _init_new_state_locked(self, key: int, now: float, is_tcp: bool, flags: str) -> str:
        """Initialize a new state entry. MUST be called with self._lock held."""
        # LRU Eviction if capacity is exceeded
        if len(self.state_table) >= self.max_capacity:
            try:
                # Evict oldest (first item in the dict)
                oldest_key = next(iter(self.state_table))
                del self.state_table[oldest_key]
            except StopIteration:
                pass
                
        state = TCPState.NEW
        # If strict TCP is enforced, we technically should only allow 'S' (SYN) here.
        # Tolerate mid-stream captures as ESTABLISHED or NEW.
        flags = flags.upper()
        if is_tcp and "R" in flags:
            state = TCPState.CLOSE
        elif is_tcp and "F" in flags:
            state = TCPState.FIN_WAIT
            
        self.state_table[key] = {
            "state": state,
            "last_seen": now,
            "is_tcp": is_tcp
        }
        return state

    def _advance_tcp_state(self, conn: dict, flags: str):
        flags = flags.upper()
        current = conn["state"]
        prev_state = current
        
        if "R" in flags: # RST kills it instantly
            conn["state"] = TCPState.CLOSE
        elif current == TCPState.NEW:
            if "S" in flags and "A" in flags:
                conn["state"] = TCPState.SYN_RECV
            elif "A" in flags:
                conn["state"] = TCPState.ESTABLISHED
        elif current == TCPState.SYN_RECV:
            if "A" in flags:
                conn["state"] = TCPState.ESTABLISHED
        elif current == TCPState.ESTABLISHED:
            if "F" in flags:
                conn["state"] = TCPState.FIN_WAIT
        elif current == TCPState.FIN_WAIT:
            if "F" in flags:
                conn["state"] = TCPState.TIME_WAIT

        # L1: Log state transitions for security analysis and AI telemetry
        if conn["state"] != prev_state:
            logger.debug("TCP state transition: %s -> %s (flags=%s)", prev_state, conn["state"], flags)

    def _get_timeout_for_state(self, conn: dict) -> int:
        if not conn["is_tcp"]:
            return self.udp_timeout
        state = conn["state"]
        if state == TCPState.ESTABLISHED:
            return self.tcp_timeout
        elif state in (TCPState.CLOSE, TCPState.TIME_WAIT):
            return self.short_timeout
        # Intermediary TCP states (SYN_RECV, FIN_WAIT)
        return 60 

    def cleanup(self) -> int:
        now = time.time()
        with self._lock:
            expired = []
            for k, v in self.state_table.items():
                if now - v["last_seen"] > self._get_timeout_for_state(v):
                    expired.append(k)
                    
            for k in expired:
                del self.state_table[k]
            
        if expired:
            logger.debug(f"StateTracker cleanup: removed {len(expired)} fast-path entries.")
        return len(expired)

    def get_stats(self) -> dict:
        with self._lock:
            count = len(self.state_table)
        return {
            "active_connections": count,
            "tcp_timeout": self.tcp_timeout,
            "udp_timeout": self.udp_timeout
        }

    async def start_cleanup_task(self, interval_s: int = 15) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            return
        async def _loop():
            logger.debug("StateTracker: hardware-grade background cleanup started")
            while True:
                await asyncio.sleep(interval_s)
                try:
                    self.cleanup()
                except Exception as exc:
                    logger.error(f"StateTracker cleanup error: {exc}")
        self._cleanup_task = asyncio.create_task(_loop())

    def stop_cleanup_task(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()

    @staticmethod
    def _fast_hash_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> int:
        """
        Uses pure C-level tuple hashing over integers.
        Bi-directional: A->B matches B->A.
        Handles domain names (non-IP dst) via stable string-based fallback.
        """
        try:
            s_int = int(ipaddress.ip_address(src_ip))
        except ValueError:
            s_int = None

        try:
            d_int = int(ipaddress.ip_address(dst_ip))
        except ValueError:
            d_int = None

        # FIX: If either address is a domain name (not a valid IP), use a
        # stable string-based hash. Previously this logged WARNING 160x/session
        # because transparent_proxy passes domain names as dst_ip for HTTP relay.
        if s_int is None or d_int is None:
            # Deterministic string hash — bidirectional via sorted tuple
            key = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])) + (proto.lower(),)
            return hash(key)

        # Fast lexicographic integer ordering to ensure bidirectional symmetry
        if s_int < d_int:
            return hash((s_int, src_port, d_int, dst_port, proto.lower()))
        elif s_int > d_int:
            return hash((d_int, dst_port, s_int, src_port, proto.lower()))
        else:
            if src_port < dst_port:
                return hash((s_int, src_port, d_int, dst_port, proto.lower()))
            return hash((d_int, dst_port, s_int, src_port, proto.lower()))


