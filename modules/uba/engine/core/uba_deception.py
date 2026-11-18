"""
Enterprise bunyanx - UBA Intelligent Honeytoken Engine (Patent PoC)

This module generates contextual baits (Honeytokens) when a user's behavior 
exhibits high anomaly but hasn't reached an absolute blocking threshold.
If the user interacts with the generated bait, their suspicious intent
is proven with 100% confidence, leading to an immediate lockout.

MITRE ATT&CK Coverage:
  - T1071: Application Layer Protocol (Deception Layer)
  - T1078: Valid Accounts (Intent Verification)
  - T1567: Exfiltration Over Web Service (Bait Injection)
"""

import time
import logging
import uuid
import secrets
import string
from typing import Optional, Tuple
from system.core.deception.unified_engine import UnifiedDeceptionEngine

logger = logging.getLogger(__name__)

class UBAHoneytokenEngine:
    """
    UBA Facade for the central Unified Causal Deception Engine.
    Implemented as a Singleton to match earlier UBA architecture.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(UBAHoneytokenEngine, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, ttl_seconds: int = 3600):
        if getattr(self, '_initialized', False):
            return
        self.unified_engine = UnifiedDeceptionEngine(ttl_seconds=ttl_seconds)
        self._initialized = True
        logger.info("UBA Intelligent Honeytoken wrapper initialized")

    def generate_contextual_bait(
        self,
        username: str,
        source_ip: str,
        target_service: str,
        anomaly_score: float = 0.6,
    ) -> dict:
        """
        Generates a bait response by delegating to the unified engine.
        
        Args:
            anomaly_score: The actual anomaly score from the UBA profiler
                           that triggered the deception response.
        """
        trap_id, bait_response = self.unified_engine.generate_trap(
            module="uba",
            username=username,
            source_ip=source_ip,
            target_service=target_service,
            anomaly_score=anomaly_score,
        )
        return bait_response

    def verify_honeytoken_access(self, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an incoming payload contains any generated unified honeytoken.
        Returns: (is_honeytoken_accessed: bool, evidence_message: str)
        """
        intent_proven, evidence, threat_score = self.unified_engine.verify_intent(
            payload_or_content=payload,
            reporting_module="uba"
        )
        
        if intent_proven:
            return True, evidence
            
        return False, None


def _generate_fake_key(prefix: str = "AKIA", length: int = 20) -> str:
    """Generate a random fake AWS-style key for deception (never real)."""
    chars = string.ascii_uppercase + string.digits
    return prefix + ''.join(secrets.choice(chars) for _ in range(length - len(prefix)))


def _generate_fake_secret(length: int = 40) -> str:
    """Generate a random fake secret key for deception (never real)."""
    chars = string.ascii_letters + string.digits + '/+'
    return ''.join(secrets.choice(chars) for _ in range(length))


import threading

class GenerativeLabyrinthEngine:
    """
    AP-GDR Research Concept (Mid-Session Decoy Routing).
    Instead of static honeytokens, this engine dynamically generates 
    virtual filesystem responses and fake data based on what the attacker requests.
    
    MITRE ATT&CK:
      - T1036: Masquerading (Reverse — system masquerades as target)
      - T1583: Acquire Infrastructure (Decoy Infrastructure)
    """
    def __init__(self):
        self._active_labyrinths = {}
        self._lock = threading.RLock()
        
    def start_labyrinth_session(self, username: str, source_ip: str) -> str:
        """Create a new ephemeral reality for the attacker."""
        with self._lock:
            session_id = str(uuid.uuid4())
            self._active_labyrinths[session_id] = {
                "username": username,
                "ip": source_ip,
                "virtual_cwd": "/",
                "hallucinated_files": [],
                "interaction_count": 0,
                "created_at": time.time(),
                "last_active": time.time(),
            }
            logger.warning(
                "[AP-GDR] Generated Mid-Session Labyrinth %s for %s (%s)",
                session_id, username, source_ip,
            )
            return session_id
        
    def handle_attacker_request(self, session_id: str, command: str) -> str:
        """
        Takes the attacker's raw command (e.g., 'ls /finance') and hallucinates
        a response on the fly to tarpit the attacker.
        (In a full implementation, an LLM handles the prompt. Simulated here.)
        """
        with self._lock:
            if session_id not in self._active_labyrinths:
                return "Connection reset by peer."
            
            lab = self._active_labyrinths[session_id]
            lab["interaction_count"] += 1
            lab["last_active"] = time.time()
                
            cmd = command.strip().lower()
            if "finance" in cmd or "ls" in cmd or "dir" in cmd:
                fake_file = f"Q4_Layoffs_{secrets.token_hex(4)}.xlsx"
                response = f"{fake_file}\nMaster_Keys.pem\nPasswords_{secrets.token_hex(2)}.txt\n"
                lab["hallucinated_files"].append(fake_file)
                return response
                
            if "cat" in cmd or "type" in cmd:
                # Generate unique fake credentials per session
                fake_access = _generate_fake_key()
                fake_secret = _generate_fake_secret()
                return f"aws_access_key_id = {fake_access}\naws_secret_access_key = {fake_secret}"
                
            return "Command executed successfully."

    def cleanup_session(self, session_id: str) -> Optional[dict]:
        """Remove a labyrinth session and return forensic evidence."""
        with self._lock:
            return self._active_labyrinths.pop(session_id, None)

    def prune_sessions(self, ttl_seconds: float = 3600.0) -> None:
        """Prune expired labyrinth sessions to prevent memory leaks."""
        with self._lock:
            now = time.time()
            expired = [
                sid for sid, data in self._active_labyrinths.items()
                if now - data.get("last_active", data["created_at"]) > ttl_seconds
            ]
            for sid in expired:
                self._active_labyrinths.pop(sid, None)
                logger.warning("[AP-GDR] Pruned expired Labyrinth session: %s", sid)
