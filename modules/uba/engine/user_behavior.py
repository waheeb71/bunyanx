import logging
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class UserProfile:
    """Represents the baseline behavior sequence of a user."""
    user_id: int
    username: str
    normal_work_hours: tuple = (8, 18)  # 8 AM to 6 PM
    typical_ips: set = field(default_factory=set)
    typical_services: set = field(default_factory=set)
    avg_daily_bytes: float = 0.0
    baseline_risk_score: int = 10
    last_seen: float = 0.0
    
class UserBehaviorAnalytics:
    """
    Analyzes user activity against their established profile to detect
    insider threats or compromised accounts. Supports both simple in-memory
    tracking and delegating to the full database-backed UserProfiler.
    """
    
    def __init__(self, db_manager=None, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.db_manager = db_manager
        self.profiles: Dict[str, UserProfile] = {}
        self._profiler = None
        if db_manager:
            try:
                from modules.uba.engine.core.user_profiler import UserProfiler
                self._profiler = UserProfiler(db_manager=db_manager)
            except Exception as exc:
                self.logger.debug("Could not initialize UserProfiler in UserBehaviorAnalytics: %s", exc)

    def get_or_create_profile(self, username: str) -> UserProfile:
        """Fetch existing profile or create a default one."""
        if username not in self.profiles:
            user_id = 0
            self.profiles[username] = UserProfile(
                user_id=user_id,
                username=username
            )
        return self.profiles[username]
        
    def analyze_activity(
        self,
        username: str,
        source_ip: str,
        target_service: str,
        bytes_transferred: int
    ) -> float:
        """
        Analyze an event against the user's profile.
        Returns an anomaly score between 0.0 (normal) and 1.0 (highly anomalous).
        """
        if not username:
            return 0.0
            
        profile = self.get_or_create_profile(username)

        # Delegate to full database profiler if initialized
        if self._profiler:
            try:
                res = self._profiler.analyze(
                    username=username,
                    source_ip=source_ip,
                    target_service=target_service,
                    bytes_transferred=float(bytes_transferred),
                )
                profile.typical_ips.add(source_ip)
                profile.typical_services.add(target_service)
                profile.last_seen = time.time()
                return res.anomaly_score
            except Exception as exc:
                self.logger.warning("UserProfiler analysis failed in fallback: %s", exc)

        anomaly_score = 0.0
        
        # 1. Check Time Anomaly
        current_hour = time.localtime().tm_hour
        start, end = profile.normal_work_hours
        if current_hour < start or current_hour > end:
            anomaly_score += 0.3
            
        # 2. Check Location/IP Anomaly
        if profile.typical_ips and source_ip not in profile.typical_ips:
            anomaly_score += 0.4
            
        # 3. Check Service Anomaly
        if profile.typical_services and target_service not in profile.typical_services:
            anomaly_score += 0.2
            
        # Update profile learning
        profile.typical_ips.add(source_ip)
        profile.typical_services.add(target_service)
        profile.last_seen = time.time()
        
        # Prevent set from growing unbounded
        if len(profile.typical_ips) > 20:
            profile.typical_ips.pop()
        if len(profile.typical_services) > 50:
            profile.typical_services.pop()
            
        return min(anomaly_score, 1.0)

