"""
Time Schedules
Time-based policy enforcement.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import List
try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # Python 3.9+
except ImportError:
    ZoneInfo = None
    ZoneInfoNotFoundError = Exception

logger = logging.getLogger(__name__)


@dataclass
class Schedule:
    name: str
    days: List[str]  # Mon, Tue, Wed...
    start_time: time
    end_time: time
    timezone: str = "UTC"  # M5: Now actually used for timezone-aware comparison

    def _get_local_now(self) -> datetime:
        """Return current time localized to this schedule's timezone."""
        if ZoneInfo is not None and self.timezone and self.timezone.upper() != "UTC":
            try:
                tz = ZoneInfo(self.timezone)
                return datetime.now(tz)
            except (ZoneInfoNotFoundError, Exception):
                logger.warning(
                    "Schedule '%s': unknown timezone '%s', falling back to UTC",
                    self.name, self.timezone
                )
        return datetime.now(timezone.utc)

    def is_active(self, current_time: datetime = None) -> bool:
        """Check if the schedule is currently active, respecting the timezone field."""
        now = current_time or self._get_local_now()
        now_time = now.time().replace(tzinfo=None)
        width_day = now.strftime("%a")

        if self.start_time <= self.end_time:
            # Same-day window
            if width_day not in self.days:
                return False
            return self.start_time <= now_time <= self.end_time

        # Crosses midnight: late night of listed day OR early hours of next day
        if now_time >= self.start_time:
            return width_day in self.days

        # After midnight: compare against previous day
        prev_day = (now - timedelta(days=1)).strftime("%a")
        return prev_day in self.days and now_time <= self.end_time
