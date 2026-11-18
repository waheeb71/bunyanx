"""
bunyanx NGFW — DB Rule Repository
======================================
SQLAlchemy adapter for FirewallOptimizer.
Reads live firewall rules from the SQLite database instead of
the static DictRuleRepository (which only worked with local dicts).

Usage:
    from system.firewall.db_rule_repository import DBRuleRepository, DBTelemetrySource
    from system.firewall.optimizer import FirewallOptimizer

    repo = DBRuleRepository(db_manager)
    optimizer = FirewallOptimizer(repo)
    report = optimizer.analyze()
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List

from modules.firewall.engine.optimizer import (
    RuleRepository, TelemetrySource,
    FirewallRule as OptimizerRule, TelemetryLog,
)

logger = logging.getLogger(__name__)


class DBRuleRepository(RuleRepository):
    """
    Reads active firewall rules from the SQLite 'firewall_rules' table.
    Adapts the SQLAlchemy model to the optimizer's FirewallRule dataclass.
    """

    def __init__(self, db_manager):
        """
        Args:
            db_manager: DatabaseManager instance (system.database.database.DatabaseManager)
        """
        self._db = db_manager

    def get_all_rules(self) -> List[OptimizerRule]:
        try:
            from modules.firewall.models import FirewallRule as DBFirewallRule

            with self._db.session() as session:
                db_rules = (
                    session.query(DBFirewallRule)
                    .filter(DBFirewallRule.enabled == True)
                    .order_by(DBFirewallRule.priority.asc(), DBFirewallRule.id.asc())
                    .all()
                )

                rules = []
                for r in db_rules:
                    rules.append(OptimizerRule(
                        id=r.id,
                        name=r.name or f"Rule-{r.id}",
                        action=r.action.value,        # "ALLOW" | "DROP" | ...
                        source_ip=r.source_ip or "any",
                        dest_ip=r.destination_ip or "any",
                        protocol=r.protocol or "any",
                        dest_port=str(r.destination_port or "any"),
                        priority=r.priority or 100,
                        hit_count=getattr(r, "hit_count", 0) or 0,
                        enabled=r.enabled,
                        is_critical=getattr(r, "is_critical", False),
                        created_at=r.created_at or datetime.now(timezone.utc),
                    ))

                logger.info(f"[DBRuleRepository] Loaded {len(rules)} rules from DB")
                return rules

        except Exception as exc:
            logger.error(f"[DBRuleRepository] Failed to load rules: {exc}")
            return []


class DBTelemetrySource(TelemetrySource):
    """
    Reads audit/telemetry logs from the DB to determine which rules
    have been recently triggered (used by detect_unused_rules).

    Falls back to empty list gracefully when the table doesn't exist yet.
    """

    def __init__(self, db_manager):
        self._db = db_manager

    def get_logs_since(self, since: datetime) -> List[TelemetryLog]:
        try:
            # Try reading from firewall_audit_logs table if it exists.
            # Graceful fallback if the table hasn't been created yet.
            with self._db.session() as session:
                from sqlalchemy import text
                result = session.execute(
                    text(
                        "SELECT rule_id, timestamp, decision, src_ip, dst_ip "
                        "FROM firewall_audit_logs "
                        "WHERE timestamp >= :since "
                        "ORDER BY timestamp DESC "
                        "LIMIT 50000"
                    ),
                    {"since": since.isoformat()}
                )
                logs = []
                for row in result:
                    try:
                        ts = datetime.fromisoformat(str(row[1]))
                    except Exception:
                        ts = datetime.now(timezone.utc)
                    logs.append(TelemetryLog(
                        rule_id=row[0],
                        timestamp=ts,
                        decision=row[2] or "allow",
                        src_ip=row[3] or "",
                        dst_ip=row[4] or "",
                    ))
                logger.debug(f"[DBTelemetrySource] Retrieved {len(logs)} telemetry entries")
                return logs

        except Exception as exc:
            # Table likely doesn't exist yet — return empty (no telemetry = conservative)
            logger.debug(f"[DBTelemetrySource] Telemetry unavailable ({exc}) — using empty source")
            return []


def create_db_optimizer(db_manager):
    """
    Factory: build a FirewallOptimizer backed by the live SQLite database.

    Usage:
        optimizer = create_db_optimizer(app.db)
        report = optimizer.analyze()
    """
    from modules.firewall.engine.optimizer import FirewallOptimizer
    repo = DBRuleRepository(db_manager)
    telemetry = DBTelemetrySource(db_manager)
    return FirewallOptimizer(repo, telemetry)
