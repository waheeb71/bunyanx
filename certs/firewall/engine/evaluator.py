import logging
import time
import uuid
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from modules.firewall.models import FirewallRule as DBFirewallRule
from modules.firewall.policy.access_control.acl_engine import ACLEngine
from modules.firewall.policy.access_control.geoip import GeoIPFilter
from modules.firewall.policy.access_control.zones import ZoneManager
from modules.firewall.policy.app_control.engine import AppControlEngine
from modules.firewall.logging.async_logger import firewall_telemetry
from system.policy.schema import FirewallRule, AppRule, PolicyContext, Action, Protocol, TimeSchedule

logger = logging.getLogger(__name__)

class UnifiedEvaluator:
    """ Evaluates network traffic seamlessly against multiple firewall module policy engines """
    
    def __init__(self, db_session: Session, config: dict = None):
        self.db_session = db_session
        self._config = config or {}

        # ── Default policy from settings.yaml ─────────────────────────────────
        # default_policy: DROP  → block everything not explicitly allowed
        # default_policy: ALLOW → allow everything not explicitly blocked
        raw_default = self._config.get('default_policy', 'DROP').upper()
        default_action = Action.BLOCK if raw_default == 'DROP' else Action.ALLOW
        self.acl_engine = ACLEngine(default_action=default_action)
        self.app_engine = AppControlEngine()

        # ── Management port allowlist (always allowed, read from config) ───────
        self._mgmt_ports: set = set(
            int(p) for p in self._config.get('management_ports', [22, 443, 8888])
        )

        # ── Dev/proxy bypass ports (allowed when dev_ports_enabled=true) ───────
        _dev_enabled = self._config.get('dev_ports_enabled', True)
        self._dev_ports: set = (
            set(int(p) for p in self._config.get('dev_ports', [8000, 5173]))
            if _dev_enabled else set()
        )

        # All bypass ports combined (checked first, before GeoIP/ACL)
        self._bypass_ports: set = self._mgmt_ports | self._dev_ports

        # ZoneManager: maps interface names to logical zones (H5)
        zone_map = self._config.get('zones', {})
        self.zone_manager = ZoneManager(interface_map=zone_map)

        # Initialize GeoIP with paths and policies from firewall module config
        geoip_conf = self._config.get('geoip', {})
        self.geoip_filter = GeoIPFilter(
            db_path=geoip_conf.get('db_path'),
            asn_db_path=geoip_conf.get('asn_db_path'),
        )

        # Apply country/continent blacklists from config
        for code in geoip_conf.get('blocked_countries', []):
            self.geoip_filter.blacklist_country(code)
        for code in geoip_conf.get('whitelisted_countries', []):
            self.geoip_filter.whitelist_country(code)

        self._load_rules()

        
    def _parse_schedule(self, schedule_str: str) -> Optional[TimeSchedule]:
        if not schedule_str or schedule_str.lower() == "always":
            return None
        # Simplified: Assuming schedule string is comma separated: "Mon,Tue,09:00,17:00" for demo
        # In a real system, you'd look this up from a Schedules table.
        parts = schedule_str.split(',')
        if len(parts) >= 4:
            days = parts[:-2]
            return TimeSchedule(name="ParsedSchedule", days=days, start_time=parts[-2], end_time=parts[-1])
        return None

    def _load_rules(self):
        """ Loads rules from database and maps them to policy schemas """
        if not self.db_session:
            return
            
        try:
            db_rules = self.db_session.query(DBFirewallRule)\
                                      .filter(DBFirewallRule.enabled == True)\
                                      .order_by(DBFirewallRule.priority.asc(), DBFirewallRule.id.asc())\
                                      .all()
            
            acl_rules = []
            app_rules = []
            
            for dbr in db_rules:
                action_enum = Action.ALLOW
                if dbr.action.value == "DROP": action_enum = Action.BLOCK
                elif dbr.action.value == "REJECT": action_enum = Action.REJECT
                elif dbr.action.value == "LOG": action_enum = Action.LOG_ONLY
                
                proto = Protocol.ANY
                if (dbr.protocol or "any").lower() == "tcp": proto = Protocol.TCP
                elif (dbr.protocol or "any").lower() == "udp": proto = Protocol.UDP
                elif (dbr.protocol or "any").lower() == "icmp": proto = Protocol.ICMP
                
                # If app_category is strictly any, or we treat it as an L3/L4 rule primarily:
                if dbr.app_category == "any":
                    acl_rule = FirewallRule(
                        id=str(dbr.id),
                        name=dbr.name,
                        action=action_enum,
                        enabled=dbr.enabled,
                        priority=dbr.priority,
                        src_zone=dbr.zone_src,
                        dst_zone=dbr.zone_dst,
                        src_ip=dbr.source_ip,
                        dst_ip=dbr.destination_ip,
                        src_port=dbr.source_port,
                        dst_port=dbr.destination_port,
                        protocol=proto,
                        schedule=self._parse_schedule(dbr.schedule),
                        log=dbr.log_traffic
                    )
                    acl_rules.append(acl_rule)
                else:
                    # Treat as App Rule
                    app_rule = AppRule(
                        id=str(dbr.id),
                        name=dbr.name,
                        action=action_enum,
                        enabled=dbr.enabled,
                        priority=dbr.priority,
                        application=(dbr.file_type or "any").lower(), # Use file_type to specify app
                        category=dbr.app_category,
                        schedule=self._parse_schedule(dbr.schedule),
                        log=dbr.log_traffic
                    )
                    app_rules.append(app_rule)
            
            self.acl_engine.load_rules(acl_rules)
            self.app_engine.load_rules(app_rules)
            logger.debug(f"Loaded {len(acl_rules)} ACL rules and {len(app_rules)} App rules.")
            
        except Exception as e:
            logger.error(f"Failed to load firewall rules: {e}")
                
    def reload(self):
        """ Reload rules from database """
        self._load_rules()
        
    def evaluate(self, context_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a context dict against the unified rulebase (GeoIP -> ACL -> App Control).
        Uses Async Telemetry to ensure sub-millisecond return times.
        """
        # M8: Generate a unique flow ID to correlate all log entries for this packet
        flow_id = context_dict.get('flow_id') or str(uuid.uuid4())[:8]
        context_dict['flow_id'] = flow_id

        try:
            dst_port = context_dict.get('dst_port')

            # ── Step 0: Management / dev port bypass ────────────────────────────
            # These ports are ALWAYS allowed regardless of GeoIP / ACL rules.
            # Ports are configured in settings.yaml:
            #   management_ports: [22, 443, 8888]
            #   dev_ports:        [8000, 5173]  (only when dev_ports_enabled: true)
            if dst_port in self._bypass_ports:
                category = (
                    "Management Port"
                    if dst_port in self._mgmt_ports
                    else "Dev Port"
                )
                logger.debug(
                    "[Firewall] Bypass: port %s (%s) — src=%s",
                    dst_port, category, context_dict.get('src_ip')
                )
                return {
                    "action":    "ALLOW",
                    "confidence": 1.0,
                    "reason":    f"{category} bypass (port {dst_port})",
                    "rule_name": "Built-In System Rule",
                }

            # ── Step 1: GeoIP evaluation ────────────────────────────────────────
            src_ip = context_dict.get('src_ip', '')
            country_code = None
            if src_ip:
                is_blocked, reason = self.geoip_filter.is_blocked(src_ip)
                # M7: Enrich context with country info for telemetry
                geo_info = self.geoip_filter.lookup(src_ip)
                if geo_info:
                    country_code = geo_info.country_code
                    context_dict['country_code'] = country_code
                if is_blocked:
                    firewall_telemetry.log_verdict(context_dict, "DROP", reason, "GeoIP Block")
                    return {"action": "DROP", "confidence": 1.0, "reason": reason, "rule_name": "GeoIP Block"}

            # H5: Resolve zone from interface name via ZoneManager
            raw_interface = context_dict.get('interface', 'any')
            resolved_zone = self.zone_manager.get_zone(raw_interface)
            effective_interface = resolved_zone if resolved_zone != 'unknown' else raw_interface

            # Build PolicyContext
            context = PolicyContext(
                src_ip=src_ip,
                dst_ip=context_dict.get('dst_ip', ''),
                src_port=context_dict.get('src_port', 0),
                dst_port=context_dict.get('dst_port', 0),
                protocol=context_dict.get('protocol', 'any'),
                interface=effective_interface,
                app_id=context_dict.get('app_id')
            )

            # ── Step 2: Layer 3/4 ACL evaluation (Radix Fast-Path) ─────────────
            acl_action, matched_rule_id = self.acl_engine.evaluate_with_rule(context)
            if acl_action in [Action.BLOCK, Action.REJECT]:
                # H8: Increment hit_count for the matched rule in the DB
                self._increment_hit_count(matched_rule_id)

                # ── IMPORTANT: Only log to fast_logger for EXPLICIT rule matches ──
                # When matched_rule_id is None/"ACLEngine" it means NO explicit rule
                # matched — the default DROP policy fired.  The firewall_plugin layer
                # will override this to ALLOW for RFC-1918 sources, so logging BLOCK
                # here creates misleading telemetry (traffic shows as BLOCK but passes).
                # Only log when a real admin-configured rule actually matched.
                _is_explicit_rule = matched_rule_id and matched_rule_id not in ("ACLEngine", "Default-DROP", "")
                if _is_explicit_rule:
                    firewall_telemetry.log_verdict(
                        context_dict, acl_action.value.upper(),
                        "Matched ACL Fast-Path Rule", matched_rule_id
                    )
                else:
                    logger.debug(
                        "[Firewall] Default-DROP for %s→%s:%s (no explicit rule — "
                        "plugin will apply RFC-1918 bypass if applicable)",
                        context_dict.get("src_ip"), context_dict.get("dst_ip"),
                        context_dict.get("dst_port"),
                    )
                return {
                    "action":    acl_action.value.upper(),
                    "confidence": 1.0,
                    "reason":    "Matched ACL Rule" if _is_explicit_rule else "Default policy: DROP",
                    "rule_name": matched_rule_id or "ACLEngine",
                }

            # ── Step 3: Layer 7 App Control evaluation ─────────────────────────
            app_action = None
            if context.app_id or context_dict.get('domain'):
                if not context.app_id:
                    context.domain = context_dict['domain']
                app_action = self.app_engine.evaluate(context)
                if app_action in [Action.BLOCK, Action.REJECT]:
                    firewall_telemetry.log_verdict(
                        context_dict, app_action.value.upper(),
                        "Matched L7 App Rule", "AppEngine"
                    )
                    return {
                        "action":    app_action.value.upper(),
                        "confidence": 1.0,
                        "reason":    "Matched App Rule",
                        "rule_name": "AppEngine",
                    }

            # ── Step 4: Explicit Allow Rule Matched ─────────────────────────
            # If the ACL explicitly matched an ALLOW rule, it should allow the traffic
            if acl_action == Action.ALLOW and matched_rule_id is not None:
                self._increment_hit_count(matched_rule_id)
                firewall_telemetry.log_verdict(
                    context_dict, "ALLOW", "Matched ACL Fast-Path Rule", matched_rule_id
                )
                return {
                    "action":    "ALLOW",
                    "confidence": 1.0,
                    "reason":    "Matched ACL Rule",
                    "rule_name": matched_rule_id,
                }

            # ── Step 5: Default policy ─────────────────────────────────────────
            # default_policy is set in settings.yaml:
            #   default_policy: DROP  → block (secure by default)
            #   default_policy: ALLOW → allow (permissive)
            raw_default = self._config.get('default_policy', 'DROP').upper()
            if raw_default == 'DROP':
                firewall_telemetry.log_verdict(
                    context_dict, "DROP", "Default policy: DROP", "Default"
                )
                return {
                    "action":    "DROP",
                    "confidence": 1.0,
                    "reason":    "No matching rule — default policy is DROP",
                    "rule_name": "Default-DROP",
                }

            firewall_telemetry.log_verdict(
                context_dict, "ALLOW", "Default policy: ALLOW", "Default"
            )
            return {
                "action":    "ALLOW",
                "confidence": 0.8,
                "reason":    "No matching rule — default policy is ALLOW",
                "rule_name": "Default-ALLOW",
            }

        except Exception as e:
            logger.error("Error during policy evaluation: %s", e)
            return {"action": "DROP", "confidence": 0.0, "reason": "Evaluation Error", "rule_name": "Error"}


    def _increment_hit_count(self, rule_id: Optional[str]):
        """H8: Atomically increment hit_count for the matched rule.
        
        Uses a SQL-level atomic UPDATE to prevent lost increments under
        concurrent packet processing (avoids read-modify-write race).
        """
        if not rule_id or not self.db_session:
            return
        try:
            from sqlalchemy import update, func
            rule_int_id = int(rule_id)
            stmt = (
                update(DBFirewallRule)
                .where(DBFirewallRule.id == rule_int_id)
                .values(hit_count=func.coalesce(DBFirewallRule.hit_count, 0) + 1)
            )
            self.db_session.execute(stmt)
            self.db_session.commit()
        except Exception as exc:
            # Rollback to prevent the session from entering a broken state
            try:
                self.db_session.rollback()
            except Exception:
                pass
            logger.debug("hit_count increment skipped: %s", exc)
