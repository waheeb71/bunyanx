"""
High-Performance Access Control List (ACL) Engine
Layer 3/4 Firewall Rule Evaluation via Multi-Stage Filtering
Enforces Zero Trust (Deny by Default) and UTC Scheduling.
"""

import logging
import ipaddress
from datetime import datetime, timezone
from typing import List, Optional, Union, Dict, Any, Tuple
from system.policy.schema import FirewallRule, PolicyContext, Action, Protocol

logger = logging.getLogger(__name__)

class CompiledRule:
    """Pre-computes rule matching criteria for maximum speed."""
    __slots__ = ['id', 'action', 'protocol', 'src_zone', 'src_ips', 'dst_ips', 'src_ports', 'dst_ports', 'schedule', 'rule_ref']
    
    def __init__(self, rule: FirewallRule):
        self.rule_ref = rule
        self.id = rule.id
        self.action = rule.action
        self.protocol = rule.protocol.value.lower() if rule.protocol != Protocol.ANY else "any"
        self.src_zone = rule.src_zone
        
        # Convert IPs to integer ranges: [(start_int, end_int)]
        self.src_ips = self._compile_ips(rule.src_ip)
        self.dst_ips = self._compile_ips(rule.dst_ip)
        
        # Convert Ports to integer ranges: [(start, end)]
        self.src_ports = self._compile_ports(rule.src_port)
        self.dst_ports = self._compile_ports(rule.dst_port)
        
        self.schedule = rule.schedule

    def _compile_ips(self, ip_data) -> Optional[List[Tuple[int, int]]]:
        if not ip_data or ip_data == "any":
            return None
        
        if isinstance(ip_data, str):
            raw_ips = [x.strip() for x in ip_data.split(",") if x.strip()]
        elif isinstance(ip_data, list):
            raw_ips = []
            for item in ip_data:
                if isinstance(item, str):
                    raw_ips.extend([x.strip() for x in item.split(",") if x.strip()])
                else:
                    raw_ips.append(item)
        else:
            raw_ips = [ip_data]

        compiled = []
        for ip in raw_ips:
            try:
                if '/' in ip:
                    net = ipaddress.ip_network(ip, strict=False)
                    compiled.append((int(net.network_address), int(net.broadcast_address)))
                else:
                    addr = int(ipaddress.ip_address(ip))
                    compiled.append((addr, addr))
            except ValueError:
                pass
        return compiled

    def _compile_ports(self, port_data) -> Optional[List[Tuple[int, int]]]:
        if not port_data or port_data == "any":
            return None

        if isinstance(port_data, str):
            raw_ports = [x.strip() for x in port_data.split(",") if x.strip()]
        elif isinstance(port_data, list):
            raw_ports = []
            for item in port_data:
                if isinstance(item, str):
                    raw_ports.extend([x.strip() for x in item.split(",") if x.strip()])
                else:
                    raw_ports.append(item)
        else:
            raw_ports = [port_data]

        compiled = []
        for p in raw_ports:
            if isinstance(p, int):
                compiled.append((p, p))
            elif isinstance(p, str):
                p = p.strip()
                if '-' in p:
                    try:
                        s, e = p.split('-')
                        compiled.append((int(s.strip()), int(e.strip())))
                    except ValueError:
                        pass
                else:
                    try:
                        compiled.append((int(p), int(p)))
                    except ValueError:
                        pass
        return compiled

class ACLEngine:
    """
    Evaluates Firewall Rules using integer boundary checking instead of string/object comparison.
    Speed optimizations yield sub-millisecond evaluation times even for 10K+ rules.
    """
    
    def __init__(self, default_action: Action = Action.BLOCK):
        self.rules: List[CompiledRule] = []
        # Protocol-based Fast Path hash
        self.protocol_index: Dict[str, List[CompiledRule]] = {"any": []}
        self.logger = logger
        # Zero Trust: Default policy is implicit deny
        self.default_action = default_action 

    def load_rules(self, rules: List[FirewallRule]):
        """Compile rules to integers and group via Protocol Fast Path.
        
        Each protocol key gets a pre-merged list that includes both
        protocol-specific rules AND 'any' rules, globally sorted by priority.
        This guarantees first-match-wins correctness regardless of protocol.
        """
        raw_index: Dict[str, List[CompiledRule]] = {"any": [], "tcp": [], "udp": [], "icmp": []}
        self.rules = []
        
        # Enforce 'First Match Wins' Strategy
        sorted_rules = sorted(rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            compiled = CompiledRule(rule)
            self.rules.append(compiled)
            
            # Bucket by protocol
            if compiled.protocol in raw_index:
                raw_index[compiled.protocol].append(compiled)
            else:
                raw_index[compiled.protocol] = [compiled]

        # Build merged candidate lists: protocol-specific + "any" rules,
        # re-sorted by priority to guarantee global first-match-wins.
        any_rules = raw_index.get("any", [])
        self.protocol_index = {}
        for proto_key, proto_rules in raw_index.items():
            if proto_key == "any":
                # "any" queries only match "any" rules
                self.protocol_index["any"] = sorted(any_rules, key=lambda c: c.rule_ref.priority)
            else:
                # Merge protocol-specific + "any", then sort by priority
                merged = proto_rules + any_rules
                self.protocol_index[proto_key] = sorted(merged, key=lambda c: c.rule_ref.priority)
                
        self.logger.info(f"Loaded {len(self.rules)} rules into high-performance Fast-Path Engine")

    def evaluate(self, context: PolicyContext) -> Action:
        """Find first matching rule executing inside Fast Path boundaries"""
        proto = context.protocol.lower() if context.protocol else "any"
        # Retrieve pre-merged candidates (protocol-specific + "any" rules,
        # already sorted by priority at load time).
        candidates = self.protocol_index.get(proto, self.protocol_index.get("any", []))
            
        # Compile transient packet IPs to integers
        try:
            src_ip_int = int(ipaddress.ip_address(context.src_ip)) if context.src_ip else 0
            dst_ip_int = int(ipaddress.ip_address(context.dst_ip)) if context.dst_ip else 0
        except ValueError:
            return self.default_action # Malformed IP safely drops
            
        for cr in candidates:
            if self._match_rule(cr, context, src_ip_int, dst_ip_int):
                self.logger.debug(f"Matched Fast-Path ACL Rule: {cr.rule_ref.name}")
                return cr.action
                
        return self.default_action

    def evaluate_with_rule(self, context: PolicyContext):
        """Like evaluate() but returns (Action, rule_id) for hit_count tracking."""
        proto = context.protocol.lower() if context.protocol else "any"
        # Pre-merged candidates (protocol-specific + "any", sorted by priority)
        candidates = self.protocol_index.get(proto, self.protocol_index.get("any", []))
        try:
            src_ip_int = int(ipaddress.ip_address(context.src_ip)) if context.src_ip else 0
            dst_ip_int = int(ipaddress.ip_address(context.dst_ip)) if context.dst_ip else 0
        except ValueError:
            return self.default_action, None
        for cr in candidates:
            if self._match_rule(cr, context, src_ip_int, dst_ip_int):
                self.logger.debug("Matched Fast-Path ACL Rule: %s", cr.rule_ref.name)
                return cr.action, cr.id
        return self.default_action, None

    def _match_rule(self, cr: CompiledRule, context: PolicyContext, src_ip_int: int, dst_ip_int: int) -> bool:
        # 1. Zone Math
        if cr.src_zone != "any" and context.interface != "any":
            if cr.src_zone != context.interface:
                return False

        # 2. IP Integer Fast Match (O(1) continuous interval check)
        if cr.src_ips is not None:
            if not any(start <= src_ip_int <= end for start, end in cr.src_ips):
                return False
                
        if cr.dst_ips is not None:
            if not any(start <= dst_ip_int <= end for start, end in cr.dst_ips):
                return False

        # 3. Port Boundaries Match
        if cr.src_ports is not None:
            if context.src_port is None or not any(start <= context.src_port <= end for start, end in cr.src_ports):
                return False

        if cr.dst_ports is not None:
            if context.dst_port is None or not any(start <= context.dst_port <= end for start, end in cr.dst_ports):
                return False

        # 4. UTC Schedule Match
        if cr.schedule is not None:
            if not self._match_schedule(cr.schedule):
                return False
                
        return True

    def _match_schedule(self, schedule: Any) -> bool:
        """UTC-Agile check to prevent timezone drift"""
        now = datetime.now(timezone.utc)
        current_day = now.strftime("%a")
        
        if schedule.days and current_day not in schedule.days:
            return False
            
        try:
            now_time = now.time()
            start_time = datetime.strptime(schedule.start_time, "%H:%M").time()
            end_time = datetime.strptime(schedule.end_time, "%H:%M").time()
            return start_time <= now_time <= end_time
        except Exception:
            return False
