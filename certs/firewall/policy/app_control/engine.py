"""
Application Control Engine
Layer 7 Policy Enforcement (SNI & Identity Aware)
"""

import logging
from typing import List
from datetime import datetime, timezone
from system.policy.schema import AppRule, PolicyContext, Action
from modules.firewall.policy.app_control.signatures import EncryptedAppSignatures
from modules.firewall.policy.identity import identity_manager, IdentityContext

logger = logging.getLogger(__name__)

class AppControlEngine:
    """
    Evaluates Application Control Rules natively integrating with Cisco-ISE style 
    Identity contexts and ultra-fast hierarchical SNI dictionaries.
    """
    
    def __init__(self):
        self.rules: List[AppRule] = []
        self.logger = logger
        # Zero Trust: unclassified L7 traffic is blocked by default,
        # consistent with ACLEngine's default-deny posture.
        self.default_action = Action.BLOCK

    def load_rules(self, rules: List[AppRule]):
        self.rules = sorted(rules, key=lambda r: r.priority)
        self.logger.info(f"Loaded {len(self.rules)} App Control rules")

    def evaluate(self, context: PolicyContext, identity_ctx: IdentityContext = None) -> Action:
        """Evaluate identified application against rules using injected identity"""
        
        # 1. Identify App SNI
        if not context.app_id and context.domain:
            context.app_id = EncryptedAppSignatures.identify_by_sni(context.domain)
            if context.app_id:
                self.logger.debug(f"Identified App: {context.app_id} from SNI: {context.domain}")

        if not context.app_id:
            return self.default_action

        # Resolve identity if not provided directly
        identity = identity_ctx or identity_manager.resolve(context.src_ip)

        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if self._match_rule(rule, context, identity):
                self.logger.debug(f"Matched App Rule: {rule.name} [{context.app_id}] -> {rule.action.value}")
                return rule.action
                
        return self.default_action

    def _match_rule(self, rule: AppRule, context: PolicyContext, identity: IdentityContext) -> bool:
        # 0. Time Schedule Match (UTC Agile)
        if rule.schedule:
            if not self._match_schedule(rule.schedule):
                return False

        # 1. Match Application Name
        if rule.application != "any" and rule.application.lower() != context.app_id.lower():
            return False
            
        # 2. Match Category Hierarchy
        if rule.category:
            app_category = EncryptedAppSignatures.get_category(context.app_id)
            if app_category and app_category.lower() != rule.category.lower():
                return False
            
        # 3. Match Cisco ISE Identity (User / Group Binding)
        if rule.users:
            if identity.user not in rule.users:
                if not any(group in rule.users for group in identity.groups):
                    return False
        
        return True

    def _match_schedule(self, schedule) -> bool:
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
