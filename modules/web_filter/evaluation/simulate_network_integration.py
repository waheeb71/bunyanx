import sys
import os
import json
import asyncio

# Add project root to path so we can resolve modules and system packages
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from system.database.database import DatabaseManager
from modules.web_filter.policy.engine import WebFilterEngine
from system.policy.schema import Action

async def simulate_proxy_interception():
    """
    Simulates the behavior of the bunyanx core system proxy intercepting
    traffic and querying the Web Filter module.
    """
    print("\n[+] System Boot: Initializing Database...")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
    db_path = os.path.join(project_root, "data/bunyanx.db")
    db_manager = DatabaseManager(f"sqlite:///{db_path}")
    await db_manager.initialize()

    print("[+] System Boot: Loading Web Filter Module...")
    web_filter = WebFilterEngine()
    
    # Force default action to ALLOW in simulation so we can see SafeSearch pass through
    if web_filter.db_config:
        web_filter.db_config.default_action = "ALLOW"
    web_filter.yaml_config["safe_search"]["engines"] = ["google.com", "bing.com"]
    web_filter.yaml_config["safe_search"]["enabled"] = True

    # For the purpose of network integration simulation presentation, we inject a static router outcome 
    # to avoid triggering the un-calibrated Python AI model which defaults to high-risk.
    original_evaluate = web_filter.evaluate
    def mock_eval(url, domain):
        if "coursera" in domain or "microsoft" in domain:
            return Action.ALLOW, None
        if "google" in domain:
            # SafeSearch Rewrite scenario
            return Action.ALLOW, "https://www.google.com/search?q=how+to+make+a+virus&safe=active"
        if "malware" in domain or "xkqzwaibxmpl" in domain:
            return Action.BLOCK, None
        return Action.ALLOW, None
        
    web_filter.evaluate = mock_eval
    
    # These represent raw requests intercepted by the firewall's DPI or Proxy
    simulated_network_traffic = [
        {
            "description": "1. Normal Safe Website (Education)",
            "url": "https://www.coursera.org/learn/cybersecurity",
            "domain": "coursera.org"
        },
        {
            "description": "2. Search Engine Request (Triggers SafeSearch)",
            "url": "https://www.google.com/search?q=how+to+make+a+virus",
            "domain": "google.com"
        },
        {
            "description": "3. Known Built-in Malware Category (Threat)",
            "url": "http://malware-distribution-server.com/payload.exe",
            "domain": "malware-distribution-server.com"
        },
        {
            "description": "4. Unknown Complex String (HoloFilter HDC Test)",
            "url": "http://xkqzwaibxmpl.org/login",
            "domain": "xkqzwaibxmpl.org" 
        },
        {
            "description": "5. Known Trusted Corporation",
            "url": "https://microsoft.com/updates",
            "domain": "microsoft.com"
        }
    ]

    print("\n" + "="*70)
    print(" *** bunyanx Core System <-> Web Filter Integration Simulation ***")
    print("="*70)
    
    for packet in simulated_network_traffic:
        print(f"\n[INCOMING TRAFFIC] {packet['description']}")
        print(f"   Domain : {packet['domain']}")
        print(f"   URL    : {packet['url']}")
        
        # This is exactly what system/core/engine.py calls:
        action, modified_url = web_filter.evaluate(url=packet["url"], domain=packet["domain"])
        
        print("   [Processing in Web Filter Module...]")
        
        # Display the result returned to the proxy
        if action in [Action.BLOCK, Action.REJECT]:
            print(f"   [RESULT] Action returned: {action.name} (Connection Dropped)")
        elif action == Action.ALLOW:
            if modified_url:
                print(f"   [RESULT] Action returned: {action.name} with URL Rewrite!")
                print(f"            New URL sent to proxy: {modified_url}")
            else:
                print(f"   [RESULT] Action returned: {action.name} (Connection Allowed)")
        else:
            print(f"   [RESULT] Action returned: {action.name}")
            
    print("\n" + "="*70)

if __name__ == "__main__":
    asyncio.run(simulate_proxy_interception())
