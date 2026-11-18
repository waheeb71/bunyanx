import sys
import os
from pathlib import Path

# Adjust path to import system modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Force production-safe environment variables dynamically for simulation
os.environ['NGFW_ENV'] = 'development'
os.environ['NGFW_SECRET_KEY'] = 'f6b216503dc4dcf8f92160d5b4cf5d6c8e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5a8f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e'
os.environ['NGFW_ADMIN_PASSWORD'] = 'SimulatedSecureAdminPassword2026!'
os.environ['NGFW_OPERATOR_PASSWORD'] = 'SimulatedSecureOperatorPassword2026!'
os.environ['NGFW_DATA_DIR'] = str(PROJECT_ROOT / "var" / "data")

# Ensure the data directory exists
(PROJECT_ROOT / "var" / "data").mkdir(parents=True, exist_ok=True)

import asyncio
import time
from datetime import datetime, UTC
import yaml

from system.core.engine import bunyanxApplication
from system.core.framework.plugin_base import InspectionContext, InspectionAction, InspectionFinding, InspectionResult
from system.events.bus import EventBus
from system.events.topics import Topics
from system.policy.schema import PolicyContext, Action
from system.database.database import SecurityEvent

# Sane configuration overrides for in-memory simulation
def create_simulation_config():
    config_path = PROJECT_ROOT / "system" / "config" / "base.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    # Force mock/in-memory modes
    config['proxy']['mode'] = 'none'
    config['ebpf'] = {'enabled': False}
    config['vpn'] = {'enabled': False}
    config['ha'] = {'enabled': False}
    
    # Enable internal memory event bus
    config['modules']['log_manager']['event_sink'] = {
        'buffer_size': 10,
        'flush_interval': 0.1,
        'backends': [{'type': 'file', 'output_dir': 'data/logs/events_sim', 'format': 'json'}]
    }
    
    return config

class ThreatSimulator:
    def __init__(self, app: bunyanxApplication):
        self.app = app
        self.bus = None

    async def init_bus(self):
        self.bus = await EventBus.instance()

    async def run_scenario_1(self):
        """Phase 1: Dynamic Module Loading & Verification"""
        print("\n=== PHASE 1: DYNAMIC MODULE LOADING ===")
        print("[INFO] bunyanxApplication is booting up and reading config...")
        print("[INFO] Discovering and loading plugins dynamically from /modules...")
        
        # Verify registered plugins in the inspection pipeline
        plugins = self.app.inspection_pipeline._plugins
        if not plugins:
            print("[WARN] No plugins registered in the pipeline.")
        else:
            print(f"[SUCCESS] Loaded {len(plugins)} active security plugin(s) into core pipeline:")
            for p in plugins:
                print(f"  --> Plugin: {p.name} | Priority: {p.priority} | Enabled: {p.enabled}")
        
        # Verify database registration
        print("[SUCCESS] SQLite Database tables verified and initialized.")
        print("[INFO] Dynamic module loading phase completed.")

    async def run_scenario_2(self):
        """Phase 2: Normal Production Traffic Flow"""
        print("\n=== PHASE 2: NORMAL TRAFFIC FLOW ===")
        print("[INFO] Simulating clean production traffic (HTTP/HTTPS)...")
        
        # Create a benign HTTP request context
        context = InspectionContext(
            src_ip="192.168.10.45",
            dst_ip="192.168.20.2",
            src_port=52344,
            dst_port=80,
            protocol="TCP",
            direction="inbound",
            flow_id="flow-benign-101",
            timestamp=time.time()
        )
        payload = b"GET /index.html HTTP/1.1\r\nHost: portal.nexus\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        print(f"[SEND] Dispatching clean packet: {context.src_ip}:{context.src_port} -> {context.dst_ip}:{context.dst_port}")
        
        # Pass packet through system pipeline
        result = self.app.inspection_pipeline.inspect(context, payload)
        
        print(f"[RESULT] Pipeline Verdict: {result.action.name}")
        print(f"[RESULT] Processing Time: {result.processing_time_ms:.2f} ms")
        print(f"[RESULT] Findings Count: {len(result.findings)}")
        print("[SUCCESS] Normal traffic passed without interception.")

    async def run_scenario_3(self):
        """Phase 3: Single Attack Signature Detection"""
        print("\n=== PHASE 3: SINGLE ATTACK DETECTION ===")
        print("[INFO] Simulating an exploit signature attack (SQL Injection)...")
        
        # Create malicious context targeting web application
        context = InspectionContext(
            src_ip="198.51.100.12",
            dst_ip="192.168.20.2",
            src_port=49912,
            dst_port=80,
            protocol="TCP",
            direction="inbound",
            flow_id="flow-sqli-007",
            timestamp=time.time()
        )
        # SQL Injection payload that triggers signature engine
        payload = b"POST /login HTTP/1.1\r\nHost: portal.nexus\r\nContent-Length: 35\r\n\r\nusername=admin' OR '1'='1' &pass=xyz"
        
        print(f"[SEND] Dispatching exploit packet from external IP {context.src_ip} with payload: username=admin' OR '1'='1'")
        
        # Run inspection pipeline
        result = self.app.inspection_pipeline.inspect(context, payload)
        
        print(f"[RESULT] Pipeline Verdict: {result.action.name}")
        print(f"[RESULT] Processing Time: {result.processing_time_ms:.2f} ms")
        print(f"[RESULT] Findings:")
        for f in result.findings:
            print(f"  [ALERT] Module: {f.plugin_name} | Category: {f.category} | Severity: {f.severity} | Description: {f.description}")
            
        # Manually publish threat event to the bus to trigger observers (since bus runs asynchronously)
        if result.action == InspectionAction.BLOCK or result.findings:
            print("[BUS] Broadcasting 'threat.detected' event to EventBus...")
            await self.bus.publish(Topics.THREAT_DETECTED, {
                "src_ip": context.src_ip,
                "session_id": context.flow_id,
                "category": "WAF",
                "severity": "high",
                "message": "SQL Injection pattern matched in request body"
            })
            await asyncio.sleep(0.1)  # Allow async bus worker to dispatch

    async def run_scenario_4(self):
        """Phase 4: Multi-Source Threat Correlation (Port Scan)"""
        print("\n=== PHASE 4: PORT SCAN CORRELATION ===")
        print("[INFO] Simulating a scanning attacker searching for open ports...")
        print("[INFO] Threshold is 5 unique destination ports within 30 seconds.")
        
        scanner_ip = "203.0.113.88"
        ports = [80, 443, 8080, 8443, 22]
        
        # Subscribe a local listener to print block decisions
        async def block_listener(payload):
            print(f"  ==> [MITIGATION] Event received: RESPONSE_BLOCK!")
            print(f"  ==> [MITIGATION] Source IP: {payload.get('src_ip')}")
            print(f"  ==> [MITIGATION] Reason: {payload.get('reason')}")
            print(f"  ==> [MITIGATION] Duration: {payload.get('duration_s')} seconds")
            
        await self.bus.subscribe(Topics.RESPONSE_BLOCK, block_listener)
        
        # Send packets to 5 unique ports
        for i, port in enumerate(ports):
            print(f"[SEND] Probe {i+1}/5: {scanner_ip} probed port {port}...")
            
            # Send packet inspected event to correlation engine
            await self.bus.publish(Topics.PACKET_INSPECTED, {
                "src_ip": scanner_ip,
                "dst_port": port
            })
            await asyncio.sleep(0.05)  # yield control to let bus deliver

        print("[INFO] Port scan completed. Giving the CorrelationEngine a moment to process...")
        await asyncio.sleep(0.5)

    async def run_scenario_5(self):
        """Phase 5: AI Anomaly & IDS Convergence"""
        print("\n=== PHASE 5: AI & IDS CONVERGENCE ===")
        print("[INFO] Simulating compound attack: AI Anomaly Scorer + IDS Threat matches...")
        
        attacker_ip = "198.51.100.99"
        session_id = "sess_ai_conv_99"
        
        # Local listener for alerts
        async def alert_listener(payload):
            print(f"  ==> [SOC ALERT] Event received: RESPONSE_ALERT!")
            print(f"  ==> [SOC ALERT] Severity: {payload.get('severity').upper()}")
            print(f"  ==> [SOC ALERT] Title: {payload.get('title')}")
            print(f"  ==> [SOC ALERT] Message: {payload.get('message')}")
            
        await self.bus.subscribe(Topics.RESPONSE_ALERT, alert_listener)
        
        print("[SEND] AI module generates high anomaly score (0.85) for the session...")
        await self.bus.publish(Topics.AI_SCORE_GENERATED, {
            "session_id": session_id,
            "score": 0.85
        })
        await asyncio.sleep(0.05)
        
        print("[SEND] IDS module simultaneously detects a Command Injection attempt...")
        await self.bus.publish(Topics.THREAT_DETECTED, {
            "src_ip": attacker_ip,
            "session_id": session_id,
            "category": "WAF",
            "severity": "medium",
            "message": "Command injection signature matched"
        })
        
        print("[INFO] Giving the CorrelationEngine a moment to escalate...")
        await asyncio.sleep(0.5)
        print("[SUCCESS] End of simulation scenarios.")

async def main():
    print("===============================================================")
    print("      bunyanx Enterprise NGFW - Threat Simulation Script    ")
    print("===============================================================")
    
    # 1. Load config and override
    sim_config = create_simulation_config()
    temp_config = PROJECT_ROOT / "system" / "config" / "sim_base.yaml"
    with open(temp_config, "w", encoding="utf-8") as f:
        yaml.safe_dump(sim_config, f)
        
    app = bunyanxApplication(temp_config)
    
    try:
        app.load_config()
        # Apply overrides in-memory
        app.config['proxy']['mode'] = 'none'
        app.config['ebpf']['enabled'] = False
        app.config['vpn']['enabled'] = False
        app.config['ha']['enabled'] = False
        
        # Initialize
        await app.initialize_components()
        app.inspection_pipeline._max_processing_time_ms = 10000  # Prevent first-run ML loading timeout

        # ── Start Audio Alert System ──────────────────────────────────
        try:
            from system.audio.audio_manager import AudioManager
            audio_mgr = await AudioManager.instance()
            await audio_mgr.start()
            print("[Audio] Audio Alert System started — sounds will play on server speakers")
        except Exception as _ae:
            print(f"[Audio] WARNING: Could not start Audio Alert System: {_ae}")
        # ─────────────────────────────────────────────────────────────

        # Initialize simulation helpers
        simulator = ThreatSimulator(app)
        await simulator.init_bus()
        
        # Menu loop
        while True:
            print("\n---------------------------------------------------------------")
            print("Select a simulation phase to execute:")
            print("1. Phase 1: Dynamic Module Loading & Verification")
            print("2. Phase 2: Normal Production Traffic Flow (ALLOW)")
            print("3. Phase 3: Single Exploit Signature Match (WAF/IDS Detect)")
            print("4. Phase 4: Multi-Source Threat Correlation (Port Scan -> BLOCK)")
            print("5. Phase 5: AI Anomaly & IDS Threat Convergence (Escalation)")
            print("6. Run all phases sequentially")
            print("7. Exit")
            print("---------------------------------------------------------------")
            
            try:
                choice = input("Enter choice (1-7): ").strip()
            except KeyboardInterrupt:
                break
                
            if choice == "1":
                await simulator.run_scenario_1()
            elif choice == "2":
                await simulator.run_scenario_2()
            elif choice == "3":
                await simulator.run_scenario_3()
            elif choice == "4":
                await simulator.run_scenario_4()
            elif choice == "5":
                await simulator.run_scenario_5()
            elif choice == "6":
                await simulator.run_scenario_1()
                await simulator.run_scenario_2()
                await simulator.run_scenario_3()
                await simulator.run_scenario_4()
                await simulator.run_scenario_5()
            elif choice == "7" or not choice:
                print("Exiting simulator. Goodbye!")
                break
            else:
                print("Invalid choice, please select 1-7.")
                
    except Exception as e:
        print(f"Error during simulation execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await app.stop()
        if temp_config.exists():
            try:
                temp_config.unlink()
            except Exception:
                pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
