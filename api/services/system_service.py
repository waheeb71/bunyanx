"""
Enterprise bunyanx - System Service Layer
===================================================
Contains business logic for system controls, health checks, and script execution.
"""
import os
import asyncio
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

async def get_detailed_health(ctrl=None) -> dict:
    from system.core.circuit_breaker import breaker_registry
    from system.config.feature_flags import FeatureFlagManager
    import time

    flags = FeatureFlagManager.instance().current
    summary = breaker_registry.health_summary()

    # Calculate circuit_breakers with reset_timeout_s and failures keys
    circuit_breakers = {}
    with breaker_registry._lock:
        for name, breaker in breaker_registry._breakers.items():
            s = breaker.stats
            reset_timeout_s = 0
            if s.current_state.value == "OPEN":
                elapsed = time.perf_counter() - s.last_state_change
                reset_timeout_s = max(0, int(breaker._timeout_s - elapsed))
            circuit_breakers[name] = {
                "state": s.current_state.value,
                "failures": s.consecutive_failures,
                "reset_timeout_s": reset_timeout_s,
                "error_rate": round(s.error_rate, 3),
                "total_calls": s.total_calls,
            }

    ebpf_active = False
    if ctrl:
        if hasattr(ctrl, "ip_blocklist") and ctrl.ip_blocklist:
            xdp = getattr(ctrl.ip_blocklist, "_xdp", None)
            if xdp:
                ebpf_active = getattr(xdp, "enabled", False)
        if not ebpf_active and hasattr(ctrl, "xdp_engine") and ctrl.xdp_engine:
            ebpf_active = getattr(ctrl.xdp_engine, "enabled", False)
    if not ebpf_active:
        ebpf_active = getattr(flags.data_plane, "ebpf_acceleration", False)

    mtls_active = getattr(flags.security, "mtls_internal", False)

    ha_data = {
        "enabled": False,
        "is_leader": False,
        "active_nodes": 1,
        "peer_ip": "",
        "priority": 100,
        "last_sync": 0.0
    }
    if ctrl and getattr(ctrl, "ha_manager", None):
        mgr = ctrl.ha_manager
        ha_data = {
            "enabled": True,
            "is_leader": getattr(ctrl, "is_ha_master", False),
            "active_nodes": 2 if getattr(mgr, "peer_ip", None) else 1,
            "peer_ip": getattr(mgr, "peer_ip", "") or "",
            "priority": getattr(mgr, "priority", 100),
            "last_sync": getattr(mgr, "last_heartbeat_received", 0.0) or 0.0
        }
    else:
        ha_data["enabled"] = getattr(flags.ha, "enabled", False)

    try:
        from system.networking.core_affinity import CoreAffinityManager
        mgr = CoreAffinityManager.instance()
        affinity_data = {
            "pinned": mgr.is_enabled(),
            "total_logical_cores": mgr._cpu_count,
            "roles": {role.value: cores for role, cores in mgr._assignments.items()}
        }
    except Exception:
        import os
        affinity_data = {
            "pinned": False,
            "total_logical_cores": os.cpu_count() or 1,
            "roles": {}
        }

    return {
        **summary,
        "circuit_breakers": circuit_breakers,
        "ebpf_active": ebpf_active,
        "mtls_active": mtls_active,
        "ha": ha_data,
        "affinity": affinity_data,
        "timestamp": int(time.time()),
        "wasm_active": getattr(getattr(flags, "wasm", None), "enabled", False),
        "feature_flags": {
            "event_bus_enabled": flags.event_bus.enabled,
            "event_bus_backend": flags.event_bus.backend,
            "ai_enabled": flags.ai_engine.enabled,
            "ai_mode": flags.ai_engine.mode,
            "ai_inline_blocking": flags.ai_engine.inline_blocking,
            "observability_metrics": flags.observability.metrics,
            "observability_tracing": flags.observability.tracing,
            "threat_intel_enabled": flags.threat_intel.enabled,
            "mtls_internal": flags.security.mtls_internal,
            "ha_enabled": flags.ha.enabled,
        }
    }

async def reset_circuit_breaker(module_name: str) -> dict:
    from system.core.circuit_breaker import breaker_registry
    breaker = breaker_registry._breakers.get(module_name)
    if not breaker:
        raise ValueError(f"No circuit breaker found for module '{module_name}'")
    breaker.reset()
    return {"status": "reset", "module": module_name}

async def get_system_features() -> dict:
    from system.config.feature_flags import FeatureFlagManager
    flags = FeatureFlagManager.instance().current
    return {
        "data_plane": {
            "enabled": flags.data_plane.enabled,
            "ebpf_acceleration": flags.data_plane.ebpf_acceleration,
            "tls_inspection": flags.data_plane.tls_inspection,
            "fail_mode": flags.data_plane.fail_mode,
        },
        "event_bus": {
            "enabled": flags.event_bus.enabled,
            "backend": flags.event_bus.backend,
        },
        "ai_engine": {
            "enabled": flags.ai_engine.enabled,
            "mode": flags.ai_engine.mode,
            "inline_blocking": flags.ai_engine.inline_blocking,
            "model_version": flags.ai_engine.model_version,
        },
        "observability": {
            "metrics": flags.observability.metrics,
            "logs": flags.observability.logs,
            "tracing": flags.observability.tracing,
        },
        "threat_intel": {"enabled": flags.threat_intel.enabled},
        "ha": {"enabled": flags.ha.enabled, "mode": flags.ha.mode},
        "security": {"mtls_internal": flags.security.mtls_internal},
        "optimizer": {"enabled": flags.optimizer.enabled},
    }

async def reload_system_features() -> dict:
    from system.config.feature_flags import FeatureFlagManager
    mgr = FeatureFlagManager.instance()
    mgr.force_reload()
    return {"status": "reloaded", "message": "Feature flags reloaded from features.yaml"}

async def start_firewall_engine(controller: Any) -> dict:
    if not controller:
        raise RuntimeError("bunyanx Controller not found in app state")
        
    if getattr(controller, 'engine_running', True):
        return {"status": "success", "message": "Engine is already running."}
    
    await controller.start_firewall_components()
    return {"status": "success", "message": "Firewall Engine started successfully"}

async def stop_firewall_engine(controller: Any) -> dict:
    if not controller:
        raise RuntimeError("bunyanx Controller not found in app state")
        
    if not getattr(controller, 'engine_running', True):
        return {"status": "success", "message": "Engine is already stopped."}
        
    await controller.stop_firewall_components()
    return {"status": "success", "message": "Engine stopped successfully."}

async def execute_system_script(script_name: str, args: list) -> dict:
    allowed_scripts = ["update.sh", "install/install.sh", "install/deps.sh"]
    if script_name not in allowed_scripts:
        raise PermissionError("Script execution forbidden or unrecognized.")
        
    scripts_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "scripts")
    script_path = os.path.join(scripts_dir, script_name)
    
    if not os.path.exists(script_path):
        raise FileNotFoundError("Script file not found.")

    cmd = ["bash", script_path] + args
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=os.path.dirname(script_path)
    )
    
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
        return {
            "status": "success" if process.returncode == 0 else "error",
            "message": f"Exit code: {process.returncode}. Output extracted but truncated."
        }
    except asyncio.TimeoutError:
        try:
            process.kill()
        except OSError:
            pass
        return {"status": "error", "message": "Script execution timed out after 30 seconds and was killed."}
