from pathlib import Path

project_root = Path(__file__).resolve().parent.parent.parent
target = project_root / "modules" / "ids_ips" / "engine" / "phantom_plugin.py"
with open(target, "r", encoding="utf-8") as f:
    code = f.read()

# 1. Update init
init_target = """        # ── Config (injected by ModuleManager via plugin.config = …) ────
        self.config: Dict[str, Any] = {}

        # ── Stats ────────────────────────────────────────────────────────"""

init_repl = """        # ── Config (injected by ModuleManager via plugin.config = …) ────
        self.config: Dict[str, Any] = {}

        # ── Telemetry ────────────────────────────────────────────────────────
        self._tel = None
        try:
            from modules.ids_ips.engine.core.telemetry import Telemetry
            self._tel = Telemetry.instance()
        except Exception:
            pass

        # ── Stats ────────────────────────────────────────────────────────"""

code = code.replace(init_target, init_repl)

# 2. Update inspect start and SBE layer
sbe_target = """        # ── Layer 1: Spectral Byte Encoding ──────────────────────────────
        sbe_vec    = None
        sbe_avail  = False
        if self._sbe is not None and payload:
            try:
                sbe_vec   = self._sbe.encode(payload)
                sbe_avail = True
            except Exception as exc:
                logger.debug("SBE encode failed for %s→%s: %s", src_ip, dst_ip, exc)"""

sbe_repl = """        # ── Telemetry: Pipeline root span ─────────────────────────────────
        span_ctx = self._tel.trace.pipeline(src_ip, dst_ip) if self._tel else _NoOpTracker()
        
        with span_ctx as root_span:
            if self._tel:
                self._tel.metrics.record_packet(protocol=context.protocol, direction=context.direction)
            
            # ── Layer 1: Spectral Byte Encoding ──────────────────────────────
            sbe_vec    = None
            sbe_avail  = False
            
            sbe_span_ctx = self._tel.trace.sbe() if self._tel else _NoOpTracker()
            with sbe_span_ctx as sbe_span:
                if self._sbe is not None and payload:
                    try:
                        s0 = time.perf_counter()
                        sbe_vec   = self._sbe.encode(payload)
                        sbe_avail = True
                        dt = (time.perf_counter() - s0) * 1000
                        if self._tel:
                            self._tel.log.sbe_encoded(src_ip, len(payload), cache_hit=False, elapsed_ms=dt)
                    except Exception as exc:
                        sbe_span.set_status_error(str(exc))
                        logger.debug("SBE encode failed for %s→%s: %s", src_ip, dst_ip, exc)"""

code = code.replace(sbe_target, sbe_repl)


# We need a small dummy _NoOpTracker for `with` blocks if telemetry is None
noop_target = """import logging
from typing import Optional, Dict, Any, List

from system.core.framework.plugin_base import ("""
noop_repl = """import logging
from typing import Optional, Dict, Any, List

class _NoOpTracker:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def set(self, k, v): pass
    def set_status_error(self, e): pass

from system.core.framework.plugin_base import ("""

code = code.replace(noop_target, noop_repl)

# 3. Update CTGB layer
ctgb_target = """        # ── Layer 2: Causal Temporal Graph ───────────────────────────────
        causal_density = 0.0
        if self._ctgb is not None:
            try:
                graph = self._ctgb.update(src_ip, dst_ip, sbe_vec, ts)
                causal_density = graph.causal_density()
            except Exception as exc:
                logger.debug("CTGB update failed: %s", exc)"""

ctgb_repl = """            # ── Layer 2: Causal Temporal Graph ───────────────────────────────
            causal_density = 0.0
            ctgb_span_ctx = self._tel.trace.ctgb() if self._tel else _NoOpTracker()
            with ctgb_span_ctx as ctgb_span:
                if self._ctgb is not None:
                    try:
                        graph = self._ctgb.update(src_ip, dst_ip, sbe_vec, ts)
                        causal_density = graph.causal_density()
                        ctgb_span.set("causal_density", causal_density)
                        if self._tel:
                            self._tel.metrics.set_causal_density(causal_density)
                            self._tel.metrics.set_graph_topology(len(graph.nodes), len(graph.edges))
                            # self._tel.log.graph_updated(...)  # skipped for performance
                    except Exception as exc:
                        ctgb_span.set_status_error(str(exc))
                        logger.debug("CTGB update failed: %s", exc)"""

code = code.replace(ctgb_target, ctgb_repl)

# 4. Update HGTC layer - Just wrapping the inference in span, and logging result
hgtc_target = """        # ── Layer 3: PHANTOM Threat Classification ────────────────────────
        phantom_class      = "benign"
        phantom_confidence = 0.0
        phantom_is_threat  = False
        inference_ms       = 0.0

        if self._phantom is not None and sbe_vec is not None:
            try:
                with _SBE_HISTORY_LOCK:
                    hist = list(_SBE_HISTORY[src_ip])

                result: PHANTOMResult = self._phantom.predict(
                    sbe=sbe_vec,
                    temporal_sbes=hist if hist else None,
                    causal_density=causal_density,
                )

                phantom_class      = result.threat_class
                phantom_confidence = result.confidence
                phantom_is_threat  = result.is_threat
                inference_ms       = result.inference_ms

                # Update SBE history for this host
                with _SBE_HISTORY_LOCK:
                    _SBE_HISTORY[src_ip].append(sbe_vec)

                if phantom_is_threat:
                    self._total_phantom_threats += 1
                    logger.warning(
                        "PHANTOM THREAT | %s→%s | class=%s conf=%.3f "
                        "causal_density=%.3f inference=%.1fms",
                        src_ip, dst_ip, phantom_class,
                        phantom_confidence, causal_density, inference_ms,
                    )

            except Exception as exc:
                logger.error("PHANTOM inference error: %s", exc)"""

hgtc_repl = """            # ── Layer 3: PHANTOM Threat Classification ────────────────────────
            phantom_class      = "benign"
            phantom_confidence = 0.0
            phantom_is_threat  = False
            inference_ms       = 0.0

            hgtc_span_ctx = self._tel.trace.hgtc() if self._tel else _NoOpTracker()
            with hgtc_span_ctx as hgtc_span:
                if self._phantom is not None and sbe_vec is not None:
                    try:
                        with _SBE_HISTORY_LOCK:
                            hist = list(_SBE_HISTORY[src_ip])

                        result: PHANTOMResult = self._phantom.predict(
                            sbe=sbe_vec,
                            temporal_sbes=hist if hist else None,
                            causal_density=causal_density,
                        )

                        phantom_class      = result.threat_class
                        phantom_confidence = result.confidence
                        phantom_is_threat  = result.is_threat
                        inference_ms       = result.inference_ms

                        hgtc_span.set("threat_class", phantom_class)
                        hgtc_span.set("confidence", phantom_confidence)

                        if self._tel:
                            self._tel.metrics.record_inference_latency(inference_ms / 1000.0)
                            if phantom_is_threat:
                                self._tel.metrics.record_threat(phantom_class)
                                self._tel.log.inference_result(
                                    src_ip, dst_ip, phantom_class, 
                                    phantom_confidence, True, inference_ms
                                )

                        # Update SBE history for this host
                        with _SBE_HISTORY_LOCK:
                            _SBE_HISTORY[src_ip].append(sbe_vec)

                        if phantom_is_threat:
                            self._total_phantom_threats += 1
                            logger.warning(
                                "PHANTOM THREAT | %s→%s | class=%s conf=%.3f "
                                "causal_density=%.3f inference=%.1fms",
                                src_ip, dst_ip, phantom_class,
                                phantom_confidence, causal_density, inference_ms,
                            )

                    except Exception as exc:
                        hgtc_span.set_status_error(str(exc))
                        logger.error("PHANTOM inference error: %s", exc)"""
code = code.replace(hgtc_target, hgtc_repl)

# 5. Indent the remainder of the method (layer 4, fusion, up to return result)
# We can just inject an extra indent level by looking for exact match of Layer 4.

layer4_target = """        # ── Layer 4: Legacy IPSEngine ─────────────────────────────────────"""
layer4_repl = """            # ── Layer 4: Legacy IPSEngine ─────────────────────────────────────"""
code = code.replace(layer4_target, layer4_repl)

fusion_block_target = """        # ── Fusion Decision ───────────────────────────────────────────────
        final_action = self._fuse_decision(
            phantom_is_threat=phantom_is_threat,
            phantom_confidence=phantom_confidence,
            causal_density=causal_density,
            legacy_action_str=legacy_action_str,
        )

        # ── XAI Evidence ─────────────────────────────────────────────────
        latency_ms = (time.perf_counter() - t_start) * 1000
        record = PHANTOMInspectionRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            sbe_available=sbe_avail,
            causal_density=causal_density,
            phantom_class=phantom_class,
            phantom_confidence=phantom_confidence,
            phantom_is_threat=phantom_is_threat,
            inference_ms=inference_ms,
            legacy_action=legacy_action_str,
            final_action=final_action.name,
            latency_ms=latency_ms,
        )

        if final_action == InspectionAction.BLOCK:
            self._total_blocked += 1

        # Resolve threshold here (same logic as _fuse_decision) for severity tagging
        _clf          = self.config.get("classifier", {})
        conf_threshold = _clf.get("confidence_threshold",
                         self.config.get("phantom_confidence_threshold", 0.70))

        from system.core.framework.plugin_base import InspectionFinding
        result = InspectionResult(action=final_action)

        # Always attach phantom metadata to result.metadata (accessible via pipeline)
        result.metadata["phantom"] = record.to_dict()

        # Add InspectionFinding so pipeline.detected counter increments correctly
        if phantom_is_threat:
            severity = "CRITICAL" if phantom_confidence >= conf_threshold else "HIGH"
            result.findings.append(InspectionFinding(
                plugin_name="PHANTOMPlugin",
                severity=severity,
                category=phantom_class,
                description=(
                    f"PHANTOM detected {phantom_class} "
                    f"(conf={phantom_confidence:.3f}, "
                    f"causal_density={causal_density:.3f})"
                ),
                confidence=phantom_confidence,
                recommends_block=(final_action == InspectionAction.BLOCK),
                metadata=record.to_dict(),
            ))

        # Mirror to context.metadata for downstream enrichers / UBA integration
        if context.metadata is None:
            context.metadata = {}
        context.metadata["phantom"] = record.to_dict()

        return result
"""

fusion_block_repl = """            # ── Fusion Decision ───────────────────────────────────────────────
            fusion_span_ctx = self._tel.trace.fusion() if self._tel else _NoOpTracker()
            with fusion_span_ctx as fuse_span:
                final_action = self._fuse_decision(
                    phantom_is_threat=phantom_is_threat,
                    phantom_confidence=phantom_confidence,
                    causal_density=causal_density,
                    legacy_action_str=legacy_action_str,
                )
                fuse_span.set("action", final_action.name)
                root_span.set("action", final_action.name)

            # ── XAI Evidence ─────────────────────────────────────────────────
            latency_ms = (time.perf_counter() - t_start) * 1000
            if self._tel:
                self._tel.metrics.record_pipeline_latency(latency_ms / 1000.0)

            record = PHANTOMInspectionRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                sbe_available=sbe_avail,
                causal_density=causal_density,
                phantom_class=phantom_class,
                phantom_confidence=phantom_confidence,
                phantom_is_threat=phantom_is_threat,
                inference_ms=inference_ms,
                legacy_action=legacy_action_str,
                final_action=final_action.name,
                latency_ms=latency_ms,
            )

            if final_action == InspectionAction.BLOCK:
                self._total_blocked += 1
                if self._tel:
                    self._tel.metrics.record_block(phantom_class)
                    self._tel.log.block(src_ip, dst_ip, phantom_class, phantom_confidence)
            elif phantom_is_threat:
                if self._tel:
                    self._tel.log.allow_low_conf(src_ip, phantom_class, phantom_confidence)

            # Resolve threshold here (same logic as _fuse_decision) for severity tagging
            _clf          = self.config.get("classifier", {})
            conf_threshold = _clf.get("confidence_threshold",
                             self.config.get("phantom_confidence_threshold", 0.70))

            from system.core.framework.plugin_base import InspectionFinding
            result = InspectionResult(action=final_action)

            # Always attach phantom metadata to result.metadata (accessible via pipeline)
            result.metadata["phantom"] = record.to_dict()

            # Add InspectionFinding so pipeline.detected counter increments correctly
            if phantom_is_threat:
                severity = "CRITICAL" if phantom_confidence >= conf_threshold else "HIGH"
                result.findings.append(InspectionFinding(
                    plugin_name="PHANTOMPlugin",
                    severity=severity,
                    category=phantom_class,
                    description=(
                        f"PHANTOM detected {phantom_class} "
                        f"(conf={phantom_confidence:.3f}, "
                        f"causal_density={causal_density:.3f})"
                    ),
                    confidence=phantom_confidence,
                    recommends_block=(final_action == InspectionAction.BLOCK),
                    metadata=record.to_dict(),
                ))

            # Mirror to context.metadata for downstream enrichers / UBA integration
            if context.metadata is None:
                context.metadata = {}
            context.metadata["phantom"] = record.to_dict()

            return result
"""

code = code.replace(fusion_block_target, fusion_block_repl)

# Manually indent lines starting from legacy to the fusion block start
to_indent = """        legacy_action_str = "ALLOW"
        from system.policy.schema import PolicyContext, Action
        if self._ips is not None:
            try:
                policy_ctx = PolicyContext(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=context.src_port,
                    dst_port=context.dst_port,
                    protocol=context.protocol,
                    domain=context.metadata.get("domain") if context.metadata else None,
                    metrics=context.metadata,
                )
                legacy_action = self._ips.evaluate(policy_ctx, payload)
                legacy_action_str = legacy_action.name
            except Exception as exc:
                logger.debug("Legacy IPSEngine error (non-fatal): %s", exc)"""

indented = """            legacy_action_str = "ALLOW"
            from system.policy.schema import PolicyContext, Action
            if self._ips is not None:
                try:
                    policy_ctx = PolicyContext(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=context.src_port,
                        dst_port=context.dst_port,
                        protocol=context.protocol,
                        domain=context.metadata.get("domain") if context.metadata else None,
                        metrics=context.metadata,
                    )
                    legacy_action = self._ips.evaluate(policy_ctx, payload)
                    legacy_action_str = legacy_action.name
                except Exception as exc:
                    logger.debug("Legacy IPSEngine error (non-fatal): %s", exc)"""

code = code.replace(to_indent, indented)

with open(target, "w", encoding="utf-8") as f:
    f.write(code)

print("Patch applied")

