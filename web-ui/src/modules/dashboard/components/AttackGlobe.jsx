/**
 * AttackGlobe.jsx
 * ─────────────────────────────────────────────────────────────
 * 3D Globe component using globe.gl
 * Displays real-time 3D attack flow arcs, origin ripple rings,
 * infrastructure target markers, and interactive threat details.
 * Sourced from live WebSocket feeds + REST APIs
 */
import { useEffect, useRef, useMemo } from 'react';

// ── HQ default coordinates (Taiz, Yemen) ──
export const HQ_COORDS = [13.5795, 44.0206];

export default function AttackGlobe({ arcs = [], targets = [], onSelectArc }) {
  const mountRef = useRef(null);
  const globeRef = useRef(null);

  const displayArcs = useMemo(() => {
    if (Array.isArray(arcs)) return arcs;
    return [];
  }, [arcs]);

  const targetList = useMemo(() => {
    if (Array.isArray(targets)) {
      return targets.map(t => ({
        id: t.id || t.name,
        name: t.name || 'المقر الرئيسي – تعز',
        lat: typeof t.lat === 'number' ? t.lat : HQ_COORDS[0],
        lng: typeof t.lng === 'number' ? t.lng : typeof t.lon === 'number' ? t.lon : HQ_COORDS[1],
        color: t.color || '#00e676',
      }));
    }
    return [];
  }, [targets]);

  const arcsRef = useRef(displayArcs);
  const targetsRef = useRef(targetList);

  useEffect(() => {
    arcsRef.current = displayArcs;
    targetsRef.current = targetList;
    if (globeRef.current) {
      globeRef.current.arcsData(displayArcs);
      globeRef.current.ringsData(displayArcs);
      globeRef.current.pointsData(targetList);
      globeRef.current.htmlElementsData(targetList);
    }
  }, [displayArcs, targetList]);

  useEffect(() => {
    let instance;
    let resizeObserver;

    import('globe.gl').then((mod) => {
      if (!mountRef.current) return;
      const Globe = mod.default;
      instance = Globe()(mountRef.current);
      
      const width = mountRef.current.clientWidth || 400;
      const height = mountRef.current.clientHeight || 370;

      instance
        .globeImageUrl('/textures/earth-night.jpg')
        .backgroundImageUrl('/textures/night-sky.png')

        // ── Arc coordinate accessors ──
        .arcStartLat(d => d.srcLat ?? d.startLat ?? 0)
        .arcStartLng(d => d.srcLng ?? d.startLng ?? 0)
        .arcEndLat(d => d.dstLat ?? d.endLat ?? HQ_COORDS[0])
        .arcEndLng(d => d.dstLng ?? d.endLng ?? HQ_COORDS[1])
        .arcsData(arcsRef.current)
        .arcColor(d => d.color || d.col || '#ef4444')
        .arcDashLength(0.45)
        .arcDashGap(0.18)
        .arcDashAnimateTime(1600)
        .arcStroke(1.4)
        .arcAltitude(0.24)
        .arcLabel(d => `
          <div style="background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(0, 212, 255, 0.35); border-radius: 10px; padding: 10px 14px; font-family: Cairo, sans-serif; direction: rtl; color: #fff; box-shadow: 0 10px 30px rgba(0,0,0,0.6); min-width: 180px;">
            <div style="font-weight: 800; font-size: 0.88rem; color: ${d.color || '#ff4d6d'}; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
              <span>${d.flag || '🌐'}</span>
              <span>${d.country || 'موقع غريب'}</span>
              <span style="opacity: 0.5;">➔</span>
              <span>${d.targetName || 'المقر – تعز'}</span>
            </div>
            <div style="font-size: 0.78rem; color: rgba(255,255,255,0.7); margin-bottom: 2px;">
              النوع: <strong style="color: #fff;">${d.type || 'Intrusion'}</strong>
            </div>
            <div style="font-size: 0.75rem; color: rgba(255,255,255,0.6); font-family: monospace;">
              المصدر: ${d.ip || '—'}
            </div>
            <div style="font-size: 0.72rem; color: #00d4ff; margin-top: 6px; font-weight: 700;">
              انقر لعرض السجل والتفاصيل الكاملة 🔍
            </div>
          </div>
        `)
        .onArcClick((arc) => {
          if (onSelectArc && arc) {
            onSelectArc(arc.raw || arc);
          }
        })

        // ── Origin Ripple Rings ──
        .ringLat(d => d.srcLat ?? d.startLat ?? 0)
        .ringLng(d => d.srcLng ?? d.startLng ?? 0)
        .ringsData(arcsRef.current)
        .ringColor(d => d.color || d.col || '#ef4444')
        .ringMaxRadius(4.8)
        .ringPropagationSpeed(3.2)
        .ringRepeatPeriod(600)
        .onRingClick((ring) => {
          if (onSelectArc && ring) {
            onSelectArc(ring.raw || ring);
          }
        })

        // ── 3D Target Pins ──
        .pointsData(targetsRef.current)
        .pointLat(d => d.lat)
        .pointLng(d => d.lng)
        .pointColor(d => d.color || '#00e676')
        .pointAltitude(0.04)
        .pointRadius(0.35)

        // ── HTML Target Marker Overlay ──
        .htmlLat(d => d.lat)
        .htmlLng(d => d.lng)
        .htmlAltitude(0.02)
        .htmlElementsData(targetsRef.current)
        .htmlElement(d => {
          const el = document.createElement('div');
          el.innerHTML = `
            <div style="display: flex; align-items: center; gap: 6px; background: rgba(0, 230, 118, 0.2); border: 1px solid ${d.color || '#00e676'}; border-radius: 20px; padding: 4px 10px; color: ${d.color || '#00e676'}; font-size: 0.72rem; font-weight: 800; box-shadow: 0 0 16px ${d.color || '#00e676'}; pointer-events: none; direction: rtl; font-family: Cairo, sans-serif; backdrop-filter: blur(4px); white-space: nowrap;">
              <span style="width: 8px; height: 8px; border-radius: 50%; background: ${d.color || '#00e676'}; box-shadow: 0 0 8px ${d.color || '#00e676'}; display: inline-block;"></span>
              ${d.name || 'المقر الرئيسي – تعز 🇾🇪'}
            </div>
          `;
          return el;
        })

        // ── Globe Atmosphere & View ──
        .atmosphereColor('#00d4ff')
        .atmosphereAltitude(0.22)
        .width(width)
        .height(height);

      // Camera view point centered on Taiz, Yemen HQ
      try {
        instance.pointOfView({ lat: 15, lng: 44, altitude: 2.0 }, 1000);
        const controls = instance.controls();
        if (controls) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.5;
        }
      } catch (e) {
        // ignore if controls initialization is async
      }

      globeRef.current = instance;

      // Watch for container resizes and adjust canvas width/height accordingly
      if (window.ResizeObserver) {
        resizeObserver = new ResizeObserver((entries) => {
          for (let entry of entries) {
            const { width, height } = entry.contentRect;
            if (width && height && globeRef.current) {
              globeRef.current.width(width);
              globeRef.current.height(height);
            }
          }
        });
        resizeObserver.observe(mountRef.current);
      }
    });

    return () => {
      if (resizeObserver && mountRef.current) {
        resizeObserver.disconnect();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={mountRef}
      style={{
        width: '100%',
        height: '100%',
        cursor: 'grab',
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    />
  );
}
