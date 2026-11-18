import { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe, Filter, Maximize2, X, ShieldAlert, Ban, CheckCircle2, Crosshair, MapPin, Activity,
  Plus, Minus, RotateCcw, Volume2, VolumeX, Pause, Play, Palette, Layers, Info
} from 'lucide-react';
import { responseApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';
import { useUnifiedMapData } from '../../../hooks/useUnifiedMapData';
import '../DashboardPro.css';

/**
 * Equirectangular projection: lat/lng → SVG coords in viewBox 0 0 1010 505
 */
function project(lat, lng) {
  const x = ((lng + 180) / 360) * 1010;
  const y = ((90 - lat) / 180) * 505;
  return { x, y };
}

/**
 * Build a curved arc path between two SVG points
 */
function arcPath(sx, sy, ex, ey) {
  const mx = (sx + ex) / 2;
  const dist = Math.sqrt((ex - sx) ** 2 + (ey - sy) ** 2);
  const my = Math.min(sy, ey) - dist * 0.2 - 20;
  return `M ${sx} ${sy} Q ${mx} ${my} ${ex} ${ey}`;
}

const DEFAULT_HQ = { name: 'المقر الرئيسي – تعز 🇾🇪', country: 'اليمن', flag: '🇾🇪', lat: 13.5795, lng: 44.0206 };
const EMPTY_BRANCHES = [];

// Themes Configuration
const MAP_THEMES = {
  cyberpunk: {
    name: 'Cyberpunk Dark',
    landFill: 'url(#land-fill-cyberpunk)',
    stroke: 'rgba(99, 102, 241, 0.3)',
    grid: 'rgba(0,212,255,0.035)',
    containerClass: 'theme-cyberpunk'
  },
  matrix: {
    name: 'Matrix Tactical',
    landFill: 'url(#land-fill-matrix)',
    stroke: 'rgba(16, 185, 129, 0.4)',
    grid: 'rgba(16,185,129,0.05)',
    containerClass: 'theme-matrix'
  },
  hologram: {
    name: 'Holographic Blue',
    landFill: 'url(#land-fill-hologram)',
    stroke: 'rgba(56, 189, 248, 0.45)',
    grid: 'rgba(56,189,248,0.05)',
    containerClass: 'theme-hologram'
  }
};

export default function AttackMap({ liveAlerts, mapStats, mapMode = '2d', onToggleMapMode }) {
  const toast = useToast();
  const [activeArcs, setActiveArcs] = useState([]);
  const [attackOrigins, setAttackOrigins] = useState({});
  const [worldSvg, setWorldSvg] = useState("M 150 120 L 220 110 L 280 140 L 300 190 L 220 220 L 140 180 Z M 210 260 L 280 270 L 310 350 L 260 420 L 210 340 Z M 440 100 L 580 90 L 600 170 L 520 180 L 450 140 Z M 460 210 L 580 220 L 600 320 L 520 370 L 450 280 Z M 620 90 L 920 100 L 950 240 L 820 280 L 650 220 Z M 800 320 L 920 330 L 930 400 L 810 410 Z");
  const [timeframe, setTimeframe] = useState('24h');
  const [filterSev, setFilterSev] = useState('all');
  const [filterCat, setFilterCat] = useState('all');
  const [selectedCountryFilter, setSelectedCountryFilter] = useState(null);
  
  // New Interactive States
  const [mapThemeKey, setMapThemeKey] = useState('cyberpunk');
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [hoveredTarget, setHoveredTarget] = useState(null);

  const [showFilterModal, setShowFilterModal] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isBlocking, setIsBlocking] = useState(false);
  
  // IP Blocking Options State
  const [blockReason, setBlockReason] = useState('malicious_attack');
  const [customReason, setCustomReason] = useState('');
  const [blockDuration, setBlockDuration] = useState('permanent');

  const mapRef = useRef(null);
  const currentTheme = MAP_THEMES[mapThemeKey] || MAP_THEMES.cyberpunk;

  // ── Load real world map SVG ──
  useEffect(() => {
    fetch('/textures/land-110m.json')
      .then(r => r.json())
      .then(topology => {
        const land = topology.objects?.land;
        if (!land) return;
        const arcsData = topology.arcs;
        const transform = topology.transform;

        function decodeArc(arcIdx) {
          const isReverse = arcIdx < 0;
          const idx = isReverse ? ~arcIdx : arcIdx;
          const arc = arcsData[idx];
          const points = [];
          let x = 0, y = 0;
          arc.forEach(([dx, dy]) => {
            x += dx;
            y += dy;
            const lng = x * transform.scale[0] + transform.translate[0];
            const lat = y * transform.scale[1] + transform.translate[1];
            const p = project(lat, lng);
            points.push(`${p.x.toFixed(1)},${p.y.toFixed(1)}`);
          });
          if (isReverse) points.reverse();
          return points;
        }

        function geometryToPath(geom) {
          if (geom.type === 'Polygon') {
            return geom.arcs.map(ring =>
              ring.flatMap(arcIdx => decodeArc(arcIdx)).join(' L ')
            ).map(d => `M ${d} Z`).join(' ');
          }
          if (geom.type === 'MultiPolygon') {
            return geom.arcs.map(polygon =>
              polygon.map(ring =>
                ring.flatMap(arcIdx => decodeArc(arcIdx)).join(' L ')
              ).map(d => `M ${d} Z`).join(' ')
            ).join(' ');
          }
          if (geom.type === 'GeometryCollection') {
            return geom.geometries.map(g => geometryToPath(g)).join(' ');
          }
          return '';
        }

        const pathD = geometryToPath(land);
        if (pathD) setWorldSvg(pathD);
      })
      .catch(() => {});
  }, []);

  // Fullscreen listener
  useEffect(() => {
    const handleFS = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handleFS);
    return () => document.removeEventListener('fullscreenchange', handleFS);
  }, []);

  const toggleFullscreen = () => {
    if (!mapRef.current) return;
    if (!document.fullscreenElement) {
      mapRef.current.requestFullscreen().catch(err => {
        toast.error(`تعذر الدخول في وضع ملء الشاشة: ${err.message}`);
      });
    } else {
      document.exitFullscreen();
    }
  };

  // Zoom controls
  const handleZoomIn = () => setZoomLevel(prev => Math.min(prev + 0.3, 3));
  const handleZoomOut = () => setZoomLevel(prev => Math.max(prev - 0.3, 1));
  const handleResetZoom = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
  };

  // Unified Backend Threat Data
  const mapData = useUnifiedMapData({
    timeframe,
    severityFilter: filterSev,
    categoryFilter: filterCat,
    refetchInterval: 5000,
  });

  const hq = useMemo(() => mapData.targets[0] || DEFAULT_HQ, [mapData.targets]);
  const branches = useMemo(() => mapData.targets.slice(1) || EMPTY_BRANCHES, [mapData.targets]);
  const hqProj = project(hq.lat, hq.lng);

  const lastProcessedId = useRef(null);

  // Update arcs feed
  useEffect(() => {
    if (isPaused) return;
    if (mapData.arcs && Array.isArray(mapData.arcs)) {
      const initialArcs = mapData.arcs.slice(0, 25).map((threat, idx) => {
        const start = project(threat.srcLat || 0, threat.srcLng || 0);
        const end = project(threat.dstLat || hq.lat, threat.dstLng || hq.lng);
        return {
          id: threat.id || `threat-${idx}`,
          start, end,
          color: threat.color || threat.col || '#ef4444',
          ip: threat.ip || '—',
          country: threat.country || 'Unknown',
          flag: threat.flag || '🌐',
          type: threat.type || 'Intrusion',
          sev: threat.severity || 'high',
          targetName: hq.name,
          raw: threat,
        };
      });
      setActiveArcs(initialArcs);

      const origins = {};
      mapData.arcs.forEach(t => {
        if (t.country && t.country !== 'Unknown' && t.country !== 'غير معروف') {
          origins[t.country] = (origins[t.country] || 0) + 1;
        }
      });
      setAttackOrigins(origins);
    }
  }, [mapData.arcs, hq.lat, hq.lng, hq.name, isPaused]);

  // Live alert incoming stream
  useEffect(() => {
    if (isPaused || !liveAlerts || liveAlerts.length === 0) return;
    const latest = liveAlerts[0];
    if (latest.id === lastProcessedId.current) return;
    lastProcessedId.current = latest.id;

    if (filterSev !== 'all' && (latest.severity || '').toLowerCase() !== filterSev.toLowerCase()) return;
    if (filterCat !== 'all' && !(latest.category || '').toLowerCase().includes(filterCat.toLowerCase())) return;

    const targets = [hq, ...branches];
    const targetNode = targets[Math.floor(Math.random() * targets.length)];
    const srcLat = +(latest.src_lat || latest.latitude || 0);
    const srcLng = +(latest.src_lng || latest.longitude || 0);

    if (srcLat === 0 && srcLng === 0) return;

    const start = project(srcLat, srcLng);
    const end = project(targetNode.lat, targetNode.lng);
    const arcId = `live-${latest.id}-${Date.now()}`;

    const newArc = {
      id: arcId,
      start, end,
      color: latest.severity === 'critical' ? '#ef4444' : latest.severity === 'high' ? '#f97316' : '#eab308',
      ip: latest.src || latest.src_ip || '—',
      country: latest.country || 'Unknown',
      flag: latest.flag || '🌐',
      type: latest.category || latest.event_type || 'Intrusion',
      sev: latest.severity || 'medium',
      targetName: targetNode.name,
      raw: latest,
    };

    setActiveArcs(prev => [...prev.slice(-25), newArc]);

    if (latest.country && latest.country !== 'Unknown' && latest.country !== 'غير معروف') {
      setAttackOrigins(prev => ({ ...prev, [latest.country]: (prev[latest.country] || 0) + 1 }));
    }

    const timer = setTimeout(() => setActiveArcs(prev => prev.filter(a => a.id !== arcId)), 5000);
    return () => clearTimeout(timer);
  }, [liveAlerts, branches, hq, filterSev, filterCat, isPaused]);

  // Filtered arcs by country
  const displayedArcs = useMemo(() => {
    if (!selectedCountryFilter) return activeArcs;
    return activeArcs.filter(a => a.country === selectedCountryFilter);
  }, [activeArcs, selectedCountryFilter]);

  // Top attack origins
  const topOrigins = useMemo(() => {
    const total = Object.values(attackOrigins).reduce((a, b) => a + b, 0) || 1;
    const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6'];
    return Object.entries(attackOrigins)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([country, count], i) => ({ country, count, pct: Math.round((count / total) * 100), color: COLORS[i] || '#64748b' }));
  }, [attackOrigins]);

  const stats = useMemo(() => {
    const raw = mapStats || {};
    return {
      attacks_today: raw.attacks_today || { value: String(raw.total ?? '0'), change: '0%' },
      targeted_countries: raw.targeted_countries || { value: String(raw.countries ?? '0'), change: '0' },
      active_attacks: raw.active_attacks || { value: String(raw.blocked ?? '0'), change: '0' },
      data_exfiltration: raw.data_exfiltration || { value: '0 B', change: '0%' },
    };
  }, [mapStats]);

  // Advanced Block IP handler
  const handleBlockIp = async () => {
    if (!selectedThreat || !selectedThreat.ip || selectedThreat.ip === '—') return;
    const ip = selectedThreat.ip;
    const reasonText = blockReason === 'custom' ? customReason : blockReason;
    setIsBlocking(true);

    try {
      await responseApi.triggerAction('INC-MAP', {
        action: 'block_ip',
        ip: ip,
        reason: reasonText,
        duration: blockDuration,
        label: `Block IP ${ip} (${blockDuration})`
      });
      toast.success(`تم حظر IP الهجوم ${ip} بنجاح عبر جدار الحماية (${blockDuration})`, 'تم الحظر');
      setSelectedThreat(null);
    } catch (err) {
      toast.error(`تعذر حظر IP: ${err.message || 'حدث خطأ في النظام'}`);
    } finally {
      setIsBlocking(false);
    }
  };

  // Grid lines
  const gridLines = useMemo(() => {
    const lines = [];
    for (let lat = -60; lat <= 80; lat += 20) {
      const pts = [];
      for (let lng = -180; lng <= 180; lng += 10) {
        const p = project(lat, lng);
        pts.push(`${p.x.toFixed(0)},${p.y.toFixed(0)}`);
      }
      lines.push(<polyline key={`lat-${lat}`} points={pts.join(' ')} fill="none" stroke={currentTheme.grid} strokeWidth="0.5" />);
    }
    for (let lng = -180; lng <= 180; lng += 30) {
      const pts = [];
      for (let lat = -80; lat <= 85; lat += 5) {
        const p = project(lat, lng);
        pts.push(`${p.x.toFixed(0)},${p.y.toFixed(0)}`);
      }
      lines.push(<polyline key={`lng-${lng}`} points={pts.join(' ')} fill="none" stroke={currentTheme.grid} strokeWidth="0.5" />);
    }
    return lines;
  }, [currentTheme.grid]);

  return (
    <div className={`pro-map-card ${isFullscreen ? 'fullscreen-map' : ''}`} ref={mapRef}>
      {/* Header */}
      <div className="pro-map-header">
        <div className="pro-map-title">
          <span className="live-dot" />
          <span>خريطة الهجمات السيبرانية العالمية</span>
          <span className="live-badge">مباشر</span>

          {selectedCountryFilter && (
            <span
              style={{ fontSize: '0.68rem', color: '#00d4ff', background: 'rgba(0,212,255,0.12)', padding: '2px 8px', borderRadius: 4, cursor: 'pointer', border: '1px solid rgba(0,212,255,0.3)', display: 'flex', alignItems: 'center', gap: 4 }}
              onClick={() => setSelectedCountryFilter(null)}
              title="إلغاء التصفية بالدولة"
            >
              دولة: {selectedCountryFilter} <X size={11} />
            </span>
          )}

          {(filterSev !== 'all' || filterCat !== 'all') && (
            <span style={{ fontSize: '0.68rem', color: '#38bdf8', background: 'rgba(56,189,248,0.1)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(56,189,248,0.3)' }}>
              مصفى: {filterSev} / {filterCat}
            </span>
          )}
        </div>

        <div className="pro-map-controls">
          {/* 2D / 3D Mode Toggle Pill */}
          {onToggleMapMode && (
            <div className="map-mode-toggle">
              <button
                type="button"
                className={`map-mode-btn ${mapMode === '2d' ? 'active' : ''}`}
                onClick={() => onToggleMapMode('2d')}
              >
                <Layers size={12} />
                خريطة الهجمات تفاعلية (2D Attack Map)
              </button>
              <button
                type="button"
                className={`map-mode-btn ${mapMode === '3d' ? 'active' : ''}`}
                onClick={() => onToggleMapMode('3d')}
              >
                <Globe size={12} />
                كرة أرضية (3D Globe)
              </button>
            </div>
          )}
          {/* Pause / Play */}
          <button
            className={`map-btn ${isPaused ? 'active-btn' : ''}`}
            title={isPaused ? 'استئناف البث الحي' : 'إيقاف الحركة مؤقتاً'}
            onClick={() => setIsPaused(!isPaused)}
          >
            {isPaused ? <Play size={13} className="text-amber-400" /> : <Pause size={13} />}
          </button>

          {/* Sound Toggle */}
          <button
            className={`map-btn ${soundEnabled ? 'active-btn' : ''}`}
            title={soundEnabled ? 'إيقاف الأصوات' : 'تفعيل التنبيهات الصوتية'}
            onClick={() => setSoundEnabled(!soundEnabled)}
          >
            {soundEnabled ? <Volume2 size={13} className="text-emerald-400" /> : <VolumeX size={13} />}
          </button>

          {/* Theme Selector */}
          <select
            className="map-select"
            value={mapThemeKey}
            onChange={(e) => setMapThemeKey(e.target.value)}
            title="تغيير ثيم الخريطة"
          >
            <option value="cyberpunk">Cyberpunk Dark</option>
            <option value="matrix">Matrix Green</option>
            <option value="hologram">Hologram Blue</option>
          </select>

          {/* Timeframe */}
          <select
            className="map-select"
            value={timeframe}
            onChange={(e) => setTimeframe(e.target.value)}
          >
            <option value="24h">آخر 24 ساعة</option>
            <option value="12h">آخر 12 ساعة</option>
            <option value="1h">آخر ساعة</option>
            <option value="7d">آخر 7 أيام</option>
          </select>

          {/* Filter Modal Button */}
          <button
            className={`map-btn ${showFilterModal ? 'active-btn' : ''}`}
            title="تصفية خريطة الهجمات"
            onClick={() => setShowFilterModal(true)}
          >
            <Filter size={13} />
          </button>

          {/* Fullscreen Toggle */}
          <button
            className="map-btn"
            title={isFullscreen ? 'خروج من ملء الشاشة' : 'ملء الشاشة'}
            onClick={toggleFullscreen}
          >
            <Maximize2 size={13} />
          </button>
        </div>
      </div>

      {/* Map Container */}
      <div className={`pro-map-container ${currentTheme.containerClass}`}>
        
        {/* Live Attack Ticker Bar */}
        {activeArcs.length > 0 && (
          <div className="pro-map-ticker-bar">
            <div className="ticker-label">
              <Activity size={12} className="animate-pulse" />
              <span>هجوم متبوع:</span>
            </div>
            <div className="ticker-stream">
              <div className="ticker-item-content">
                {activeArcs.slice(-8).map(arc => (
                  <div key={`tick-${arc.id}`} className="ticker-chip" onClick={() => setSelectedThreat(arc)} style={{ cursor: 'pointer' }}>
                    <span>{arc.flag}</span>
                    <span style={{ color: arc.color, fontWeight: 700 }}>{arc.ip}</span>
                    <span style={{ color: '#94a3b8' }}>[{arc.type}]</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Zoom Controls */}
        <div className="map-zoom-controls">
          <button className="zoom-btn" onClick={handleZoomIn} title="تكبير (+)"><Plus size={13} /></button>
          <button className="zoom-btn" onClick={handleZoomOut} title="تصغير (-)"><Minus size={13} /></button>
          <button className="zoom-btn" onClick={handleResetZoom} title="إعادة الضبط"><RotateCcw size={12} /></button>
        </div>

        {/* Map SVG */}
        <svg className="pro-map-svg" viewBox="0 0 1010 505" preserveAspectRatio="xMidYMid slice">
          <defs>
            <filter id="marker-glow-r" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="marker-glow-b" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="arc-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="2" />
            </filter>

            {/* Gradient Definitions */}
            <radialGradient id="land-fill-cyberpunk" cx="50%" cy="50%" r="70%">
              <stop offset="0%" stopColor="#1c2446" />
              <stop offset="100%" stopColor="#0f1428" />
            </radialGradient>
            <radialGradient id="land-fill-matrix" cx="50%" cy="50%" r="70%">
              <stop offset="0%" stopColor="#064e3b" />
              <stop offset="100%" stopColor="#022c22" />
            </radialGradient>
            <radialGradient id="land-fill-hologram" cx="50%" cy="50%" r="70%">
              <stop offset="0%" stopColor="#075985" />
              <stop offset="100%" stopColor="#0c4a6e" />
            </radialGradient>

            <filter id="land-shadow" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="4" stdDeviation="5" floodColor="#000" floodOpacity="0.7" />
            </filter>

            {['ef4444', 'f97316', 'eab308', '3b82f6', '10b981'].map(color => (
              <marker
                key={color}
                id={`arrow-${color}`}
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill={`#${color}`} opacity="0.65" />
              </marker>
            ))}
          </defs>

          {/* Scalable Transform Layer */}
          <g transform={`translate(${505 * (1 - zoomLevel) + panOffset.x}, ${252.5 * (1 - zoomLevel) + panOffset.y}) scale(${zoomLevel})`}>
            {/* Background grid */}
            <g>{gridLines}</g>

            {/* World land masses SVG */}
            {worldSvg && (
              <path
                d={worldSvg}
                fill={currentTheme.landFill}
                stroke={currentTheme.stroke}
                strokeWidth="0.75"
                strokeLinejoin="round"
                filter="url(#land-shadow)"
              />
            )}

            {/* Region labels */}
            <text x="150" y="160" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">NORTH AMERICA</text>
            <text x="220" y="340" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">SOUTH AMERICA</text>
            <text x="470" y="145" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">EUROPE</text>
            <text x="490" y="270" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">AFRICA</text>
            <text x="660" y="140" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">ASIA</text>
            <text x="790" y="370" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="700" fontFamily="monospace" letterSpacing="2">AUSTRALIA</text>

            {/* Attack Arcs */}
            <g>
              {(displayedArcs || []).map(arc => {
                if (!arc?.start?.x || !arc?.end?.x) return null;
                const color = arc.color || '#ef4444';
                const d = arcPath(arc.start.x, arc.start.y, arc.end.x, arc.end.y);
                return (
                  <g key={arc.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedThreat(arc)}>
                    <path d={d} fill="none" stroke={color} strokeWidth="6" opacity="0.06" filter="url(#arc-glow)" />
                    <path d={d} fill="none" stroke={color} strokeWidth="1.4" strokeOpacity="0.3" markerEnd={`url(#arrow-${color.replace('#', '')})`} />
                    <path
                      d={d}
                      fill="none"
                      stroke={color}
                      strokeWidth="2.8"
                      strokeDasharray="18, 280"
                      strokeLinecap="round"
                      className={isPaused ? '' : 'map-arc-animation'}
                    />
                    <circle cx={arc.start.x} cy={arc.start.y} r="3.5" fill={color}>
                      {!isPaused && <animate attributeName="r" from="2" to="12" dur="1.4s" repeatCount="indefinite" />}
                      {!isPaused && <animate attributeName="opacity" from="0.7" to="0" dur="1.4s" repeatCount="indefinite" />}
                    </circle>
                    <circle cx={arc.start.x} cy={arc.start.y} r="2.5" fill={color} />
                    <circle cx={arc.end.x} cy={arc.end.y} r="4.5" fill="none" stroke={color} strokeWidth="1.5">
                      {!isPaused && <animate attributeName="r" from="3" to="16" dur="1.2s" repeatCount="indefinite" />}
                      {!isPaused && <animate attributeName="opacity" from="0.6" to="0" dur="1.2s" repeatCount="indefinite" />}
                    </circle>
                  </g>
                );
              })}
            </g>

            {/* HQ Marker */}
            <g
              filter="url(#marker-glow-r)"
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredTarget({ name: hq.name, type: 'المقر الرئيسي', count: activeArcs.length, lat: hq.lat, lng: hq.lng })}
              onMouseLeave={() => setHoveredTarget(null)}
              onClick={() => toast.info(`المقر الرئيسي – تعز: تم رصد ${activeArcs.length} تنبيه هجوم استهدف المقر`)}
            >
              <circle cx={hqProj.x} cy={hqProj.y} r="6" fill="#ef4444" />
              <circle cx={hqProj.x} cy={hqProj.y} r="10" fill="none" stroke="#ef4444" strokeWidth="1.5" opacity="0.5">
                {!isPaused && <animate attributeName="r" from="7" to="18" dur="2s" repeatCount="indefinite" />}
                {!isPaused && <animate attributeName="opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />}
              </circle>
            </g>

            {/* Branch Markers */}
            {branches.map(branch => {
              const p = project(branch.lat, branch.lng);
              return (
                <g
                  key={branch.name}
                  filter="url(#marker-glow-b)"
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={() => setHoveredTarget({ name: branch.name, type: 'فرع محمي', count: activeArcs.filter(a => a.targetName === branch.name).length, lat: branch.lat, lng: branch.lng })}
                  onMouseLeave={() => setHoveredTarget(null)}
                  onClick={() => toast.info(`فرع ${branch.name}: الموقع المحمي نشط`)}
                >
                  <circle cx={p.x} cy={p.y} r="4.5" fill="#3b82f6" />
                  <circle cx={p.x} cy={p.y} r="9" fill="none" stroke="#3b82f6" strokeWidth="1.2" opacity="0.4">
                    {!isPaused && <animate attributeName="r" from="6" to="15" dur="2s" repeatCount="indefinite" />}
                    {!isPaused && <animate attributeName="opacity" from="0.4" to="0" dur="2s" repeatCount="indefinite" />}
                  </circle>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Label overlays */}
        <div className="map-marker" style={{ left: `${(hqProj.x / 1010) * 100}%`, top: `${(hqProj.y / 505) * 100}%` }}>
          <div className="marker-label" style={{ borderColor: 'rgba(239,68,68,0.3)' }}>
            <span>{hq.flag}</span>
            <span className="name">{hq.name}</span>
          </div>

          {hoveredTarget?.name === hq.name && (
            <div className="map-target-tooltip">
              <span className="tt-title">🇾🇪 {hq.name}</span>
              <span className="tt-sub">هجمات مستهدِفة: {activeArcs.length}</span>
            </div>
          )}
        </div>

        {branches.map(branch => {
          const p = project(branch.lat, branch.lng);
          return (
            <div key={branch.name} className="map-marker" style={{ left: `${(p.x / 1010) * 100}%`, top: `${(p.y / 505) * 100}%` }}>
              <div className="marker-label">
                <span>{branch.flag}</span>
                <span className="name">{branch.name}</span>
              </div>
            </div>
          );
        })}

        {/* Top Origin Overlay */}
        <div className="pro-map-origin-overlay">
          <span className="overlay-hdr">أعلى مصادر الهجمات (انقر للتصفية)</span>
          <div className="overlay-list">
            {topOrigins.length > 0 ? (
              topOrigins.map(o => (
                <div
                  key={o.country}
                  className="overlay-item"
                  style={{
                    cursor: 'pointer',
                    background: selectedCountryFilter === o.country ? 'rgba(56,189,248,0.15)' : undefined,
                    padding: '2px 4px',
                    borderRadius: 4
                  }}
                  onClick={() => {
                    if (selectedCountryFilter === o.country) {
                      setSelectedCountryFilter(null);
                      toast.info(`إلغاء التصفية بالدولة`);
                    } else {
                      setSelectedCountryFilter(o.country);
                      toast.info(`عرض هجمات ${o.country} فقط (${o.count} ضربة)`);
                    }
                  }}
                >
                  <span className="dot" style={{ backgroundColor: o.color }} />
                  <span className="country">{o.country}</span>
                  <span className="value">{o.pct}%</span>
                </div>
              ))
            ) : (
              <div style={{ color: 'rgba(255,255,255,0.15)', fontSize: '0.65rem', textAlign: 'center', padding: '4px 0' }}>
                في انتظار البيانات...
              </div>
            )}
          </div>
        </div>

        {/* Bottom Tactical Stats */}
        <div className="pro-map-bottom-tactical">
          <div className="tactical-stat">
            <span className="label">ATTACKS TODAY</span>
            <span className="val">
              {stats?.attacks_today?.value || '0'}
              <span className="diff red">{stats?.attacks_today?.change || '0%'}</span>
            </span>
          </div>
          <div className="tactical-stat">
            <span className="label">TARGETED COUNTRIES</span>
            <span className="val">
              {stats?.targeted_countries?.value || '0'}
              <span className="diff blue">{stats?.targeted_countries?.change || '0'}</span>
            </span>
          </div>
          <div className="tactical-stat">
            <span className="label">ACTIVE ATTACKS</span>
            <span className="val">
              {stats?.active_attacks?.value || '0'}
              <span className="diff purple">{stats?.active_attacks?.change || '0'}</span>
            </span>
          </div>
          <div className="tactical-stat">
            <span className="label">DATA EXFILTRATION</span>
            <span className="val">
              {stats?.data_exfiltration?.value || '0 B'}
              <span className="diff green">{stats?.data_exfiltration?.change || '0%'}</span>
            </span>
          </div>
        </div>
      </div>

      {/* Filter Modal */}
      <AnimatePresence>
        {showFilterModal && (
          <div className="map-modal-backdrop" onClick={() => setShowFilterModal(false)}>
            <motion.div
              className="map-filter-modal"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              dir="rtl"
            >
              <div className="modal-hdr">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Filter size={16} className="text-cyan-400" />
                  <span style={{ color: '#fff', fontWeight: 800 }}>تصفية خريطة الهجمات المباشرة</span>
                </div>
                <button className="close-btn" onClick={() => setShowFilterModal(false)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: 6 }}>مستوى الخطورة</label>
                  <select
                    className="modal-select"
                    value={filterSev}
                    onChange={(e) => setFilterSev(e.target.value)}
                  >
                    <option value="all">جميع المستويات</option>
                    <option value="critical">حرج (Critical)</option>
                    <option value="high">عالي (High)</option>
                    <option value="medium">متوسط (Medium)</option>
                    <option value="low">منخفض (Low)</option>
                  </select>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: 6 }}>تصنيف الهجوم</label>
                  <select
                    className="modal-select"
                    value={filterCat}
                    onChange={(e) => setFilterCat(e.target.value)}
                  >
                    <option value="all">جميع التصنيفات</option>
                    <option value="waf">WAF - جدار التطبيقات</option>
                    <option value="ids">IDS/IPS - كشف التسلل</option>
                    <option value="dlp">DLP - منع التسريب</option>
                    <option value="malware">Malware - البرمجيات الخبيثة</option>
                    <option value="dns">DNS - حماية النطاقات</option>
                  </select>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 20 }}>
                  <button
                    className="modal-btn-primary"
                    onClick={() => {
                      setShowFilterModal(false);
                      toast.success('تم تطبيق الفلاتر على الخريطة بنجاح');
                    }}
                  >
                    تطبيق الفلترة
                  </button>

                  <button
                    className="modal-btn-secondary"
                    onClick={() => {
                      setFilterSev('all');
                      setFilterCat('all');
                      setSelectedCountryFilter(null);
                      setShowFilterModal(false);
                      toast.info('تم إعادة ضبط الفلاتر');
                    }}
                  >
                    إعادة ضبط
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Enhanced Threat Inspection & IP Blocking Modal */}
      <AnimatePresence>
        {selectedThreat && (
          <div className="map-modal-backdrop" onClick={() => setSelectedThreat(null)}>
            <motion.div
              className="threat-inspect-modal"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              dir="rtl"
              style={{ maxWidth: 460 }}
            >
              <div className="modal-hdr">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldAlert size={18} style={{ color: selectedThreat.color }} />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>تفاصيل الهجوم & إجراءات الحظر</span>
                </div>
                <button className="close-btn" onClick={() => setSelectedThreat(null)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div className="threat-inspect-grid" style={{ marginBottom: 16 }}>
                  <div className="inspect-field">
                    <span className="lbl">عنوان المصدر (IP):</span>
                    <span className="val mono">{selectedThreat.ip}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">الدولة المصدر:</span>
                    <span className="val">{selectedThreat.flag} {selectedThreat.country}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">الهدف المستهدف:</span>
                    <span className="val">{selectedThreat.targetName}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">مستوى الخطورة:</span>
                    <span className="val" style={{ color: selectedThreat.color, fontWeight: 700 }}>
                      {selectedThreat.sev?.toUpperCase() || 'HIGH'}
                    </span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">نوع التهديد:</span>
                    <span className="val">{selectedThreat.type}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">التوقيت:</span>
                    <span className="val mono">{new Date().toLocaleTimeString('ar-SA')}</span>
                  </div>
                </div>

                {/* Enhanced IP Block Options */}
                <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: 12, marginBottom: 16 }}>
                  <span style={{ display: 'block', fontSize: '0.75rem', fontWeight: 700, color: '#f87171', marginBottom: 8 }}>
                    إعدادات حظر IP المباشر:
                  </span>

                  <div style={{ marginBottom: 10 }}>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: 4 }}>سبب الحظر:</label>
                    <select
                      className="modal-select"
                      value={blockReason}
                      onChange={(e) => setBlockReason(e.target.value)}
                    >
                      <option value="malicious_attack">هجوم اختراق دائم (Malicious Intrusion)</option>
                      <option value="brute_force">محاولات كسر كلمة السر (Brute Force Attack)</option>
                      <option value="data_leak">محاولة تسريب بيانات (DLP Exfiltration)</option>
                      <option value="suspicious_recon">سلوك استطلاع مشبوه (Suspicious Reconnaissance)</option>
                      <option value="custom">سبب مخصص...</option>
                    </select>
                  </div>

                  {blockReason === 'custom' && (
                    <div style={{ marginBottom: 10 }}>
                      <input
                        type="text"
                        placeholder="أدخل سبب الحظر المخصص..."
                        value={customReason}
                        onChange={(e) => setCustomReason(e.target.value)}
                        style={{
                          width: '100%',
                          background: 'rgba(15, 23, 42, 0.8)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: 6,
                          padding: '6px 10px',
                          color: '#fff',
                          fontSize: '0.75rem'
                        }}
                      />
                    </div>
                  )}

                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: 4 }}>مدة الحظر:</label>
                    <select
                      className="modal-select"
                      value={blockDuration}
                      onChange={(e) => setBlockDuration(e.target.value)}
                    >
                      <option value="permanent">حظر دائم (Permanent)</option>
                      <option value="24h">24 ساعة</option>
                      <option value="12h">12 ساعة</option>
                      <option value="1h">ساعة واحدة</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    className="modal-btn-danger"
                    disabled={isBlocking}
                    onClick={handleBlockIp}
                  >
                    <Ban size={15} />
                    {isBlocking ? 'جاري الحظر...' : `حظر IP المصدر (${selectedThreat.ip})`}
                  </button>
                  <button
                    className="modal-btn-secondary"
                    onClick={() => setSelectedThreat(null)}
                  >
                    إغلاق النافذة
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
