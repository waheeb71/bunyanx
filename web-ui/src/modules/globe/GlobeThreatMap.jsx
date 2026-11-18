/**
 * GlobeThreatMap.jsx
 * ─────────────────────────────────────────────────────────────
 * Redesigned 3D Globe Threat Map — Enterprise SOC Command Center
 * Sourced from live WebSocket feeds + REST APIs + Database Telemetry
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Clock } from 'lucide-react';

import { useGlobe } from './hooks/useGlobe';
import { useGlobeStore } from './stores/useGlobeStore';
import { dashboardApi } from '../dashboard/api/dashboardApi';
import { RadarLoader } from '../../components/Shared';

// Subcomponents
import { GlobeCanvas } from './components/GlobeCanvas';
import { GlobeHeaderControls } from './components/GlobeHeaderControls';
import { GlobalSeverityCard } from './components/GlobalSeverityCard';
import { TargetedCountriesCard } from './components/TargetedCountriesCard';
import { AttackTypesCard } from './components/AttackTypesCard';
import { ThreatTimelineCard } from './components/ThreatTimelineCard';
import { LiveThreatFeedTicker } from './components/LiveThreatFeedTicker';
import { ThreatDetailModal } from './components/ThreatDetailModal';

import './GlobeThreatMap.css';

const DEFAULT_TARGETS = [
  { id: 'taiz-hq', name: 'المقر الرئيسي – تعز 🇾🇪', country: 'اليمن', lat: 13.5795, lon: 44.0206, color: '#00e676', flag: '🇾🇪' },
];

export default function GlobeThreatMap() {
  const { threatFeed, statsSummary, isLoading } = useGlobe();
  const setSelectedThreat = useGlobeStore((s) => s.setSelectedThreat);
  const isFeedPaused = useGlobeStore((s) => s.isFeedPaused);

  const [loadingScene, setLoadingScene] = useState(true);
  const [clockStr, setClockStr] = useState('');

  // Fetch infrastructure targets
  const { data: locationData } = useQuery({
    queryKey: ['dashboard_location'],
    queryFn: () => dashboardApi.location().then((res) => res?.data || {}),
    staleTime: 600000,
  });

  const targets = useMemo(() => {
    if (!locationData) return DEFAULT_TARGETS;
    const list = [];
    if (locationData.headquarters) {
      const hq = locationData.headquarters;
      list.push({
        id: 'taiz-hq',
        name: hq.name || 'المقر الرئيسي – تعز 🇾🇪',
        country: hq.country || 'اليمن',
        flag: hq.flag || '🇾🇪',
        lat: hq.lat ?? 13.5795,
        lon: hq.lng ?? 44.0206,
        color: '#00e676',
      });
    }
    if (Array.isArray(locationData.branches)) {
      locationData.branches.forEach((b, i) => {
        list.push({
          id: `branch-${i}`,
          name: b.name || `فرع ${i + 1}`,
          country: b.country || '',
          flag: b.flag || '🌐',
          lat: b.lat ?? 0,
          lon: b.lng ?? 0,
          color: '#00d4ff',
        });
      });
    }
    return list.length > 0 ? list : DEFAULT_TARGETS;
  }, [locationData]);

  // Real-time Clock
  useEffect(() => {
    const tick = () => {
      setClockStr(new Date().toLocaleTimeString('ar-SA', { hour12: false }));
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSceneLoaded = useCallback(() => {
    setLoadingScene(false);
  }, []);

  // Threat feed arcs sourced from unified backend telemetry
  const liveAttacks = useMemo(() => {
    if (isFeedPaused) return [];
    return (threatFeed || []).slice(0, 35);
  }, [threatFeed, isFeedPaused]);

  return (
    <div className="gtm-dashboard" dir="rtl">
      {/* 3D Canvas Background */}
      <GlobeCanvas
        activeAttacks={liveAttacks}
        regionCounts={statsSummary.regions}
        targets={targets}
        onLoaded={handleSceneLoaded}
        onSelectThreat={setSelectedThreat}
      />

      <div className="gtm-overlay" />
      <div className="gtm-scan" />

      {/* Initial Loading Overlay */}
      {loadingScene && (
        <div className="gtm-loading">
          <RadarLoader color="blue" text="جارِ تحميل مركز قيادة الخريطة الأمني..." />
        </div>
      )}

      {/* Top Header Control Bar */}
      <GlobeHeaderControls clockStr={clockStr} />

      {/* Left Sidebar: Threat Ticker & Severity Legend */}
      <div className="gtm-sidebar-left">
        <LiveThreatFeedTicker threatFeed={liveAttacks} onSelectThreat={setSelectedThreat} />

        <div className="gtm-card">
          <div className="gtm-card-header">
            <h3 className="gtm-card-title">مستويات خطورة التهديدات</h3>
          </div>
          <div className="gtm-legend-list">
            <div className="gtm-legend-item">
              <span className="gtm-legend-dot" style={{ background: '#ff4d6d', boxShadow: '0 0 10px #ff4d6d' }} />
              <span className="gtm-legend-label">حرج جداً (Critical)</span>
            </div>
            <div className="gtm-legend-item">
              <span className="gtm-legend-dot" style={{ background: '#ff9800', boxShadow: '0 0 10px #ff9800' }} />
              <span className="gtm-legend-label">خطورة مرتفعة (High)</span>
            </div>
            <div className="gtm-legend-item">
              <span className="gtm-legend-dot" style={{ background: '#ffc107', boxShadow: '0 0 10px #ffc107' }} />
              <span className="gtm-legend-label">خطورة متوسطة (Medium)</span>
            </div>
            <div className="gtm-legend-item">
              <span className="gtm-legend-dot" style={{ background: '#00d4ff', boxShadow: '0 0 10px #00d4ff' }} />
              <span className="gtm-legend-label">منخفض (Low)</span>
            </div>
            <div className="gtm-legend-item">
              <span className="gtm-legend-dot" style={{ background: '#00e676', boxShadow: '0 0 10px #00e676' }} />
              <span className="gtm-legend-label">معلوماتي / تم الحظر</span>
            </div>
          </div>
        </div>
      </div>

      {/* Right Sidebar: Analytics Cards */}
      <div className="gtm-sidebar-right">
        <GlobalSeverityCard severityData={statsSummary.severity} />
        <TargetedCountriesCard topCountries={statsSummary.top_countries} />
        <AttackTypesCard attackTypes={statsSummary.attack_types} />
      </div>

      {/* Bottom Timeline Section & Status Indicator Bar */}
      <div className="gtm-bottom-section">
        <ThreatTimelineCard timelineData={statsSummary.timeline} />

        <div className="gtm-live-indicator-bar">
          <div className="gtm-live-dot-wrap">
            <span className="gtm-live-ping-dot" />
            <span className="gtm-live-text">بث متصل مباشر</span>
          </div>
          <div className="gtm-clock-wrap">
            <Clock size={12} className="gtm-clock-icon" />
            <span className="gtm-clock-text">التحديث الأخير {clockStr}</span>
          </div>
        </div>
      </div>

      {/* Threat Detail Forensic Modal */}
      <ThreatDetailModal />
    </div>
  );
}
