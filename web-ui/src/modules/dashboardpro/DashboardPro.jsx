import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  AlertTriangle,
  Users,
  Monitor,
  Search,
  Bell,
  CircleDot,
  Clock,
  RefreshCw,
  Download,
  Filter,
  X,
  Calendar,
} from 'lucide-react';

import './DashboardPro.css';

// API Services
import {
  dashboardApi,
  systemApi,
  responseApi
} from '../../services/api';

// Zustand Stores
import { useLiveFeedStore } from '../../stores/liveFeedStore';
import { useAlertStore } from '../../stores/alertStore';
import { useToast } from '../../components/Toast';

// Widgets
import StatCard from './widgets/StatCard';
import AttackMap from './widgets/AttackMap';
import AlertsSeverityDonut from './widgets/AlertsSeverityDonut';
import AlertsTrendArea from './widgets/AlertsTrendArea';
import LatestAlertsTable from './widgets/LatestAlertsTable';
import ActiveIncidentsList from './widgets/ActiveIncidentsList';
import TopServicesProgress from './widgets/TopServicesProgress';
import SystemHealthGauge from './widgets/SystemHealthGauge';

// Stable empty fallbacks
const EMPTY_FEED = [];
const EMPTY_HISTORY = [];
const NOOP = () => {};

export default function DashboardPro() {
  const toast = useToast();

  // Zustand live stores
  const _alertsFeed    = useLiveFeedStore(s => s.alertsFeed);
  const _trafficHistory = useLiveFeedStore(s => s.trafficHistory);
  const _unreadCount   = useAlertStore(s => s.unreadCount);
  const _clearUnread   = useAlertStore(s => s.clearUnread);

  // Apply fallbacks with stable references
  const alertsFeed    = _alertsFeed    ?? EMPTY_FEED;
  const trafficHistory = _trafficHistory ?? EMPTY_HISTORY;
  const unreadCount   = _unreadCount   ?? 0;
  const clearUnread   = _clearUnread   ?? NOOP;

  // Global Timeframe & Filter states
  const [globalTimeframe, setGlobalTimeframe] = useState('24h');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [showNotificationDrawer, setShowNotificationDrawer] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);

  // ── Real API Queries with query params ──
  const kpiQuery = useQuery({
    queryKey: ['dashboard_kpi_telemetry', globalTimeframe],
    queryFn: () => dashboardApi.kpi({ timeframe: globalTimeframe }).then(r => r?.data || {}),
    refetchInterval: 5000,
  });

  const mapStatsQuery = useQuery({
    queryKey: ['dashboard_map_stats_overlay', globalTimeframe],
    queryFn: () => dashboardApi.mapStats({ timeframe: globalTimeframe }).then(r => r?.data || {}),
    refetchInterval: 5000,
  });

  const detailedHealthQuery = useQuery({
    queryKey: ['dashboard_detailed_health_states'],
    queryFn: () => systemApi.healthDetailed().then(r => r?.data || {}),
    refetchInterval: 10000,
  });

  const incidentsQuery = useQuery({
    queryKey: ['dashboard_incidents_list', globalTimeframe],
    queryFn: () => responseApi.incidents().then(r => r?.data || []),
    refetchInterval: 5000,
  });

  // Manual refresh trigger
  const isFetchingAny = kpiQuery.isFetching || mapStatsQuery.isFetching || incidentsQuery.isFetching;
  const handleManualRefresh = () => {
    kpiQuery.refetch();
    mapStatsQuery.refetch();
    detailedHealthQuery.refetch();
    incidentsQuery.refetch();
    toast.success('تم إرسال طلب تحديث المؤشرات المباشرة للباك إند');
  };

  // Export Executive Report
  const handleExportExecutiveReport = () => {
    const reportData = {
      timestamp: new Date().toISOString(),
      timeframe: globalTimeframe,
      kpis: kpiQuery.data || {},
      mapStats: mapStatsQuery.data || {},
      incidentsCount: Array.isArray(incidentsQuery.data) ? incidentsQuery.data.length : 0,
      recentAlertsCount: (alertsFeed || []).length,
    };
    const jsonStr = JSON.stringify(reportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SOC_Executive_Report_${globalTimeframe}_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setShowExportModal(false);
    toast.success('تم تصدير التقرير التنفيذي بنجاح');
  };

  // ── KPIs Defensive Formatting ──
  const kpis = useMemo(() => {
    const raw = kpiQuery.data || {};
    return {
      total_alerts: raw.total_alerts || { value: '0', change: '0%', is_positive: true },
      critical_alerts: raw.critical_alerts || { value: '0', change: '0%', is_positive: true },
      active_incidents: raw.active_incidents || { value: '0', change: '0%', is_positive: true },
      assets_monitored: raw.assets_monitored || { value: '0', change: '0%', is_positive: true },
      endpoints_connected: raw.endpoints_connected || { value: '0', change: '0%', is_positive: true },
      active_users: raw.active_users || { value: '0', change: '0%', is_positive: true },
    };
  }, [kpiQuery.data]);

  const sparkAlerts = useMemo(() => {
    const list = Array.isArray(trafficHistory) ? trafficHistory : [];
    return list.length > 0
      ? list.map((h, i) => ({ id: i, val: h?.blocks || 0 }))
      : [{ id: 0, val: 0 }];
  }, [trafficHistory]);

  const sparkTraffic = useMemo(() => {
    const list = Array.isArray(trafficHistory) ? trafficHistory : [];
    return list.length > 0
      ? list.map((h, i) => ({ id: i, val: h?.reqs || 0 }))
      : [{ id: 0, val: 0 }];
  }, [trafficHistory]);

  const sparkSystem = useMemo(() => {
    const list = Array.isArray(trafficHistory) ? trafficHistory : [];
    return list.length > 0
      ? list.map((h, i) => ({ id: i, val: h?.active_users || 0 }))
      : [{ id: 0, val: 0 }];
  }, [trafficHistory]);

  const sparkAlertsTail = useMemo(() => sparkAlerts.slice(-10), [sparkAlerts]);
  const sparkTrafficTail = useMemo(() => sparkTraffic.slice(-8), [sparkTraffic]);

  const statsCards = useMemo(() => [
    {
      title: 'إجمالي التنبيهات',
      value: typeof kpis.total_alerts === 'object' ? kpis.total_alerts.value : String(kpis.total_alerts || '0'),
      change: typeof kpis.total_alerts === 'object' ? kpis.total_alerts.change : '0%',
      isPositive: typeof kpis.total_alerts === 'object' ? kpis.total_alerts.is_positive ?? true : true,
      trendData: sparkAlerts,
      color: 'red',
      icon: ShieldAlert,
    },
    {
      title: 'التنبيهات الحرجة',
      value: typeof kpis.critical_alerts === 'object' ? kpis.critical_alerts.value : String(kpis.critical_alerts || '0'),
      change: typeof kpis.critical_alerts === 'object' ? kpis.critical_alerts.change : '0%',
      isPositive: typeof kpis.critical_alerts === 'object' ? kpis.critical_alerts.is_positive ?? true : true,
      trendData: sparkAlertsTail,
      color: 'orange',
      icon: AlertTriangle,
    },
    {
      title: 'الحوادث النشطة',
      value: typeof kpis.active_incidents === 'object' ? kpis.active_incidents.value : String(kpis.active_incidents || '0'),
      change: typeof kpis.active_incidents === 'object' ? kpis.active_incidents.change : '0%',
      isPositive: typeof kpis.active_incidents === 'object' ? kpis.active_incidents.is_positive ?? true : true,
      trendData: sparkAlerts,
      color: 'purple',
      icon: CircleDot,
    },
    {
      title: 'الأصول المراقبة',
      value: typeof kpis.assets_monitored === 'object' ? kpis.assets_monitored.value : String(kpis.assets_monitored || '0'),
      change: typeof kpis.assets_monitored === 'object' ? kpis.assets_monitored.change : '0%',
      isPositive: typeof kpis.assets_monitored === 'object' ? kpis.assets_monitored.is_positive ?? true : true,
      trendData: sparkTraffic,
      color: 'blue',
      icon: Shield,
    },
    {
      title: 'النقاط الطرفية',
      value: typeof kpis.endpoints_connected === 'object' ? kpis.endpoints_connected.value : String(kpis.endpoints_connected || '0'),
      change: typeof kpis.endpoints_connected === 'object' ? kpis.endpoints_connected.change : '0%',
      isPositive: typeof kpis.endpoints_connected === 'object' ? kpis.endpoints_connected.is_positive ?? true : true,
      trendData: sparkTrafficTail,
      color: 'green',
      icon: Monitor,
    },
    {
      title: 'المستخدمون',
      value: typeof kpis.active_users === 'object' ? kpis.active_users.value : String(kpis.active_users || '0'),
      change: typeof kpis.active_users === 'object' ? kpis.active_users.change : '0%',
      isPositive: typeof kpis.active_users === 'object' ? kpis.active_users.is_positive ?? true : true,
      trendData: sparkSystem,
      color: 'yellow',
      icon: Users,
    },
  ], [kpis, sparkAlerts, sparkAlertsTail, sparkTraffic, sparkTrafficTail, sparkSystem]);

  // Current time
  const [now] = useState(() => new Date().toLocaleDateString('ar-SA', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  }));

  // Filter live alerts feed by search term & severity selection
  const filteredAlerts = useMemo(() => {
    const list = Array.isArray(alertsFeed) ? alertsFeed : [];
    return list.filter(a => {
      if (!a) return false;
      if (selectedSeverity !== 'all' && String(a.severity || '').toLowerCase() !== selectedSeverity.toLowerCase()) {
        return false;
      }
      if (!searchTerm.trim()) return true;
      const q = searchTerm.toLowerCase();
      return (
        String(a.title || a.description || '').toLowerCase().includes(q) ||
        String(a.src || a.src_ip || '').includes(q) ||
        String(a.dst_ip || '').includes(q) ||
        String(a.category || '').toLowerCase().includes(q)
      );
    });
  }, [alertsFeed, selectedSeverity, searchTerm]);

  return (
    <div className="dashboard-pro-container" dir="rtl">
      {/* ── Header ── */}
      <div className="dashboard-pro-header">
        <div className="dashboard-pro-title-wrapper">
          <h1 className="dashboard-pro-title">
            لوحة مركز العمليات الأمنية (SOC Command Center)
            <span className="live-badge">مباشر</span>
          </h1>
          <span className="dashboard-pro-subtitle">
            <Clock size={13} style={{ marginLeft: 4, verticalAlign: 'middle', opacity: 0.5 }} />
            {now} — نظرة شاملة على جميع مكونات المنصة الأمنية في الوقت الفعلي
          </span>
        </div>

        <div className="dashboard-pro-header-right">
          {/* Global Timeframe Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(15,23,42,0.5)', padding: '3px 8px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)' }}>
            <Calendar size={13} style={{ color: '#06b6d4' }} />
            <select
              className="map-select"
              value={globalTimeframe}
              onChange={e => setGlobalTimeframe(e.target.value)}
              style={{ background: 'transparent', border: 'none', padding: '3px 4px' }}
            >
              <option value="1h">آخر ساعة</option>
              <option value="12h">آخر 12 ساعة</option>
              <option value="24h">آخر 24 ساعة</option>
              <option value="7d">آخر 7 أيام</option>
            </select>
          </div>

          {/* Quick Search */}
          <div className="pro-search-bar">
            <Search size={15} className="search-icon" />
            <input
              type="text"
              placeholder="البحث الشامل في التنبيهات والمحطات..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          {/* Action controls */}
          <div className="pro-header-actions">
            <button
              className="pro-icon-btn"
              title="تصدير تقرير SOC التنفيذي"
              onClick={() => setShowExportModal(true)}
            >
              <Download size={16} />
            </button>

            <button
              className="pro-icon-btn"
              title="تحديث البيانات الفوري"
              onClick={handleManualRefresh}
            >
              <RefreshCw size={16} className={isFetchingAny ? 'spin-anim' : ''} />
            </button>

            <button
              className="pro-icon-btn"
              title="درج الإشعارات الأمني"
              onClick={() => setShowNotificationDrawer(true)}
            >
              <Bell size={16} />
              {unreadCount > 0 && (
                <span className="badge-dot">{unreadCount > 99 ? '99+' : unreadCount}</span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* ── Active Severity Filter Indicator ── */}
      {selectedSeverity !== 'all' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, background: 'rgba(239,68,68,0.1)', padding: '6px 14px', borderRadius: 8, border: '1px solid rgba(239,68,68,0.25)', width: 'fit-content' }}>
          <Filter size={14} style={{ color: '#ef4444' }} />
          <span style={{ fontSize: '0.8rem', color: '#fff' }}>تصفية حسب الخطورة: <strong>{selectedSeverity.toUpperCase()}</strong></span>
          <button
            style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', display: 'flex', alignItems: 'center', marginRight: 8 }}
            onClick={() => setSelectedSeverity('all')}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Top Row: 6 KPI Cards ── */}
      <div className="dashboard-pro-kpi-grid">
        {statsCards.map((card, idx) => (
          <StatCard key={idx} {...card} />
        ))}
      </div>

      {/* ── Middle Row: Attack Map & Right Charts ── */}
      <div className="dashboard-pro-main-grid">
        <AttackMap liveAlerts={filteredAlerts} mapStats={mapStatsQuery.data} />
        <div className="pro-side-charts-wrapper">
          <AlertsSeverityDonut onSelectSeverity={(sev) => setSelectedSeverity(sev)} />
          <AlertsTrendArea />
        </div>
      </div>

      {/* ── Bottom Row: Tables & Gauges ── */}
      <div className="dashboard-pro-bottom-grid">
        <LatestAlertsTable alerts={filteredAlerts} />
        <ActiveIncidentsList incidents={incidentsQuery.data} />
        <div className="pro-bottom-split">
          <TopServicesProgress />
          <SystemHealthGauge detailedHealth={detailedHealthQuery.data?.circuit_breakers || detailedHealthQuery.data?.components || detailedHealthQuery.data?.plugins || detailedHealthQuery.data} />
        </div>
      </div>

      {/* ── Notification Drawer Modal ── */}
      <AnimatePresence>
        {showNotificationDrawer && (
          <div className="map-modal-backdrop" onClick={() => setShowNotificationDrawer(false)}>
            <motion.div
              className="map-filter-modal"
              initial={{ x: 300, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 300, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              dir="rtl"
              style={{ position: 'fixed', left: 20, top: 70, width: 380, maxHeight: '80vh', overflowY: 'auto' }}
            >
              <div className="modal-hdr">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Bell size={18} className="text-cyan-400" />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>مركز الإشعارات المباشرة</span>
                </div>
                <button className="close-btn" onClick={() => setShowNotificationDrawer(false)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>التنبيهات غير المقروءة: {unreadCount}</span>
                  <button
                    className="modal-btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                    onClick={() => {
                      clearUnread();
                      toast.success('تم تعيين جميع التنبيهات كمقروءة');
                    }}
                  >
                    تحديد الكل كمقروء
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
