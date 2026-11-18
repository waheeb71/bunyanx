import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, ShieldAlert, FileText, Users, Target,
  Wifi, ShieldCheck, Clock, AlertOctagon
} from 'lucide-react';
import { systemApi } from '../../services/api';

import LiveMonitor from './views/LiveMonitor';
import EventsSearch from './views/EventsSearch';
import LogsExplorer from './views/LogsExplorer';
import VisitorTracker from './views/VisitorTracker';
import ThreatIntel from './views/ThreatIntel';
import './Dashboard.css';

import useDashboardStore from './stores/useDashboardStore';

/* ─── Tab definitions ─────────────────────────────── */
const TABS = [
  { id: 'live', name: 'SIEM مباشر', icon: Activity, color: '#00d4ff' },
  { id: 'events', name: 'تحليل الأحداث', icon: ShieldAlert, color: '#ff5f5f' },
  { id: 'logs', name: 'السجلات الخام', icon: FileText, color: '#ffc107' },
  { id: 'visitors', name: 'تتبع الزوار', icon: Users, color: '#a78bfa' },
  { id: 'intel', name: 'استخبارات التهديدات', icon: Target, color: '#ff9f43' },
];

/* ─── Live clock ──────────────────────────────────── */
function LiveClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const iv = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(iv);
  }, []);
  return (
    <div className="db-live-clock" dir="ltr">
      <Clock size={12} />
      {time.toLocaleTimeString('ar-SA', { hour12: false })}
    </div>
  );
}

/* ─── Main ────────────────────────────────────────── */
export default function Dashboard() {
  const activeTab = useDashboardStore((s) => s.activeTab);
  const setActiveTab = useDashboardStore((s) => s.setActiveTab);

  const { data: sysStatus } = useQuery({
    queryKey: ['dash_sys_status_header'],
    queryFn: () => systemApi.status().then(r => r.data),
    refetchInterval: 5000,
  });

  const isHealthy = sysStatus?.status !== 'error';

  return (
    <div className="db-root" dir="rtl">

      {/* ══════════ TOPBAR ══════════ */}
      <motion.header
        className="db-topbar"
        initial={{ opacity: 0, y: -14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        {/* Brand */}
        <div className="db-brand">
          <div className="db-brand-icon">
            <ShieldCheck size={22} style={{ color: '#00d4ff' }} />
          </div>
          <div>
            <div className="db-brand-title">مركز عمليات الأمان</div>
            <div className="db-brand-sub">bunyanx NGFW · Enterprise SOC Platform</div>
          </div>
        </div>

        {/* Right cluster */}
        <div className="db-topbar-right">
          {/* System status */}
          <div className={`db-sys-pill ${isHealthy ? 'db-sys-pill--ok' : 'db-sys-pill--err'}`}>
            <span className="db-sys-dot" />
            {isHealthy ? 'جميع الأنظمة تعمل' : 'تحذير — النظام متدهور'}
          </div>

          {/* Network live indicator */}
          <div className="db-net-pill">
            <Wifi size={13} />
            <span>متصل</span>
          </div>

          <LiveClock />
        </div>
      </motion.header>

      {/* ══════════ TABS BAR ══════════ */}
      <div className="db-tab-bar">
        {TABS.map(tab => {
          const active = activeTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`db-tab ${active ? 'db-tab--active' : ''}`}
              style={active ? { '--tab-c': tab.color } : {}}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={15} style={{ color: active ? tab.color : undefined }} />
              <span>{tab.name}</span>
              {active && <span className="db-tab-bar-indicator" style={{ background: tab.color }} />}
            </button>
          );
        })}

        {/* Warning badge */}
        {!isHealthy && (
          <div className="db-tab-bar-alert">
            <AlertOctagon size={13} />
            <span>تحقق من صحة النظام</span>
          </div>
        )}
      </div>

      {/* ══════════ VIEW AREA ══════════ */}
      <div className="db-view-area">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            className="db-view-pane"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
          >
            {activeTab === 'live' && <LiveMonitor sysStatus={sysStatus} />}
            {activeTab === 'events' && <EventsSearch />}
            {activeTab === 'logs' && <LogsExplorer />}
            {activeTab === 'visitors' && <VisitorTracker />}
            {activeTab === 'intel' && <ThreatIntel />}
          </motion.div>
        </AnimatePresence>
      </div>

    </div>
  );
}
