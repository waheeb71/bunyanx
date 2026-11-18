import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Users, MapPin, Activity, Calendar, Search, ShieldAlert, ShieldCheck, RefreshCw } from 'lucide-react';
import { dashboardApi } from '../api/dashboardApi';
import { useLiveFeedStore } from '../../../stores/liveFeedStore';

export default function VisitorTracker() {
  const [searchTerm, setSearchTerm] = useState('');
  const alertsFeed = useLiveFeedStore((s) => s.alertsFeed) || [];

  const { data: rawData, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['siem_visitors_live'],
    queryFn: () => dashboardApi.visitors(100).then((r) => r.data?.data || []),
    refetchInterval: 10000,
    placeholderData: (previousData) => previousData,
    staleTime: 5000,
  });

  const visitors = useMemo(() => {
    const list = Array.isArray(rawData) ? [...rawData] : [];

    // Merge real-time alerts from WebSocket feed
    (alertsFeed || []).forEach((item) => {
      if (!item) return;
      const ip = item.src || item.src_ip || item.source_ip || item.ip;
      if (!ip || ip === '0.0.0.0') return;

      const existing = list.find((v) => (v.src_ip || v.source_ip || v.ip) === ip);
      if (existing) {
        existing.total_events = (existing.total_events || 1) + 1;
        if (item.severity === 'critical' || item.severity === 'high' || item.action === 'BLOCK') {
          existing.blocked_count = (existing.blocked_count || 0) + 1;
          existing.last_action = 'BLOCK';
        }
      } else {
        list.unshift({
          src_ip: ip,
          country: item.country || 'موقع خارجي',
          flag: item.flag || '🌐',
          last_action: item.severity === 'critical' || item.severity === 'high' ? 'BLOCK' : 'INSPECT',
          last_seen: item.timestamp || item.time || new Date().toISOString(),
          total_events: 1,
          blocked_count: item.severity === 'critical' || item.severity === 'high' ? 1 : 0,
        });
      }
    });

    return list.map((v) => {
      const ip = v.src_ip || v.source_ip || v.ip || '127.0.0.1';
      const isLan = ip.startsWith('10.')  || ip.startsWith('172.') || ip.startsWith('127.');
      return {
        ...v,
        ip,
        isLan,
        country: v.country || (isLan ? 'شبكة محلية (LAN)' : 'موقع خارجي'),
        flag: v.flag || (isLan ? '🏠' : '🌐'),
        lastSeen: v.last_seen || v.timestamp || new Date().toISOString(),
        action: (v.last_action || v.action || v.verdict || 'ALLOW').toUpperCase(),
        totalEvents: v.total_events || v.totalEvents || v.count || 1,
        blockedCount: v.blocked_count || v.blockedCount || 0,
      };
    });
  }, [rawData, alertsFeed]);

  const filteredVisitors = useMemo(() => {
    if (!searchTerm.trim()) return visitors;
    const term = searchTerm.toLowerCase().trim();
    return visitors.filter(
      (v) =>
        v.ip.toLowerCase().includes(term) ||
        v.country.toLowerCase().includes(term) ||
        v.action.toLowerCase().includes(term)
    );
  }, [visitors, searchTerm]);

  // Statistics Summary
  const stats = useMemo(() => {
    const totalUniqueIps = visitors.length;
    const externalCount = visitors.filter((v) => !v.isLan).length;
    const blockedIps = visitors.filter((v) => v.blockedCount > 0 || v.action === 'BLOCK' || v.action === 'DROP').length;
    const totalRequests = visitors.reduce((sum, v) => sum + (v.totalEvents || 0), 0);
    return { totalUniqueIps, externalCount, blockedIps, totalRequests };
  }, [visitors]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex-col h-full gap-4">
      
      {/* Top KPI Cards Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 12 }}>
        <div className="dash-panel glass-panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <Users size={22} style={{ color: '#00d4ff' }} />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>إجمالي عناوين IP المتصلة</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', fontFamily: 'JetBrains Mono' }}>
              {stats.totalUniqueIps.toLocaleString()}
            </div>
          </div>
        </div>

        <div className="dash-panel glass-panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <MapPin size={22} style={{ color: '#a78bfa' }} />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>الزوار من الخارج (WAN)</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', fontFamily: 'JetBrains Mono' }}>
              {stats.externalCount.toLocaleString()}
            </div>
          </div>
        </div>

        <div className="dash-panel glass-panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <ShieldAlert size={22} style={{ color: '#ff4d6d' }} />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>عناوين قيد الحظر / التهديد</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', fontFamily: 'JetBrains Mono' }}>
              {stats.blockedIps.toLocaleString()}
            </div>
          </div>
        </div>

        <div className="dash-panel glass-panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <Activity size={22} style={{ color: '#00e676' }} />
          <div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>إجمالي الطلبات المسجلة</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', fontFamily: 'JetBrains Mono' }}>
              {stats.totalRequests.toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Main Table Container */}
      <div className="dash-panel glass-panel flex-1 flex-col" style={{ padding: 0, overflow: 'hidden' }}>
        
        {/* Table Header Controls */}
        <div
          className="panel-header flex-between"
          style={{ padding: '12px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(6, 12, 24, 0.4)' }}
        >
          <div className="panel-title flex-center-left gap-2" style={{ fontSize: '0.92rem', fontWeight: 800, color: '#00d4ff' }}>
            <Users size={18} /> تتبع عناوين IP والجلسات المباشرة (Live Visitor Telemetry)
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Search Input */}
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Search size={14} style={{ position: 'absolute', right: 10, color: '#64748b' }} />
              <input
                type="text"
                placeholder="بحث برقم IP أو الدولة..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  background: 'rgba(0, 212, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 6,
                  padding: '4px 30px 4px 10px',
                  color: '#fff',
                  fontSize: '0.78rem',
                  fontFamily: 'Cairo, sans-serif',
                  outline: 'none',
                  width: 220,
                }}
              />
            </div>

            <button
              type="button"
              onClick={() => refetch()}
              title="تحديث البيانات حياً"
              style={{
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(255,255,255,0.1)',
                color: '#38bdf8',
                borderRadius: 6,
                padding: '5px 10px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                fontSize: '0.75rem',
              }}
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
              <span>تحديث</span>
            </button>
          </div>
        </div>

        {/* Data Table */}
        <div className="custom-scrollbar flex-1" style={{ overflow: 'auto' }}>
          <table className="siem-data-grid text-sm" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(15, 23, 42, 0.6)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                <th style={{ padding: '10px 16px', textAlign: 'right' }}><Calendar size={13} /> آخر ظهور</th>
                <th style={{ padding: '10px 16px', textAlign: 'right' }}><MapPin size={13} /> المنطقة / الدولة</th>
                <th style={{ padding: '10px 16px', textAlign: 'right' }}>عنوان IP المصدر</th>
                <th style={{ padding: '10px 16px', textAlign: 'right' }}><Activity size={13} /> آخر إجراء أمني</th>
                <th style={{ padding: '10px 16px', textAlign: 'center' }}>عدد الطلبات</th>
                <th style={{ padding: '10px 16px', textAlign: 'center' }}>التهديدات المحجوبة</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && !rawData ? (
                <tr>
                  <td colSpan="6" className="text-center text-muted" style={{ padding: '3rem' }}>
                    جاري تجميع وتحليل سجلات الزوار الحية...
                  </td>
                </tr>
              ) : filteredVisitors.length > 0 ? (
                filteredVisitors.map((v, i) => {
                  const isBlocked = v.action === 'BLOCK' || v.action === 'DROP' || v.action === 'DENY' || v.blockedCount > 0;
                  return (
                    <tr
                      key={v.ip + i}
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        transition: 'background 0.2s ease',
                      }}
                    >
                      {/* Last Seen */}
                      <td style={{ padding: '10px 16px', color: '#94a3b8', fontFamily: 'JetBrains Mono', fontSize: '0.78rem' }}>
                        {new Date(v.lastSeen).toLocaleTimeString('ar-SA', { hour12: false })} · {new Date(v.lastSeen).toLocaleDateString('ar-SA')}
                      </td>

                      {/* Geo Location */}
                      <td style={{ padding: '10px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: '1.1rem' }}>{v.flag}</span>
                          <span style={{ fontWeight: 600, color: v.isLan ? '#38bdf8' : '#e2e8f0' }}>{v.country}</span>
                          {v.city && <span style={{ fontSize: '0.7rem', color: '#64748b' }}>({v.city})</span>}
                        </div>
                      </td>

                      {/* IP Address */}
                      <td style={{ padding: '10px 16px' }}>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontWeight: 700,
                            color: '#00d4ff',
                            background: 'rgba(0, 212, 255, 0.08)',
                            padding: '3px 8px',
                            borderRadius: 4,
                            border: '1px solid rgba(0, 212, 255, 0.2)',
                          }}
                        >
                          {v.ip}
                        </span>
                      </td>

                      {/* Action */}
                      <td style={{ padding: '10px 16px' }}>
                        {isBlocked ? (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              background: 'rgba(255, 77, 109, 0.12)',
                              color: '#ff4d6d',
                              border: '1px solid rgba(255, 77, 109, 0.3)',
                              padding: '2px 8px',
                              borderRadius: 4,
                              fontSize: '0.72rem',
                              fontWeight: 700,
                            }}
                          >
                            <ShieldAlert size={12} /> محجوب ({v.action})
                          </span>
                        ) : (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              background: 'rgba(0, 230, 118, 0.12)',
                              color: '#00e676',
                              border: '1px solid rgba(0, 230, 118, 0.3)',
                              padding: '2px 8px',
                              borderRadius: 4,
                              fontSize: '0.72rem',
                              fontWeight: 700,
                            }}
                          >
                            <ShieldCheck size={12} /> مسموح ({v.action})
                          </span>
                        )}
                      </td>

                      {/* Total Events */}
                      <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono',
                            fontWeight: 700,
                            color: '#fff',
                            background: 'rgba(255,255,255,0.06)',
                            padding: '2px 8px',
                            borderRadius: 10,
                            fontSize: '0.75rem',
                          }}
                        >
                          {v.totalEvents.toLocaleString()} طلب
                        </span>
                      </td>

                      {/* Blocked Count */}
                      <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono',
                            fontWeight: 700,
                            color: v.blockedCount > 0 ? '#ff4d6d' : '#64748b',
                            background: v.blockedCount > 0 ? 'rgba(255, 77, 109, 0.1)' : 'transparent',
                            padding: '2px 8px',
                            borderRadius: 10,
                            fontSize: '0.75rem',
                          }}
                        >
                          {v.blockedCount.toLocaleString()}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="text-center text-muted" style={{ padding: '3rem' }}>
                    لا يوجد زوار قيد التتبع حالياً.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}
