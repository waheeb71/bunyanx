import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend
} from 'recharts';
import {
  Shield, AlertTriangle, Activity, CheckCircle2, ArrowUpRight,
  PieChart as PieIcon, Users, Percent, ShieldCheck
} from 'lucide-react';
import { SectionCard, EmptyState, CxTooltip } from '../../../components/Shared';
import ActionBadge from './ActionBadge';

const CHART_COLORS = ['#ff4d6a', '#ffab40', '#00c8ff', '#a78bfa', '#00e676', '#ffd600', '#f50057'];

export function DNSStatsView({ stats }) {
  const topBlocked = stats.top_blocked || [];
  const topClients = stats.top_clients || [];
  const categoryBreakdown = stats.category_breakdown || {};

  const barData = topBlocked.slice(0, 8).map(r => ({
    name: r.domain_pattern.length > 20 ? r.domain_pattern.slice(0, 18) + '…' : r.domain_pattern,
    count: r.blocked_count,
  }));

  const categoryData = Object.entries(categoryBreakdown).map(([name, value]) => ({
    name,
    value,
  }));

  return (
    <div className="dns-stats-container" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      
      {/* ── Summary Stats Cards ───────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 14,
      }}>
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 14
        }}>
          <div style={{
            width: 44, height: 44, borderRadius: 10,
            background: 'rgba(0, 200, 255, 0.12)', color: 'var(--accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Activity size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>إجمالي الاستعلامات</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
              {(stats.total_queries || 0).toLocaleString()}
            </div>
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 14
        }}>
          <div style={{
            width: 44, height: 44, borderRadius: 10,
            background: 'rgba(255, 77, 106, 0.12)', color: 'var(--danger)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <AlertTriangle size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>الاستعلامات المحجوبة</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--danger)', fontFamily: 'var(--font-mono)' }}>
              {(stats.blocked_count || 0).toLocaleString()}
            </div>
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 14
        }}>
          <div style={{
            width: 44, height: 44, borderRadius: 10,
            background: 'rgba(255, 171, 64, 0.12)', color: 'var(--warning)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <ArrowUpRight size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>المعزولة / الموجهة</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
              {(stats.sinkhole_count || 0).toLocaleString()}
            </div>
          </div>
        </div>

        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          gap: 14
        }}>
          <div style={{
            width: 44, height: 44, borderRadius: 10,
            background: 'rgba(0, 230, 118, 0.12)', color: 'var(--success)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Percent size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>نسبة الحظر والحماية</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--success)', fontFamily: 'var(--font-mono)' }}>
              {stats.block_rate || 0}%
            </div>
          </div>
        </div>
      </div>

      {/* ── Charts Row ────────────────────────── */}
      <div className="content-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 20 }}>
        {/* Top Blocked Bar Chart */}
        <SectionCard title="أعلى النطاقات المحظورة" icon={Activity}>
          {barData.length === 0 ? (
            <EmptyState message="لم يتم تسجيل أي أحداث حظر حتى الآن" />
          ) : (
            <div style={{ width: '100%', height: 260 }}>
              <ResponsiveContainer>
                <BarChart data={barData} layout="vertical" margin={{ left: 10, right: 30 }}>
                  <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis
                    type="category" dataKey="name" width={160}
                    tick={{ fill: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                    axisLine={false} tickLine={false}
                  />
                  <Tooltip content={<CxTooltip />} cursor={{ fill: 'var(--bg-hover)' }} />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                    {barData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionCard>

        {/* Category Breakdown Pie Chart */}
        <SectionCard title="توزيع تصنيفات التهديدات" icon={PieIcon}>
          {categoryData.length === 0 ? (
            <EmptyState message="لا توجد بيانات كافية لعرض توزيع التصنيفات" />
          ) : (
            <div style={{ width: '100%', height: 260 }}>
              <ResponsiveContainer>
                <PieChart>
                  <Pie
                    data={categoryData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {categoryData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip content={<CxTooltip />} />
                  <Legend
                    verticalAlign="bottom"
                    formatter={(val) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionCard>
      </div>

      {/* ── Tables Row ────────────────────────── */}
      <div className="content-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 20 }}>
        {/* Top Blocked Table */}
        <SectionCard title="أعلى النطاقات المحظورة (تفصيلي)" icon={AlertTriangle}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>النطاق</th>
                  <th>الإجراء</th>
                  <th>التصنيف</th>
                  <th>العدد</th>
                </tr>
              </thead>
              <tbody>
                {topBlocked.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: 'center' }}><EmptyState /></td></tr>
                )}
                {topBlocked.map((r, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                    <td className="mono" style={{ direction: 'ltr', textAlign: 'right', fontWeight: 600, color: 'var(--danger)' }}>
                      {r.domain_pattern}
                    </td>
                    <td><ActionBadge action={r.action} /></td>
                    <td>
                      <span style={{ fontSize: '0.75rem', padding: '2px 6px', borderRadius: 4, background: 'var(--bg-hover)' }}>
                        {r.category || 'BLOCK'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--danger)', fontWeight: 700 }}>{r.blocked_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>

        {/* Top Clients Table */}
        <SectionCard title="أكثر الأجهزة طلباً للنطاقات (Clients)" icon={Users}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>عنوان العميل (IP)</th>
                  <th>إجمالي الطلبات</th>
                  <th>الطلبات المحجوبة</th>
                  <th>معدل الخطورة</th>
                </tr>
              </thead>
              <tbody>
                {topClients.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: 'center' }}><EmptyState /></td></tr>
                )}
                {topClients.map((c, i) => {
                  const threatRatio = c.total_queries > 0 ? Math.round((c.blocked_queries / c.total_queries) * 100) : 0;
                  return (
                    <tr key={i}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td className="mono" style={{ direction: 'ltr', textAlign: 'right', fontWeight: 600 }}>
                        {c.client_ip}
                      </td>
                      <td className="mono" style={{ color: 'var(--text-primary)' }}>{c.total_queries}</td>
                      <td className="mono" style={{ color: 'var(--danger)', fontWeight: 700 }}>{c.blocked_queries}</td>
                      <td>
                        <span style={{
                          fontSize: '0.75rem',
                          padding: '2px 8px',
                          borderRadius: 4,
                          fontWeight: 700,
                          background: threatRatio > 30 ? 'rgba(255, 77, 106, 0.15)' : 'rgba(0, 230, 118, 0.15)',
                          color: threatRatio > 30 ? 'var(--danger)' : 'var(--success)',
                        }}>
                          {threatRatio}%
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </SectionCard>
      </div>

    </div>
  );
}

export default DNSStatsView;
