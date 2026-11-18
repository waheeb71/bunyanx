/**
 * bunyanx — ChartKit (مكتبة التصورات البيانية المشتركة)
 * ═══════════════════════════════════════════════════════════
 * مكونات رسوم بيانية وخرائط جاهزة تُستخدم في Dashboard, IDS/IPS,
 * UBA, Predictive AI, وأي صفحة تحتاج تحليل بيانات.
 *
 * الاستخدام:
 *   import { CxAreaChart, CxBarChart, CxGauge, ... } from '../../components/ChartKit';
 */
import { useRef, useEffect, useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell, RadialBarChart, RadialBar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Legend
} from 'recharts';

/* ── Design tokens (mirroring tokens.css for JS usage) ──── */
const T = {
  accent: '#00c8ff',
  success: '#00e676',
  warning: '#ffab40',
  danger: '#ff4d6a',
  info: '#448aff',
  purple: '#a78bfa',
  bgRaised: '#0f1525',
  bgOverlay: '#141b30',
  border: 'rgba(255,255,255,0.07)',
  textMuted: 'rgba(255,255,255,0.35)',
  textPrimary: '#f0f0f5',
  fontMono: 'JetBrains Mono, Fira Code, monospace',
};

const PALETTE = [T.accent, T.success, T.warning, T.danger, T.purple, T.info];

/* ── SOC Tooltip (shared across all charts) ──────────────── */
function SocTooltip({ active, payload, label, formatter, unit }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(10,14,26,0.92)',
      backdropFilter: 'blur(12px)',
      border: `1px solid ${T.border}`,
      borderRadius: 10,
      padding: '10px 14px',
      direction: 'rtl',
      textAlign: 'right',
      minWidth: 140,
    }}>
      {label && <div style={{ fontSize: '0.72rem', color: T.textMuted, marginBottom: 6, fontFamily: T.fontMono }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, fontSize: '0.82rem', marginBottom: 2 }}>
          <span style={{ color: T.textMuted }}>{p.name}</span>
          <span style={{ color: p.color || T.accent, fontFamily: T.fontMono, fontWeight: 700 }}>
            {formatter ? formatter(p.value) : p.value}{unit || ''}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   1. CxAreaChart — مخطط المساحة (Traffic, Bandwidth, Timeline)
   ═══════════════════════════════════════════════════════════ */
export function CxAreaChart({
  data,
  dataKeys = [{ key: 'value', name: 'القيمة', color: T.accent }],
  xKey = 'time',
  height = 240,
  showGrid = false,
  unit,
  formatter,
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          {dataKeys.map((dk, i) => (
            <linearGradient key={i} id={`cxArea-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={dk.color || PALETTE[i]} stopOpacity={0.35} />
              <stop offset="95%" stopColor={dk.color || PALETTE[i]} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        {showGrid && <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />}
        <XAxis dataKey={xKey} tick={{ fill: T.textMuted, fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: T.textMuted, fontSize: 11, fontFamily: T.fontMono }} axisLine={false} tickLine={false} />
        <Tooltip content={<SocTooltip formatter={formatter} unit={unit} />} />
        {dataKeys.map((dk, i) => (
          <Area
            key={dk.key}
            type="monotone"
            dataKey={dk.key}
            name={dk.name}
            stroke={dk.color || PALETTE[i]}
            strokeWidth={2}
            fillOpacity={1}
            fill={`url(#cxArea-${i})`}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

/* ═══════════════════════════════════════════════════════════
   2. CxBarChart — أعمدة (Top Blocked, Top Attacks, etc.)
   ═══════════════════════════════════════════════════════════ */
export function CxBarChart({
  data,
  dataKey = 'value',
  nameKey = 'name',
  height = 240,
  layout = 'vertical',
  colors = PALETTE,
  unit,
  formatter,
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout={layout} margin={{ left: 10, right: 20 }}>
        <XAxis
          type={layout === 'vertical' ? 'number' : 'category'}
          dataKey={layout === 'vertical' ? undefined : nameKey}
          tick={{ fill: T.textMuted, fontSize: 11 }}
          axisLine={false} tickLine={false}
        />
        <YAxis
          type={layout === 'vertical' ? 'category' : 'number'}
          dataKey={layout === 'vertical' ? nameKey : undefined}
          width={layout === 'vertical' ? 140 : undefined}
          tick={{ fill: T.textPrimary, fontSize: 11, fontFamily: T.fontMono }}
          axisLine={false} tickLine={false}
        />
        <Tooltip content={<SocTooltip formatter={formatter} unit={unit} />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
        <Bar dataKey={dataKey} radius={layout === 'vertical' ? [0, 6, 6, 0] : [6, 6, 0, 0]}>
          {data.map((_, i) => <Cell key={i} fill={colors[i % colors.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/* ═══════════════════════════════════════════════════════════
   3. CxLineChart — خطوط (Trends, Comparisons)
   ═══════════════════════════════════════════════════════════ */
export function CxLineChart({
  data,
  dataKeys = [{ key: 'value', name: 'القيمة', color: T.accent }],
  xKey = 'time',
  height = 240,
  showDots = false,
  unit,
  formatter,
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <XAxis dataKey={xKey} tick={{ fill: T.textMuted, fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: T.textMuted, fontSize: 11, fontFamily: T.fontMono }} axisLine={false} tickLine={false} />
        <Tooltip content={<SocTooltip formatter={formatter} unit={unit} />} />
        {dataKeys.map((dk, i) => (
          <Line
            key={dk.key}
            type="monotone"
            dataKey={dk.key}
            name={dk.name}
            stroke={dk.color || PALETTE[i]}
            strokeWidth={2}
            dot={showDots ? { r: 3, fill: dk.color || PALETTE[i] } : false}
            activeDot={{ r: 5, stroke: dk.color || PALETTE[i], strokeWidth: 2, fill: T.bgRaised }}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

/* ═══════════════════════════════════════════════════════════
   4. CxGauge — مقياس دائري (CPU, Bandwidth, Utilization)
   ═══════════════════════════════════════════════════════════ */
export function CxGauge({
  value = 0,
  max = 100,
  label = '',
  color = T.accent,
  size = 160,
  thickness = 12,
}) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  const gaugeData = [{ name: label, value: pct, fill: color }];
  const autoColor = pct > 85 ? T.danger : pct > 60 ? T.warning : color;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <ResponsiveContainer>
          <RadialBarChart
            innerRadius={`${100 - thickness * 2}%`}
            outerRadius="100%"
            data={gaugeData}
            startAngle={225}
            endAngle={-45}
          >
            <RadialBar
              dataKey="value"
              cornerRadius={10}
              background={{ fill: 'rgba(255,255,255,0.04)' }}
              fill={autoColor}
              isAnimationActive={false}
            />
          </RadialBarChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
        }}>
          <span style={{ fontSize: size * 0.17, fontWeight: 800, fontFamily: T.fontMono, color: autoColor }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </span>
          <span style={{ fontSize: size * 0.07, color: T.textMuted, marginTop: 2 }}>
            / {max}
          </span>
        </div>
      </div>
      {label && <div style={{ fontSize: '0.78rem', color: T.textMuted, fontWeight: 600, textAlign: 'center' }}>{label}</div>}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   5. CxDonut — دائري مجوّف (Distribution, Categories)
   ═══════════════════════════════════════════════════════════ */
export function CxDonut({
  data,
  dataKey = 'value',
  nameKey = 'name',
  height = 220,
  colors = PALETTE,
  centerLabel,
  centerValue,
}) {
  return (
    <div style={{ position: 'relative' }}>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={data}
            dataKey={dataKey}
            nameKey={nameKey}
            cx="50%" cy="50%"
            innerRadius="60%" outerRadius="80%"
            paddingAngle={3}
            stroke="none"
          >
            {data.map((_, i) => <Cell key={i} fill={colors[i % colors.length]} />)}
          </Pie>
          <Tooltip content={<SocTooltip />} />
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(v) => <span style={{ color: T.textMuted, fontSize: '0.75rem', marginRight: 4 }}>{v}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
      {(centerLabel || centerValue) && (
        <div style={{
          position: 'absolute', top: '42%', left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
        }}>
          {centerValue && <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: T.fontMono, color: T.textPrimary }}>{centerValue}</div>}
          {centerLabel && <div style={{ fontSize: '0.7rem', color: T.textMuted }}>{centerLabel}</div>}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   6. CxSparkline — خط مصغّر (inline في KPI Cards)
   ═══════════════════════════════════════════════════════════ */
export function CxSparkline({ data, dataKey = 'value', color = T.accent, width = 80, height = 28 }) {
  return (
    <ResponsiveContainer width={width} height={height}>
      <LineChart data={data}>
        <Line
          type="monotone"
          dataKey={dataKey}
          stroke={color}
          strokeWidth={1.5}
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

/* ═══════════════════════════════════════════════════════════
   7. CxHeatmap — خريطة حرارية (Activity Heatmap by Hour/Day)
   ═══════════════════════════════════════════════════════════ */
export function CxHeatmap({
  data,         // 2D array [rows][cols] of numbers
  rowLabels,    // e.g. ['السبت','الأحد',...]
  colLabels,    // e.g. ['00','01',...'23']
  maxVal,
  colorScale = [T.bgOverlay, T.accent],  // [cold, hot]
  cellSize = 22,
}) {
  const max = maxVal || Math.max(...data.flat(), 1);

  const lerp = (a, b, t) => {
    const ah = parseInt(a.slice(1), 16);
    const bh = parseInt(b.slice(1), 16);
    const ar = ah >> 16, ag = (ah >> 8) & 0xff, ab = ah & 0xff;
    const br = bh >> 16, bg = (bh >> 8) & 0xff, bb = bh & 0xff;
    const r = Math.round(ar + (br - ar) * t);
    const g = Math.round(ag + (bg - ag) * t);
    const bl = Math.round(ab + (bb - ab) * t);
    return `rgb(${r},${g},${bl})`;
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {/* Column labels */}
        <div style={{ display: 'flex', paddingRight: 70, gap: 2 }}>
          {colLabels?.map((c, i) => (
            <div key={i} style={{ width: cellSize, textAlign: 'center', fontSize: '0.6rem', color: T.textMuted, fontFamily: T.fontMono }}>
              {c}
            </div>
          ))}
        </div>
        {data.map((row, ri) => (
          <div key={ri} style={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <div style={{ width: 65, fontSize: '0.7rem', color: T.textMuted, textAlign: 'left', flexShrink: 0 }}>
              {rowLabels?.[ri] || ri}
            </div>
            {row.map((val, ci) => (
              <div
                key={ci}
                title={`${rowLabels?.[ri] || ri} — ${colLabels?.[ci] || ci}: ${val}`}
                style={{
                  width: cellSize, height: cellSize,
                  borderRadius: 4,
                  background: val === 0 ? 'rgba(255,255,255,0.02)' : lerp(colorScale[0], colorScale[1], val / max),
                  transition: 'background 0.2s',
                  cursor: 'default',
                }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   8. CxTimeline — جدول زمني (Attack Sequence, Event Timeline)
   ═══════════════════════════════════════════════════════════ */
export function CxTimeline({ events }) {
  if (!events?.length) return null;

  const sevColor = (sev) => {
    if (sev === 'critical') return T.danger;
    if (sev === 'high') return T.warning;
    if (sev === 'medium') return T.info;
    return T.textMuted;
  };

  return (
    <div style={{ position: 'relative', paddingRight: 20 }}>
      {/* Vertical line */}
      <div style={{
        position: 'absolute', right: 7, top: 0, bottom: 0,
        width: 2, background: T.border,
      }} />

      {events.map((ev, i) => (
        <motion.div
          key={ev.id || i}
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.04 }}
          style={{
            display: 'flex', gap: 16, marginBottom: 16, position: 'relative',
          }}
        >
          {/* Dot */}
          <div style={{
            width: 14, height: 14, borderRadius: '50%',
            background: sevColor(ev.severity),
            border: `2px solid ${T.bgRaised}`,
            flexShrink: 0, marginTop: 4, zIndex: 1,
            boxShadow: `0 0 8px ${sevColor(ev.severity)}44`,
          }} />

          {/* Content */}
          <div style={{
            flex: 1, background: T.bgRaised,
            border: `1px solid ${T.border}`,
            borderRadius: 10, padding: '10px 14px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontWeight: 700, color: T.textPrimary, fontSize: '0.88rem' }}>{ev.title}</span>
              <span style={{ fontSize: '0.7rem', color: T.textMuted, fontFamily: T.fontMono }}>{ev.time}</span>
            </div>
            {ev.description && <div style={{ fontSize: '0.8rem', color: T.textMuted, lineHeight: 1.5 }}>{ev.description}</div>}
            {ev.tags && (
              <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                {ev.tags.map((tag, ti) => (
                  <span key={ti} style={{
                    fontSize: '0.68rem', padding: '2px 8px', borderRadius: 6,
                    background: `${sevColor(ev.severity)}18`,
                    color: sevColor(ev.severity),
                    fontFamily: T.fontMono,
                  }}>{tag}</span>
                ))}
              </div>
            )}
          </div>
        </motion.div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   9. CxMiniStat — رقم KPI مصغّر (لاستخدام داخل البطاقات)
   ═══════════════════════════════════════════════════════════ */
export function CxMiniStat({ label, value, trend, color = T.accent }) {
  const trendUp = trend > 0;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: '0.7rem', color: T.textMuted, fontWeight: 600 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: T.fontMono, color }}>{value}</span>
        {trend !== undefined && (
          <span style={{
            fontSize: '0.7rem', fontFamily: T.fontMono, fontWeight: 700,
            color: trendUp ? T.danger : T.success,
          }}>
            {trendUp ? '▲' : '▼'} {Math.abs(trend)}%
          </span>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════
   10. CxAttackMap — غلاف لـ globe.gl (Lazy-loaded)
   ═══════════════════════════════════════════════════════════ */
export function CxAttackMap({ arcs = [], height = 400, ...props }) {
  const mountRef = useRef(null);
  const globeRef = useRef(null);

  useEffect(() => {
    let instance;
    import('globe.gl').then((mod) => {
      if (!mountRef.current) return;
      const Globe = mod.default;
      instance = Globe()(mountRef.current);
      instance
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .arcsData(arcs)
        .arcColor('color')
        .arcDashLength(0.35)
        .arcDashGap(0.15)
        .arcDashAnimateTime(2000)
        .arcStroke(0.8)
        .arcAltitude(0.2)
        .atmosphereColor('#00c8ff')
        .atmosphereAltitude(0.15)
        .width(mountRef.current.clientWidth)
        .height(height);
      globeRef.current = instance;
    });
    return () => { if (instance) instance._destructor?.(); };
  }, []);

  useEffect(() => {
    if (globeRef.current) globeRef.current.arcsData(arcs);
  }, [arcs]);

  return <div ref={mountRef} style={{ width: '100%', height, cursor: 'grab', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }} />;
}

/* ═══════════════════════════════════════════════════════════
   Re-export palette for external usage
   ═══════════════════════════════════════════════════════════ */
export { T as ChartTokens, PALETTE as ChartPalette };
