/**
 * bunyanx — Shared UI Components
 * مكونات React مشتركة تُستخدم في جميع الوحدات.
 * استيراد واحد بدلاً من تكرار الكود في كل صفحة.
 */
import { motion } from 'framer-motion';
import { Search, Inbox } from 'lucide-react';

/* ── Page Header ──────────────────────────────────────── */
export function PageHeader({ icon: Icon, title, subtitle, children }) {
  return (
    <motion.div
      className="page-header"
      initial={{ opacity: 0, y: -14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="page-header-info">
        <h1 className="page-header-title">
          {Icon && <Icon size={24} style={{ color: 'var(--accent)' }} />}
          {title}
        </h1>
        {subtitle && <p className="page-header-sub">{subtitle}</p>}
      </div>
      {children && <div className="page-header-actions">{children}</div>}
    </motion.div>
  );
}

/* ── KPI Card ─────────────────────────────────────────── */
export function KpiCard({ icon, value, label, color = 'var(--accent)', delay = 0 }) {
  return (
    <motion.div
      className="kpi-card"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
    >
      <div className="kpi-card-glow" style={{ background: color }} />
      <div className="kpi-card-icon" style={{ background: color + '22', color }}>
        {icon}
      </div>
      <div className="kpi-card-value">{value ?? '—'}</div>
      <div className="kpi-card-label">{label}</div>
    </motion.div>
  );
}

/* ── Section Card ─────────────────────────────────────── */
export function SectionCard({ title, icon: Icon, actions, children, style }) {
  return (
    <motion.div
      className="section-card"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      style={style}
    >
      {(title || actions) && (
        <div className="section-card-header">
          <div className="section-card-title">
            {Icon && <Icon size={17} style={{ color: 'var(--accent)' }} />}
            {title}
          </div>
          {actions && <div style={{ display: 'flex', gap: '8px' }}>{actions}</div>}
        </div>
      )}
      {children}
    </motion.div>
  );
}

/* ── Filter / Search Bar ──────────────────────────────── */
export function FilterBar({ placeholder = 'بحث...', value, onChange, children }) {
  return (
    <div className="filter-bar">
      <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
        <Search size={14} style={{
          position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
          color: 'var(--text-muted)', pointerEvents: 'none'
        }} />
        <input
          className="search-input"
          style={{ paddingRight: 36 }}
          placeholder={placeholder}
          value={value}
          onChange={e => onChange(e.target.value)}
        />
      </div>
      {children}
    </div>
  );
}

/* ── Progress Bar ─────────────────────────────────────── */
export function ProgressBar({ percent = 0, color = 'var(--accent)' }) {
  const clamped = Math.min(100, Math.max(0, percent));
  return (
    <div className="progress-bar-bg">
      <div
        className="progress-bar-fill"
        style={{ width: `${clamped}%`, background: color }}
      />
    </div>
  );
}

/* ── Status Badge ─────────────────────────────────────── */
export function StatusBadge({ status }) {
  const map = {
    active: { cls: 'badge-success', text: 'نشط' },
    enabled: { cls: 'badge-success', text: 'مُفعّل' },
    disabled: { cls: 'badge-info', text: 'مُعطّل' },
    warning: { cls: 'badge-warning', text: 'تحذير' },
    error: { cls: 'badge-danger', text: 'خطأ' },
    blocked: { cls: 'badge-danger', text: 'محظور' },
    monitor: { cls: 'badge-accent', text: 'مراقبة' },
    enforce: { cls: 'badge-warning', text: 'تنفيذ' },
  };
  const m = map[status] || { cls: 'badge-info', text: status };
  return <span className={`badge ${m.cls}`}>{m.text}</span>;
}

/* ── Live Dot ─────────────────────────────────────────── */
export function LiveDot({ active = true }) {
  return (
    <span
      className={active ? 'pulse' : ''}
      style={{
        display: 'inline-block',
        width: 8, height: 8,
        borderRadius: '50%',
        background: active ? 'var(--success)' : 'var(--text-muted)',
      }}
    />
  );
}

/* ── Empty State ──────────────────────────────────────── */
export function EmptyState({ message = 'لا توجد بيانات', icon: Icon = Inbox }) {
  return (
    <div className="empty-state">
      <Icon size={40} className="empty-state-icon" />
      <div className="empty-state-text">{message}</div>
    </div>
  );
}

/* ── Skeleton Loader ──────────────────────────────────── */
export function SkeletonLines({ count = 4 }) {
  return (
    <div>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="skeleton skeleton-line"
          style={{ width: `${70 + Math.random() * 30}%` }}
        />
      ))}
    </div>
  );
}

/* ── Recharts Custom Tooltip ──────────────────────────── */
export function CxTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="cx-tooltip">
      <div className="cx-tooltip-label">{label}</div>
      {payload.map((p, i) => (
        <div key={i} className="cx-tooltip-value" style={{ color: p.color }}>
          {p.name}: {formatter ? formatter(p.value) : p.value}
        </div>
      ))}
    </div>
  );
}

/* ── Error State ───────────────────────────────────────── */
export function ErrorState({ message = 'حدث خطأ في التحميل', onRetry }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', gap: 14, padding: '48px 24px',
      color: 'var(--danger, #ff5f5f)', fontFamily: 'Cairo, sans-serif',
    }}>
      <div style={{
        width: 48, height: 48, borderRadius: 12,
        background: 'rgba(255,95,95,0.1)', border: '1px solid rgba(255,95,95,0.25)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem',
      }}>⚠️</div>
      <p style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.5)', textAlign: 'center', margin: 0 }}>
        {message}
      </p>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            padding: '8px 20px', borderRadius: 8,
            background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)',
            color: '#00d4ff', cursor: 'pointer', fontFamily: 'Cairo, sans-serif',
            fontWeight: 600, fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: 8,
          }}
        >🔄 إعادة المحاولة</button>
      )}
    </div>
  );
}

/* ── Pagination ────────────────────────────────────────── */
export function Pagination({ page, totalPages, onPageChange }) {
  if (!totalPages || totalPages <= 1) return null;
  const pages = Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
    if (totalPages <= 7) return i + 1;
    if (i === 0) return 1;
    if (i === 6) return totalPages;
    return page - 2 + i;
  }).filter(p => p >= 1 && p <= totalPages);

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      gap: 6, padding: '14px 0', fontFamily: 'Cairo, sans-serif',
    }}>
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page <= 1}
        style={{
          padding: '6px 14px', borderRadius: 7,
          background: 'var(--bg-overlay, rgba(255,255,255,0.04))',
          border: '1px solid var(--border, rgba(255,255,255,0.07))',
          color: page <= 1 ? 'var(--text-muted)' : 'var(--text-primary)',
          cursor: page <= 1 ? 'not-allowed' : 'pointer', fontSize: '0.82rem',
          fontFamily: 'Cairo, sans-serif', opacity: page <= 1 ? 0.4 : 1,
          transition: 'all 0.15s',
        }}
      >السابق</button>
      {pages.map(p => (
        <button
          key={p}
          onClick={() => onPageChange(p)}
          style={{
            width: 32, height: 32, borderRadius: 7, fontSize: '0.82rem',
            background: p === page ? 'rgba(0,212,255,0.15)' : 'var(--bg-overlay, rgba(255,255,255,0.04))',
            border: `1px solid ${p === page ? 'rgba(0,212,255,0.4)' : 'var(--border, rgba(255,255,255,0.07))'}`,
            color: p === page ? '#00d4ff' : 'var(--text-secondary)',
            cursor: 'pointer', fontFamily: 'Fira Code, monospace', transition: 'all 0.15s',
          }}
        >{p}</button>
      ))}
      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page >= totalPages}
        style={{
          padding: '6px 14px', borderRadius: 7,
          background: 'var(--bg-overlay, rgba(255,255,255,0.04))',
          border: '1px solid var(--border, rgba(255,255,255,0.07))',
          color: page >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
          cursor: page >= totalPages ? 'not-allowed' : 'pointer', fontSize: '0.82rem',
          fontFamily: 'Cairo, sans-serif', opacity: page >= totalPages ? 0.4 : 1,
          transition: 'all 0.15s',
        }}
      >التالي</button>
    </div>
  );
}

/* ── Radar Loader ────────────────────────────────────────── */
export function RadarLoader({ color = 'green', text = '... في انتظار البيانات' }) {
  // Map color names to fallback color variables
  const colorMap = {
    green: 'green',
    orange: 'orange',
    blue: 'blue',
  };
  const activeColor = colorMap[color] || 'green';

  return (
    <div className={`panel-loading panel-loading--${activeColor}`}>
      <div className="panel-loading-radar">
        <div className="panel-radar-sweep"></div>
        <div className="panel-radar-dot"></div>
      </div>
      {text && <div className="panel-loading-text">{text}</div>}
    </div>
  );
}

