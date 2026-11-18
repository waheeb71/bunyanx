import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '../../services/api';
import {
  Blocks, RefreshCw, AlertTriangle, Clock,
  ShieldCheck, ShieldOff, Zap, Activity, Search,
  Shield, Layers, Lock, UserCheck, Globe, KeyRound,
  Filter, Mail, Radio, Key, Network, BrainCircuit,
  Server, Crosshair, Sparkles, CheckCircle2
} from 'lucide-react';
import './ModulesManager.css';

/* ═══════════════════════════════════════
   Module metadata with Professional Lucide Icons
═══════════════════════════════════════ */
const MODULE_META = {
  waf: {
    label: 'WAF — جدار تطبيقات الويب',
    abbr: 'WAF GNN',
    category: 'perimeter',
    desc: 'حجب هجمات SQLi وXSS واستغلال ثغرات OWASP Top 10 بدقة متقدمة.',
    icon: Layers,
    color: '#00c8ff',
  },
  ids_ips: {
    label: 'IDS/IPS — كشف واعتراض الاختراق',
    abbr: 'Phantom IPS',
    category: 'perimeter',
    desc: 'اعتراض فوري لحزم البيانات المشبوهة على مستوى النواة (XDP/eBPF).',
    icon: Shield,
    color: '#ff4d6a',
  },
  malware_av: {
    label: 'Malware AV — مكافحة البرمجيات',
    abbr: 'AV Scanner',
    category: 'data',
    desc: 'فحص ملفات HTTP/FTP/SMTP بالذكاء الاصطناعي ومطابقة البصمات.',
    icon: ShieldCheck,
    color: '#ffab40',
  },
  dns_security: {
    label: 'DNS Security — أمان استعلامات DNS',
    abbr: 'DNS Shield',
    category: 'perimeter',
    desc: 'تحليل وتصفية استعلامات DNS وحجب النطاقات الخبيثة وDGA.',
    icon: Globe,
    color: '#00c8ff',
  },
  dlp: {
    label: 'DLP — منع تسريب البيانات',
    abbr: 'DLP Engine',
    category: 'data',
    desc: 'اكتشاف ومنع تسريب المستندات السرية وأرقام البطاقات والبيانات الحساسة.',
    icon: Lock,
    color: '#a78bfa',
  },
  uba: {
    label: 'UBA — تحليل سلوك المستخدم',
    abbr: 'UBA AI',
    category: 'identity',
    desc: 'تتبع سلوكيات الحسابات واكتشاف محاولات الاستيلاء والشذوذ في الدخول.',
    icon: UserCheck,
    color: '#00e676',
  },
  ssl_inspection: {
    label: 'SSL/TLS — فحص التشفير العميق',
    abbr: 'SSL MiTM',
    category: 'data',
    desc: 'اعتراض وفك تشفير TLS وفحص المحتوى الداخلي وإعادة التوقيع الآمن.',
    icon: KeyRound,
    color: '#fbbf24',
  },
  http_inspection: {
    label: 'HTTP Inspection — فحص الويب المتقدم',
    abbr: 'HTTP L7',
    category: 'perimeter',
    desc: 'فحص ترويسات HTTP وفك ضغط البيانات واكتشاف التلاعب بالبروتوكول.',
    icon: Search,
    color: '#38bdf8',
  },
  web_filter: {
    label: 'Web Filter — تصفية المواقع',
    abbr: 'WebFilter',
    category: 'perimeter',
    desc: 'قوائم الحظر والسماح حسب التصنيف العالمي للنطاقات والمواقع.',
    icon: Filter,
    color: '#f97316',
  },
  email_security: {
    label: 'Email Security — أمان البريد',
    abbr: 'Email Shield',
    category: 'data',
    desc: 'فحص رسائل SMTP ضد هجمات التصيد والبريد الاحتيالي والمرفقات الملغومة.',
    icon: Mail,
    color: '#f472b6',
  },
  qos: {
    label: 'QoS — جودة الخدمة وتشكيل التدفق',
    abbr: 'QoS Shaper',
    category: 'perimeter',
    desc: 'تحديد أولويات النطاق الترددي للخدمات الحيوية ومنع استنزاف الشبكة.',
    icon: Radio,
    color: '#2dd4bf',
  },
  vpn: {
    label: 'VPN — بوابة WireGuard الآمنة',
    abbr: 'WireGuard VPN',
    category: 'identity',
    desc: 'تأمين الاتصال البعيد والأنفاق المشفرة بأعلى سرعة وأقل تأخير.',
    icon: Key,
    color: '#818cf8',
  },
  proxy: {
    label: 'Proxy — الوكيل الشفاف L7',
    abbr: 'L7 Proxy',
    category: 'perimeter',
    desc: 'إعادة توجيه واعتراض شفاف للحزم الشبكية عبر خط الأنابيب الأمني.',
    icon: Network,
    color: '#94a3b8',
  },
  predictive_ai: {
    label: 'Predictive AI — الذكاء التنبؤي',
    abbr: 'ONNX Core',
    category: 'identity',
    desc: 'محرك نماذج الشبكات العصبية للتنبؤ بالهجمات مجهولة المصدر (Zero-Day).',
    icon: BrainCircuit,
    color: '#c084fc',
  },
  ha: {
    label: 'HA — التوافر العالي والمزامنة',
    abbr: 'HA Cluster',
    category: 'perimeter',
    desc: 'مزامنة حالة الجلسات وجداول الحماية بين العقد النشطة (Active-Active).',
    icon: Server,
    color: '#34d399',
  },
  deception: {
    label: 'Deception — محرك الخداع السيبراني',
    abbr: 'Honeypot',
    category: 'identity',
    desc: 'نشر مصائد وهمية وعناوين مضللة لاستدراج وتصنيف المهاجمين.',
    icon: Crosshair,
    color: '#f59e0b',
  },
};

function relTime(iso) {
  if (!iso) return '—';
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60) return `${diff} ثانية`;
  if (diff < 3600) return `${Math.floor(diff / 60)} دقيقة`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} ساعة`;
  return `${Math.floor(diff / 86400)} يوم`;
}

/* ═══════════════════════════════════════
   Luxury Module Card Component
═══════════════════════════════════════ */
function ModuleCard({ name, config, moduleStat, onToggle, pending }) {
  const isEnabled = config.enabled || false;
  const meta = MODULE_META[name] || {
    label: name,
    abbr: name,
    desc: '—',
    icon: Shield,
    color: '#00c8ff',
  };
  const IconComponent = meta.icon;
  const eventCount = moduleStat?.event_count ?? null;
  const lastSeen = moduleStat?.last_seen ?? null;

  return (
    <div
      className={`mm-card ${isEnabled ? 'mm-card--on' : 'mm-card--off'}`}
      style={{ '--mm-color': meta.color }}
    >
      <div className="mm-card-strip" style={{ background: meta.color }} />

      <div className="mm-card-head">
        <div
          className="mm-card-icon"
          style={{
            background: `${meta.color}15`,
            borderColor: `${meta.color}35`,
            color: meta.color,
          }}
        >
          <IconComponent size={20} />
        </div>
        <div className="mm-card-title-group">
          <div className="mm-card-name">{meta.label}</div>
          <div className="mm-card-abbr" style={{ color: meta.color }}>
            {meta.abbr}
          </div>
        </div>
        <span
          className={`mm-status-badge ${
            isEnabled ? 'mm-status-badge--on' : 'mm-status-badge--off'
          }`}
        >
          <span className="mm-status-dot" />
          {isEnabled ? 'نشط ويعمل' : 'مُعطّل'}
        </span>
      </div>

      <p className="mm-card-desc">{meta.desc}</p>

      <div className="mm-card-stats">
        <div className="mm-mini-stat">
          <Activity size={12} style={{ color: '#00c8ff' }} />
          <span>الأحداث المفحوصة:</span>
          <strong style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            {eventCount !== null ? eventCount.toLocaleString('ar-SA') : '0'}
          </strong>
        </div>
        <div className="mm-mini-stat">
          <Clock size={12} style={{ color: 'var(--text-muted)' }} />
          <span>آخر نشاط:</span>
          <strong>{relTime(lastSeen)}</strong>
        </div>
      </div>

      <div className="mm-card-footer">
        <div className="mm-footer-label">
          <Zap size={13} style={{ color: isEnabled ? meta.color : 'rgba(255,255,255,0.3)' }} />
          <span>خط أنابيب الفحص الحي</span>
        </div>
        <label className="mm-switch">
          <input
            type="checkbox"
            checked={isEnabled}
            onChange={() => onToggle(name, !isEnabled)}
            disabled={pending}
          />
          <span className="mm-switch-track" />
        </label>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════
   MAIN COMPONENT
═══════════════════════════════════════ */
export default function ModulesManager() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');

  const { data: modules, isLoading, isError } = useQuery({
    queryKey: ['system-modules'],
    queryFn: async () => (await systemApi.modules()).data,
  });

  const { data: stats } = useQuery({
    queryKey: ['module-stats'],
    queryFn: async () => (await systemApi.moduleStats()).data,
    retry: 1,
    refetchInterval: 15000,
  });

  const toggleMutation = useMutation({
    mutationFn: ({ name, enabled }) => systemApi.toggleModule(name, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['system-modules'] });
      qc.invalidateQueries({ queryKey: ['dash_mods_health'] });
      qc.invalidateQueries({ queryKey: ['exec_modules'] });
    },
  });

  const handleToggle = (name, enabled) => toggleMutation.mutate({ name, enabled });

  if (isLoading) {
    return (
      <div className="mm-loading">
        <RefreshCw size={22} className="mm-spin text-cyan-400" />
        <span>جاري مزامنة حالة وحدات الفحص مع النواة...</span>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="mm-error">
        <AlertTriangle size={22} />
        <span>فشل تحميل حالة الوحدات — تأكد من تشغيل محرك الأمان المركزي</span>
      </div>
    );
  }

  const entries = modules ? Object.entries(modules) : [];
  const activeCount = entries.filter(([, c]) => c.enabled).length;
  const totalEvents = stats
    ? Object.values(stats).reduce((s, m) => s + (m.event_count || 0), 0)
    : 0;

  const filtered = entries.filter(([name]) => {
    const meta = MODULE_META[name];
    const matchesSearch =
      !search ||
      name.toLowerCase().includes(search.toLowerCase()) ||
      meta?.label.includes(search) ||
      meta?.abbr.toLowerCase().includes(search.toLowerCase()) ||
      meta?.desc.includes(search);

    const matchesCategory =
      categoryFilter === 'all' || meta?.category === categoryFilter;

    return matchesSearch && matchesCategory;
  });

  return (
    <div className="mm-root" dir="rtl">
      {/* ── Top Hero Summary ── */}
      <div className="mm-hero">
        <div className="mm-hero-glow" />
        <div className="mm-hero-content">
          <div className="mm-hero-left">
            <div className="mm-hero-icon">
              <Blocks size={26} style={{ color: '#00c8ff' }} />
            </div>
            <div>
              <h2 className="mm-hero-title">مدير وحدات الفحص وخط الأنابيب الأمني</h2>
              <p className="mm-hero-sub">
                تفعيل وإيقاف محركات التهديدات فورياً في خط أنابيب المعالجة دون إعادة تشغيل الخادم
              </p>
            </div>
          </div>
          <div className="mm-hero-badge">
            <Sparkles size={14} />
            حقن مباشر (Zero-Downtime Pipeline)
          </div>
        </div>
      </div>

      {/* ── KPI Metric Strip ── */}
      <div className="mm-kpi-strip">
        {[
          { icon: Blocks, label: 'إجمالي المحركات', value: entries.length, color: '#00c8ff' },
          { icon: ShieldCheck, label: 'المحركات النشطة', value: activeCount, color: '#00e676' },
          { icon: ShieldOff, label: 'المحركات المعطلة', value: entries.length - activeCount, color: '#ff4d6a' },
          { icon: Activity, label: 'إجمالي الأحداث المعالجة', value: totalEvents.toLocaleString('ar-SA'), color: '#818cf8' },
        ].map((k) => {
          const Icon = k.icon;
          return (
            <div className="mm-kpi" key={k.label}>
              <div className="mm-kpi-icon" style={{ background: `${k.color}15`, color: k.color }}>
                <Icon size={18} />
              </div>
              <div className="mm-kpi-body">
                <div className="mm-kpi-val" style={{ color: k.color }}>
                  {k.value}
                </div>
                <div className="mm-kpi-label">{k.label}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Filter & Search Control Bar ── */}
      <div className="mm-controls-bar">
        <div className="mm-category-tabs">
          {[
            { id: 'all', label: 'كافة الوحدات' },
            { id: 'perimeter', label: 'حماية المحيط والشبكة' },
            { id: 'data', label: 'البيانات والتشفير' },
            { id: 'identity', label: 'الهوية والذكاء الاصطناعي' },
          ].map((tab) => (
            <button
              key={tab.id}
              className={`mm-tab-btn ${categoryFilter === tab.id ? 'active' : ''}`}
              onClick={() => setCategoryFilter(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="mm-search-box">
          <Search size={15} style={{ color: 'var(--text-muted)' }} />
          <input
            className="mm-search-input"
            placeholder="بحث عن وحدة أمنية..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <span className="mm-count-tag">{filtered.length} وحدة</span>
        </div>
      </div>

      {/* ── Responsive Modules Grid ── */}
      <div className="mm-grid">
        {filtered.map(([name, config]) => (
          <ModuleCard
            key={name}
            name={name}
            config={config}
            moduleStat={stats?.[name] ?? null}
            onToggle={handleToggle}
            pending={toggleMutation.isPending}
          />
        ))}
      </div>

      {/* ── Live Toast Feedback ── */}
      {toggleMutation.isPending && (
        <div className="mm-toast">
          <RefreshCw size={15} className="mm-spin" />
          جاري حقن التغيير في خط الأنابيب الأمني...
        </div>
      )}
    </div>
  );
}
