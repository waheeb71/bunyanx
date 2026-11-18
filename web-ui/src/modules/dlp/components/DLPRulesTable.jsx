import React, { useState } from 'react';
import {
  AlertTriangle, Plus, Trash2, Search, Code, Lock, SlidersHorizontal,
  Copy, Check, ShieldAlert, CheckCircle2
} from 'lucide-react';
import { useDLPStore } from '../store/dlpStore';
import { useDLP } from '../hooks/useDLP';

const SEVERITY_COLORS = {
  CRITICAL: '#ff4d6a',
  HIGH: '#ffab40',
  MEDIUM: '#00c8ff',
  LOW: '#00e676',
};

const SEVERITY_BADGES = {
  CRITICAL: 'حرج جداً',
  HIGH: 'عالي',
  MEDIUM: 'متوسط',
  LOW: 'منخفض',
};

const BUILTIN_PATTERNS = [
  { name: 'أرقام بطاقات الائتمان (Luhn Algorithm)', pattern: '\\b(?:\\d{4}[ -]?){3}(?:\\d{4}|\\d{3})\\b', severity: 'HIGH', desc: 'مطابقة أرقام فيزا وماستركارد ومدى' },
  { name: 'رقم الهوية الوطنية / الإقامة (Saudi National ID / Iqama)', pattern: '\\b[12]\\d{9}\\b', severity: 'CRITICAL', desc: 'مطابقة أرقام الهوية المكونة من 10 أرقام تبدأ بـ 1 أو 2' },
  { name: 'رقم الحساب البنكي الدولي (IBAN)', pattern: '\\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9a-zA-Z]{4}){3,7}\\b', severity: 'HIGH', desc: 'مطابقة أرقام الآيبان البنكية' },
  { name: 'عناوين البريد الإلكتروني للشركات', pattern: '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+', severity: 'MEDIUM', desc: 'كشف تسريب قوائم الإيميلات' },
  { name: 'مفاتيح التوثيق الخاصة (Private Keys / API Secrets)', pattern: '-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----', severity: 'CRITICAL', desc: 'كشف تسريب المفاتيح البرمجية' },
  { name: 'أرقام الهواتف الدولية', pattern: '\\b(?:\\+?1[-. ]?)?\\(?([0-9]{3})\\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\\b', severity: 'MEDIUM', desc: 'مطابقة أرقام الاتصال' },
];

export default function DLPRulesTable() {
  const { rulesSearch, setRulesSearch, rulesActiveTab, setRulesActiveTab } = useDLPStore();
  const { rules = [], createRule, deleteRule } = useDLP();

  const [showAddForm, setShowAddForm] = useState(false);
  const [copiedPattern, setCopiedPattern] = useState(null);
  const [newRule, setNewRule] = useState({ name: '', pattern: '', severity: 'HIGH', description: '' });

  const handleAdd = (e) => {
    e.preventDefault();
    if (!newRule.name.trim() || !newRule.pattern.trim()) return;
    createRule.mutate(newRule, {
      onSuccess: () => {
        setNewRule({ name: '', pattern: '', severity: 'HIGH', description: '' });
        setShowAddForm(false);
      },
    });
  };

  const handleCopy = (pattern, id) => {
    navigator.clipboard.writeText(pattern);
    setCopiedPattern(id);
    setTimeout(() => setCopiedPattern(null), 2000);
  };

  const filtered = rules.filter(
    (r) =>
      r.name?.toLowerCase().includes(rulesSearch.toLowerCase()) ||
      r.pattern?.toLowerCase().includes(rulesSearch.toLowerCase())
  );

  return (
    <div
      className="card"
      style={{
        background: 'rgba(10, 14, 26, 0.75)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(0, 200, 255, 0.15)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
      }}
    >
      {/* ── Card Header ───────────────────────────────────────── */}
      <div
        style={{
          padding: '18px 24px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(255, 171, 64, 0.12)',
              color: '#ffab40',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldAlert size={18} />
          </div>
          <div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
              أنماط وقواعد كشف تسريب البيانات (DLP Patterns)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              مطابقة التعابير النمطية (Regex) وفحص المحتوى بالنواة
            </span>
          </div>
        </div>

        {/* Tab & Action Group */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              display: 'flex',
              gap: 2,
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '8px',
              padding: 2,
            }}
          >
            <button
              onClick={() => setRulesActiveTab('custom')}
              className="btn"
              style={{
                padding: '6px 14px',
                fontSize: '0.78rem',
                fontWeight: rulesActiveTab === 'custom' ? 700 : 500,
                background: rulesActiveTab === 'custom' ? 'rgba(0, 200, 255, 0.18)' : 'transparent',
                color: rulesActiveTab === 'custom' ? '#00c8ff' : 'var(--text-secondary)',
                borderRadius: '6px',
                border: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <SlidersHorizontal size={14} /> أنماط مخصصة ({rules.length})
            </button>
            <button
              onClick={() => setRulesActiveTab('builtin')}
              className="btn"
              style={{
                padding: '6px 14px',
                fontSize: '0.78rem',
                fontWeight: rulesActiveTab === 'builtin' ? 700 : 500,
                background: rulesActiveTab === 'builtin' ? 'rgba(0, 200, 255, 0.18)' : 'transparent',
                color: rulesActiveTab === 'builtin' ? '#00c8ff' : 'var(--text-secondary)',
                borderRadius: '6px',
                border: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Lock size={14} /> أنماط النظام المدمجة ({BUILTIN_PATTERNS.length})
            </button>
          </div>

          {rulesActiveTab === 'custom' && (
            <button
              className="btn btn-primary"
              onClick={() => setShowAddForm(!showAddForm)}
              style={{ padding: '6px 14px', fontSize: '0.78rem', fontWeight: 700 }}
            >
              <Plus size={14} /> {showAddForm ? 'إلغاء' : 'إضافة قاعدة جديدة'}
            </button>
          )}
        </div>
      </div>

      {/* ── Form Card for Adding Custom Rule ─────────────────── */}
      {showAddForm && rulesActiveTab === 'custom' && (
        <form
          onSubmit={handleAdd}
          style={{
            margin: '18px 24px',
            padding: '18px 20px',
            background: 'rgba(0, 200, 255, 0.03)',
            border: '1px solid rgba(0, 200, 255, 0.25)',
            borderRadius: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#00c8ff', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Plus size={16} /> إضافة قاعدة كشف تسريب مخصصة
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                اسم القاعدة
              </label>
              <input
                className="input"
                placeholder="مثال: أرقام العقود السرية"
                value={newRule.name}
                onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                التعبير النمطي (Regex Pattern)
              </label>
              <input
                className="input"
                placeholder="مثال: \bSEC-[0-9]{6}\b"
                value={newRule.pattern}
                onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                style={{ fontFamily: 'JetBrains Mono, monospace', direction: 'ltr', textAlign: 'left' }}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                مستوى الخطورة
              </label>
              <select
                className="input"
                value={newRule.severity}
                onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
              >
                <option value="CRITICAL">حرج جداً (CRITICAL)</option>
                <option value="HIGH">عالي (HIGH)</option>
                <option value="MEDIUM">متوسط (MEDIUM)</option>
                <option value="LOW">منخفض (LOW)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                الوصف / الهدف
              </label>
              <input
                className="input"
                placeholder="حجب مستندات المشاريع..."
                value={newRule.description}
                onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
            <button type="submit" className="btn btn-primary" style={{ padding: '7px 18px', fontSize: '0.8rem' }}>
              <CheckCircle2 size={14} /> حفظ وتفعيل القاعدة
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => setShowAddForm(false)}
              style={{ padding: '7px 16px', fontSize: '0.8rem' }}
            >
              إلغاء
            </button>
          </div>
        </form>
      )}

      {/* ── Built-in Patterns Tab ────────────────────────────── */}
      {rulesActiveTab === 'builtin' ? (
        <div style={{ padding: '20px 24px' }}>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
            تم تجميع هذه الأنماط الحساسة مسبقاً في قلب محرك DLP بالنواة ومطابقتها بكفاءة أداء معالجة 0-overhead.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {BUILTIN_PATTERNS.map((p, idx) => {
              const sevColor = SEVERITY_COLORS[p.severity] || '#00c8ff';
              return (
                <div
                  key={p.name}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '14px 18px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    borderRadius: '10px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    flexWrap: 'wrap',
                    gap: 12,
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                      {p.name}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                      {p.desc}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <code
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.75rem',
                        background: 'rgba(0, 200, 255, 0.08)',
                        color: '#00c8ff',
                        padding: '4px 10px',
                        borderRadius: '6px',
                        direction: 'ltr',
                      }}
                    >
                      {p.pattern}
                    </code>

                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 800,
                        padding: '2px 8px',
                        borderRadius: '12px',
                        color: sevColor,
                        background: `${sevColor}15`,
                        border: `1px solid ${sevColor}35`,
                      }}
                    >
                      {SEVERITY_BADGES[p.severity] || p.severity}
                    </span>

                    <button
                      className="btn btn-ghost"
                      onClick={() => handleCopy(p.pattern, `builtin-${idx}`)}
                      title="نسخ التعبير النمطي"
                      style={{ padding: '5px 8px' }}
                    >
                      {copiedPattern === `builtin-${idx}` ? <Check size={14} color="#00e676" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        /* ── Custom Patterns Tab ────────────────────────────── */
        <div style={{ padding: '0 24px 20px' }}>
          {/* Search Filter */}
          <div style={{ padding: '16px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ position: 'relative', width: 280 }}>
              <Search size={14} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                className="input"
                style={{ width: '100%', paddingRight: 32, fontSize: '0.8rem' }}
                placeholder="بحث في القواعد المخصصة..."
                value={rulesSearch}
                onChange={(e) => setRulesSearch(e.target.value)}
              />
            </div>
          </div>

          <table className="table" style={{ width: '100%' }}>
            <thead>
              <tr>
                <th>اسم القاعدة</th>
                <th>التعبير النمطي (Regex)</th>
                <th>مستوى الخطورة</th>
                <th>الوصف</th>
                <th style={{ textAlign: 'left' }}>إجراء</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    لا توجد قواعد مطابقة مخصصة مضافة حالياً.
                  </td>
                </tr>
              ) : (
                filtered.map((rule) => {
                  const sevColor = SEVERITY_COLORS[rule.severity?.toUpperCase()] || '#00c8ff';
                  return (
                    <tr key={rule.id}>
                      <td style={{ fontWeight: 700 }}>{rule.name}</td>
                      <td>
                        <code
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '0.75rem',
                            background: 'rgba(0, 200, 255, 0.08)',
                            color: '#00c8ff',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            direction: 'ltr',
                            display: 'inline-block',
                          }}
                        >
                          {rule.pattern}
                        </code>
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            fontWeight: 800,
                            padding: '2px 8px',
                            borderRadius: '12px',
                            color: sevColor,
                            background: `${sevColor}15`,
                            border: `1px solid ${sevColor}35`,
                          }}
                        >
                          {SEVERITY_BADGES[rule.severity?.toUpperCase()] || rule.severity}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                        {rule.description || '—'}
                      </td>
                      <td style={{ textAlign: 'left' }}>
                        <button
                          className="btn btn-ghost"
                          style={{ color: '#ff4d6a', padding: '4px 8px' }}
                          title="حذف القاعدة"
                          onClick={() => deleteRule.mutate(rule.id)}
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
