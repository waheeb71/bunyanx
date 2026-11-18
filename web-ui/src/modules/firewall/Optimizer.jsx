import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { optimizerApi } from './api/firewallApi';
import useFirewallStore from '../../stores/firewallStore';
import {
  BrainCircuit, Zap, Trash2, GitMerge, RefreshCw,
  CheckCircle2, ShieldOff, ArrowUpDown, AlertTriangle,
  Layers, Check, X, ShieldAlert, Sparkles, TrendingUp, Cpu
} from 'lucide-react';

/* ── Action Visual Configurations ── */
const ACTION_CONFIG = {
  shadowed: {
    Icon: ShieldOff,
    color: '#ff4d6a',
    bg: 'rgba(255, 77, 106, 0.12)',
    border: 'rgba(255, 77, 106, 0.3)',
    badgeLabel: 'قاعدة محجوبة (Shadowed Rule)',
    tag: 'تعارض أمني',
    canAccept: true,
  },
  delete: {
    Icon: Trash2,
    color: '#ffab40',
    bg: 'rgba(255, 171, 64, 0.12)',
    border: 'rgba(255, 171, 64, 0.3)',
    badgeLabel: 'قاعدة ميتة (Dead / 0-Hits)',
    tag: 'حمل زائد',
    canAccept: true,
  },
  merge: {
    Icon: GitMerge,
    color: '#00c8ff',
    bg: 'rgba(0, 200, 255, 0.12)',
    border: 'rgba(0, 200, 255, 0.3)',
    badgeLabel: 'مرشحة للدمج (Mergeable Subnets)',
    tag: 'تحسين الذاكرة',
    canAccept: false,
  },
  reorder: {
    Icon: ArrowUpDown,
    color: '#818cf8',
    bg: 'rgba(129, 140, 248, 0.12)',
    border: 'rgba(129, 140, 248, 0.3)',
    badgeLabel: 'إعادة ترتيب التردد (Reorder by Hit Rate)',
    tag: 'تسريع الأداء',
    canAccept: false,
  },
};

const suggestionKey = (s) => {
  if (s.rule_id != null) return `${s.action}-${s.rule_id}`;
  if (s.rules) return `${s.action}-${s.rules.join('_')}`;
  if (s.new_order) return `${s.action}-reorder`;
  return `${s.action}-${crypto.randomUUID()}`;
};

export default function Optimizer() {
  const qc = useQueryClient();
  const [dismissed, setDismissed] = useState(new Set());
  const [accepted, setAccepted] = useState(new Set());
  const [confirmApply, setConfirmApply] = useState(false);
  const { showToast } = useFirewallStore();

  const { data: report, isFetching, refetch } = useQuery({
    queryKey: ['optimizer-report'],
    queryFn: () => optimizerApi.analyze().then((r) => r.data),
    enabled: false,
    retry: false,
  });

  const applyMut = useMutation({
    mutationFn: (ids) => optimizerApi.applyDeletes(ids),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['optimizer-report'] });
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      setAccepted(new Set());
      setDismissed(new Set());
      setConfirmApply(false);
      showToast('تم تطبيق التحسينات وحذف القواعد المتعارضة بنجاح', 'success');
    },
    onError: (e) => {
      setConfirmApply(false);
      showToast('فشل التطبيق: ' + e.message, 'error');
    },
  });

  const allSuggestions = report?.suggestions || [];
  const suggestions = allSuggestions.filter((s) => !dismissed.has(suggestionKey(s)));

  const acceptedDeleteIds = allSuggestions
    .filter((s) => accepted.has(suggestionKey(s)) && (s.action === 'delete' || s.action === 'shadowed') && s.rule_id != null)
    .map((s) => s.rule_id);

  const toggleAccept = (key) =>
    setAccepted((prev) => {
      const n = new Set(prev);
      n.has(key) ? n.delete(key) : n.add(key);
      return n;
    });

  const dismiss = (key) => setDismissed((prev) => new Set([...prev, key]));

  const shadowedCount = suggestions.filter((s) => s.action === 'shadowed').length;
  const deadCount = suggestions.filter((s) => s.action === 'delete').length;
  const mergeCount = suggestions.filter((s) => s.action === 'merge').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }} dir="rtl">
      {/* ── Hero Top Bar ── */}
      <div
        className="card"
        style={{
          position: 'relative',
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.2)',
          borderRadius: 'var(--radius-lg)',
          padding: '20px 24px',
          overflow: 'hidden',
        }}
      >
        <div style={{ position: 'absolute', top: -50, right: -50, width: 180, height: 180, borderRadius: '50%', background: 'radial-gradient(circle, rgba(0, 200, 255, 0.15) 0%, transparent 70%)', pointerEvents: 'none' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div
              style={{
                width: 48,
                height: 48,
                borderRadius: 12,
                background: 'rgba(0, 200, 255, 0.12)',
                border: '1px solid rgba(0, 200, 255, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#00c8ff',
              }}
            >
              <BrainCircuit size={24} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                المُحسِّن الذكي لقواعد الجدار الناري (Firewall Policy AI Optimizer)
              </h2>
              <p style={{ margin: '2px 0 0', fontSize: '0.74rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                Rule Shadowing Detection · Redundant Cleanup · Latency Reduction Matrix
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              onClick={() => refetch()}
              disabled={isFetching}
              style={{ padding: '8px 18px', fontSize: '0.82rem', fontWeight: 700 }}
            >
              <RefreshCw size={14} className={isFetching ? 'spin' : ''} />
              {isFetching ? 'جاري التحليل المعمق...' : 'تشغيل فحص التعارضات والتحسين'}
            </button>

            {acceptedDeleteIds.length > 0 && (
              <button
                className="btn btn-danger"
                onClick={() => setConfirmApply(true)}
                style={{ padding: '8px 18px', fontSize: '0.82rem', fontWeight: 700 }}
              >
                <Trash2 size={14} /> تطبيق وحذف ({acceptedDeleteIds.length}) قواعد محددة
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── KPI Metrics Strip ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
        <div
          className="card"
          style={{
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.65)',
            border: '1px solid rgba(255, 77, 106, 0.2)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}
        >
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldOff size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontWeight: 700 }}>قواعد محجوبة ومتعارضة</div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ff4d6a', fontFamily: 'JetBrains Mono, monospace' }}>
              {shadowedCount}
            </div>
          </div>
        </div>

        <div
          className="card"
          style={{
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.65)',
            border: '1px solid rgba(255, 171, 64, 0.2)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}
        >
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(255, 171, 64, 0.12)', color: '#ffab40', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Trash2 size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontWeight: 700 }}>قواعد ميتة (0-Hits)</div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffab40', fontFamily: 'JetBrains Mono, monospace' }}>
              {deadCount}
            </div>
          </div>
        </div>

        <div
          className="card"
          style={{
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.65)',
            border: '1px solid rgba(0, 200, 255, 0.2)',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}
        >
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <GitMerge size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontWeight: 700 }}>فرص الدمج والاختصار</div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, color: '#00c8ff', fontFamily: 'JetBrains Mono, monospace' }}>
              {mergeCount}
            </div>
          </div>
        </div>
      </div>

      {/* ── Suggestions Feed ── */}
      {report == null && !isFetching ? (
        <div
          className="card"
          style={{
            padding: '60px 20px',
            textAlign: 'center',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
          }}
        >
          <BrainCircuit size={48} style={{ display: 'block', margin: '0 auto 14px', color: '#00c8ff', opacity: 0.7 }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', margin: '0 0 6px' }}>
            محرك التحليل الذكي في وضع الاستعداد
          </h3>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto 18px', lineHeight: 1.6 }}>
            اضغط على زر "تشغيل فحص التعارضات والتحسين" للبدء في مسح كافة قواعد السياسة واكتشاف التعارضات وحساب زمن الاستجابة الفعلي.
          </p>
          <button className="btn btn-primary" onClick={() => refetch()} style={{ padding: '8px 20px', fontSize: '0.85rem' }}>
            <Zap size={14} /> فحص القواعد الآن
          </button>
        </div>
      ) : isFetching ? (
        <div
          className="card"
          style={{
            padding: '60px 20px',
            textAlign: 'center',
            color: 'var(--text-secondary)',
            background: 'rgba(10, 14, 26, 0.75)',
            borderRadius: 'var(--radius-lg)',
          }}
        >
          <RefreshCw size={32} className="spin" style={{ color: '#00c8ff', margin: '0 auto 12px', display: 'block' }} />
          <div>جاري مطابقة مصفوفة القواعد وتحليل مسارات الحزم (Packet Evaluation Tree)...</div>
        </div>
      ) : suggestions.length === 0 ? (
        <div
          className="card"
          style={{
            padding: '60px 20px',
            textAlign: 'center',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 230, 118, 0.2)',
            borderRadius: 'var(--radius-lg)',
          }}
        >
          <CheckCircle2 size={48} style={{ display: 'block', margin: '0 auto 12px', color: '#00e676', opacity: 0.9 }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', margin: '0 0 4px' }}>
            مصفوفة القواعد مثالية تماماً 100%!
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
            لم يتم العثور على أي قواعد محجوبة أو تعارضات أو فرص دمج معلقة.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {suggestions.map((s) => {
            const key = suggestionKey(s);
            const cfg = ACTION_CONFIG[s.action] || ACTION_CONFIG.delete;
            const ActionIcon = cfg.Icon;
            const isAccepted = accepted.has(key);
            const confidencePct = Math.round((s.confidence ?? 0.85) * 100);

            return (
              <div
                key={key}
                className="card"
                style={{
                  background: 'rgba(10, 14, 26, 0.75)',
                  backdropFilter: 'blur(16px)',
                  border: `1px solid ${isAccepted ? cfg.color : cfg.border}`,
                  borderRadius: 'var(--radius-lg)',
                  padding: '18px 22px',
                  boxShadow: isAccepted ? `0 4px 24px ${cfg.color}25` : '0 2px 12px rgba(0, 0, 0, 0.3)',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', flex: 1, minWidth: 280 }}>
                    <div
                      style={{
                        width: 40,
                        height: 40,
                        borderRadius: 10,
                        background: cfg.bg,
                        border: `1px solid ${cfg.border}`,
                        color: cfg.color,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                      }}
                    >
                      <ActionIcon size={20} />
                    </div>

                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                        <span
                          style={{
                            fontSize: '0.72rem',
                            fontWeight: 800,
                            padding: '2px 8px',
                            borderRadius: '12px',
                            color: cfg.color,
                            background: cfg.bg,
                            border: `1px solid ${cfg.border}`,
                          }}
                        >
                          {cfg.badgeLabel}
                        </span>

                        <span style={{ fontSize: '0.68rem', background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-secondary)', padding: '2px 7px', borderRadius: 4, fontFamily: 'JetBrains Mono, monospace' }}>
                          ثقة التحليل: {confidencePct}%
                        </span>

                        {s.rule_id != null && (
                          <span style={{ fontSize: '0.72rem', color: '#00c8ff', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                            القاعدة #{s.rule_id}
                          </span>
                        )}
                      </div>

                      <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                        {s.reason || s.description || 'تم اكتشاف تعارض في مصفوفة القواعد'}
                      </div>

                      {/* Details & Conflict Reason Box */}
                      {s.shadowed_by != null && (
                        <div
                          style={{
                            marginTop: 8,
                            padding: '8px 12px',
                            background: 'rgba(255, 77, 106, 0.08)',
                            border: '1px solid rgba(255, 77, 106, 0.25)',
                            borderRadius: '8px',
                            fontSize: '0.76rem',
                            color: '#ff4d6a',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                          }}
                        >
                          <ShieldAlert size={14} />
                          <span>
                            هذه القاعدة محجوبة بالكامل بواسطة <strong>القاعدة الأسبق #{s.shadowed_by}</strong> ولن يتم الوصول إليها أبداً في خط الأنابيب.
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions (Select / Dismiss) */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {cfg.canAccept && (
                      <button
                        className={`btn ${isAccepted ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => toggleAccept(key)}
                        style={{
                          padding: '6px 14px',
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          background: isAccepted ? cfg.color : 'rgba(255, 255, 255, 0.03)',
                          borderColor: isAccepted ? 'transparent' : 'rgba(255, 255, 255, 0.1)',
                          color: isAccepted ? '#fff' : 'var(--text-secondary)',
                        }}
                      >
                        {isAccepted ? <Check size={14} /> : null}
                        {isAccepted ? 'تم التحديد للحذف' : 'تحديد للتنفيذ'}
                      </button>
                    )}

                    <button
                      className="btn btn-ghost"
                      onClick={() => dismiss(key)}
                      title="تجاهل التوصية"
                      style={{ padding: '6px 10px', color: 'var(--text-secondary)' }}
                    >
                      <X size={14} />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Safety Confirmation Modal ── */}
      {confirmApply && (
        <div className="bl-modal" onClick={() => setConfirmApply(false)}>
          <div className="bl-modal-card bl-modal-card--danger" onClick={(e) => e.stopPropagation()} dir="rtl">
            <div className="bl-modal-header">
              <h3 className="bl-modal-title">
                <AlertTriangle size={18} style={{ color: '#ff4d6a' }} />
                تأكيد حذف القواعد المتعارضة ({acceptedDeleteIds.length})
              </h3>
              <button className="bl-modal-close" onClick={() => setConfirmApply(false)}>
                <X size={16} />
              </button>
            </div>

            <div className="bl-modal-body">
              <p style={{ margin: '0 0 16px', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                أنت على وشك حذف <strong>{acceptedDeleteIds.length} قواعد</strong> تم تحديدها تلقائياً كقواعد ميتة أو محجوبة بالكامل.
                سيؤدي ذلك إلى تسريع معالجة الحزم وتقليل استهلاك الذاكرة بالنواة.
              </p>

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
                {acceptedDeleteIds.map((id) => (
                  <span key={id} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a', border: '1px solid rgba(255, 77, 106, 0.3)', padding: '2px 8px', borderRadius: 4 }}>
                    Rule #{id}
                  </span>
                ))}
              </div>

              <div className="bl-modal-actions">
                <button type="button" className="bl-action-btn" onClick={() => setConfirmApply(false)}>
                  إلغاء
                </button>
                <button
                  type="button"
                  className="bl-action-btn bl-action-btn--primary"
                  onClick={() => applyMut.mutate(acceptedDeleteIds)}
                  disabled={applyMut.isPending}
                >
                  {applyMut.isPending ? <RefreshCw size={14} className="bl-spin" /> : <Trash2 size={14} />}
                  تأكيد الحذف وتحسين السياسة
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
