import React, { useState } from 'react';
import { BrainCircuit, ThumbsUp, ThumbsDown, Send, RefreshCw, ShieldOff, CheckCircle2, AlertCircle } from 'lucide-react';
import { useAuth } from '../../../hooks/useAuth';
import { useDLPStore } from '../store/dlpStore';
import { useDLP } from '../hooks/useDLP';

export default function FeedbackPanelCard() {
  const { user } = useAuth() ?? {};
  const isAdmin = user?.role === 'admin';

  const {
    feedbackEventId, setFeedbackEventId,
    feedbackLabel, setFeedbackLabel,
    showAdminFeedback, toggleShowAdminFeedback,
  } = useDLPStore();

  const {
    submitFeedback,
    reviewFeedback,
    pendingFeedback = [],
    isFetchingPendingFeedback,
    refetchPendingFeedback,
  } = useDLP();

  const [sentSuccess, setSentSuccess] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!feedbackEventId) return;

    submitFeedback.mutate(
      { event_id: feedbackEventId, label: feedbackLabel },
      {
        onSuccess: () => {
          setSentSuccess(true);
          setFeedbackEventId('');
          setTimeout(() => setSentSuccess(false), 4000);
        },
      }
    );
  };

  return (
    <div
      className="card"
      style={{
        background: 'rgba(10, 14, 26, 0.75)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(0, 200, 255, 0.15)',
        borderRadius: 'var(--radius-lg)',
        padding: '22px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(129, 140, 248, 0.12)',
              color: '#818cf8',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <BrainCircuit size={18} />
          </div>
          <div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
              التعلم الذاتي ومراجعة قرارات الذكاء الاصطناعي (Active Learning Loop)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              تقييم تنبيهات النماذج وتدريبها لمنع الإنذارات الكاذبة
            </span>
          </div>
        </div>

        {isAdmin && (
          <button
            className="btn btn-ghost"
            onClick={toggleShowAdminFeedback}
            style={{
              fontSize: '0.78rem',
              padding: '6px 14px',
              background: showAdminFeedback ? 'rgba(0, 200, 255, 0.12)' : 'transparent',
              borderColor: showAdminFeedback ? 'rgba(0, 200, 255, 0.3)' : 'rgba(255, 255, 255, 0.1)',
              color: showAdminFeedback ? '#00c8ff' : 'var(--text-secondary)',
              fontWeight: 700,
            }}
          >
            {showAdminFeedback ? 'إخفاء مراجعة المشرف' : `قائمة مراجعة المشرف (${pendingFeedback.length})`}
          </button>
        )}
      </div>

      {!showAdminFeedback ? (
        <>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 18, lineHeight: 1.6 }}>
            ساعد النموذج العصبي على التمييز بين حركة البيانات المشروعة ومحاولات التسريب الحقيقية. يتم وضع التقييمات في طابور مراجعة أمني قبل إعادة التمرين التلقائي.
          </p>

          <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ flex: 1, minWidth: '220px', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem', direction: 'ltr', textAlign: 'left' }}
              placeholder="معرف الحدث (Event ID من السجل)"
              value={feedbackEventId}
              onChange={(e) => setFeedbackEventId(e.target.value)}
              required
            />

            <div style={{ display: 'flex', gap: 4, background: 'rgba(255, 255, 255, 0.04)', borderRadius: 8, padding: 3, border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <button
                type="button"
                onClick={() => setFeedbackLabel('true_positive')}
                style={{
                  padding: '6px 14px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  borderRadius: 6,
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                  background: feedbackLabel === 'true_positive' ? 'rgba(255, 77, 106, 0.15)' : 'transparent',
                  color: feedbackLabel === 'true_positive' ? '#ff4d6a' : 'var(--text-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <ThumbsDown size={14} /> تسريب حقيقي (TP)
              </button>

              <button
                type="button"
                onClick={() => setFeedbackLabel('false_positive')}
                style={{
                  padding: '6px 14px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  borderRadius: 6,
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                  background: feedbackLabel === 'false_positive' ? 'rgba(0, 230, 118, 0.15)' : 'transparent',
                  color: feedbackLabel === 'false_positive' ? '#00e676' : 'var(--text-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <ThumbsUp size={14} /> إيجابي كاذب (FP)
              </button>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitFeedback.isPending}
              style={{ padding: '8px 18px', fontSize: '0.8rem', fontWeight: 700 }}
            >
              <Send size={14} /> إرسال التقييم
            </button>
          </form>

          {sentSuccess && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 8,
                background: 'rgba(0, 230, 118, 0.1)',
                border: '1px solid rgba(0, 230, 118, 0.25)',
                color: '#00e676',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <CheckCircle2 size={16} />
              تم تسجيل تقييمك بنجاح وسيتلقاه طابور إعادة تدريب النموذج!
            </div>
          )}
        </>
      ) : (
        /* ── Admin Feedback Review Queue ── */
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              مراجعة التقييمات المعلقة لاعتمادها أو رفضها
            </span>
            <button
              className="btn btn-ghost"
              onClick={() => refetchPendingFeedback && refetchPendingFeedback()}
              style={{ padding: '4px 10px', fontSize: '0.75rem' }}
            >
              <RefreshCw size={12} style={{ animation: isFetchingPendingFeedback ? 'spin 1s linear infinite' : 'none' }} /> تحديث
            </button>
          </div>

          {pendingFeedback.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
              لا توجد تقييمات معلقة بانتظار اعتماد المشرف.
            </div>
          ) : (
            pendingFeedback.map((fb) => (
              <div
                key={fb.id || fb.event_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 14px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  borderRadius: 8,
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                }}
              >
                <div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: '#00c8ff' }}>
                    {fb.event_id}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                    التصنيف المقترح: {fb.label === 'true_positive' ? 'تسريب حقيقي (TP)' : 'إيجابي كاذب (FP)'}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    className="btn btn-ghost"
                    style={{ color: '#00e676', padding: '4px 10px', fontSize: '0.75rem' }}
                    onClick={() => reviewFeedback.mutate({ id: fb.id, action: 'approve' })}
                  >
                    اعتماد
                  </button>
                  <button
                    className="btn btn-ghost"
                    style={{ color: '#ff4d6a', padding: '4px 10px', fontSize: '0.75rem' }}
                    onClick={() => reviewFeedback.mutate({ id: fb.id, action: 'reject' })}
                  >
                    رفض
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
