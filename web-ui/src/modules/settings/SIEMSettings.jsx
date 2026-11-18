import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { siemApi } from '../../services/api';
import { Database, RefreshCw, Send, ShieldAlert, CheckCircle2, AlertTriangle, Loader2, Activity, Server } from 'lucide-react';
import './Settings.css';

export default function SIEMSettings() {
  const qc = useQueryClient();
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const { data: status, isLoading, error, refetch } = useQuery({
    queryKey: ['siem-status'],
    queryFn: () => siemApi.status().then((r) => r.data),
    refetchInterval: 15000,
  });

  const testMut = useMutation({
    mutationFn: () => siemApi.test(),
    onSuccess: (res) => {
      setTestResult({ success: true, message: res.data?.message || 'تم إرسال حدث الاختبار بنجاح إلى خادم SIEM!' });
      refetch();
    },
    onError: (err) => {
      setTestResult({ success: false, message: `فشل الاتصال بخادم SIEM: ${err.response?.data?.detail || err.message}` });
    },
  });

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    testMut.mutate(undefined, {
      onSettled: () => setIsTesting(false),
    });
  };

  if (isLoading) {
    return (
      <div className="s-loading">
        <RefreshCw className="spin text-cyan-400" size={20} />
        <span>جاري التحقق من إعدادات وتكامل موصل سجلات الـ SIEM...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="s-card" style={{ padding: 24, textAlign: 'center', color: '#ff4d6a' }}>
        <AlertTriangle size={24} style={{ margin: '0 auto 8px' }} />
        <div>فشل الاتصال بخدمة إعدادات وتكامل SIEM الخارجية</div>
      </div>
    );
  }

  const isEnabled = status?.enabled;
  const isRunning = status?.status === 'active';

  return (
    <div dir="rtl" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── بطاقة حالة SIEM الرئيسية ── */}
      <div className="s-card">
        <div className="s-card-header">
          <div className="s-card-icon primary">
            <Database size={18} />
          </div>
          <div>
            <h3 className="s-card-title">موصل وتكامل سجلات SIEM الخارجي</h3>
            <p className="s-card-subtitle">تصدير سجلات الأحداث الأمنية والتهديدات إلى خوادم Splunk أو Elastic أو Syslog</p>
          </div>
          <span
            className={`s-badge ${
              isEnabled ? (isRunning ? 's-badge-success' : 's-badge-warning') : 's-badge-danger'
            }`}
            style={{ marginRight: 'auto' }}
          >
            {!isEnabled ? 'غير مفعل' : isRunning ? 'متصل ونشط 🟢' : 'متوقف'}
          </span>
        </div>

        <div className="s-card-body">
          {!isEnabled ? (
            <div style={{
              padding: '24px',
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: '12px',
              border: '1px solid rgba(255, 255, 255, 0.07)',
              display: 'flex',
              alignItems: 'center',
              gap: '14px'
            }}>
              <AlertTriangle size={24} style={{ color: '#ffab40', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                  تكامل SIEM معطل حالياً في ملف الإعدادات
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', lineHeight: 1.6 }}>
                  لتفعيل تصدير السجلات تلقائياً: انتقل إلى تبويب 
                  <strong
                    style={{ color: '#00c8ff', cursor: 'pointer', margin: '0 4px' }}
                    onClick={() => (window.location.hash = '#features.yaml')}
                  >
                    features.yaml
                  </strong>
                  وفعّل خيار <code className="s-code-badge forward">integration.siem.enabled = true</code>.
                </div>
              </div>
            </div>
          ) : (
            <>
              {/* شبكة الإعدادات الحالية */}
              <div className="s-form-grid" style={{ marginBottom: 20 }}>
                <div className="s-stat-pill">
                  <div className="s-stat-pill-icon" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
                    <Server size={18} />
                  </div>
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">نوع المنصة المستهدفة</div>
                    <div style={{ fontWeight: 800, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                      {status.type || 'Syslog Server'}
                    </div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">عنوان الخادم والمنفذ</div>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem', color: '#00c8ff' }}>
                      {status.config?.server ? `${status.config.server}:${status.config.port}` : (status.config?.hosts?.join(', ') || status.config?.url || '---')}
                    </div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">بروتوكول النقل</div>
                    <div style={{ fontWeight: 700, color: '#818cf8', textTransform: 'uppercase' }}>
                      {status.config?.protocol || 'TCP / TLS'}
                    </div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">سعة المخزن المؤقت (Buffer)</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                      {status.config?.buffer_size || 5000} حدث
                    </div>
                  </div>
                </div>
              </div>

              {/* إحصائيات التصدير */}
              <div className="s-stat-bar" style={{ marginBottom: 20 }}>
                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-val" style={{ color: '#00e676' }}>
                      {status.stats?.sent?.toLocaleString() || 0}
                    </div>
                    <div className="s-stat-pill-lbl">سجلات تم تصديرها بنجاح</div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-val" style={{ color: '#ff4d6a' }}>
                      {status.stats?.failed?.toLocaleString() || 0}
                    </div>
                    <div className="s-stat-pill-lbl">سجلات فشل تسليمها</div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-val" style={{ color: '#ffab40' }}>
                      {status.stats?.buffered?.toLocaleString() || 0}
                    </div>
                    <div className="s-stat-pill-lbl">سجلات في قائمة الانتظار</div>
                  </div>
                </div>
              </div>

              {/* أزرار الإجراءات */}
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  className="s-btn s-btn-primary"
                  onClick={handleTestConnection}
                  disabled={isTesting}
                >
                  {isTesting ? <Loader2 size={14} className="spin" /> : <Send size={14} />}
                  إرسال حدث تجريبي واختبار الاتصال
                </button>
                <button className="s-btn s-btn-ghost" onClick={() => refetch()}>
                  <RefreshCw size={14} /> تحديث الإحصائيات
                </button>
              </div>

              {/* نتيجة الاختبار */}
              {testResult && (
                <div
                  style={{
                    marginTop: '16px',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    fontSize: '0.8rem',
                    background: testResult.success ? 'rgba(0, 230, 118, 0.1)' : 'rgba(255, 77, 106, 0.1)',
                    border: `1px solid ${testResult.success ? 'rgba(0, 230, 118, 0.3)' : 'rgba(255, 77, 106, 0.3)'}`,
                    color: testResult.success ? '#00e676' : '#ff4d6a',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  {testResult.success ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                  <span>{testResult.message}</span>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
