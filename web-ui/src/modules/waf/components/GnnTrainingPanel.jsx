import { useState } from 'react';
import { Cpu, RefreshCw, Database, Play, CheckCircle2, AlertTriangle, Zap, HardDrive } from 'lucide-react';
import { SectionCard, KpiCard, StatusBadge } from '../../../components/Shared';

export function GnnTrainingPanel({
  gnnStatus,
  gnnStatusLoading,
  gnnLogs,
  gnnLogsLoading,
  trainingStatus,
  flushSessionLogs,
  flushingLogs,
  startGnnTraining,
  startingTraining,
  activateGnnModel,
  activatingModel,
}) {
  const [epochs, setEpochs] = useState(30);
  const [nSynthetic, setNSynthetic] = useState(500);
  const [actionMsg, setActionMsg] = useState(null);

  const handleFlush = async () => {
    try {
      const res = await flushSessionLogs();
      setActionMsg({ type: 'success', text: `تم تفريغ ${res.data?.records_flushed || 0} سجل إلى ملف CSV بنجاح!` });
    } catch (e) {
      setActionMsg({ type: 'error', text: e.response?.data?.detail || 'فشل تفريغ المؤقت.' });
    }
  };

  const handleStartTrain = async () => {
    try {
      await startGnnTraining({ epochs, n_synthetic: nSynthetic });
      setActionMsg({ type: 'success', text: 'تم بدء تدريب محرك GNN في الخلفية!' });
    } catch (e) {
      setActionMsg({ type: 'error', text: e.response?.data?.detail || 'فشل بدء عملية التدريب.' });
    }
  };

  const handleActivate = async () => {
    try {
      const res = await activateGnnModel();
      setActionMsg({ type: 'success', text: res.data?.message || 'تم تفعيل النموذج المحدث بنجاح!' });
    } catch (e) {
      setActionMsg({ type: 'error', text: e.response?.data?.detail || 'فشل تحميل وتفعيل النموذج.' });
    }
  };

  const sess = gnnStatus?.session_log || {};
  const isTraining = trainingStatus?.state === 'running' || trainingStatus?.state === 'starting';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      
      {/* Action Notification Banner */}
      {actionMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          background: actionMsg.type === 'success' ? 'rgba(40, 199, 111, 0.1)' : 'rgba(234, 84, 85, 0.1)',
          border: `1px solid ${actionMsg.type === 'success' ? 'var(--success)' : 'var(--danger)'}`,
          color: actionMsg.type === 'success' ? 'var(--success)' : 'var(--danger)',
          display: 'flex',
          justify: 'space-between',
          alignItems: 'center',
          fontSize: '0.9rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {actionMsg.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
            <span>{actionMsg.text}</span>
          </div>
          <button onClick={() => setActionMsg(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {/* Top Status KPIs */}
      <div className="kpi-row">
        <KpiCard
          icon={<Cpu size={18} />}
          value={gnnStatus?.gnn_enabled ? 'مُفعّل' : 'معطّل'}
          label="حالة محرك GNN"
          color={gnnStatus?.gnn_enabled ? '#a78bfa' : 'var(--text-muted)'}
        />
        <KpiCard
          icon={<CheckCircle2 size={18} />}
          value={gnnStatus?.model_loaded_in_waf ? 'جاهز' : 'غير محمل'}
          label="النموذج النشط"
          color={gnnStatus?.model_loaded_in_waf ? 'var(--success)' : 'var(--warning)'}
        />
        <KpiCard
          icon={<Database size={18} />}
          value={sess.buffer_count ?? 0}
          label="جلسات في ذاكرة المؤقت"
          color="var(--accent)"
        />
        <KpiCard
          icon={<HardDrive size={18} />}
          value={`${sess.file_size_mb || 0} MB`}
          label="حجم ملف الجلسات (CSV)"
          color="var(--info)"
        />
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 'var(--sp-4)' }}>
        
        {/* Training Control Box */}
        <SectionCard title="إدارة وتدريب نموذج GNN" icon={Zap}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              يدرب هذا القسم شبكات الرسم البياني العصبي (Graph Neural Networks) لاكتشاف أنماط التنقل الشاذة والهجمات التسلسلية الموزعة.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, background: 'var(--bg-overlay)', padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.85rem' }}>عدد دورات التدريب (Epochs)</span>
                <input
                  type="number"
                  value={epochs}
                  onChange={e => setEpochs(parseInt(e.target.value) || 10)}
                  min={5} max={200}
                  style={{ width: 80, padding: '4px 8px', background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-main)', textAlign: 'center' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.85rem' }}>جلسات اصطناعية (عند نقص البيانات)</span>
                <input
                  type="number"
                  value={nSynthetic}
                  onChange={e => setNSynthetic(parseInt(e.target.value) || 100)}
                  min={100} max={5000}
                  style={{ width: 80, padding: '4px 8px', background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-main)', textAlign: 'center' }}
                />
              </div>
            </div>

            {/* Live Training Status */}
            {trainingStatus?.state && trainingStatus.state !== 'idle' && (
              <div style={{ background: 'rgba(0,200,255,0.05)', border: '1px solid var(--accent)', borderRadius: 8, padding: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: 6 }}>
                  <span style={{ fontWeight: 'bold' }}>حالة التدريب: {(trainingStatus.state || '').toUpperCase()}</span>
                  <span className="mono">{trainingStatus.epoch ? `${trainingStatus.epoch} / ${trainingStatus.total_epochs}` : ''}</span>
                </div>
                {trainingStatus.progress_percent !== undefined && (
                  <div style={{ height: 6, background: 'var(--bg-overlay)', borderRadius: 3, overflow: 'hidden', margin: '6px 0' }}>
                    <div style={{ height: '100%', width: `${trainingStatus.progress_percent}%`, background: 'var(--accent)', transition: 'width 0.4s' }} />
                  </div>
                )}
                {trainingStatus.loss !== undefined && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} className="mono">
                    Loss: {trainingStatus.loss?.toFixed(4)} | Accuracy: {((trainingStatus.val_acc || 0) * 100).toFixed(1)}%
                  </div>
                )}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                onClick={handleStartTrain}
                disabled={startingTraining || isTraining}
                style={{ flex: 1 }}
              >
                {isTraining ? <RefreshCw size={14} className="waf-spin" /> : <Play size={14} />}
                {isTraining ? 'جاري التدريب...' : 'بدء التدريب'}
              </button>

              <button
                className="btn btn-success"
                onClick={handleActivate}
                disabled={activatingModel || !gnnStatus?.model_file_exists}
                style={{ flex: 1 }}
              >
                {activatingModel ? <RefreshCw size={14} className="waf-spin" /> : <Zap size={14} />}
                تفعيل النموذج وتطبيقه
              </button>
            </div>
          </div>
        </SectionCard>

        {/* Log Buffer Management */}
        <SectionCard title="ذاكرة وسجل الجلسات (Dataset Logs)" icon={Database}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              مسار الملف: <code className="mono" style={{ color: 'var(--accent)', fontSize: '0.8rem' }}>{gnnStatus?.session_log?.path || 'N/A'}</code>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-overlay)', padding: 12, borderRadius: 8 }}>
              <div>
                <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>إجمالي الجلسات المُفرغة</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>تم تفريغ {sess.total_flushed || 0} سجل للقرص</div>
              </div>
              <button
                onClick={handleFlush}
                disabled={flushingLogs || sess.buffer_count === 0}
                className="btn btn-ghost"
                style={{ border: '1px solid var(--border)' }}
              >
                {flushingLogs ? <RefreshCw size={14} className="waf-spin" /> : <Database size={14} />}
                تفريغ الذاكرة الآن
              </button>
            </div>

            {/* CSV Preview */}
            <div style={{ border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '8px 12px', background: 'var(--bg-raised)', fontSize: '0.8rem', fontWeight: 'bold', borderBottom: '1px solid var(--border)' }}>
                معاينة آخر الجلسات المسجلة (CSV Preview)
              </div>
              <div style={{ padding: 10, background: '#090d16', maxHeight: 180, overflowY: 'auto' }}>
                {gnnLogs?.preview_lines?.length > 0 ? (
                  <pre className="mono" style={{ fontSize: '0.75rem', color: '#a78bfa', margin: 0, whiteSpace: 'pre-wrap' }}>
                    {gnnLogs.preview_lines.join('\n')}
                  </pre>
                ) : (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: 20 }}>
                    لا توجد معاينة حالياً. قم بتفعيل تسجيل الجلسات وتشغيل الحركة.
                  </div>
                )}
              </div>
            </div>
          </div>
        </SectionCard>

      </div>
    </div>
  );
}
