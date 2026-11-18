import { useState, useRef } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Search, X, RotateCcw, Brain, AlertTriangle, Clock, ArrowLeft, UserCheck, RefreshCw } from 'lucide-react';
import { aiApi } from '../api/aiApi';
import { fmtTs } from './Helpers';

export function IpInspectorModal({ onClose }) {
  const [ip, setIp] = useState('');
  const [queried, setQ] = useState('');
  const inputRef = useRef();

  const { data: belief, isLoading: bL, error: bE } = useQuery({
    queryKey: ['AEGIS_belief', queried],
    queryFn: () => aiApi.AEGISBeliefIp(queried).then(r => r.data),
    enabled: !!queried,
    retry: false,
  });
  const { data: hist, isLoading: hL } = useQuery({
    queryKey: ['ip_intent_hist', queried],
    queryFn: () => aiApi.ipIntent(queried).then(r => r.data),
    enabled: !!queried,
    retry: false,
  });
  const { data: ueba, isLoading: uL } = useQuery({
    queryKey: ['ueba_baseline', queried],
    queryFn: () => aiApi.uebaBaseline(queried).then(r => r.data),
    enabled: !!queried,
    retry: false,
  });

  const resetMut = useMutation({
    mutationFn: () => aiApi.resetAttacker(queried),
    onSuccess: () => alert(`تم إعادة تعيين حالة AEGIS للـIP: ${queried}`),
  });

  const search = () => { if (ip.trim()) setQ(ip.trim()); };

  return (
    <div className="pai-modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="pai-modal">
        <div className="pai-modal-header">
          <div className="pai-panel-title"><Search size={14} /> فحص IP بالمحرك AEGIS</div>
          <button className="pai-refresh-btn" onClick={onClose}><X size={14} /></button>
        </div>
        <div className="pai-modal-body">
          <div className="pai-ip-search-row">
            <input
              ref={inputRef}
              className="pai-ip-input pai-mono"
              placeholder="192.168.1.100"
              value={ip}
              dir="ltr"
              onChange={e => setIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && search()}
            />
            <button className="pai-search-btn" onClick={search}>بحث</button>
            {queried && (
              <button
                className="pai-reset-btn"
                onClick={() => resetMut.mutate()}
                disabled={resetMut.isPending}
                title="إعادة تعيين حالة AEGIS لهذا الـIP"
              >
                <RotateCcw size={13} />
                {resetMut.isPending ? '...' : 'إعادة تعيين'}
              </button>
            )}
          </div>

          {queried && (
            <div className="pai-ip-results">
              <div className="pai-ip-section">
                <div className="pai-ip-section-title"><Brain size={12} /> حالة الاعتقاد (ASE Belief)</div>
                {bL ? <div className="pai-empty"><RefreshCw size={16} className="pai-spin" /><span>تحميل...</span></div>
                  : bE ? <div className="pai-empty"><AlertTriangle size={16} style={{ color: '#ff5f5f' }} /><span>غير مرصود بعد</span></div>
                    : belief?.belief ? (
                      <div className="pai-belief-grid">
                        <div className="pai-belief-kpi">
                          <div className="pai-belief-kpi-lbl">المرحلة الأرجح</div>
                          <div className="pai-belief-kpi-val">{typeof belief.belief.most_likely_stage === 'object' ? JSON.stringify(belief.belief.most_likely_stage) : (belief.belief.most_likely_stage || '—')}</div>
                        </div>
                        <div className="pai-belief-kpi">
                          <div className="pai-belief-kpi-lbl">يقينية</div>
                          <div className="pai-belief-kpi-val pai-mono">{((Number(belief.belief.stage_certainty || 0)) * 100).toFixed(1)}%</div>
                        </div>
                        <div className="pai-belief-kpi">
                          <div className="pai-belief-kpi-lbl">إنتروبيا</div>
                          <div className="pai-belief-kpi-val pai-mono">{(Number(belief.belief.entropy || 0)).toFixed(3)}</div>
                        </div>
                      </div>
                    ) : null}
              </div>

              <div className="pai-ip-section">
                <div className="pai-ip-section-title"><Clock size={12} /> سجل التنبؤات ({hist?.predictions?.length ?? 0})</div>
                {hL ? <div className="pai-empty"><RefreshCw size={16} className="pai-spin" /><span>تحميل...</span></div>
                  : (Array.isArray(hist?.predictions) ? hist.predictions : []).slice(-8).reverse().map((p, i) => (
                    <div key={i} className="pai-hist-row">
                      <span className="pai-mono" dir="ltr" style={{ color: 'rgba(255,255,255,.3)', fontSize: '.7rem' }}>
                        {fmtTs(p.timestamp)}
                      </span>
                      <span className="pai-stage-badge">{typeof p.current_stage === 'object' ? JSON.stringify(p.current_stage) : String(p.current_stage ?? '—')}</span>
                      <ArrowLeft size={11} style={{ opacity: .3 }} />
                      <span className="pai-stage-badge pai-stage-badge--predicted">{typeof p.predicted_next === 'object' ? JSON.stringify(p.predicted_next) : String(p.predicted_next ?? '—')}</span>
                      <span className="pai-mono" dir="ltr" style={{ color: '#fbbf24', fontSize: '.75rem' }}>
                        {((Number(p.confidence || 0)) * 100).toFixed(1)}%
                      </span>
                    </div>
                  ))}
              </div>

              <div className="pai-ip-section">
                <div className="pai-ip-section-title"><UserCheck size={12} /> ملف UEBA السلوكي</div>
                {uL ? <div className="pai-empty"><RefreshCw size={16} className="pai-spin" /><span>تحميل...</span></div>
                  : ueba?.baseline ? (
                    <div className="pai-ueba-summary pai-mono" dir="ltr">
                      {JSON.stringify(ueba.baseline, null, 2).slice(0, 400)}...
                    </div>
                  ) : (
                    <div className="pai-empty"><UserCheck size={16} style={{ opacity: .1 }} /><span>لا يوجد ملف UEBA لهذا الـIP</span></div>
                  )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default IpInspectorModal;
