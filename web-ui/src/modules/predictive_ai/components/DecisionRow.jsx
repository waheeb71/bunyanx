import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { fmtIso } from './Helpers';

export function DecisionRow({ dec }) {
  const [open, setOpen] = useState(false);
  const belief = dec.belief_state ?? {};
  const ttps   = dec.ttp_distribution ?? dec.predicted_ttps ?? [];

  const strategyStr = typeof dec.counter_strategy === 'object' && dec.counter_strategy !== null
    ? (dec.counter_strategy.action || dec.counter_strategy.name || JSON.stringify(dec.counter_strategy))
    : (dec.counter_strategy || '—');

  const explanationStr = typeof dec.explanation === 'object' && dec.explanation !== null
    ? (dec.explanation.text || dec.explanation.reason || JSON.stringify(dec.explanation))
    : (dec.explanation || (typeof dec.counter_strategy === 'object' ? dec.counter_strategy?.explanation : null));

  return (
    <div className="pai-dec-row">
      <div className="pai-dec-header" onClick={() => setOpen(o => !o)}>
        <span className="pai-mono" dir="ltr" style={{ color:'#818cf8', minWidth:130 }}>
          {typeof dec.src_ip === 'object' ? JSON.stringify(dec.src_ip) : dec.src_ip}
        </span>
        <span className="pai-stage-badge" style={{ fontSize:'.72rem' }}>
          {typeof dec.event_type === 'object' ? JSON.stringify(dec.event_type) : dec.event_type}
        </span>
        <span className="pai-stage-badge pai-stage-badge--predicted" style={{ fontSize:'.72rem' }}>
          {strategyStr}
        </span>
        {dec.decoy_deployed && (
          <span className="pai-chip" style={{ background:'rgba(251,191,36,.12)', color:'#fbbf24', border:'1px solid rgba(251,191,36,.2)' }}>
            🪤 فخ
          </span>
        )}
        <span style={{ marginRight:'auto', fontSize:'.7rem', color:'rgba(255,255,255,.22)' }} dir="ltr">
          {dec.timestamp ? fmtIso(dec.timestamp) : ''}
        </span>
        {open ? <ChevronDown size={13} style={{ opacity:.4 }} /> : <ChevronRight size={13} style={{ opacity:.4 }} />}
      </div>
      {open && (
        <div className="pai-dec-body">
          {Array.isArray(ttps) && ttps.length > 0 && (
            <div className="pai-dec-section">
              <div className="pai-dec-section-title">توزيع TTPs المتوقعة</div>
              <div className="pai-ttp-list">
                {ttps.slice(0,5).map((t,i) => {
                  const ttpName = typeof t === 'object' ? (t.ttp || t.name || t.id || JSON.stringify(t)) : String(t);
                  const ttpProb = typeof t === 'object' ? (t.probability ?? t.prob ?? 0) : 0;
                  return (
                    <div key={i} className="pai-ttp-item">
                      <span className="pai-mono" dir="ltr" style={{ minWidth:130, color:'#e2e8f0' }}>{ttpName}</span>
                      <div className="pai-prob-track" style={{ flex:1, maxWidth:200 }}>
                        <div className="pai-prob-fill" style={{ width:`${ttpProb * 100}%` }} />
                      </div>
                      <span className="pai-mono" dir="ltr" style={{ color:'#818cf8', minWidth:44 }}>
                        {(ttpProb * 100).toFixed(1)}%
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
          {explanationStr && (
            <div className="pai-dec-section">
              <div className="pai-dec-section-title">التفسير</div>
              <div className="pai-dec-explanation pai-mono" dir="ltr">{explanationStr}</div>
            </div>
          )}
          {belief && typeof belief === 'object' && Object.keys(belief).length > 0 && (
            <div className="pai-dec-section">
              <div className="pai-dec-section-title">حالة الاعتقاد (ASE)</div>
              <div className="pai-belief-row">
                <span>المرحلة الأرجح:</span>
                <span className="pai-stage-badge" style={{ fontSize:'.72rem' }}>
                  {typeof belief.most_likely_stage === 'object' ? JSON.stringify(belief.most_likely_stage) : (belief.most_likely_stage || '—')}
                </span>
                <span style={{ opacity:.5 }}>يقينية:</span>
                <span className="pai-mono" dir="ltr">{((belief.stage_certainty||0)*100).toFixed(1)}%</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default DecisionRow;
