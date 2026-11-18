/**
 * EmailAIStats.jsx — AI Engine Status Panel (PLSF + VSDE stats)
 * FIX-10: Previously invisible — shows linguistic anomaly & visual desync stats.
 */
import { Brain, Eye, Shield, Activity, TrendingUp } from 'lucide-react';

function StatCard({ title, value, sub, color, icon: Icon, progress }) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.03)',
      border: `1px solid ${color}22`,
      borderRadius: 10,
      padding: '14px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `${color}15`, border: `1px solid ${color}25`,
        }}>
          <Icon size={15} style={{ color }} />
        </div>
        <div>
          <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.35)' }}>{title}</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 700, color, lineHeight: 1.2 }}>{value}</div>
        </div>
      </div>
      {progress !== undefined && (
        <div style={{ height: 3, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
          <div style={{ width: `${Math.min(progress, 100)}%`, height: '100%', background: color, borderRadius: 3 }} />
        </div>
      )}
      {sub && <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.3)' }}>{sub}</div>}
    </div>
  );
}

export default function EmailAIStats({ stats, modelMetrics }) {
  const total        = stats?.total_inspected  || 0;
  const aiMimicry    = stats?.ai_mimicry_detected   || 0;
  const visualDesync = stats?.visual_desync_detected || 0;
  const phishing     = stats?.phishing_detected || 0;
  const blocked      = stats?.total_blocked    || 0;

  const aiRate  = total > 0 ? ((aiMimicry    / total) * 100).toFixed(1) : '0.0';
  const vsdRate = total > 0 ? ((visualDesync / total) * 100).toFixed(1) : '0.0';
  const blockRate = total > 0 ? ((blocked     / total) * 100).toFixed(1) : '0.0';
  const phishRate = total > 0 ? ((phishing    / total) * 100).toFixed(1) : '0.0';

  return (
    <div className="em-panel" style={{ marginTop: 16 }}>
      <div className="em-panel-header">
        <div className="em-panel-title" style={{ color: '#a78bfa' }}>
          <Brain size={14} /> محركات الذكاء الاصطناعي — إحصائيات مفصلة
        </div>
      </div>
      <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
        <StatCard
          title="انتحال هوية (PLSF/BEC)"
          value={aiMimicry.toLocaleString('ar-SA')}
          sub={`${aiRate}% من الإجمالي — محرك PLSF الاصطناعي`}
          color="#a78bfa"
          icon={Brain}
          progress={parseFloat(aiRate)}
        />
        <StatCard
          title="هجمات CSS/HTML (VSDE)"
          value={visualDesync.toLocaleString('ar-SA')}
          sub={`${vsdRate}% من الإجمالي — محرك VSDE`}
          color="#fb923c"
          icon={Eye}
          progress={parseFloat(vsdRate)}
        />
        <StatCard
          title="رسائل تصيد (Phishing)"
          value={phishing.toLocaleString('ar-SA')}
          sub={`${phishRate}% معدل التصيد`}
          color="#ff5f5f"
          icon={Shield}
          progress={parseFloat(phishRate)}
        />
        <StatCard
          title="معدل الحظر الإجمالي"
          value={`${blockRate}%`}
          sub={`${blocked.toLocaleString('ar-SA')} رسالة محظورة`}
          color="#28c76f"
          icon={Activity}
          progress={parseFloat(blockRate)}
        />
        <StatCard
          title="متوسط درجة الخطورة"
          value={`${((stats?.avg_risk_score || 0) * 100).toFixed(1)}%`}
          sub="متوسط نتيجة Risk Engine"
          color="#fbbf24"
          icon={TrendingUp}
          progress={(stats?.avg_risk_score || 0) * 100}
        />
        <StatCard
          title="إجمالي الرسائل المفحوصة"
          value={total.toLocaleString('ar-SA')}
          sub={`اليوم: ${(stats?.today_total || 0).toLocaleString('ar-SA')}`}
          color="#818cf8"
          icon={Activity}
        />
      </div>

      {/* Engine health indicators */}
      <div style={{ padding: '0 16px 16px' }}>
        <div style={{ fontSize: '.72rem', color: 'rgba(255,255,255,0.25)', marginBottom: 8 }}>حالة المحركات</div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {[
            { name: 'PLSF (BEC Detection)',       color: '#a78bfa', active: true },
            { name: 'VSDE (CSS Evasion)',          color: '#fb923c', active: true },
            { name: 'Phishing Detector',           color: '#ff5f5f', active: true },
            { name: 'URL Scanner + Threat Intel',  color: '#818cf8', active: true },
            { name: 'Attachment Guard + Entropy',  color: '#fbbf24', active: true },
            { name: 'Sender Reputation (SPF/DMARC)', color: '#28c76f', active: true },
            { name: 'Spam Filter',                 color: '#94a3b8', active: true },
          ].map(e => (
            <div key={e.name} style={{
              display: 'flex', alignItems: 'center', gap: 5,
              fontSize: '.7rem', color: 'rgba(255,255,255,0.45)',
              background: 'rgba(255,255,255,0.04)', borderRadius: 20,
              padding: '4px 10px', border: '1px solid rgba(255,255,255,0.07)',
            }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%', background: e.active ? e.color : '#444',
                boxShadow: e.active ? `0 0 5px ${e.color}` : 'none',
              }} />
              {e.name}
            </div>
          ))}
        </div>
      </div>

      {/* Model Performance panel */}
      {modelMetrics && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16, marginTop: 16 }}>
          <div style={{ fontSize: '.85rem', fontWeight: 700, color: 'rgba(255,255,255,0.5)', marginBottom: 12 }}>
            معايير أداء النموذج الحالي (PLSF Classifier Performance)
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
              <div style={{ fontSize: '.68rem', color: 'rgba(255,255,255,0.3)' }}>الدقة العامة (Accuracy)</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#28c76f', fontFamily: 'Fira Code, monospace', marginTop: 4 }}>
                {((modelMetrics.metrics?.accuracy ?? 0) * 100).toFixed(2)}%
              </div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
              <div style={{ fontSize: '.68rem', color: 'rgba(255,255,255,0.3)' }}>مساحة ROC-AUC</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#818cf8', fontFamily: 'Fira Code, monospace', marginTop: 4 }}>
                {(modelMetrics.metrics?.roc_auc ?? 0).toFixed(4)}
              </div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
              <div style={{ fontSize: '.68rem', color: 'rgba(255,255,255,0.3)' }}>درجة F1-Score</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#a78bfa', fontFamily: 'Fira Code, monospace', marginTop: 4 }}>
                {((modelMetrics.metrics?.f1 ?? 0) * 100).toFixed(2)}%
              </div>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
              <div style={{ fontSize: '.68rem', color: 'rgba(255,255,255,0.3)' }}>معامل MCC</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fbbf24', fontFamily: 'Fira Code, monospace', marginTop: 4 }}>
                {(modelMetrics.metrics?.mcc ?? 0).toFixed(4)}
              </div>
            </div>
          </div>
          <div style={{ marginTop: 12, fontSize: '.72rem', color: 'rgba(255,255,255,0.25)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <span>نموذج التضمين: <strong style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'Fira Code' }}>{modelMetrics.model?.embedding_model_name ?? 'all-MiniLM-L6-v2'}</strong></span>
            <span>المصنف: <strong style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'Fira Code' }}>{modelMetrics.model?.classifier ?? 'LogisticRegression'}</strong></span>
            <span>حجم العينة الإجمالي للتدريب: <strong style={{ color: 'rgba(255,255,255,0.45)' }}>{(modelMetrics.dataset_info?.total ?? 0).toLocaleString()}</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
