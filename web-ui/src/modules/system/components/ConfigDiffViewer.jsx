import React from 'react';
import { FileDiff, RotateCcw, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

export default function ConfigDiffViewer({
  diff,
  isDiffLoading,
  selectedVersion,
  onOpenRollbackModal,
}) {
  return (
    <div className="cfg-diff-card">
      <div className="cfg-diff-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <FileDiff size={18} className="text-accent" />
          <span>مراجعة فروق الإعدادات (Config Diff)</span>
        </div>
      </div>

      <div className="cfg-diff-body font-mono">
        {isDiffLoading ? (
          <div className="cfg-empty-state">
            <Loader2 size={22} className="sys-spin" style={{ margin: '0 auto 8px', display: 'block' }} />
            جاري توليد مستند الفروق (Diff)...
          </div>
        ) : !diff ? (
          <div className="cfg-empty-state">
            حدد لقطة أقدم من القائمة لعرض الفرق بينها وبين الإعدادات النشطة الحالية.
          </div>
        ) : (
          <div className="cfg-diff-content">
            <div className="cfg-diff-banner">
              Comparing <span className="text-accent">ACTIVE</span> vs{' '}
              <span className="text-warning">{diff.target}</span>
            </div>

            {Object.keys(diff.changes || {}).length === 0 ? (
              <div className="cfg-no-changes">
                <CheckCircle2 size={16} />
                <span>لا توجد تغييرات جوهرية. الإعدادات متطابقة تماماً.</span>
              </div>
            ) : (
              Object.entries(diff.changes).map(([key, change]) => (
                <div key={key} className="cfg-diff-row">
                  <div className="cfg-diff-key">{key}</div>
                  <div className="cfg-diff-box cfg-box-old">
                    <div className="cfg-box-title text-danger">ACTIVE VALUE:</div>
                    <pre>{JSON.stringify(change.old, null, 2)}</pre>
                  </div>
                  <div className="cfg-diff-box cfg-box-new">
                    <div className="cfg-box-title text-success">SNAPSHOT VALUE:</div>
                    <pre>{JSON.stringify(change.new, null, 2)}</pre>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {diff && (
        <div className="cfg-diff-footer">
          <button
            onClick={() => onOpenRollbackModal(diff.target)}
            className="sys-btn sys-btn-warning"
          >
            <RotateCcw size={15} /> التراجع إلى هذه اللقطة
          </button>
        </div>
      )}
    </div>
  );
}
