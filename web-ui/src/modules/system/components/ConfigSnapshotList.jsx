import React from 'react';
import { Calendar, RefreshCw, Clock, Camera } from 'lucide-react';

export default function ConfigSnapshotList({
  versions,
  activeVersion,
  selectedVersion,
  onSelectVersion,
  isLoading,
  onRefresh,
  onTakeSnapshot,
  isTakingSnapshot,
}) {
  return (
    <div className="cfg-sidebar-card">
      <div className="cfg-sidebar-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Clock size={18} className="text-accent" />
          <span>سجل لقطات الإعدادات</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="sys-icon-btn"
            onClick={onTakeSnapshot}
            disabled={isTakingSnapshot}
            title="أخذ لقطة جديدة الآن"
          >
            <Camera size={15} />
          </button>
          <button
            className="sys-icon-btn"
            onClick={onRefresh}
            title="تحديث القائمة"
          >
            <RefreshCw size={15} className={isLoading ? 'sys-spin' : ''} />
          </button>
        </div>
      </div>

      <div className="cfg-sidebar-body">
        {isLoading ? (
          <div className="cfg-empty-state">جاري تحميل السجل...</div>
        ) : versions.length === 0 ? (
          <div className="cfg-empty-state">لم يتم العثور على لقطات.</div>
        ) : (
          versions.map((ver, idx) => {
            const isActive = idx === 0 || ver.version_id === activeVersion;
            const isSelected = selectedVersion === ver.version_id;

            return (
              <div
                key={ver.version_id}
                onClick={() => !isActive && onSelectVersion(ver.version_id)}
                className={`cfg-version-item ${isActive ? 'cfg-item-active' : ''} ${isSelected ? 'cfg-item-selected' : ''}`}
              >
                <div className="cfg-version-top">
                  <span className="cfg-version-id mono" dir="ltr">
                    {ver.version_id.substring(0, 15)}
                  </span>
                  {isActive && <span className="cfg-active-pill">نشط</span>}
                </div>

                <div className="cfg-version-meta">
                  <Calendar size={12} />
                  <span>
                    {ver.created_at
                      ? new Date(ver.created_at).toLocaleString('ar-SA')
                      : '—'}
                  </span>
                </div>

                <div className="cfg-version-source">
                  المصدر: {ver.source === 'automatic' ? 'تلقائي' : ver.source || 'يدوي'}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
