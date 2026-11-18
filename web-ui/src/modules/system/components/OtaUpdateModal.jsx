import React, { useState } from 'react';
import { X, RefreshCw, HardDrive, CheckCircle2, AlertTriangle, GitCommit, Download } from 'lucide-react';

export default function OtaUpdateModal({
  isOpen,
  onClose,
  checkResult,
  isChecking,
  onRunCheck,
  onApplyUpdate,
  isApplying,
}) {
  const [branch, setBranch] = useState('main');
  const [statusMsg, setStatusMsg] = useState(null);

  if (!isOpen) return null;

  const handleApply = async () => {
    try {
      setStatusMsg({ type: 'info', text: 'جاري بدء تحديث النظام في الخلفية...' });
      const res = await onApplyUpdate({ branch, run_migrations: true, restart_service: true });
      setStatusMsg({
        type: 'success',
        text: res.data?.message || 'تم بدء عملية التحديث OTA بنجاح.',
      });
    } catch (err) {
      setStatusMsg({
        type: 'error',
        text: err.response?.data?.detail || err.message || 'فشل تشغيل التحديث الهوائي.',
      });
    }
  };

  return (
    <div className="sys-modal-overlay" dir="rtl">
      <div className="sys-modal-content">
        <div className="sys-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <HardDrive size={20} className="text-info" />
            <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#fff' }}>إدارة التحديث الهوائي (OTA Update)</h3>
          </div>
          <button className="sys-icon-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="sys-modal-body">
          {/* Action Check Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.7)' }}>
              فحص المستودع الرسمي لنسخ Core Engine
            </div>
            <button
              className="sys-btn sys-btn-secondary"
              onClick={onRunCheck}
              disabled={isChecking}
              style={{ fontSize: 12 }}
            >
              <RefreshCw size={13} className={isChecking ? 'sys-spin' : ''} />
              {isChecking ? 'جاري الفحص...' : 'فحص التحديثات'}
            </button>
          </div>

          {/* Result Card */}
          {checkResult && (
            <div className="sys-modal-box">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>حالة الإصدار:</span>
                {checkResult.update_available ? (
                  <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <AlertTriangle size={12} /> تحديث متوفر ({checkResult.commits_behind} التزام)
                  </span>
                ) : (
                  <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircle2 size={12} /> النظام بأحدث إصدار
                  </span>
                )}
              </div>

              {checkResult.current && (
                <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)', marginTop: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <GitCommit size={14} className="text-accent" />
                    <span>الالتزام الحالي: </span>
                    <code className="mono text-accent">{checkResult.current.commit?.substring(0, 10)}</code>
                  </div>
                  <div style={{ marginTop: 4 }}>الرسالة: {checkResult.current.message}</div>
                  <div style={{ marginTop: 2 }}>التاريخ: {checkResult.current.date}</div>
                </div>
              )}
            </div>
          )}

          {/* Branch & Apply */}
          <div style={{ marginTop: 16 }}>
            <label style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.7)', display: 'block', marginBottom: 6 }}>
              الفرع المطلوب (Git Branch):
            </label>
            <input
              type="text"
              className="sys-input mono"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
            />
          </div>

          {statusMsg && (
            <div
              style={{
                marginTop: 14,
                padding: '10px 14px',
                borderRadius: 8,
                fontSize: '0.8rem',
                background:
                  statusMsg.type === 'success'
                    ? 'rgba(40,199,111,0.1)'
                    : statusMsg.type === 'error'
                    ? 'rgba(255,95,95,0.1)'
                    : 'rgba(0,212,255,0.1)',
                border: `1px solid ${
                  statusMsg.type === 'success'
                    ? 'rgba(40,199,111,0.3)'
                    : statusMsg.type === 'error'
                    ? 'rgba(255,95,95,0.3)'
                    : 'rgba(0,212,255,0.3)'
                }`,
                color:
                  statusMsg.type === 'success'
                    ? '#28c76f'
                    : statusMsg.type === 'error'
                    ? '#ff5f5f'
                    : '#00d4ff',
              }}
            >
              {statusMsg.text}
            </div>
          )}
        </div>

        <div className="sys-modal-footer">
          <button className="sys-btn sys-btn-secondary" onClick={onClose}>
            إغلاق
          </button>
          <button
            className="sys-btn sys-btn-primary"
            onClick={handleApply}
            disabled={isApplying}
          >
            <Download size={14} />
            {isApplying ? 'جاري السحب والتثبيت...' : 'تثبيت التحديث الآن'}
          </button>
        </div>
      </div>
    </div>
  );
}
