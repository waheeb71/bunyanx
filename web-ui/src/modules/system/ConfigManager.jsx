import React, { useState } from 'react';
import { useConfigManager } from './hooks/useConfigManager';
import ConfigSnapshotList from './components/ConfigSnapshotList';
import ConfigDiffViewer from './components/ConfigDiffViewer';
import RollbackModal from './components/RollbackModal';
import { Settings, CheckCircle2, AlertOctagon } from 'lucide-react';
import './Enterprise.css';
import './System.css';

export default function ConfigManager() {
  const {
    versions,
    activeVersion,
    isVersionsLoading,
    versionsError,
    refetchVersions,

    selectedVersion,
    setSelectedVersion,

    diff,
    isDiffLoading,

    rollback,
    isRollingBack,

    takeSnapshot,
    isTakingSnapshot,
  } = useConfigManager();

  const [rollbackTarget, setRollbackTarget] = useState(null);
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const handleOpenRollback = (verId) => {
    setRollbackTarget(verId);
  };

  const handleConfirmRollback = async (verId) => {
    try {
      await rollback(verId);
      setRollbackTarget(null);
      setSuccessMsg(`تمت العودة بنجاح إلى إصدار الإعدادات [${verId}]`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch (err) {
      setErrorMsg(err.response?.data?.detail || 'فشل عملية التراجع (Rollback).');
      setTimeout(() => setErrorMsg(''), 5000);
    }
  };

  const handleManualSnapshot = async () => {
    try {
      const res = await takeSnapshot();
      setSuccessMsg(`تم إنشاء لقطة إعدادات جديدة: ${res.data?.version_id}`);
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch (err) {
      setErrorMsg('فشل في إنشاء اللقطة.');
      setTimeout(() => setErrorMsg(''), 5000);
    }
  };

  return (
    <div className="sys-root" dir="rtl">
      {/* Header */}
      <div className="sys-header" style={{ marginBottom: 10 }}>
        <div>
          <h1 className="sys-title">
            <Settings size={26} className="text-accent" /> مدير الإعدادات واللقطات (Config Manager)
          </h1>
          <p className="sys-subtitle">
            التحكم في الإصدارات، مراجعة الفروق التناظرية (Diff)، والتراجع الآمن عند الطوارئ
          </p>
        </div>
      </div>

      {errorMsg && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            background: 'rgba(255,95,95,0.1)',
            border: '1px solid rgba(255,95,95,0.3)',
            color: '#ff5f5f',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <AlertOctagon size={16} />
          {errorMsg}
        </div>
      )}

      {successMsg && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            background: 'rgba(40,199,111,0.1)',
            border: '1px solid rgba(40,199,111,0.3)',
            color: '#28c76f',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <CheckCircle2 size={16} />
          {successMsg}
        </div>
      )}

      <div className="cfg-grid-container">
        {/* Left Sidebar: Version Snapshots */}
        <ConfigSnapshotList
          versions={versions}
          activeVersion={activeVersion}
          selectedVersion={selectedVersion}
          onSelectVersion={setSelectedVersion}
          isLoading={isVersionsLoading}
          onRefresh={refetchVersions}
          onTakeSnapshot={handleManualSnapshot}
          isTakingSnapshot={isTakingSnapshot}
        />

        {/* Main Diff & Actions Panel */}
        <ConfigDiffViewer
          diff={diff}
          isDiffLoading={isDiffLoading}
          selectedVersion={selectedVersion}
          onOpenRollbackModal={handleOpenRollback}
        />
      </div>

      {/* Rollback Confirmation Modal */}
      <RollbackModal
        isOpen={Boolean(rollbackTarget)}
        targetVersion={rollbackTarget}
        onClose={() => setRollbackTarget(null)}
        onConfirmRollback={handleConfirmRollback}
        isRollingBack={isRollingBack}
      />
    </div>
  );
}
