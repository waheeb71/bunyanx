import React, { useState } from 'react';
import { Settings, CheckCircle, Zap } from 'lucide-react';
import { useSystemStatus, useOtaUpdate } from './hooks/useSystemStatus';
import { useNetworkInterfaces } from './hooks/useNetworkInterfaces';
import SystemStatusOverview from './components/SystemStatusOverview';
import NetworkInterfacesList from './components/NetworkInterfacesList';
import OtaUpdateModal from './components/OtaUpdateModal';
import './System.css';

export default function System() {
  const [isOtaModalOpen, setIsOtaModalOpen] = useState(false);

  const {
    status,
    modules,
    syncHa,
    isSyncingHa,
  } = useSystemStatus();

  const ota = useOtaUpdate();
  const net = useNetworkInterfaces();

  const handleSyncHa = async () => {
    try {
      await syncHa();
      alert('تم بدء مزامنة التوافرية العالية بنجاح.');
    } catch (err) {
      alert('فشل المزامنة: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div className="sys-root" dir="rtl">
      {/* Header */}
      <div className="sys-header">
        <div>
          <h1 className="sys-title">
            <Settings size={26} className="text-accent" /> لوحة التحكم بالنظام
          </h1>
          <p className="sys-subtitle">
            الصحة التشغيلية، استهلاك الموارد، المنافذ الفيزيائية، وحالة الوحدات البرمجية
          </p>
        </div>
        <span className="sys-badge-operational">
          <CheckCircle size={14} />{' '}
          {status?.status === 'operational' ? 'يعمل بكفاءة' : (status?.status || 'ONLINE').toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 0.7fr)', gap: 20 }}>
        {/* Left Column: Status Overview & NICs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <SystemStatusOverview
            status={status}
            onOpenOta={() => {
              setIsOtaModalOpen(true);
              ota.runCheck();
            }}
            onSyncHa={handleSyncHa}
            isSyncingHa={isSyncingHa}
          />

          <div className="sys-card" style={{ padding: 20 }}>
            <NetworkInterfacesList
              nics={net.nics}
              isLoading={net.isLoading}
              pendingRoles={net.pendingRoles}
              pendingModes={net.pendingModes}
              stage={net.stage}
              errorMessage={net.errorMessage}
              hasChanges={net.hasChanges}
              onRoleChange={net.updateRole}
              onModeChange={net.updateMode}
              onApply={net.handleApply}
              onConfirm={net.confirmChanges}
              onCancel={net.cancelChanges}
            />
          </div>
        </div>

        {/* Right Column: Module Pipeline Pipeline Status */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="sys-card" style={{ overflow: 'hidden', height: '100%' }}>
            <div className="sys-card-header">
              <Zap size={18} className="text-warning" />
              <span>خط أنابيب الوحدات (Inspection Modules)</span>
            </div>
            <div style={{ maxHeight: 600, overflowY: 'auto' }}>
              {(modules ? Object.entries(modules) : []).map(([name, cfg]) => (
                <div
                  key={name}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 18px',
                    borderBottom: '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  <span className="mono" style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.7)' }}>
                    {name}
                  </span>
                  <span className={`badge ${cfg?.enabled !== false ? 'badge-success' : 'badge-info'}`}>
                    {cfg?.enabled !== false ? 'نشط' : 'متوقف'}
                  </span>
                </div>
              ))}
              {Object.keys(modules || {}).length === 0 && (
                <div style={{ padding: 24, textCenter: 'center', color: 'rgba(255,255,255,0.4)', fontSize: '0.85rem' }}>
                  لم يتم رصد وحدات فحص مسجلة.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* OTA Update Modal */}
      <OtaUpdateModal
        isOpen={isOtaModalOpen}
        onClose={() => setIsOtaModalOpen(false)}
        checkResult={ota.checkResult}
        isChecking={ota.isChecking}
        onRunCheck={ota.runCheck}
        onApplyUpdate={ota.applyUpdate}
        isApplying={ota.isApplying}
      />
    </div>
  );
}
