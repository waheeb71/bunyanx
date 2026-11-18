import React, { useState, useEffect } from 'react';
import { Network, Lock, ShieldCheck, Wifi, WifiOff, CheckCircle2, AlertTriangle, Loader2, Save, RotateCcw } from 'lucide-react';

const ROLES = [
  { value: 'unassigned', label: 'غير مُعيّن', color: '#64748b', bg: 'rgba(100,116,139,0.12)' },
  { value: 'wan', label: 'WAN — شبكة خارجية', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
  { value: 'lan', label: 'LAN — شبكة داخلية', color: '#22c55e', bg: 'rgba(34,197,94,0.12)' },
  { value: 'dmz', label: 'DMZ — منطقة معزولة', color: '#a855f7', bg: 'rgba(168,85,247,0.12)' },
];

function RoleBadge({ role }) {
  const meta = ROLES.find((r) => r.value === role) || ROLES[0];
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '3px 10px',
        borderRadius: 20,
        fontSize: 11,
        fontWeight: 600,
        color: meta.color,
        background: meta.bg,
        border: `1px solid ${meta.color}40`,
      }}
    >
      {meta.label}
    </span>
  );
}

function NicCard({ nic, pendingRole, pendingMode, onRoleChange, onModeChange, disabled }) {
  const isLocked = nic.locked || nic.role === 'management';
  const isUp = nic.is_up;

  return (
    <div
      style={{
        border: `1.5px solid ${isLocked ? 'rgba(239,68,68,0.3)' : isUp ? 'var(--border, rgba(255,255,255,0.1))' : 'rgba(100,116,139,0.3)'}`,
        borderRadius: 12,
        padding: '16px',
        background: 'rgba(20,22,34,0.7)',
        opacity: disabled ? 0.6 : 1,
        transition: 'all 0.2s',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {isLocked && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: 3,
            background: 'linear-gradient(90deg, #ef4444, #b91c1c)',
          }}
        />
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: isUp ? '#22c55e' : '#64748b',
              boxShadow: isUp ? '0 0 8px #22c55e' : 'none',
              flexShrink: 0,
            }}
          />
          <span style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 700, fontSize: 13 }}>
            {nic.name}
          </span>
          {isLocked && <Lock size={13} color="#ef4444" />}
        </div>
        {isUp ? <Wifi size={16} color="#22c55e" /> : <WifiOff size={16} color="#64748b" />}
      </div>

      <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'rgba(255,255,255,0.5)', marginBottom: 8, letterSpacing: '0.05em' }}>
        {nic.mac}
      </div>

      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', marginBottom: 12 }}>
        {nic.speed_mbps > 0 ? `${nic.speed_mbps} Mbps` : 'سرعة غير متاحة'} · {isUp ? 'متصل' : 'غير متصل'}
      </div>

      {isLocked ? (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 10px',
            borderRadius: 8,
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.2)',
            fontSize: 11,
            color: '#ef4444',
          }}
        >
          <ShieldCheck size={13} />
          منفذ الإدارة (MGMT) — مقفل · 192.168.1.1/24
        </div>
      ) : (
        <>
          <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', display: 'block', marginBottom: 4 }}>الدور</label>
          <select
            value={pendingRole}
            onChange={(e) => onRoleChange(nic.mac, e.target.value)}
            disabled={disabled}
            style={{
              width: '100%',
              padding: '6px 10px',
              borderRadius: 8,
              fontSize: 12,
              background: '#13141e',
              border: '1px solid rgba(255,255,255,0.15)',
              color: '#f0f0f5',
              marginBottom: 10,
            }}
          >
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>

          {pendingRole === 'wan' && (
            <>
              <label style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)', display: 'block', marginBottom: 4 }}>وضع الـ IP</label>
              <select
                value={pendingMode}
                onChange={(e) => onModeChange(nic.mac, e.target.value)}
                disabled={disabled}
                style={{
                  width: '100%',
                  padding: '6px 10px',
                  borderRadius: 8,
                  fontSize: 12,
                  background: '#13141e',
                  border: '1px solid rgba(255,255,255,0.15)',
                  color: '#f0f0f5',
                }}
              >
                <option value="dhcp">DHCP — تلقائي</option>
                <option value="static">Static — يدوي</option>
              </select>
            </>
          )}

          {nic.role && nic.role !== 'unassigned' && (
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)' }}>الحالي: </span>
              <RoleBadge role={nic.role} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ConfirmBar({ onConfirm, onCancel }) {
  const [seconds, setSeconds] = useState(30);

  useEffect(() => {
    if (seconds <= 0) return;
    const id = setTimeout(() => setSeconds((s) => s - 1), 1000);
    return () => clearTimeout(id);
  }, [seconds]);

  const pct = (seconds / 30) * 100;
  const color = seconds > 15 ? '#22c55e' : seconds > 8 ? '#f59e0b' : '#ef4444';

  return (
    <div
      style={{
        border: `1.5px solid ${color}60`,
        borderRadius: 12,
        padding: '16px',
        background: `${color}0D`,
        marginTop: 16,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} color={color} />
          <span style={{ fontSize: 13, fontWeight: 600, color }}>
            انتظار التأكيد… {seconds}ث قبل التراجع التلقائي
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="sys-btn sys-btn-secondary" onClick={onCancel} style={{ fontSize: 12, padding: '5px 12px' }}>
            <RotateCcw size={13} /> رجوع
          </button>
          <button
            className="sys-btn sys-btn-primary"
            onClick={onConfirm}
            style={{ fontSize: 12, padding: '5px 14px', background: color, borderColor: color }}
          >
            <CheckCircle2 size={13} /> تأكيد الحفظ
          </button>
        </div>
      </div>
      <div style={{ height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 4, overflow: 'hidden' }}>
        <div
          style={{
            width: `${pct}%`,
            height: '100%',
            background: color,
            borderRadius: 4,
            transition: 'width 1s linear, background 0.3s',
          }}
        />
      </div>
    </div>
  );
}

export default function NetworkInterfacesList({
  nics,
  isLoading,
  pendingRoles,
  pendingModes,
  stage,
  errorMessage,
  hasChanges,
  onRoleChange,
  onModeChange,
  onApply,
  onConfirm,
  onCancel,
}) {
  return (
    <div style={{ marginTop: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Network size={18} className="text-accent" />
          <span className="sys-section-title">إدارة المنافذ الفيزيائية (Hardware NICs)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)' }}>
            {nics.filter((n) => n.is_up).length} من {nics.length} متصل
          </span>
          <button
            className="sys-btn sys-btn-primary"
            disabled={!hasChanges || stage !== 'idle'}
            onClick={onApply}
            style={{ fontSize: 12, padding: '6px 14px' }}
          >
            {stage === 'applying' ? (
              <>
                <Loader2 size={13} className="sys-spin" /> جاري التطبيق...
              </>
            ) : (
              <>
                <Save size={13} /> تطبيق التغييرات
              </>
            )}
          </button>
        </div>
      </div>

      {isLoading ? (
        <div style={{ textAlign: 'center', padding: 32, color: 'rgba(255,255,255,0.4)' }}>
          <Loader2 size={24} className="sys-spin" style={{ margin: '0 auto 12px', display: 'block' }} />
          جاري استشعار منافذ الكروت الفيزيائية...
        </div>
      ) : nics.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 32, color: 'rgba(255,255,255,0.4)' }}>
          لم يتم العثور على كروت شبكة. تأكد من تشغيل OOBE أولاً.
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
            gap: 16,
          }}
        >
          {nics.map((nic) => (
            <NicCard
              key={nic.mac}
              nic={nic}
              pendingRole={pendingRoles[nic.mac] || nic.role || 'unassigned'}
              pendingMode={pendingModes[nic.mac] || 'dhcp'}
              onRoleChange={onRoleChange}
              onModeChange={onModeChange}
              disabled={stage !== 'idle'}
            />
          ))}
        </div>
      )}

      {stage === 'awaiting_confirm' && <ConfirmBar onConfirm={onConfirm} onCancel={onCancel} />}

      {stage === 'confirmed' && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginTop: 16,
            padding: '12px 16px',
            borderRadius: 10,
            background: 'rgba(34,197,94,0.1)',
            border: '1px solid rgba(34,197,94,0.3)',
            color: '#22c55e',
          }}
        >
          <CheckCircle2 size={16} />
          <span style={{ fontSize: 13 }}>تم حفظ إعدادات الشبكة بنجاح وإلغاء مؤقت التراجع.</span>
        </div>
      )}

      {stage === 'error' && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginTop: 16,
            padding: '12px 16px',
            borderRadius: 10,
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.3)',
            color: '#ef4444',
          }}
        >
          <AlertTriangle size={16} />
          <span style={{ fontSize: 13 }}>{errorMessage || 'فشل تطبيق الإعدادات. تم التراجع للحالة السابقة.'}</span>
          <button
            className="sys-btn sys-btn-secondary"
            style={{ marginRight: 'auto', fontSize: 11 }}
            onClick={onCancel}
          >
            إغلاق
          </button>
        </div>
      )}
    </div>
  );
}
