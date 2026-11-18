import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Network, Lock, ShieldCheck, Wifi, WifiOff, 
  CheckCircle2, AlertTriangle, Loader2, Save, RotateCcw
} from 'lucide-react';
import { interfacesApi } from '../../services/api';

/* ─── Role metadata ──────────────────────────────────────── */
const ROLES = [
  { value: 'unassigned', label: 'غير مُعيّن',       color: '#64748b', bg: 'rgba(100,116,139,0.12)' },
  { value: 'wan',        label: 'WAN — شبكة خارجية', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)'  },
  { value: 'lan',        label: 'LAN — شبكة داخلية', color: '#22c55e', bg: 'rgba(34,197,94,0.12)'   },
  { value: 'dmz',        label: 'DMZ — منطقة معزولة', color: '#a855f7', bg: 'rgba(168,85,247,0.12)' },
];

function RoleBadge({ role }) {
  const meta = ROLES.find(r => r.value === role) || ROLES[0];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 600,
      color: meta.color, background: meta.bg, border: `1px solid ${meta.color}40`,
    }}>
      {meta.label}
    </span>
  );
}

/* ─── Single NIC Card ────────────────────────────────────── */
function NicCard({ nic, pendingRole, pendingMode, onRoleChange, onModeChange, disabled }) {
  const isLocked = nic.locked || nic.role === 'management';
  const isUp = nic.is_up;

  return (
    <div style={{
      border: `1.5px solid ${isLocked ? 'rgba(239,68,68,0.3)' : (isUp ? 'var(--border)' : 'rgba(100,116,139,0.3)')}`,
      borderRadius: 12, padding: 'var(--sp-4)', background: 'var(--bg-overlay)',
      opacity: disabled ? 0.6 : 1, transition: 'all 0.2s',
      position: 'relative', overflow: 'hidden',
    }}>
      {/* Lock stripe for MGMT */}
      {isLocked && (
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 3,
          background: 'linear-gradient(90deg, #ef4444, #b91c1c)',
        }} />
      )}

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--sp-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 10, height: 10, borderRadius: '50%',
            background: isUp ? '#22c55e' : '#64748b',
            boxShadow: isUp ? '0 0 8px #22c55e' : 'none',
            flexShrink: 0,
          }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 'var(--text-sm)' }}>
            {nic.name}
          </span>
          {isLocked && <Lock size={13} color="#ef4444" />}
        </div>
        {isUp
          ? <Wifi size={16} color="#22c55e" />
          : <WifiOff size={16} color="#64748b" />
        }
      </div>

      {/* MAC */}
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 'var(--sp-3)', letterSpacing: '0.05em' }}>
        {nic.mac}
      </div>

      {/* Speed */}
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>
        {nic.speed_mbps > 0 ? `${nic.speed_mbps} Mbps` : 'سرعة غير متاحة'} · {isUp ? 'متصل' : 'غير متصل'}
      </div>

      {/* MGMT locked display */}
      {isLocked ? (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', borderRadius: 8,
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)',
          fontSize: 11, color: '#ef4444',
        }}>
          <ShieldCheck size={13} />
          منفذ الإدارة (MGMT) — مقفل · 192.168.1.1/24
        </div>
      ) : (
        <>
          {/* Role selector */}
          <label style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>الدور</label>
          <select
            value={pendingRole}
            onChange={e => onRoleChange(nic.mac, e.target.value)}
            disabled={disabled}
            style={{
              width: '100%', padding: '6px 10px', borderRadius: 8, fontSize: 12,
              background: 'var(--bg-overlay)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', marginBottom: 'var(--sp-3)',
            }}
          >
            {ROLES.map(r => (
              <option key={r.value} value={r.value}>{r.label}</option>
            ))}
          </select>

          {/* IP Mode (shown if WAN) */}
          {pendingRole === 'wan' && (
            <>
              <label style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>وضع الـ IP</label>
              <select
                value={pendingMode}
                onChange={e => onModeChange(nic.mac, e.target.value)}
                disabled={disabled}
                style={{
                  width: '100%', padding: '6px 10px', borderRadius: 8, fontSize: 12,
                  background: 'var(--bg-overlay)', border: '1px solid var(--border)',
                  color: 'var(--text-primary)',
                }}
              >
                <option value="dhcp">DHCP — تلقائي</option>
                <option value="static">Static — يدوي</option>
              </select>
            </>
          )}

          {/* Current role badge */}
          {nic.role && nic.role !== 'unassigned' && (
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>الحالي: </span>
              <RoleBadge role={nic.role} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ─── Confirm countdown bar ─────────────────────────────── */
function ConfirmBar({ onConfirm, onCancel }) {
  const [seconds, setSeconds] = useState(30);

  useEffect(() => {
    if (seconds <= 0) return;
    const id = setTimeout(() => setSeconds(s => s - 1), 1000);
    return () => clearTimeout(id);
  }, [seconds]);

  const pct = (seconds / 30) * 100;
  const color = seconds > 15 ? '#22c55e' : seconds > 8 ? '#f59e0b' : '#ef4444';

  return (
    <div style={{
      border: `1.5px solid ${color}60`, borderRadius: 12, padding: 'var(--sp-4)',
      background: `${color}0D`, marginTop: 'var(--sp-4)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} color={color} />
          <span style={{ fontSize: 13, fontWeight: 600, color }}>
            انتظار التأكيد… {seconds}ث قبل التراجع التلقائي
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn btn-ghost"
            onClick={onCancel}
            style={{ fontSize: 12, padding: '5px 12px' }}
          >
            <RotateCcw size={13} /> رجوع
          </button>
          <button
            className="btn btn-primary"
            onClick={onConfirm}
            style={{ fontSize: 12, padding: '5px 14px', background: color, borderColor: color }}
          >
            <CheckCircle2 size={13} /> تأكيد الحفظ
          </button>
        </div>
      </div>
      {/* Progress bar */}
      <div style={{ height: 4, background: 'var(--bg-overlay)', borderRadius: 4, overflow: 'hidden' }}>
        <div style={{
          width: `${pct}%`, height: '100%',
          background: color, borderRadius: 4,
          transition: 'width 1s linear, background 0.3s',
        }} />
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────── */
export default function NetworkInterfaces() {
  const queryClient = useQueryClient();

  // Local pending state (keyed by MAC)
  const [pendingRoles, setPendingRoles] = useState({});   // mac → role
  const [pendingModes, setPendingModes] = useState({});   // mac → mode
  const [stage, setStage] = useState('idle'); // idle | applying | awaiting_confirm | confirmed | error

  const { data, isLoading } = useQuery({
    queryKey: ['hw-interfaces'],
    queryFn: () => interfacesApi.list().then(r => r.data?.interfaces || r.data || []),
    retry: 2,
    refetchInterval: stage === 'idle' ? 8000 : false,
    placeholderData: [],
  });

  const nics = Array.isArray(data) ? data : [];

  // Seed pending state from fetched data (only once)
  useEffect(() => {
    if (nics.length && Object.keys(pendingRoles).length === 0) {
      const roles = {}, modes = {};
      nics.forEach(n => {
        roles[n.mac] = n.role || 'unassigned';
        modes[n.mac] = 'dhcp';
      });
      setPendingRoles(roles);
      setPendingModes(modes);
    }
  }, [nics]);

  // Apply mutation
  const applyMut = useMutation({
    mutationFn: (assignments) => interfacesApi.assign(assignments),
    onSuccess: () => setStage('awaiting_confirm'),
    onError: () => setStage('error'),
  });

  // Confirm mutation
  const confirmMut = useMutation({
    mutationFn: () => interfacesApi.confirm(),
    onSuccess: () => {
      setStage('confirmed');
      queryClient.invalidateQueries({ queryKey: ['hw-interfaces'] });
      setTimeout(() => setStage('idle'), 3000);
    },
    onError: () => setStage('error'),
  });

  const handleApply = useCallback(() => {
    const assignments = Object.entries(pendingRoles)
      .filter(([mac]) => {
        const nic = nics.find(n => n.mac === mac);
        return nic && !nic.locked;
      })
      .map(([mac, role]) => ({
        mac,
        role,
        mode: pendingModes[mac] || 'dhcp',
      }));

    setStage('applying');
    applyMut.mutate({ assignments });
  }, [pendingRoles, pendingModes, nics]);

  const hasChanges = nics.some(n => {
    if (n.locked) return false;
    return pendingRoles[n.mac] !== (n.role || 'unassigned');
  });

  return (
    <div style={{ marginTop: 'var(--sp-5)' }}>
      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 'var(--sp-4)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Network size={17} style={{ color: 'var(--accent)' }} />
          <span className="section-title" style={{ margin: 0 }}>إدارة المنافذ الفيزيائية</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {nics.filter(n => n.is_up).length} من {nics.length} متصل
          </span>
          <button
            className="btn btn-primary"
            disabled={!hasChanges || stage !== 'idle'}
            onClick={handleApply}
            style={{ fontSize: 12, padding: '6px 14px' }}
          >
            {stage === 'applying'
              ? <><Loader2 size={13} className="spin" /> جاري التطبيق...</>
              : <><Save size={13} /> تطبيق التغييرات</>
            }
          </button>
        </div>
      </div>

      {/* NIC Grid */}
      {isLoading ? (
        <div style={{ textAlign: 'center', padding: 'var(--sp-8)', color: 'var(--text-secondary)' }}>
          <Loader2 size={24} className="spin" style={{ margin: '0 auto var(--sp-3)', display: 'block' }} />
          جاري استشعار الكروت الفيزيائية...
        </div>
      ) : nics.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 'var(--sp-8)', color: 'var(--text-secondary)' }}>
          لم يتم العثور على كروت شبكة. تأكد من تشغيل OOBE أولاً.
        </div>
      ) : (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: 'var(--sp-4)',
        }}>
          {nics.map(nic => (
            <NicCard
              key={nic.mac}
              nic={nic}
              pendingRole={pendingRoles[nic.mac] || nic.role || 'unassigned'}
              pendingMode={pendingModes[nic.mac] || 'dhcp'}
              onRoleChange={(mac, role) => setPendingRoles(p => ({ ...p, [mac]: role }))}
              onModeChange={(mac, mode) => setPendingModes(p => ({ ...p, [mac]: mode }))}
              disabled={stage !== 'idle'}
            />
          ))}
        </div>
      )}

      {/* Confirm Bar */}
      {stage === 'awaiting_confirm' && (
        <ConfirmBar
          onConfirm={() => confirmMut.mutate()}
          onCancel={() => {
            setStage('idle');
            queryClient.invalidateQueries({ queryKey: ['hw-interfaces'] });
          }}
        />
      )}

      {/* Success Banner */}
      {stage === 'confirmed' && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginTop: 'var(--sp-4)',
          padding: 'var(--sp-3) var(--sp-4)', borderRadius: 10,
          background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', color: '#22c55e',
        }}>
          <CheckCircle2 size={16} />
          <span style={{ fontSize: 13 }}>تم حفظ إعدادات الشبكة بنجاح وإلغاء مؤقت التراجع.</span>
        </div>
      )}

      {/* Error Banner */}
      {stage === 'error' && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginTop: 'var(--sp-4)',
          padding: 'var(--sp-3) var(--sp-4)', borderRadius: 10,
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444',
        }}>
          <AlertTriangle size={16} />
          <span style={{ fontSize: 13 }}>فشل تطبيق الإعدادات. تم التراجع للحالة السابقة.</span>
          <button className="btn btn-ghost" style={{ marginRight: 'auto', fontSize: 11 }}
            onClick={() => setStage('idle')}>
            إغلاق
          </button>
        </div>
      )}
    </div>
  );
}
