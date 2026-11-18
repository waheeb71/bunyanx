import { useQuery, useMutation } from '@tanstack/react-query';
import { Zap, Shield } from 'lucide-react';
import { firewallApi } from '../api/firewallApi';
import { SectionCard, KpiCard } from '../../../components/Shared';
import useFirewallStore from '../../../stores/firewallStore';

export function XDPPanel() {
  const { showToast } = useFirewallStore();
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['xdp-status'],
    queryFn: () => firewallApi.xdpStatus().then(r => r.data),
    refetchInterval: 10000,
  });
  
  const switchMut = useMutation({
    mutationFn: (mode) => firewallApi.switchXdpMode(mode),
    onSuccess: (_, mode) => {
      refetch();
      showToast(`تم تغيير وضع XDP إلى ${mode}`, 'success');
    },
    onError: (err) => {
      showToast('فشل تغيير وضع XDP: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });
  
  const MODES = ['native', 'generic', 'offload', 'disabled'];
  const currentMode = data?.xdp_stats?.mode || (data?.ebpf_active ? 'generic' : 'disabled');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      <SectionCard title="تسريع XDP / eBPF — مستوى النواة" icon={Zap}>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>
          محرك XDP يُسقط الحزم المحظورة مباشرةً على مستوى النواة قبل وصولها لمكدس الشبكة. أسرع بـ 10x.
        </p>
        <div className="kpi-row" style={{ marginBottom: 'var(--sp-4)' }}>
          <KpiCard icon={<Zap size={18} />} value={isLoading ? '…' : (data?.ebpf_active ? '🟢 نشط' : '🔴 معطّل')} label="حالة eBPF" color="var(--accent)" />
          <KpiCard icon={<Shield size={18} />} value={isLoading ? '…' : (data?.blocked_ips_count ?? '—')} label="عناوين IP محظورة" color="var(--danger)" />
          <KpiCard icon={<Zap size={18} />} value={isLoading ? '…' : currentMode} label="الوضع الحالي" color="var(--warning)" />
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', flexWrap: 'wrap' }}>
          {MODES.map(mode => (
            <button
              key={mode}
              className={`fw-mode-btn ${currentMode === mode ? 'active' : ''}`}
              disabled={switchMut.isPending || currentMode === mode}
              onClick={() => switchMut.mutate(mode)}
            >
              {mode}
            </button>
          ))}
        </div>
        <p style={{ marginTop: 'var(--sp-3)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          <strong>native</strong>: أسرع (يتطلب دعم Driver) · <strong>generic</strong>: احتياطي مضمون · <strong>offload</strong>: على NIC · <strong>disabled</strong>: إيقاف
        </p>
      </SectionCard>
    </div>
  );
}

export default XDPPanel;
