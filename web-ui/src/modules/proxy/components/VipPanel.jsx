import { useState, useMemo } from 'react';
import { Shield, Plus, Trash2, Search } from 'lucide-react';
import { SectionCard, SkeletonLines, EmptyState } from '../../../components/Shared';
import Toggle from './Toggle';

export default function VipPanel({ vips, vipsLoading, addVip, addVipPending, deleteVip, notify }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [vipName, setVipName] = useState('');
  const [vipExtIp, setVipExtIp] = useState('');
  const [vipExtPort, setVipExtPort] = useState(443);
  const [vipIntIp, setVipIntIp] = useState('');
  const [vipIntPort, setVipIntPort] = useState(80);
  const [vipUseTls, setVipUseTls] = useState(false);

  const filteredVips = useMemo(() => {
    if (!vips) return [];
    if (!searchTerm.trim()) return vips;
    const term = searchTerm.toLowerCase().trim();
    return vips.filter(v =>
      v.name?.toLowerCase().includes(term) ||
      v.external_ip?.includes(term) ||
      v.internal_ip?.includes(term) ||
      String(v.external_port).includes(term) ||
      String(v.internal_port).includes(term)
    );
  }, [vips, searchTerm]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!vipName.trim() || !vipExtIp.trim() || !vipIntIp.trim()) return;

    addVip({
      name: vipName.trim(),
      external_ip: vipExtIp.trim(),
      external_port: Number(vipExtPort),
      internal_ip: vipIntIp.trim(),
      internal_port: Number(vipIntPort),
      use_tls_upstream: vipUseTls
    }, {
      onSuccess: () => {
        setVipName('');
        setVipExtIp('');
        setVipExtPort(443);
        setVipIntIp('');
        setVipIntPort(80);
        setVipUseTls(false);
        if (notify) notify({ type: 'success', message: `تم تسجيل عنوان الـ VIP (${vipName}) بنجاح` });
      },
      onError: (err) => {
        const errorMsg = err?.response?.data?.detail || 'حدث خطأ أثناء إدخال خريطة الـ VIP';
        if (notify) notify({ type: 'error', message: errorMsg });
      }
    });
  };

  const handleDelete = (name) => {
    deleteVip(name, {
      onSuccess: () => {
        if (notify) notify({ type: 'success', message: `تم إزالة خريطة الـ VIP (${name}) بنجاح` });
      },
      onError: (err) => {
        if (notify) notify({ type: 'error', message: err?.response?.data?.detail || 'فشل حذف خريطة الـ VIP' });
      }
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      <SectionCard title="خريطة العناوين الافتراضية (VIP Mappings)" icon={Shield}>
        {/* Search Filter Bar */}
        <div className="prx-filter-bar" style={{ marginBottom: 'var(--sp-3)' }}>
          <div className="prx-search-box">
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="البحث بالاسم أو الآيبي الخارجي/الداخلي..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="prx-search-input"
            />
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            إجمالي العناوين: <strong style={{ color: 'var(--text-primary)' }}>{filteredVips.length}</strong> / {vips?.length || 0}
          </div>
        </div>

        {vipsLoading ? (
          <SkeletonLines count={4} />
        ) : (!filteredVips || filteredVips.length === 0) ? (
          <EmptyState message={searchTerm ? "لا توجد نتائج تطابق بحثك" : "لا توجد عناوين VIP مسجلة حالياً"} icon={Shield} />
        ) : (
          <div className="prx-table-wrapper">
            <table className="prx-table">
              <thead>
                <tr>
                  <th>الاسم الوصفي</th>
                  <th>المنفذ الخارجي المعترض</th>
                  <th>الوجهة الداخلية الحقيقية</th>
                  <th>تشفير الوجهة (TLS)</th>
                  <th style={{ width: 80 }}>إجراء</th>
                </tr>
              </thead>
              <tbody>
                {filteredVips.map((vip) => (
                  <tr key={vip.name}>
                    <td style={{ fontWeight: 600 }}>{vip.name}</td>
                    <td className="mono">{vip.external_ip}:{vip.external_port}</td>
                    <td className="mono" style={{ color: 'var(--accent)' }}>{vip.internal_ip}:{vip.internal_port}</td>
                    <td>
                      <span className={`prx-badge ${vip.use_tls_upstream ? 'https' : 'http'}`}>
                        {vip.use_tls_upstream ? 'مُشفر (TLS)' : 'غير مُشفر'}
                      </span>
                    </td>
                    <td>
                      <button className="prx-btn-delete" onClick={() => handleDelete(vip.name)} title="حذف VIP">
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      {/* Form to Add VIP Mapping */}
      <SectionCard title="إضافة خريطة VIP جديدة" icon={Plus}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--sp-3)' }}>
            <div className="prx-field-group">
              <label>الاسم الوصفي (VIP Name):</label>
              <input
                type="text" placeholder="مثال: خادم البنك الرئيسي" required
                className="prx-input" value={vipName} onChange={e => setVipName(e.target.value)}
              />
            </div>
            <div className="prx-field-group">
              <label>الآيبي الخارجي المعترض:</label>
              <input
                type="text" placeholder="مثال: 192.168.1.33" required
                className="prx-input mono" value={vipExtIp} onChange={e => setVipExtIp(e.target.value)}
              />
            </div>
            <div className="prx-field-group">
              <label>المنفذ الخارجي:</label>
              <input
                type="number" required
                className="prx-input mono" value={vipExtPort} onChange={e => setVipExtPort(+e.target.value)}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--sp-3)' }}>
            <div className="prx-field-group">
              <label>الآيبي الداخلي للوجهة الحقيقية:</label>
              <input
                type="text" placeholder="مثال: 10.10.0.50" required
                className="prx-input mono" value={vipIntIp} onChange={e => setVipIntIp(e.target.value)}
              />
            </div>
            <div className="prx-field-group">
              <label>المنفذ الداخلي للوجهة:</label>
              <input
                type="number" required
                className="prx-input mono" value={vipIntPort} onChange={e => setVipIntPort(+e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', height: '100%', paddingTop: 20 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem', cursor: 'pointer' }}>
                <span>تشفير TLS للجهة الخلفية:</span>
                <Toggle checked={vipUseTls} onChange={() => setVipUseTls(!vipUseTls)} />
              </label>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 'var(--sp-2)' }}>
            <button type="submit" className="prx-btn-add" disabled={addVipPending} style={{ padding: '8px 24px' }}>
              {addVipPending ? 'جاري الحفظ...' : 'تأكيد التسجيل'}
            </button>
          </div>
        </form>
      </SectionCard>
    </div>
  );
}
