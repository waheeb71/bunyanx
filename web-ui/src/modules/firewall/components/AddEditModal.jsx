import { useState } from 'react';
import { XCircle } from 'lucide-react';

export function AddEditModal({ rule, onClose, onSave, loading }) {
  const [fd, setFd] = useState(rule || {
    name: '', action: 'ALLOW', protocol: 'tcp', source_ip: 'any',
    destination_ip: 'any', destination_port: 'any', priority: 100, enabled: true
  });
  return (
    <div className="fw-overlay" onClick={onClose}>
      <div className="fw-modal" onClick={e => e.stopPropagation()} dir="rtl">
        <div className="fw-modal-header">
          <h3 style={{ margin: 0, fontWeight: 800 }}>{rule ? 'تعديل قاعدة' : 'إضافة قاعدة جديدة'}</h3>
          <button className="fw-icon-btn" onClick={onClose}><XCircle size={16} /></button>
        </div>
        <form onSubmit={e => { e.preventDefault(); onSave(fd); }} className="fw-modal-body">
          <div className="fw-form-group">
            <label>الاسم</label>
            <input className="fw-input" value={fd.name} onChange={e => setFd({ ...fd, name: e.target.value })} required placeholder="Allow-HTTPS-Out" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="fw-form-group">
              <label>الإجراء</label>
              <select className="fw-input" value={fd.action} onChange={e => setFd({ ...fd, action: e.target.value })}>
                <option value="ALLOW">سماح (ALLOW)</option>
                <option value="DROP">حجب (DROP)</option>
                <option value="REJECT">رفض (REJECT)</option>
                <option value="LOG">تسجيل (LOG)</option>
              </select>
            </div>
            <div className="fw-form-group">
              <label>البروتوكول</label>
              <select className="fw-input" value={fd.protocol} onChange={e => setFd({ ...fd, protocol: e.target.value })}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">الكل</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="fw-form-group">
              <label>المصدر (Source IP)</label>
              <input className="fw-input" value={fd.source_ip} onChange={e => setFd({ ...fd, source_ip: e.target.value })} placeholder="any" />
            </div>
            <div className="fw-form-group">
              <label>الوجهة (Dest IP)</label>
              <input className="fw-input" value={fd.destination_ip} onChange={e => setFd({ ...fd, destination_ip: e.target.value })} placeholder="any" />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="fw-form-group">
              <label>منفذ الوجهة</label>
              <input className="fw-input" value={fd.destination_port} onChange={e => setFd({ ...fd, destination_port: e.target.value })} placeholder="443" />
            </div>
            <div className="fw-form-group">
              <label>الأولوية (1-1000)</label>
              <input className="fw-input" type="number" value={fd.priority} onChange={e => setFd({ ...fd, priority: parseInt(e.target.value) })} min="1" max="1000" />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-start', gap: 12, marginTop: 16 }}>
            <button type="submit" className="fw-btn-primary" disabled={loading}>
              {loading ? 'جاري الحفظ...' : (rule ? 'تحديث' : 'إضافة القاعدة')}
            </button>
            <button type="button" className="fw-btn-ghost" onClick={onClose}>إلغاء</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default AddEditModal;
