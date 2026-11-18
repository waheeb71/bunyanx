import React, { useState } from 'react';
import { Key, X, AlertTriangle, CheckCircle2, Upload, RefreshCw } from 'lucide-react';

export function UploadCertModal({ onClose, uploadCert }) {
  const [form, setForm] = useState({
    name: '',
    cert_type: 'ROOT_CA',
    public_cert: '',
    private_key: '',
    expiry_date: '',
    is_active: true
  });
  const [err, setErr] = useState('');

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));
  const setChk = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.checked }));

  const handleSubmit = (e) => {
    e.preventDefault();
    setErr('');

    if (!form.public_cert.includes('-----BEGIN CERTIFICATE-----')) {
      setErr('الشهادة العامة يجب أن تبدأ بـ -----BEGIN CERTIFICATE-----');
      return;
    }
    if (form.private_key && !form.private_key.includes('-----BEGIN PRIVATE KEY-----') && !form.private_key.includes('-----BEGIN RSA PRIVATE KEY-----') && !form.private_key.includes('-----BEGIN EC PRIVATE KEY-----')) {
      setErr('المفتاح الخاص يجب أن يبدأ بـ -----BEGIN PRIVATE KEY-----');
      return;
    }

    const payload = {
      name: form.name,
      cert_type: form.cert_type,
      public_cert: form.public_cert.trim(),
      private_key: form.private_key ? form.private_key.trim() : null,
      expiry_date: form.expiry_date ? new Date(form.expiry_date).toISOString() : null,
      is_active: form.is_active
    };

    uploadCert.mutate(payload, {
      onSuccess: () => {
        onClose();
      },
      onError: (ex) => {
        setErr(ex.response?.data?.detail || ex.message);
      }
    });
  };

  const saving = uploadCert.isPending;

  return (
    <div className="ssl-overlay" onClick={onClose}>
      <div className="ssl-modal" onClick={e => e.stopPropagation()}>
        <div className="ssl-modal-header">
          <div className="ssl-modal-title">
            <div className="ssl-modal-icon"><Key size={18} style={{ color: '#00d4ff' }} /></div>
            تحميل شهادة أو مرجع CA جديد
          </div>
          <button className="ssl-modal-close" onClick={onClose}><X size={15} /></button>
        </div>

        {err && <div className="ssl-modal-err"><AlertTriangle size={13} /> {err}</div>}

        <form onSubmit={handleSubmit}>
          <div className="ssl-modal-body">
            <div className="ssl-field">
              <label className="ssl-field-label">اسم الشهادة التعريفية</label>
              <input className="ssl-input" value={form.name} onChange={set('name')}
                placeholder="مثال: مرجع فحص التشفير الرئيسي" required autoFocus />
            </div>

            <div className="ssl-field">
              <label className="ssl-field-label">نوع الشهادة</label>
              <select className="ssl-select" value={form.cert_type} onChange={set('cert_type')}>
                <option value="ROOT_CA">مرجع مصادقة جذر (ROOT CA)</option>
                <option value="INTERMEDIATE_CA">مرجع مصادقة وسيط (INTERMEDIATE CA)</option>
                <option value="SERVER">شهادة خادم محلية (SERVER)</option>
              </select>
            </div>

            <div className="ssl-field">
              <label className="ssl-field-label">محتوى الشهادة العامة (PEM)</label>
              <textarea className="ssl-input" style={{ minHeight: 100, fontFamily: 'Fira Code, monospace', fontSize: '11px' }}
                value={form.public_cert} onChange={set('public_cert')}
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" required />
            </div>

            <div className="ssl-field">
              <label className="ssl-field-label">المفتاح الخاص (PEM - اختياري للخوادم، إجباري لـ CA)</label>
              <textarea className="ssl-input" style={{ minHeight: 100, fontFamily: 'Fira Code, monospace', fontSize: '11px' }}
                value={form.private_key} onChange={set('private_key')}
                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" />
              <small style={{ color: 'rgba(255,255,255,0.25)', fontSize: '10px', marginTop: '2px' }}>
                🛡️ سيتم تشفير المفتاح الخاص تلقائياً بمفتاح AES-256 قبل الحفظ في قاعدة البيانات.
              </small>
            </div>

            <div className="ssl-field-row">
              <div className="ssl-field">
                <label className="ssl-field-label">تاريخ الانتهاء</label>
                <input type="date" className="ssl-input" value={form.expiry_date} onChange={set('expiry_date')} />
              </div>
              <div className="ssl-field" style={{ justifyContent: 'center' }}>
                <label className="ssl-check-label">
                  <input type="checkbox" checked={form.is_active} onChange={setChk('is_active')} />
                  <span className="ssl-check-box">{form.is_active && <CheckCircle2 size={10} />}</span>
                  تفعيل الشهادة فوراً
                </label>
              </div>
            </div>
          </div>

          <div className="ssl-modal-footer">
            <button type="button" className="ssl-btn ssl-btn--ghost" onClick={onClose}>إلغاء</button>
            <button type="submit" className="ssl-btn ssl-btn--primary" disabled={saving}>
              {saving ? <><RefreshCw size={14} className="ssl-spin" /> يُرفع...</> : <><Upload size={14} /> تحميل وحفظ</>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default UploadCertModal;
