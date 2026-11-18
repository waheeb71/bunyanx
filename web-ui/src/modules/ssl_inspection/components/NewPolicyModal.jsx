import React, { useState } from 'react';
import { Lock, X, AlertTriangle, CheckCircle2, Save, RefreshCw } from 'lucide-react';

export function NewPolicyModal({ onClose, createPolicy }) {
  const [form, setForm] = useState({
    name: '', description: '', action: 'DECRYPT',
    target_domains: '*', source_ips: '*',
    log_traffic: true, check_revocation: true,
    block_invalid_certs: true, enabled: true,
  });
  const [err, setErr] = useState('');

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));
  const setChk = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.checked }));

  const handleSubmit = (e) => {
    e.preventDefault();
    setErr('');
    createPolicy.mutate(form, {
      onSuccess: () => {
        onClose();
      },
      onError: (ex) => {
        setErr(ex.response?.data?.detail || ex.message);
      }
    });
  };

  const saving = createPolicy.isPending;

  return (
    <div className="ssl-overlay" onClick={onClose}>
      <div className="ssl-modal" onClick={e => e.stopPropagation()}>
        <div className="ssl-modal-header">
          <div className="ssl-modal-title">
            <div className="ssl-modal-icon"><Lock size={18} style={{ color: '#00d4ff' }} /></div>
            سياسة SSL/TLS جديدة
          </div>
          <button className="ssl-modal-close" onClick={onClose}><X size={15} /></button>
        </div>

        {err && <div className="ssl-modal-err"><AlertTriangle size={13} /> {err}</div>}

        <form onSubmit={handleSubmit}>
          <div className="ssl-modal-body">
            <div className="ssl-field">
              <label className="ssl-field-label">اسم السياسة</label>
              <input className="ssl-input" value={form.name} onChange={set('name')}
                placeholder="مثال: تجاوز المواقع البنكية" required autoFocus />
            </div>

            <div className="ssl-field">
              <label className="ssl-field-label">الوصف (اختياري)</label>
              <input className="ssl-input" value={form.description} onChange={set('description')}
                placeholder="وصف قصير للسياسة" />
            </div>

            <div className="ssl-field">
              <label className="ssl-field-label">الإجراء المُتخذ</label>
              <select className="ssl-select" value={form.action} onChange={set('action')}>
                <option value="DECRYPT">فك التشفير (DECRYPT) — فحص TLS كامل</option>
                <option value="BYPASS">تجاوز (BYPASS) — مرور مباشر بدون فحص</option>
                <option value="BLOCK">حظر (BLOCK) — إسقاط الاتصال</option>
              </select>
            </div>

            <div className="ssl-field-row">
              <div className="ssl-field">
                <label className="ssl-field-label">النطاقات المستهدفة</label>
                <input className="ssl-input" dir="ltr" value={form.target_domains}
                  onChange={set('target_domains')} placeholder="* أو *.example.com" />
              </div>
              <div className="ssl-field">
                <label className="ssl-field-label">عناوين IP المصدر</label>
                <input className="ssl-input" dir="ltr" value={form.source_ips}
                  onChange={set('source_ips')} placeholder="* أو 10.0.0.0/8" />
              </div>
            </div>

            <div className="ssl-checks-row">
              {[
                ['log_traffic',        'تسجيل حركة المرور'],
                ['check_revocation',   'التحقق من الإلغاء (CRL)'],
                ['block_invalid_certs','حظر الشهادات غير الصالحة'],
                ['enabled',            'السياسة مُفعلة'],
              ].map(([k, lbl]) => (
                <label key={k} className="ssl-check-label">
                  <input type="checkbox" checked={form[k]} onChange={setChk(k)} />
                  <span className="ssl-check-box">{form[k] && <CheckCircle2 size={10} />}</span>
                  {lbl}
                </label>
              ))}
            </div>
          </div>

          <div className="ssl-modal-footer">
            <button type="button" className="ssl-btn ssl-btn--ghost" onClick={onClose}>إلغاء</button>
            <button type="submit" className="ssl-btn ssl-btn--primary" disabled={saving}>
              {saving ? <><RefreshCw size={14} className="ssl-spin" /> يُحفظ...</> : <><Save size={14} /> حفظ السياسة</>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewPolicyModal;
