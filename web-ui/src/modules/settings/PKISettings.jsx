import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { certificatesApi } from '../../services/api';
import { Shield, Key, Download, RefreshCw, AlertTriangle, CheckCircle2, Lock, FileKey } from 'lucide-react';
import './Settings.css';

export default function PKISettings() {
  const qc = useQueryClient();

  const { data: certInfo, isLoading } = useQuery({
    queryKey: ['ca-cert-info'],
    queryFn: () => certificatesApi.info().then((r) => r.data),
    retry: false,
  });

  const generateMut = useMutation({
    mutationFn: () => certificatesApi.generate(),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['ca-cert-info'] });
      alert(data.data?.message || '✅ تم توليد مفاتيح وشهادة المرجع المصدق (Root CA) بنجاح!');
    },
    onError: (err) => alert(`❌ فشل إنشاء المفاتيح: ${err.message}`),
  });

  const handleDownload = async (format) => {
    try {
      const resp = await certificatesApi.download(format);
      const url = window.URL.createObjectURL(new Blob([resp.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `bunyanx-Root-CA.${format}`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      alert(`❌ فشل التنزيل: ${err.message}`);
    }
  };

  if (isLoading) {
    return (
      <div className="s-loading">
        <RefreshCw className="spin text-cyan-400" size={20} />
        <span>جاري فحص حالة البنية التحتية للمفاتيح التشفيرية (PKI)...</span>
      </div>
    );
  }

  const isActive = certInfo?.exists === true || certInfo?.status === 'active';
  const caData = certInfo?.ca || certInfo || {};
  const subjectName = caData.cn || caData.subject || 'bunyanx Enterprise Root CA';
  const serialNo = caData.serial || caData.fingerprint || '—';
  const validFromDate = caData.not_before || caData.valid_from ? new Date(caData.not_before || caData.valid_from).toLocaleString('ar-SA') : '—';
  const validToDate = caData.expiry || caData.valid_to ? new Date(caData.expiry || caData.valid_to).toLocaleString('ar-SA') : '—';

  return (
    <div dir="rtl" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── حالة الشهادة الرئيسية ── */}
      <div className="s-card">
        <div className="s-card-header">
          <div className="s-card-icon warning">
            <Key size={18} />
          </div>
          <div>
            <h3 className="s-card-title">المرجع المصدق الجذري للمؤسسة (Enterprise Root CA)</h3>
            <p className="s-card-subtitle">إدارة الهوية التشفيرية وشهادة اعتراض وفحص اتصالات TLS/SSL العميقة</p>
          </div>
          <span className={`s-badge ${isActive ? 's-badge-success' : 's-badge-danger'}`} style={{ marginRight: 'auto' }}>
            {isActive ? 'نشط ومثبت 🟢' : 'غير متوفر 🔴'}
          </span>
        </div>

        <div className="s-card-body">
          {isActive ? (
            <>
              {/* شبكة بيانات الشهادة */}
              <div className="s-form-grid" style={{ marginBottom: 20 }}>
                <div className="s-stat-pill">
                  <div className="s-stat-pill-icon" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
                    <FileKey size={18} />
                  </div>
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">اسم الموضوع والجهة المصدرة</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.85rem' }}>{subjectName}</div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-icon" style={{ background: 'rgba(129, 140, 248, 0.12)', color: '#818cf8' }}>
                    <Lock size={18} />
                  </div>
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">بصمة / الرقم التسلسلي</div>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', color: '#818cf8' }}>{serialNo}</div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">صالح منذ</div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>{validFromDate}</div>
                  </div>
                </div>

                <div className="s-stat-pill">
                  <div className="s-stat-pill-body">
                    <div className="s-stat-pill-lbl">تاريخ الانتهاء والصلاحية</div>
                    <div style={{ fontSize: '0.82rem', color: '#00e676' }}>{validToDate}</div>
                  </div>
                </div>
              </div>

              {/* أزرار تنزيل الشهادة بصيغ متعددة */}
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: 16 }}>
                <button className="s-btn s-btn-primary" onClick={() => handleDownload('pem')}>
                  <Download size={14} /> تنزيل شهادة CA بصيغة (.pem)
                </button>
                <button className="s-btn s-btn-ghost" onClick={() => handleDownload('der')}>
                  <Download size={14} /> تنزيل بصيغة DER (.der)
                </button>
                <button className="s-btn s-btn-ghost" onClick={() => handleDownload('p12')}>
                  <Key size={14} /> تنزيل حزمة PFX / PKCS#12 (.p12)
                </button>
              </div>

              {/* إرشادات التوزيع */}
              <div style={{
                padding: '12px 16px',
                background: 'rgba(0, 200, 255, 0.05)',
                border: '1px solid rgba(0, 200, 255, 0.2)',
                borderRadius: '10px',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.6
              }}>
                <CheckCircle2 size={14} style={{ display: 'inline', color: '#00c8ff', marginLeft: '6px' }} />
                لتفعيل فحص TLS/SSL الشفاف بدون تحذيرات أمنية في المتصفحات: يجب نشر شهادة الـ Root CA عبر سياسات النطاق (Active Directory GPO) أو إضافتها لمخزن الشهادات الموثوقة على أجهزة الموظفين.
              </div>
            </>
          ) : (
            <div style={{
              padding: '24px',
              background: 'rgba(255, 77, 106, 0.08)',
              borderRadius: '12px',
              border: '1px solid rgba(255, 77, 106, 0.25)',
              display: 'flex',
              alignItems: 'center',
              gap: '14px'
            }}>
              <AlertTriangle size={24} style={{ color: '#ff4d6a', flexShrink: 0 }} />
              <div>
                <div style={{ color: '#ff4d6a', fontWeight: 800, fontSize: '0.95rem', marginBottom: 4 }}>
                  لا يوجد مرجع مصدق مثبت حالياً!
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  لا تستطيع المنظومة فك تشفير وفحص اتصالات HTTPS العميقة حتى يتم توليد وتثبيت هوية CA للمؤسسة.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── منطقة الخطر ── */}
      <div className="s-card" style={{ borderColor: 'rgba(255, 77, 106, 0.3)', background: 'rgba(255, 77, 106, 0.02)' }}>
        <div className="s-card-header">
          <div className="s-card-icon danger">
            <AlertTriangle size={18} />
          </div>
          <div>
            <h3 className="s-card-title" style={{ color: '#ff4d6a' }}>منطقة العمليات الحساسة — إعادة توليد Root CA</h3>
            <p className="s-card-subtitle">سيؤدي هذا الإجراء إلى إلغاء الشهادة السابقة وتوليد مفاتيح RSA 4096-bit جديدة</p>
          </div>
        </div>

        <div className="s-card-body">
          <p style={{ margin: '0 0 16px 0', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            تحذير: إنشاء Root CA جديد سيتطلب إعادة توزيع الشهادة على كافة أجهزة ومستخدمي الشبكة، وستتوقف وساطة فحص SSL حتى يتم التثبيت.
          </p>
          <button
            className="s-btn s-btn-danger"
            onClick={() => {
              if (window.confirm('هل أنت متأكد تماماً من رغبتك في توليد Root CA جديد؟ سيؤدي ذلك لقطع فحص TLS حتى تحديث الأجهزة.')) {
                generateMut.mutate();
              }
            }}
            disabled={generateMut.isPending}
          >
            <Key size={14} />
            {generateMut.isPending ? 'جاري توليد مفاتيح 4096-bit...' : 'توليد مرجع مصدق جديد'}
          </button>
        </div>
      </div>
    </div>
  );
}
