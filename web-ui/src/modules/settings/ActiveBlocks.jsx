import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { responseApi } from '../../services/api';
import { Shield, Trash2, RefreshCw, CheckCircle2, Ban, Activity, Zap, Cpu } from 'lucide-react';
import './Settings.css';

export default function ActiveBlocks() {
  const qc = useQueryClient();

  const { data: blocks = [], isLoading } = useQuery({
    queryKey: ['active-blocks'],
    queryFn: () => responseApi.blocks().then((r) => r.data?.active_blocks || []),
    refetchInterval: 5000,
  });

  const unblockMut = useMutation({
    mutationFn: (ip) => responseApi.unblock(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['active-blocks'] }),
  });

  if (isLoading) {
    return (
      <div className="s-loading">
        <RefreshCw className="spin text-cyan-400" size={20} />
        <span>جاري مزامنة جداول الحظر اللحظية من النواة (eBPF Kernel Tables)...</span>
      </div>
    );
  }

  return (
    <div dir="rtl" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Metric Stats Row ── */}
      <div className="s-stat-bar">
        <div className="s-stat-pill">
          <div className="s-stat-pill-icon" style={{ background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a' }}>
            <Ban size={18} />
          </div>
          <div className="s-stat-pill-body">
            <div className="s-stat-pill-val" style={{ color: '#ff4d6a' }}>
              {blocks.length}
            </div>
            <div className="s-stat-pill-lbl">عناوين IP محظورة فورياً</div>
          </div>
        </div>

        <div className="s-stat-pill">
          <div className="s-stat-pill-icon" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <Cpu size={18} />
          </div>
          <div className="s-stat-pill-body">
            <div className="s-stat-pill-val" style={{ color: '#00c8ff' }}>
              eBPF / XDP
            </div>
            <div className="s-stat-pill-lbl">محرك الحظر على مستوى كرت الشبكة</div>
          </div>
        </div>

        <div className="s-stat-pill">
          <div className="s-stat-pill-icon" style={{ background: 'rgba(0, 230, 118, 0.12)', color: '#00e676' }}>
            <Activity size={18} />
          </div>
          <div className="s-stat-pill-body">
            <div className="s-stat-pill-val" style={{ color: '#00e676' }}>
              0.01 ms
            </div>
            <div className="s-stat-pill-lbl">زمن الاستجابة وإسقاط الحزم</div>
          </div>
        </div>
      </div>

      {/* ── جدول الحظر الفوري ── */}
      <div className="s-card">
        <div className="s-card-header">
          <div className="s-card-icon danger">
            <Shield size={18} />
          </div>
          <div>
            <h3 className="s-card-title">قائمة الحظر الفوري النشطة بالنواة (Active eBPF Blocklist)</h3>
            <p className="s-card-subtitle">يتم إسقاط كافة حزم البيانات من هذه العناوين على مستوى النواة قبل وصولها للـ Stack</p>
          </div>
          <span className="s-badge s-badge-mono" style={{ marginRight: 'auto' }}>
            تحديث تلقائي كل 5 ثوانٍ
          </span>
        </div>

        <div className="s-card-body" style={{ padding: 0 }}>
          {blocks.length === 0 ? (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '48px 24px',
              gap: '10px',
              textAlign: 'center'
            }}>
              <CheckCircle2 size={40} style={{ color: '#00e676', opacity: 0.8 }} />
              <div style={{ color: 'var(--text-primary)', fontWeight: 800, fontSize: '0.95rem' }}>
                لا توجد عناوين IP محظورة حالياً
              </div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                جداول الـ eBPF نظيفة — لم يتم تسجيل أي نشاط عدائي يتطلب الحظر اللحظي
              </div>
            </div>
          ) : (
            <table className="s-table">
              <thead>
                <tr>
                  <th>عنوان IP المحظور</th>
                  <th>سبب الحظر ورقم البلاغ</th>
                  <th>طبقة التنفيذ</th>
                  <th style={{ textAlign: 'left' }}>إلغاء الحظر</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((b, idx) => {
                  const ipVal = typeof b === 'string' ? b : (b?.ip || b?.client_ip || 'غير معروف');
                  const reasonVal = typeof b === 'string' ? 'حظر فوري عبر استجابة XDP التلقائية' : (b?.reason || 'رصد هجوم أمني سيبراني على المنظومة');
                  return (
                    <tr key={ipVal || idx}>
                      <td>
                        <code className="s-code-badge danger">
                          {ipVal}
                        </code>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                        {reasonVal}
                      </td>
                      <td>
                        <span className="s-badge s-badge-danger">
                          <Zap size={11} style={{ marginLeft: 3 }} /> eBPF XDP_DROP
                        </span>
                      </td>
                      <td style={{ textAlign: 'left' }}>
                        <button
                          className="s-btn-icon danger"
                          title="رفع الحظر الفوري"
                          onClick={() => unblockMut.mutate(ipVal)}
                          disabled={unblockMut.isPending}
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
