/**
 * bunyanx NGFW — AudioUnlockBanner
 * ==================================
 * يظهر شريط صغير في أسفل الشاشة يطلب من المستخدم
 * النقر لتفعيل نغمات المتصفح (مطلوب بسياسة المتصفحات).
 *
 * يختفي تلقائياً بعد أول نقرة أو تفاعل.
 * لا يظهر إطلاقاً إذا كان الـ AudioContext مفعّلاً مسبقاً.
 */

import { useState, useEffect } from 'react';
import audioAlertService from '../../services/audioAlertService';

export default function AudioUnlockBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // فحص إذا كان يحتاج unlock
    if (audioAlertService.needsUnlock()) {
      // أعطِ لحظة للصفحة تتحمل أولاً
      const t = setTimeout(() => setVisible(true), 2000);
      return () => clearTimeout(t);
    }
  }, []);

  // مخفي إذا لا يحتاج unlock
  if (!visible) return null;

  const handleClick = async () => {
    await audioAlertService.unlock();
    setVisible(false);
  };

  return (
    <div
      onClick={handleClick}
      style={{
        position:        'fixed',
        bottom:          '20px',
        left:            '50%',
        transform:       'translateX(-50%)',
        zIndex:          9999,
        background:      'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
        border:          '1px solid rgba(99,179,237,0.3)',
        borderRadius:    '12px',
        padding:         '10px 22px',
        display:         'flex',
        alignItems:      'center',
        gap:             '10px',
        cursor:          'pointer',
        boxShadow:       '0 4px 20px rgba(0,0,0,0.4)',
        color:           '#e2e8f0',
        fontSize:        '13px',
        backdropFilter:  'blur(10px)',
        userSelect:      'none',
        animation:       'slideUp 0.3s ease',
      }}
    >
      <span style={{ fontSize: '18px' }}>🔔</span>
      <span>انقر لتفعيل نغمات التنبيه في المتصفح</span>
      <span style={{
        background:   'rgba(99,179,237,0.15)',
        border:       '1px solid rgba(99,179,237,0.3)',
        borderRadius: '6px',
        padding:      '2px 10px',
        fontSize:     '11px',
        color:        '#63b3ed',
      }}>تفعيل</span>

      <style>{`
        @keyframes slideUp {
          from { opacity: 0; transform: translateX(-50%) translateY(20px); }
          to   { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
      `}</style>
    </div>
  );
}
