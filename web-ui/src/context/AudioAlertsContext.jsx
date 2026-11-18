/**
 * bunyanx NGFW — Audio Alerts Context + Provider
 * =================================================
 * يحل مشكلة استدعاء useAudioAlerts في أكثر من مكان.
 *
 * بدلاً من ثلاثة Hook instances (= ثلاثة SSE connections):
 *   App.jsx       → useAudioAlerts() ← SSE #1
 *   Shell.jsx     → useAudioAlerts() ← SSE #2
 *   AudioSettings → useAudioAlerts() ← SSE #3
 *
 * الآن:
 *   <AudioAlertsProvider>          ← SSE واحد فقط
 *     <App>
 *       <Shell>   → useAudioAlertsContext()  ← يقرأ من Context
 *       <AudioSettings> → useAudioAlertsContext()
 *     </App>
 *   </AudioAlertsProvider>
 */

import React, { createContext, useContext } from 'react';
import { useAudioAlerts } from '../hooks/useAudioAlerts';

// ── Context ────────────────────────────────────────────────────────

const AudioAlertsContext = createContext(null);

// ── Provider ───────────────────────────────────────────────────────

/**
 * ضع هذا Provider مرة واحدة فقط بالقرب من جذر التطبيق.
 * كل المكونات التحتانية تستطيع قراءة البيانات عبر useAudioAlertsContext().
 *
 * @example
 *   // في App.jsx أو main layout:
 *   <AudioAlertsProvider>
 *     <YourApp />
 *   </AudioAlertsProvider>
 */
export function AudioAlertsProvider({ children }) {
  const audioState = useAudioAlerts(); // ← SSE connection واحد فقط هنا

  return (
    <AudioAlertsContext.Provider value={audioState}>
      {children}
    </AudioAlertsContext.Provider>
  );
}

// ── Consumer Hook ─────────────────────────────────────────────────

/**
 * استخدم هذا Hook بدلاً من useAudioAlerts() في أي مكان.
 * يقرأ من Context — لا ينشئ SSE connection جديد.
 *
 * @throws إذا استُخدم خارج <AudioAlertsProvider>
 */
export function useAudioAlertsContext() {
  const ctx = useContext(AudioAlertsContext);
  if (!ctx) {
    throw new Error(
      '[useAudioAlertsContext] يجب الاستخدام داخل <AudioAlertsProvider>.\n' +
      'تأكد من وضع <AudioAlertsProvider> في App.jsx أو layout رئيسي.'
    );
  }
  return ctx;
}

export default AudioAlertsProvider;
