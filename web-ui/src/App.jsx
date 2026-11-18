import { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './hooks/useAuth';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/Toast';
// Layout
import Shell from './layout/Shell';
import AudioUnlockBanner from './modules/audio/AudioUnlockBanner';
// Audio: keep SSE stream alive globally
import { useAudioAlerts } from './hooks/useAudioAlerts';

/* ══════════════════════════════════════════════════════════════
   Lazy-loaded route components — code splitting for performance
   ══════════════════════════════════════════════════════════════ */
const Login = lazy(() => import('./modules/auth/Login'));
const DashboardPro = lazy(() => import('./modules/dashboardpro/DashboardPro'));
const Dashboard = lazy(() => import('./modules/dashboard/Dashboard'));
const Firewall = lazy(() => import('./modules/firewall/Firewall'));
const IPBlocklist = lazy(() => import('./modules/firewall/IPBlocklist'));
const WebFilter = lazy(() => import('./modules/web_filter/WebFilter'));
const EmailSecurity = lazy(() => import('./modules/email_security/EmailSecurity'));
const MalwareAV = lazy(() => import('./modules/malware_av/MalwareAV'));
const UBA = lazy(() => import('./modules/uba/UBA'));
const PredictiveAI = lazy(() => import('./modules/predictive_ai/PredictiveAI'));
const SSLInspection = lazy(() => import('./modules/ssl_inspection/SSLInspection'));
const HTTPInspection = lazy(() => import('./modules/http_inspection/HTTPInspection'));
const DLP = lazy(() => import('./modules/dlp/DLP'));
const QoS = lazy(() => import('./modules/qos/QoS'));
const Proxy = lazy(() => import('./modules/proxy/Proxy'));
const WAF = lazy(() => import('./modules/waf/WAF'));
const IDSIPS = lazy(() => import('./modules/ids_ips/IDSIPS'));
const System = lazy(() => import('./modules/system/System'));
const SystemHealth = lazy(() => import('./modules/system/SystemHealth'));
const ConfigManager = lazy(() => import('./modules/system/ConfigManager'));
const VPN = lazy(() => import('./modules/vpn/VPN'));
const DNS = lazy(() => import('./modules/dns_security/DNS'));
const Users = lazy(() => import('./modules/users/Users'));
const Settings = lazy(() => import('./modules/settings/Settings'));
const LogsExplorer = lazy(() => import('./modules/dashboard/views/LogsExplorer'));
const AudioSettings = lazy(() => import('./modules/audio/AudioSettings'));
const SoundTester = lazy(() => import('./modules/audio/SoundTester'));
const SoundProfileMgr = lazy(() => import('./modules/audio/SoundProfileMgr'));
const EventSoundMap = lazy(() => import('./modules/audio/EventSoundMap'));
// ── New Pages ──
const ExecutiveDashboard = lazy(() => import('./modules/executive/ExecutiveDashboard'));
const ResponseCenter = lazy(() => import('./modules/response/ResponseCenter'));
const AuditTrail = lazy(() => import('./modules/audit/AuditTrail'));
const PKIManager = lazy(() => import('./modules/pki/PKIManager'));
const GlobeThreatMap = lazy(() => import('./modules/globe/GlobeThreatMap'));
const NetworkOpsTerminal = lazy(() => import('./modules/netops/NetworkOpsTerminal'));
const CVASManager = lazy(() => import('./modules/cvas/CVASManager'));

/* ── Loading Fallback ─────────────────────────────────────── */
function PageLoader() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: '100%', gap: 12, color: 'rgba(255,255,255,0.3)',
      fontFamily: 'Cairo, sans-serif', fontSize: '0.9rem',
    }}>
      <div style={{
        width: 20, height: 20, borderRadius: '50%',
        border: '2px solid rgba(0,212,255,0.2)',
        borderTopColor: '#00d4ff',
        animation: 'spin 0.8s linear infinite',
      }} />
      جاري التحميل...
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

/* ── React Query Client ──────────────────────────────────── */
const qc = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
    },
  },
});

/* ══════════════════════════════════════════════════════════════
   RBAC-aware Private Route Guard
   - any authenticated user: all public routes inside Shell
   - admin-only routes: /users, /settings, /audit
   - operator+admin routes: /response, /config-manager
   ══════════════════════════════════════════════════════════════ */
function PrivateRoute({ children, requiredRole }) {
  const { user } = useAuth();

 

  if (requiredRole) {
    const roleRank = { viewer: 0, operator: 1, admin: 2 };
    const userRank = roleRank[user?.role] ?? 0;
    const neededRank = roleRank[requiredRole] ?? 0;
    if (userRank < neededRank) {
      return (
        <div dir="rtl" style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          justifyContent: 'center', height: '100%', gap: 16,
          fontFamily: 'Cairo, sans-serif', color: '#ff5f5f',
        }}>
          <div style={{
            width: 56, height: 56, borderRadius: 14,
            background: 'rgba(255,95,95,0.1)', border: '1px solid rgba(255,95,95,0.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.8rem',
          }}>🔒</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800 }}>صلاحيات غير كافية</div>
          <div style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.4)' }}>
            هذه الصفحة متاحة فقط للمستخدمين من نوع <strong style={{ color: '#ffc107' }}>{requiredRole}</strong> وما فوق
          </div>
          <a href="/" style={{
            marginTop: 8, padding: '8px 20px', borderRadius: 8,
            background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)',
            color: '#00d4ff', textDecoration: 'none', fontWeight: 600, fontSize: '0.85rem',
          }}>العودة للرئيسية</a>
        </div>
      );
    }
  }

  return children;
}

/* ══════════════════════════════════════════════════════════════
   AudioAlertGlobalProvider — mounts once at App root so the SSE
   connection to /api/audio/events/stream is always active.
   Without this, sounds only play when the user is on the audio
   settings page (where useAudioAlerts was previously called).
   ══════════════════════════════════════════════════════════════ */
function AudioAlertGlobalProvider() {
  // Call hook — result is intentionally ignored here;
  // the side effect (SSE connection + sound playback) is what matters.
  useAudioAlerts();
  return null;
}

/* ══════════════════════════════════════════════════════════════
   App Root
   ══════════════════════════════════════════════════════════════ */
export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={qc}>
        <AuthProvider>
          <ToastProvider>
            <BrowserRouter>
              {/* Global audio: SSE listener + browser unlock banner */}
              <AudioUnlockBanner />
              <Suspense fallback={<PageLoader />}>
                <Routes>
                  {/* Public */}
                  <Route path="/login" element={<Login />} />

                  {/* Standalone Fullscreen Log Explorer */}
                  <Route
                    path="/logs-fullscreen"
                    element={
                      <PrivateRoute>
                        <div style={{ height: '100vh', width: '100vw', backgroundColor: '#060b19', overflow: 'hidden' }} dir="rtl">
                          <LogsExplorer />
                        </div>
                      </PrivateRoute>
                    }
                  />

                  {/* Protected — all inside Shell */}
                  <Route
                    path="/"
                    element={
                      <PrivateRoute>
                        <AudioAlertGlobalProvider />
                        <Shell />
                      </PrivateRoute>
                    }
                  >
                    {/* ── Overview ── */}
                    <Route index element={<DashboardPro />} />
                    <Route path="dashboard-old" element={<Dashboard />} />
                    <Route path="executive" element={<ExecutiveDashboard />} />
                    <Route path="globe" element={<GlobeThreatMap />} />
                    <Route path="netops" element={<PrivateRoute requiredRole="operator"><NetworkOpsTerminal /></PrivateRoute>} />

                    {/* ── Threat Management ── */}
                    <Route path="firewall" element={<Firewall />} />
                    <Route path="ip-blocklist" element={<IPBlocklist />} />
                    <Route path="waf" element={<WAF />} />
                    <Route path="ids-ips" element={<IDSIPS />} />
                    <Route path="malware" element={<MalwareAV />} />

                    {/* ── Network Services ── */}
                    <Route path="dns" element={<DNS />} />
                    <Route path="vpn" element={<VPN />} />
                    <Route path="proxy" element={<Proxy />} />
                    <Route path="email" element={<EmailSecurity />} />
                    <Route path="web-filter" element={<WebFilter />} />
                    <Route path="qos" element={<QoS />} />

                    {/* ── Deep Inspection ── */}
                    <Route path="http" element={<HTTPInspection />} />
                    <Route path="ssl" element={<SSLInspection />} />
                    <Route path="dlp" element={<DLP />} />

                    {/* ── Security Intelligence ── */}
                    <Route path="ai" element={<PredictiveAI />} />
                    <Route path="uba" element={<UBA />} />

                    {/* ── Incident Response ── (operator+) */}
                    <Route path="response" element={<PrivateRoute requiredRole="operator"><ResponseCenter /></PrivateRoute>} />

                    {/* ── Enterprise Control ── */}
                    <Route path="system-health" element={<SystemHealth />} />
                    <Route path="config-manager" element={<PrivateRoute requiredRole="operator"><ConfigManager /></PrivateRoute>} />

                    {/* ── PKI Manager ── (operator+) */}
                    <Route path="pki" element={<PrivateRoute requiredRole="operator"><PKIManager /></PrivateRoute>} />

                    {/* ── Administration ── (admin only) */}
                    <Route path="system" element={<PrivateRoute requiredRole="admin"><System /></PrivateRoute>} />
                    <Route path="settings" element={<PrivateRoute requiredRole="admin"><Settings /></PrivateRoute>} />
                    <Route path="users" element={<PrivateRoute requiredRole="admin"><Users /></PrivateRoute>} />
                    <Route path="audit" element={<PrivateRoute requiredRole="admin"><AuditTrail /></PrivateRoute>} />
                    <Route path="audio-settings" element={<AudioSettings />} />
                    <Route path="cvas" element={<CVASManager />} />
                    <Route path="audio-tester" element={<SoundTester />} />
                    <Route path="audio-profiles" element={<SoundProfileMgr />} />
                    <Route path="audio-event-map" element={<EventSoundMap />} />

                    {/* Catch-all */}
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Route>
                </Routes>
              </Suspense>
            </BrowserRouter>
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
