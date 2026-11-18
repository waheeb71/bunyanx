import { Component } from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

/**
 * Global Error Boundary — wraps the entire app to catch unhandled React errors.
 * Displays a styled fallback screen instead of crashing.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div dir="rtl" style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', minHeight: '100vh',
        background: '#050810', color: '#e8f4ff',
        gap: 20, padding: 40, fontFamily: 'Cairo, sans-serif',
      }}>
        <div style={{
          width: 64, height: 64, borderRadius: 16,
          background: 'rgba(255,77,106,0.1)', border: '1px solid rgba(255,77,106,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <AlertOctagon size={30} color="#ff4d6a" />
        </div>

        <div style={{ textAlign: 'center' }}>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, marginBottom: 8, color: '#ff4d6a' }}>
            حدث خطأ غير متوقع
          </h2>
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem', marginBottom: 20 }}>
            انهارت هذه الصفحة. يمكنك إعادة التحميل أو العودة للوحة التحكم.
          </p>
          {this.state.error && (
            <pre style={{
              background: 'rgba(255,77,106,0.05)', border: '1px solid rgba(255,77,106,0.15)',
              borderRadius: 8, padding: '12px 16px', fontSize: '0.72rem',
              color: 'rgba(255,100,120,0.7)', maxWidth: 500, textAlign: 'left',
              direction: 'ltr', overflow: 'auto', maxHeight: 120, margin: '0 auto',
            }}>
              {this.state.error.toString()}
            </pre>
          )}
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              padding: '10px 24px', borderRadius: 8,
              background: 'linear-gradient(135deg, #00d4ff, #0060ff)',
              color: '#fff', border: 'none', cursor: 'pointer',
              fontFamily: 'Cairo, sans-serif', fontWeight: 700, fontSize: '0.9rem',
              display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            <RefreshCw size={16} /> إعادة المحاولة
          </button>
          <button
            onClick={() => { window.location.href = '/'; }}
            style={{
              padding: '10px 24px', borderRadius: 8,
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)',
              color: 'rgba(255,255,255,0.7)', cursor: 'pointer',
              fontFamily: 'Cairo, sans-serif', fontWeight: 600, fontSize: '0.9rem',
            }}
          >
            العودة للرئيسية
          </button>
        </div>
      </div>
    );
  }
}
