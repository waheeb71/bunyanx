import { useState } from 'react';
import { UploadCloud, X, CheckCircle2, AlertTriangle, FileCode } from 'lucide-react';

export function SchemaUploadModal({ isOpen, onClose, onUpload }) {
  const [endpoint, setEndpoint] = useState('/api/v1/users');
  const [jsonText, setJsonText] = useState('{\n  "type": "object",\n  "properties": {\n    "username": { "type": "string" },\n    "email": { "type": "string", "format": "email" }\n  },\n  "required": ["username"]\n}');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      const parsedSchema = JSON.parse(jsonText);
      setLoading(true);
      const res = await onUpload(endpoint.trim(), parsedSchema);
      setMsg({ type: 'success', text: res.data?.message || 'تم رفع وتطبيق مخطط API بنجاح!' });
      setTimeout(() => {
        onClose();
        setMsg(null);
      }, 1500);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setMsg({ type: 'error', text: 'صيغة JSON غير صحيحة. يرجى التحقق من القواعد.' });
      } else {
        setMsg({ type: 'error', text: err.response?.data?.detail || 'فشل رفع المخطط.' });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999
    }}>
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 12,
        width: '90%',
        maxWidth: 600,
        padding: 24,
        boxShadow: '0 20px 50px rgba(0,0,0,0.6)',
        display: 'flex',
        flexDirection: 'column',
        gap: 16
      }}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontWeight: 800, fontSize: '1.1rem' }}>
            <FileCode size={20} style={{ color: 'var(--accent)' }} />
            <span>رفع مخطط OpenAPI / Swagger API</span>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Status Msg */}
        {msg && (
          <div style={{
            padding: '10px 14px',
            borderRadius: 6,
            background: msg.type === 'success' ? 'rgba(40, 199, 111, 0.1)' : 'rgba(234, 84, 85, 0.1)',
            border: `1px solid ${msg.type === 'success' ? 'var(--success)' : 'var(--danger)'}`,
            color: msg.type === 'success' ? 'var(--success)' : 'var(--danger)',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            {msg.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
            <span>{msg.text}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: 6, color: 'var(--text-muted)' }}>
              مسار نقطة النهاية المستهدفة (Endpoint Path)
            </label>
            <input
              type="text"
              value={endpoint}
              onChange={e => setEndpoint(e.target.value)}
              placeholder="/api/v1/resource"
              required
              style={{ width: '100%', padding: '8px 12px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
              dir="ltr"
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: 6, color: 'var(--text-muted)' }}>
              تعريف مخطط JSON (OpenAPI / JSON Schema Definition)
            </label>
            <textarea
              rows={8}
              value={jsonText}
              onChange={e => setJsonText(e.target.value)}
              required
              style={{ width: '100%', padding: '10px 12px', background: '#090d16', border: '1px solid var(--border)', borderRadius: 6, color: '#a78bfa', fontFamily: 'monospace', fontSize: '0.8rem' }}
              dir="ltr"
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 8 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>إلغاء</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <UploadCloud size={16} />
              {loading ? 'جاري الرفع...' : 'حفظ وتطبيق المخطط'}
            </button>
          </div>
        </form>

      </div>
    </div>
  );
}
