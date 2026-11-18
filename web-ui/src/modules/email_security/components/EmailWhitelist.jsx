import { useState } from 'react';
import { Plus, Trash2, CheckCircle2, Mail, Globe, Server, Search, X } from 'lucide-react';

const TYPE_META = {
  email:  { label: 'بريد',  icon: Mail,   cls: 'em-type-pill--email',  placeholder: 'ceo@company.com'  },
  domain: { label: 'نطاق',  icon: Globe,  cls: 'em-type-pill--domain', placeholder: 'partner.com'      },
  ip:     { label: 'IP',    icon: Server, cls: 'em-type-pill--ip',     placeholder: '192.168.1.50'      },
};

export default function EmailWhitelist({ whitelist, addToWhitelist, removeFromWhitelist }) {
  const [entry, setEntry] = useState({ type: 'email', value: '' });
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedType, setSelectedType] = useState('all');

  const total = ['emails', 'domains', 'ips'].reduce((s, k) => s + (whitelist[k]?.length || 0), 0);
  const meta  = TYPE_META[entry.type];

  const handleAdd = () => {
    if (!entry.value.trim()) return;
    addToWhitelist.mutate(
      { type: entry.type, value: entry.value.trim() },
      { onSuccess: () => setEntry(p => ({ ...p, value: '' })) }
    );
  };

  const allRows = ['email', 'domain', 'ip'].flatMap(type =>
    (whitelist[type + 's'] || []).map(val => ({ type, val }))
  );

  const filteredRows = allRows.filter(r => {
    if (selectedType !== 'all' && r.type !== selectedType) return false;
    if (searchFilter.trim() && !r.val.toLowerCase().includes(searchFilter.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="em-panel">
      <div className="em-panel-header">
        <div className="em-panel-title">
          <CheckCircle2 size={14} style={{ color: '#28c76f' }} />
          القائمة البيضاء الموثوقة (Trusted Whitelist)
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {/* Quick search input */}
          <div className="em-filter-bar" style={{ padding: '4px 8px' }}>
            <Search size={12} style={{ color: 'rgba(255,255,255,0.35)' }} />
            <input
              type="text"
              placeholder="بحث في القائمة..."
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              style={{
                background: 'none', border: 'none', outline: 'none', color: '#f0f0f5',
                fontSize: '.78rem', fontFamily: 'Cairo, sans-serif', width: '130px'
              }}
            />
            {searchFilter && (
              <X size={12} style={{ cursor: 'pointer', color: 'rgba(255,255,255,0.4)' }} onClick={() => setSearchFilter('')} />
            )}
          </div>

          {/* Type filter tabs */}
          <div style={{ display: 'flex', gap: 4 }}>
            {[
              { id: 'all', label: 'الكل' },
              { id: 'email', label: 'إيميلات' },
              { id: 'domain', label: 'نطاقات' },
              { id: 'ip', label: 'IPs' },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => setSelectedType(t.id)}
                style={{
                  fontSize: '.7rem', padding: '3px 9px', borderRadius: 6, border: 'none', cursor: 'pointer',
                  background: selectedType === t.id ? 'rgba(40,199,111,0.2)' : 'rgba(255,255,255,0.04)',
                  color: selectedType === t.id ? '#28c76f' : 'rgba(255,255,255,0.4)',
                  transition: 'all .15s',
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          <span className="em-count-pill">{total} إدخال</span>
        </div>
      </div>

      {/* Add form */}
      <div className="em-wl-form">
        <select
          className="em-select"
          style={{ width: 120, flexShrink: 0 }}
          value={entry.type}
          onChange={e => setEntry(p => ({ ...p, type: e.target.value }))}
        >
          <option value="email">بريد إلكتروني</option>
          <option value="domain">نطاق</option>
          <option value="ip">عنوان IP</option>
        </select>

        <input
          className="em-input em-input-wl"
          dir="ltr"
          placeholder={`أدخل ${meta.label} موثوق — مثال: ${meta.placeholder}`}
          value={entry.value}
          onChange={e => setEntry(p => ({ ...p, value: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />

        <button
          className="em-btn em-btn--primary"
          onClick={handleAdd}
          disabled={!entry.value.trim() || addToWhitelist.isPending}
        >
          <Plus size={14} /> إضافة للقائمة
        </button>
      </div>

      {/* Table */}
      <div className="em-table-wrap">
        <table className="em-table">
          <thead>
            <tr>
              <th style={{ width: 110 }}>النوع</th>
              <th>القيمة الموثوقة</th>
              <th style={{ width: 44 }}></th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.length === 0 && (
              <tr><td colSpan={3}>
                <div className="em-empty">
                  <CheckCircle2 size={26} style={{ opacity: 0.09 }} />
                  <span>لا توجد إدخالات تطابق خيارات البحث والتصفية.</span>
                </div>
              </td></tr>
            )}
            {filteredRows.map(({ type, val }) => {
              const m    = TYPE_META[type];
              const Icon = m.icon;
              return (
                <tr key={`${type}-${val}`} className="em-row">
                  <td>
                    <span className={`em-type-pill ${m.cls}`}>
                      <Icon size={10} style={{ marginLeft: 3 }} />
                      {m.label}
                    </span>
                  </td>
                  <td>
                    <span className="em-mono" dir="ltr" style={{ color: 'rgba(255,255,255,0.65)' }}>{val}</span>
                  </td>
                  <td>
                    <button
                      className="em-del-btn"
                      onClick={() => removeFromWhitelist.mutate({ type, val })}
                      disabled={removeFromWhitelist.isPending}
                      title="إزالة من القائمة"
                    >
                      <Trash2 size={12} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

