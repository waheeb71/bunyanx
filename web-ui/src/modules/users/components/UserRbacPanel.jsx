import { Lock, Plus, Key, Shield, LayoutGrid, CheckCircle, XCircle, RefreshCw } from 'lucide-react';

export const ROLE_META = {
  admin: { label: 'مدير النظام', color: '#ff5f5f', bg: 'rgba(255,95,95,0.1)', border: 'rgba(255,95,95,0.2)' },
  operator: { label: 'مشغّل', color: '#ffc107', bg: 'rgba(255,193,7,0.1)', border: 'rgba(255,193,7,0.2)' },
  viewer: { label: 'مراقب فقط', color: '#00d4ff', bg: 'rgba(0,212,255,0.08)', border: 'rgba(0,212,255,0.15)' },
};

export const RESOURCES = [
  { val: 'firewall', label: 'جدار الحماية' },
  { val: 'vpn', label: 'بوابة VPN' },
  { val: 'waf', label: 'حماية WAF' },
  { val: 'qos', label: 'جودة الخدمة' },
  { val: 'dns', label: 'أمان DNS' },
  { val: 'email', label: 'أمان البريد' },
  { val: 'ai', label: 'الذكاء التنبؤي' },
  { val: 'dlp', label: 'منع التسرب' },
];

export function Avatar({ name, size = 36 }) {
  const colors = ['#00d4ff', '#28c76f', '#ffc107', '#a78bfa', '#ff5f5f'];
  const color = name ? colors[name.charCodeAt(0) % colors.length] : '#a78bfa';
  return (
    <div
      className="usr-avatar"
      style={{ width: size, height: size, fontSize: size * 0.38, background: `${color}20`, border: `1px solid ${color}40`, color }}
    >
      {name ? name[0].toUpperCase() : 'U'}
    </div>
  );
}

export function RoleBadge({ role }) {
  const m = ROLE_META[role] || ROLE_META.viewer;
  return (
    <span className="usr-role-badge" style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}>
      {m.label}
    </span>
  );
}

export function UserRbacPanel({
  selectedUser,
  selectedMeta,
  rules,
  isLoadingRules,
  showRuleForm,
  setShowRuleForm,
  newRule,
  setNewRule,
  onAddRule,
  isAddingRule,
  onDeleteRule,
}) {
  return (
    <div className="usr-panel usr-rbac-panel">
      <div className="usr-panel-header">
        <span className="usr-panel-title">
          <Lock size={15} style={{ color: '#ffc107' }} />
          صلاحيات RBAC المخصصة
        </span>
        {selectedUser && (
          <button className="usr-btn usr-btn--ghost usr-btn--sm" onClick={() => setShowRuleForm(v => !v)}>
            <Plus size={14} /> إضافة صلاحية
          </button>
        )}
      </div>

      <div className="usr-rbac-body">
        {!selectedUser ? (
          <div className="usr-rbac-empty">
            <Key size={40} style={{ opacity: 0.12 }} />
            <span>اختر مستخدماً لإدارة صلاحياته</span>
            <p>انقر على أي مستخدم في القائمة على اليسار</p>
          </div>
        ) : (
          <>
            {/* Selected user header */}
            <div className="usr-selected-header">
              <Avatar name={selectedUser} size={42} />
              <div>
                <div className="usr-selected-name">{selectedUser}</div>
                {selectedMeta && <RoleBadge role={selectedMeta.role} />}
              </div>
            </div>

            {/* Add rule form */}
            {showRuleForm && (
              <form
                className="usr-rule-form"
                onSubmit={e => { e.preventDefault(); onAddRule(newRule); }}
              >
                <select
                  className="usr-input"
                  value={newRule.resource}
                  onChange={e => setNewRule({ ...newRule, resource: e.target.value })}
                >
                  {RESOURCES.map(r => (
                    <option key={r.val} value={r.val}>{r.label}</option>
                  ))}
                </select>
                <button type="submit" className="usr-btn usr-btn--primary usr-btn--sm" disabled={isAddingRule}>
                  {isAddingRule ? <RefreshCw size={13} className="usr-spin" /> : <CheckCircle size={13} />}
                  منح الصلاحية
                </button>
              </form>
            )}

            {/* Rules list */}
            {isLoadingRules ? (
              <div className="usr-loading"><RefreshCw size={16} className="usr-spin" /> تحميل الصلاحيات...</div>
            ) : rules.length === 0 ? (
              <div className="usr-rules-empty">
                <Shield size={24} style={{ opacity: 0.15 }} />
                <span>لا توجد موارد مخصصة — يعتمد على الدور الافتراضي</span>
              </div>
            ) : (
              <div className="usr-rules-list">
                {rules.map(r => {
                  const res = RESOURCES.find(x => x.val === r.resource);
                  return (
                    <div key={r.id} className="usr-rule-card">
                      <div className="usr-rule-info">
                        <LayoutGrid size={15} style={{ color: 'var(--accent)' }} />
                        <span className="usr-rule-resource">{res?.label || r.resource}</span>
                        <span className="usr-rule-badge">
                          <CheckCircle size={11} /> مسموح
                        </span>
                      </div>
                      <button
                        className="usr-rule-delete"
                        onClick={() => { if (window.confirm('إزالة هذه الصلاحية؟')) onDeleteRule(r.id); }}
                      >
                        <XCircle size={15} />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default UserRbacPanel;
