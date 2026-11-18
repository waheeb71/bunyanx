import {
  User, Shield, UserPlus, Trash2, Lock, CheckCircle, RefreshCw, Users as UsersIcon, X, AlertTriangle
} from 'lucide-react';
import useUsers from './hooks/useUsers';
import { UserStatCard } from './components/UserStatCard';
import { UserRbacPanel, Avatar, RoleBadge, ROLE_META } from './components/UserRbacPanel';
import './Users.css';

export default function Users() {
  const {
    users,
    isLoading,
    rules,
    isLoadingRules,
    selectedUser,
    setSelectedUser,
    selectedMeta,
    showAddForm,
    setShowAddForm,
    showRuleForm,
    setShowRuleForm,
    newUser,
    setNewUser,
    newRule,
    setNewRule,
    errorMessage,
    setErrorMessage,
    onCreateUser,
    isCreating,
    onDeleteUser,
    onAddRule,
    isAddingRule,
    onDeleteRule,
  } = useUsers();

  return (
    <div className="usr-root" dir="rtl">

      {/* ── Hero ── */}
      <div className="usr-hero">
        <div className="usr-hero-glow" />
        <div className="usr-hero-content">
          <div className="usr-hero-left">
            <div className="usr-hero-icon">
              <UsersIcon size={26} style={{ color: '#a78bfa' }} />
            </div>
            <div>
              <h1 className="usr-hero-title">إدارة المستخدمين والصلاحيات</h1>
              <p className="usr-hero-sub">التحكم في الوصول على أساس الأدوار (RBAC) — bunyanx NGFW</p>
            </div>
          </div>
          <button className="usr-btn usr-btn--primary" onClick={() => setShowAddForm(v => !v)}>
            <UserPlus size={16} />
            {showAddForm ? 'إلغاء' : 'إضافة مستخدم'}
          </button>
        </div>
      </div>

      {/* Error alert banner */}
      {errorMessage && (
        <div className="usr-add-form-card" style={{ border: '1px solid #ef4444', background: 'rgba(239, 68, 68, 0.08)', padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 10 }}>
          <AlertTriangle size={18} color="#ef4444" />
          <span style={{ color: '#ef4444', fontSize: '.85rem', fontWeight: 700, flex: 1 }}>{errorMessage}</span>
          <button className="usr-close-btn" onClick={() => setErrorMessage(null)}><X size={16} /></button>
        </div>
      )}

      {/* ── Stats row ── */}
      <div className="usr-stats-row">
        <UserStatCard label="إجمالي المستخدمين" value={users.length} color="#a78bfa" icon={UsersIcon} />
        <UserStatCard label="مديرو النظام" value={users.filter(u => u.role === 'admin').length} color="#ff5f5f" icon={Shield} />
        <UserStatCard label="المشغّلون" value={users.filter(u => u.role === 'operator').length} color="#ffc107" icon={User} />
        <UserStatCard label="المراقبون" value={users.filter(u => u.role === 'viewer').length} color="#00d4ff" icon={Lock} />
      </div>

      {/* ── Add user form ── */}
      {showAddForm && (
        <div className="usr-add-form-card">
          <div className="usr-add-form-header">
            <UserPlus size={17} style={{ color: '#a78bfa' }} />
            <span>إنشاء حساب جديد</span>
            <button className="usr-close-btn" onClick={() => setShowAddForm(false)}><X size={16} /></button>
          </div>
          <form
            className="usr-add-form"
            onSubmit={e => { e.preventDefault(); onCreateUser(newUser); }}
          >
            <div className="usr-form-group">
              <label className="usr-form-label">اسم المستخدم</label>
              <input
                type="text" required
                className="usr-input"
                value={newUser.username}
                onChange={e => setNewUser({ ...newUser, username: e.target.value })}
                placeholder="أدخل اسم المستخدم"
              />
            </div>
            <div className="usr-form-group">
              <label className="usr-form-label">كلمة المرور</label>
              <input
                type="password" required minLength={8}
                className="usr-input"
                value={newUser.password}
                onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                placeholder="8 أحرف على الأقل"
              />
            </div>
            <div className="usr-form-group">
              <label className="usr-form-label">مستوى الصلاحية</label>
              <div className="usr-role-pills">
                {Object.entries(ROLE_META).map(([val, meta]) => (
                  <button
                    key={val} type="button"
                    className={`usr-role-pill ${newUser.role === val ? 'usr-role-pill--active' : ''}`}
                    style={newUser.role === val ? { '--rp-color': meta.color, background: meta.bg, borderColor: meta.color, color: meta.color } : {}}
                    onClick={() => setNewUser({ ...newUser, role: val })}
                  >
                    {meta.label}
                  </button>
                ))}
              </div>
            </div>
            <button type="submit" className="usr-btn usr-btn--primary" disabled={isCreating}>
              {isCreating ? <><RefreshCw size={14} className="usr-spin" /> جاري الإنشاء...</> : <><CheckCircle size={14} /> حفظ المستخدم</>}
            </button>
          </form>
        </div>
      )}

      {/* ── Main grid ── */}
      <div className="usr-grid">

        {/* Users list */}
        <div className="usr-panel">
          <div className="usr-panel-header">
            <span className="usr-panel-title">
              <UsersIcon size={15} style={{ color: 'var(--accent)' }} />
              قائمة المستخدمين
            </span>
            <span className="usr-count-badge">{users.length}</span>
          </div>

          {isLoading ? (
            <div className="usr-loading"><RefreshCw size={18} className="usr-spin" /> جاري التحميل...</div>
          ) : (
            <div className="usr-user-list">
              {users.map(u => (
                <div
                  key={u.username}
                  className={`usr-user-row ${selectedUser === u.username ? 'usr-user-row--active' : ''}`}
                  onClick={() => setSelectedUser(selectedUser === u.username ? null : u.username)}
                >
                  <Avatar name={u.username} />
                  <div className="usr-user-info">
                    <div className="usr-user-name">{u.username}</div>
                    <RoleBadge role={u.role} />
                  </div>
                  <button
                    className="usr-delete-btn"
                    title="حذف المستخدم"
                    onClick={e => {
                      e.stopPropagation();
                      if (window.confirm(`حذف المستخدم "${u.username}"؟`)) onDeleteUser(u.username);
                    }}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}

              {users.length === 0 && (
                <div className="usr-empty">
                  <UsersIcon size={32} style={{ opacity: 0.15 }} />
                  <span>لا يوجد مستخدمون مسجّلون</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* RBAC Rules panel */}
        <UserRbacPanel
          selectedUser={selectedUser}
          selectedMeta={selectedMeta}
          rules={rules}
          isLoadingRules={isLoadingRules}
          showRuleForm={showRuleForm}
          setShowRuleForm={setShowRuleForm}
          newRule={newRule}
          setNewRule={setNewRule}
          onAddRule={onAddRule}
          isAddingRule={isAddingRule}
          onDeleteRule={onDeleteRule}
        />
      </div>
    </div>
  );
}
