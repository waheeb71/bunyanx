import { Search, RefreshCw, Plus, ShieldCheck, Filter, RotateCcw } from 'lucide-react';
import { usePKIStore } from '../store/usePKIStore';

export function PKIToolbar({ onOpenCSR, onOpenCA, onRefresh, isRefetching }) {
  const {
    searchTerm,
    setSearchTerm,
    statusFilter,
    setStatusFilter,
    typeFilter,
    setTypeFilter,
    sortBy,
    setSortBy,
    resetFilters,
  } = usePKIStore();

  const isFiltered = searchTerm || statusFilter !== 'ALL' || typeFilter !== 'ALL' || sortBy !== 'expiry';

  return (
    <div className="pki-toolbar-wrap">
      {/* Search Input */}
      <div className="pki-search-box">
        <Search size={15} className="pki-search-icon" />
        <input
          type="text"
          className="pki-search-input"
          placeholder="البحث باسم الشهادة (CN)، المصدر، أو الاستخدام..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        {searchTerm && (
          <button className="pki-clear-search" onClick={() => setSearchTerm('')}>×</button>
        )}
      </div>

      {/* Status Pills */}
      <div className="pki-filter-group">
        <span className="pki-filter-label"><Filter size={12} /> الحالة:</span>
        {[
          { key: 'ALL', label: 'الكل' },
          { key: 'VALID', label: 'صالحة' },
          { key: 'EXPIRING', label: 'تنتهي قريباً' },
          { key: 'EXPIRED', label: 'منتهية' },
        ].map((f) => (
          <button
            key={f.key}
            className={`pki-pill-btn ${statusFilter === f.key ? 'active' : ''}`}
            onClick={() => setStatusFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Type Filter */}
      <div className="pki-select-group">
        <select
          className="pki-toolbar-select"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="ALL">جميع الأنواع</option>
          <option value="CA">CA (سلطة تصديق)</option>
          <option value="self-signed">Self-Signed</option>
          <option value="Device">Device / Client</option>
        </select>

        {/* Sort selector */}
        <select
          className="pki-toolbar-select"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="expiry">ترتيب حسب: تاريخ الانتهاء</option>
          <option value="cn">ترتيب حسب: الاسم (CN)</option>
          <option value="issuer">ترتيب حسب: المُصدِر</option>
          <option value="type">ترتيب حسب: النوع</option>
        </select>

        {isFiltered && (
          <button className="pki-btn pki-btn-ghost pki-reset-btn" onClick={resetFilters} title="إعادة ضبط الفلاتر">
            <RotateCcw size={13} />
          </button>
        )}
      </div>

      {/* Action Buttons */}
      <div className="pki-actions-right">
        <button className="pki-btn pki-btn-ghost" onClick={onRefresh} title="تحديث البيانات">
          <RefreshCw size={14} className={isRefetching ? 'animate-spin' : ''} />
        </button>

        <button className="pki-btn pki-btn-secondary" onClick={onOpenCA}>
          <ShieldCheck size={14} /> سلطة التصديق (Root CA)
        </button>

        <button className="pki-btn pki-btn-primary" onClick={onOpenCSR}>
          <Plus size={14} /> إصدار شهادة جهاز
        </button>
      </div>
    </div>
  );
}
