import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck, Plus, Trash2, RefreshCw, AlertTriangle,
  Network, Globe, X, CheckCircle2, Info, UploadCloud,
  FileSpreadsheet, Search, Tag, Server, Check, Layers
} from "lucide-react";
import { firewallApi } from "../../services/api";
import "./IPWhitelist.css";

/* ── API Helpers ── */
const wlApi = {
  list: () => firewallApi.get("/firewall/whitelist").then((r) => r.data),
  addNetwork: (body) => firewallApi.post("/firewall/whitelist/networks", body).then((r) => r.data),
  removeNetwork: (cidr) => firewallApi.delete("/firewall/whitelist/networks", { data: { cidr } }).then((r) => r.data),
  addHost: (body) => firewallApi.post("/firewall/whitelist/hosts", body).then((r) => r.data),
  removeHost: (ip) => firewallApi.delete(`/firewall/whitelist/hosts/${encodeURIComponent(ip)}`).then((r) => r.data),
  reload: () => firewallApi.post("/firewall/whitelist/reload").then((r) => r.data),
};

function calculateCidrCapacity(cidr = "") {
  if (!cidr.includes("/")) return "مضيف فردي";
  const prefix = parseInt(cidr.split("/")[1], 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return "—";
  const hosts = Math.pow(2, 32 - prefix);
  return `${hosts.toLocaleString()} عنوان`;
}

function inferCategoryTag(label = "", reason = "") {
  const text = `${label} ${reason}`.toLowerCase();
  if (text.includes("إدارة") || text.includes("admin") || text.includes("mgmt")) return { type: "mgmt", label: "شبكة الإدارة (Management)" };
  if (text.includes("dmz") || text.includes("خارجي") || text.includes("edge")) return { type: "dmz", label: "منطقة DMZ" };
  if (text.includes("health") || text.includes("فحص") || text.includes("probe")) return { type: "health", label: "فحص الجاهزية (Health Checks)" };
  return { type: "general", label: "شبكة موثوقة (Trusted)" };
}

/* ── Modal: Add Single Network ── */
function AddNetworkModal({ onClose, onConfirm, loading, error, onReset }) {
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const [reason, setReason] = useState("");

  const handle = (e) => {
    e.preventDefault();
    if (!cidr.trim()) return;
    if (onReset) onReset();
    onConfirm({ cidr: cidr.trim(), label: label.trim(), reason: reason.trim() });
  };

  return (
    <div className="wl-modal" onClick={() => { if (onReset) onReset(); onClose(); }}>
      <div className="wl-modal-card" onClick={(e) => e.stopPropagation()} dir="rtl">
        <div className="wl-modal-header">
          <h3 className="wl-modal-title">
            <Network size={18} style={{ color: "#00e676" }} />
            إضافة نطاق شبكة CIDR للقائمة البيضاء
          </h3>
          <button className="wl-modal-close" onClick={() => { if (onReset) onReset(); onClose(); }}>
            <X size={16} />
          </button>
        </div>
        <form onSubmit={handle} className="wl-modal-body">
          <p style={{ margin: "0 0 14px", fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            الشبكات المضافة هنا لن يتم حظرها تلقائياً بواسطة بوابة الفحص (Inspection Bridge) ومحرك eBPF.
          </p>

          {error && (
            <div style={{ marginBottom: 14, padding: "10px 14px", background: "rgba(255,77,106,0.1)", border: "1px solid rgba(255,77,106,0.3)", borderRadius: 8, color: "#ff4d6a", fontSize: "0.78rem", display: "flex", alignItems: "center", gap: 8 }}>
              <AlertTriangle size={15} /><span>{error}</span>
            </div>
          )}

          <div className="wl-form-row">
            <label className="wl-form-lbl">نطاق CIDR *</label>
            <input
              className="wl-input"
              placeholder="مثال: 192.168.10.0/24"
              value={cidr}
              onChange={(e) => { if (onReset && error) onReset(); setCidr(e.target.value); }}
              required
              autoFocus
              dir="ltr"
            />
            {cidr.includes("/") && (
              <div style={{ fontSize: "0.72rem", color: "#00c8ff", marginTop: 4 }}>
                سعة النطاق التقريبية: {calculateCidrCapacity(cidr)}
              </div>
            )}
          </div>

          <div className="wl-form-row">
            <label className="wl-form-lbl">الاسم / التصنيف</label>
            <input
              className="wl-input"
              style={{ fontFamily: "Cairo, sans-serif" }}
              placeholder="مثال: شبكة إدارة الخوادم الداخلية"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>

          <div className="wl-form-row">
            <label className="wl-form-lbl">سبب الاستثناء</label>
            <input
              className="wl-input"
              style={{ fontFamily: "Cairo, sans-serif" }}
              placeholder="مثال: خوادم خلفية متصلة بقواعد البيانات"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          <div className="wl-modal-actions">
            <button type="button" className="wl-btn" onClick={() => { if (onReset) onReset(); onClose(); }}>إلغاء</button>
            <button type="submit" className="wl-btn wl-btn--primary" disabled={loading}>
              {loading ? <RefreshCw size={13} className="wl-spin" /> : <Plus size={13} />}
              إضافة الشبكة
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Modal: Bulk CIDR / Hosts Import ── */
function BulkWhitelistModal({ onClose, onConfirm, loading }) {
  const [rawText, setRawText] = useState("");
  const [bulkReason, setBulkReason] = useState("استيراد شبكات البنية التحتية الموثوقة");

  const lines = rawText
    .split(/[\n,;]/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (lines.length === 0) return;
    onConfirm({ items: lines, reason: bulkReason });
  };

  return (
    <div className="wl-modal" onClick={onClose}>
      <div className="wl-modal-card" onClick={(e) => e.stopPropagation()} dir="rtl">
        <div className="wl-modal-header">
          <h3 className="wl-modal-title">
            <UploadCloud size={18} style={{ color: "#00c8ff" }} />
            استيراد جماعي لنطاقات CIDR ومضيفين
          </h3>
          <button className="wl-modal-close" onClick={onClose}><X size={16} /></button>
        </div>

        <form onSubmit={handleSubmit} className="wl-modal-body">
          <p style={{ margin: "0 0 14px", fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
            أدخل قائمة النطاقات وعناوين IP (سطر لكل نطاق أو مفصولة بفواصل).
          </p>

          <div className="wl-form-row">
            <label className="wl-form-lbl">قائمة النطاقات (تم التعرف على {lines.length} نطاق)</label>
            <textarea
              className="wl-input"
              rows={6}
              placeholder="10.0.0.0/8&#10;172.16.0.0/12&#10;192.168.1.100"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              style={{ direction: "ltr", textAlign: "left", fontSize: "0.8rem" }}
              required
            />
          </div>

          <div className="wl-form-row">
            <label className="wl-form-lbl">سبب الاستثناء العام</label>
            <input
              className="wl-input"
              style={{ fontFamily: "Cairo, sans-serif" }}
              value={bulkReason}
              onChange={(e) => setBulkReason(e.target.value)}
            />
          </div>

          <div className="wl-modal-actions">
            <button type="button" className="wl-btn" onClick={onClose}>إلغاء</button>
            <button
              type="submit"
              className="wl-btn wl-btn--primary"
              disabled={loading || lines.length === 0}
            >
              {loading ? <RefreshCw size={14} className="wl-spin" /> : <Plus size={14} />}
              إضافة {lines.length} نطاق دفعة واحدة
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Main Component: IPWhitelist ── */
export default function IPWhitelist() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState("networks");
  const [search, setSearch] = useState("");
  const [selectedCat, setSelectedCat] = useState("ALL");
  const [modalOpen, setModalOpen] = useState(false);
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [modalErr, setModalErr] = useState("");

  const { data: wlData, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["firewall-whitelist"],
    queryFn: wlApi.list,
    refetchInterval: 15000,
  });

  const addNetMut = useMutation({
    mutationFn: wlApi.addNetwork,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewall-whitelist"] });
      setModalOpen(false);
      setModalErr("");
    },
    onError: (err) => setModalErr(err.response?.data?.detail || err.message),
  });

  const bulkAddMut = useMutation({
    mutationFn: async ({ items, reason }) => {
      for (const item of items) {
        if (item.includes("/")) {
          await wlApi.addNetwork({ cidr: item, reason, label: "استيراد جماعي" }).catch(() => {});
        } else {
          await wlApi.addHost({ ip: item, reason, label: "استيراد جماعي" }).catch(() => {});
        }
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["firewall-whitelist"] });
      setBulkModalOpen(false);
    },
  });

  const removeNetMut = useMutation({
    mutationFn: wlApi.removeNetwork,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["firewall-whitelist"] }),
  });

  const removeHostMut = useMutation({
    mutationFn: wlApi.removeHost,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["firewall-whitelist"] }),
  });

  const networks = useMemo(() => {
    return (wlData?.networks || []).map((n) => ({
      ...n,
      capacity: calculateCidrCapacity(n.cidr),
      category: inferCategoryTag(n.label, n.reason),
    }));
  }, [wlData]);

  const hosts = useMemo(() => {
    return (wlData?.hosts || []).map((h) => ({
      ...h,
      category: inferCategoryTag(h.label, h.reason),
    }));
  }, [wlData]);

  const filteredNetworks = useMemo(() => {
    return networks.filter((n) => {
      const q = search.toLowerCase();
      const matchSearch = !search || n.cidr?.toLowerCase().includes(q) || n.label?.toLowerCase().includes(q) || n.reason?.toLowerCase().includes(q);
      const matchCat = selectedCat === "ALL" || n.category.type === selectedCat;
      return matchSearch && matchCat;
    });
  }, [networks, search, selectedCat]);

  const filteredHosts = useMemo(() => {
    return hosts.filter((h) => {
      const q = search.toLowerCase();
      const matchSearch = !search || h.ip?.toLowerCase().includes(q) || h.label?.toLowerCase().includes(q) || h.reason?.toLowerCase().includes(q);
      const matchCat = selectedCat === "ALL" || h.category.type === selectedCat;
      return matchSearch && matchCat;
    });
  }, [hosts, search, selectedCat]);

  const exportCSV = () => {
    const rows = [["Type", "Address", "Label", "Category", "Reason", "Added By"]];
    networks.forEach((n) => rows.push(["Network", n.cidr, n.label || "", n.category.label, n.reason || "", n.added_by || ""]));
    hosts.forEach((h) => rows.push(["Host", h.ip, h.label || "", h.category.label, h.reason || "", h.added_by || ""]));
    const csvContent = "data:text/csv;charset=utf-8," + rows.map((e) => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "bunyanx_whitelisted_networks.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="wl-root" dir="rtl">
      {/* ── Hero Bar ── */}
      <div className="wl-hero">
        <div className="wl-hero-glow" />
        <div className="wl-hero-inner">
          <div className="wl-hero-left">
            <div className="wl-hero-icon">
              <ShieldCheck size={24} />
            </div>
            <div>
              <h2 className="wl-hero-title">قائمة الاستثناءات الموثوقة (IP & Network Whitelist)</h2>
              <p className="wl-hero-sub">Exempted Subnets & Core Infrastructure · Bypass Inspection</p>
            </div>
          </div>

          <div className="wl-hero-right">
            <button className="wl-btn" onClick={() => refetch()}>
              <RefreshCw size={13} className={isFetching ? "wl-spin" : ""} />
              تحديث
            </button>
            <button className="wl-btn" onClick={exportCSV}>
              <FileSpreadsheet size={13} />
              تصدير CSV
            </button>
            <button className="wl-btn" onClick={() => setBulkModalOpen(true)}>
              <UploadCloud size={13} />
              استيراد جماعي
            </button>
            <button className="wl-btn wl-btn--primary" onClick={() => setModalOpen(true)}>
              <Plus size={14} />
              إضافة شبكة موثوقة
            </button>
          </div>
        </div>
      </div>

      {/* ── KPI Stat Strip ── */}
      <div className="wl-stat-strip">
        <div className="wl-kpi-card" style={{ "--st-c": "#00e676" }}>
          <div className="wl-kpi-icon" style={{ background: "rgba(0, 230, 118, 0.12)", color: "#00e676" }}>
            <Network size={20} />
          </div>
          <div>
            <div className="wl-kpi-lbl">شبكات CIDR المستثناة</div>
            <div className="wl-kpi-val" style={{ color: "#00e676" }}>{networks.length}</div>
          </div>
        </div>

        <div className="wl-kpi-card" style={{ "--st-c": "#00c8ff" }}>
          <div className="wl-kpi-icon" style={{ background: "rgba(0, 200, 255, 0.12)", color: "#00c8ff" }}>
            <Globe size={20} />
          </div>
          <div>
            <div className="wl-kpi-lbl">مضيفين فرديين موثوقين</div>
            <div className="wl-kpi-val" style={{ color: "#00c8ff" }}>{hosts.length}</div>
          </div>
        </div>

        <div className="wl-kpi-card" style={{ "--st-c": "#818cf8" }}>
          <div className="wl-kpi-icon" style={{ background: "rgba(129, 140, 248, 0.12)", color: "#818cf8" }}>
            <Layers size={20} />
          </div>
          <div>
            <div className="wl-kpi-lbl">حالة المزامنة بالنواة</div>
            <div className="wl-kpi-val" style={{ color: "#818cf8", fontSize: "1.1rem" }}>مزامنة فورية 🟢</div>
          </div>
        </div>
      </div>

      {/* ── Sub-Tabs & Filter Bar ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div className="wl-tabs">
          <button
            className={`wl-tab ${activeTab === "networks" ? "active" : ""}`}
            onClick={() => setActiveTab("networks")}
          >
            <Network size={14} /> شبكات CIDR ({networks.length})
          </button>
          <button
            className={`wl-tab ${activeTab === "hosts" ? "active" : ""}`}
            onClick={() => setActiveTab("hosts")}
          >
            <Globe size={14} /> مضيفون موثوقون ({hosts.length})
          </button>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <div style={{ position: "relative", width: 220 }}>
            <Search size={14} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
            <input
              className="wl-input"
              style={{ paddingRight: 32, fontSize: "0.78rem" }}
              placeholder="بحث في القائمة البيضاء..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="wl-input"
            style={{ width: 140, fontSize: "0.78rem" }}
            value={selectedCat}
            onChange={(e) => setSelectedCat(e.target.value)}
          >
            <option value="ALL">كافة الفئات</option>
            <option value="mgmt">شبكة الإدارة</option>
            <option value="dmz">منطقة DMZ</option>
            <option value="health">فحص الجاهزية</option>
            <option value="general">شبكات موثوقة</option>
          </select>
        </div>
      </div>

      {/* ── Main Table Panel ── */}
      <div className="wl-panel">
        <div className="wl-table-wrap">
          {isLoading ? (
            <div className="wl-empty">
              <RefreshCw size={24} className="wl-spin" style={{ color: "#00e676" }} />
              <span>جاري تحميل القوائم البيضاء...</span>
            </div>
          ) : activeTab === "networks" ? (
            filteredNetworks.length === 0 ? (
              <div className="wl-empty">
                <CheckCircle2 size={40} style={{ color: "#00e676", opacity: 0.8 }} />
                <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>لا توجد شبكات CIDR تطابق معايير البحث</div>
              </div>
            ) : (
              <table className="wl-table">
                <thead>
                  <tr>
                    <th>نطاق الشبكة (CIDR)</th>
                    <th>سعة النطاق</th>
                    <th>التصنيف والفئة</th>
                    <th>الاسم / الوصف</th>
                    <th>سبب الاستثناء</th>
                    <th>أضيف بواسطة</th>
                    <th style={{ textAlign: "left" }}>إجراء</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNetworks.map((n) => (
                    <tr key={n.cidr} className="wl-row">
                      <td>
                        <span className="wl-cidr">{n.cidr}</span>
                      </td>
                      <td>
                        <span className="wl-capacity-tag">{n.capacity}</span>
                      </td>
                      <td>
                        <span className={`wl-category-tag wl-category--${n.category.type}`}>
                          <Tag size={10} /> {n.category.label}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700, color: "var(--text-primary)" }}>
                        {n.label || "—"}
                      </td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.78rem" }}>
                        {n.reason || "—"}
                      </td>
                      <td>
                        <span style={{ fontSize: "0.7rem", color: "#00c8ff", background: "rgba(0, 200, 255, 0.08)", padding: "2px 8px", borderRadius: 6 }}>
                          {n.added_by || "System"}
                        </span>
                      </td>
                      <td style={{ textAlign: "left" }}>
                        <button
                          className="wl-remove-btn"
                          onClick={() => removeNetMut.mutate(n.cidr)}
                          disabled={removeNetMut.isPending}
                          title="إزالة الشبكة من الاستثناءات"
                        >
                          <Trash2 size={13} />
                          حذف
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          ) : (
            filteredHosts.length === 0 ? (
              <div className="wl-empty">
                <CheckCircle2 size={40} style={{ color: "#00e676", opacity: 0.8 }} />
                <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>لا يوجد مضيفون موثوقون يطابقون البحث</div>
              </div>
            ) : (
              <table className="wl-table">
                <thead>
                  <tr>
                    <th>عنوان المضيف (Host IP)</th>
                    <th>التصنيف والفئة</th>
                    <th>الاسم / الوصف</th>
                    <th>سبب الاستثناء</th>
                    <th>أضيف بواسطة</th>
                    <th style={{ textAlign: "left" }}>إجراء</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHosts.map((h) => (
                    <tr key={h.ip} className="wl-row">
                      <td>
                        <span className="wl-ip">{h.ip}</span>
                      </td>
                      <td>
                        <span className={`wl-category-tag wl-category--${h.category.type}`}>
                          <Tag size={10} /> {h.category.label}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700, color: "var(--text-primary)" }}>
                        {h.label || "—"}
                      </td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.78rem" }}>
                        {h.reason || "—"}
                      </td>
                      <td>
                        <span style={{ fontSize: "0.7rem", color: "#00c8ff", background: "rgba(0, 200, 255, 0.08)", padding: "2px 8px", borderRadius: 6 }}>
                          {h.added_by || "System"}
                        </span>
                      </td>
                      <td style={{ textAlign: "left" }}>
                        <button
                          className="wl-remove-btn"
                          onClick={() => removeHostMut.mutate(h.ip)}
                          disabled={removeHostMut.isPending}
                          title="إزالة المضيف من الاستثناءات"
                        >
                          <Trash2 size={13} />
                          حذف
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
        </div>
      </div>

      {/* ── Modals ── */}
      {modalOpen && (
        <AddNetworkModal
          onClose={() => { setModalOpen(false); setModalErr(""); }}
          onConfirm={(body) => addNetMut.mutate(body)}
          loading={addNetMut.isPending}
          error={modalErr}
          onReset={() => setModalErr("")}
        />
      )}

      {bulkModalOpen && (
        <BulkWhitelistModal
          onClose={() => setBulkModalOpen(false)}
          onConfirm={(data) => bulkAddMut.mutate(data)}
          loading={bulkAddMut.isPending}
        />
      )}
    </div>
  );
}
