/**
 * UBA Module — Entity Behavior Analysis Dashboard.
 * Refactored: Split into modular components, hook, and decentralized API layer.
 */
import { useMemo } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  User, ShieldAlert, Settings, Search, AlertCircle, Clock, Database,
  UserCheck, UserX, Zap, Globe, MapPin, Activity, CheckCircle2
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar, RadarChart, PolarGrid, PolarAngleAxis, Radar 
} from 'recharts';
import useUBA from './hooks/useUBA';
import UserProfileCard from './components/UserProfileCard';
import { fmtScore, getRiskColor, translateRiskLevel } from './components/Helpers';
import './UBA.css';

const TABS = [
  { id: 'dashboard', label: 'الرئيسية (Dashboard)' },
  { id: 'users',     label: 'الكيانات المفحوصة (Profiles)' },
  { id: 'alerts',    label: 'أحداث AP-GDR' },
  { id: 'settings',  label: 'إعدادات المحرك' }
];

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background:'#13141e', padding:10, border:'1px solid rgba(255,255,255,0.1)', borderRadius:8, direction:'rtl' }}>
        <div style={{ margin:0, fontWeight:700, fontSize:'.85rem', color:'#f0f0f5', marginBottom:4, direction:'ltr', textAlign:'right' }}>{label}</div>
        <div style={{ margin:0, color:payload[0].color, fontSize:'.85rem', direction:'ltr', textAlign:'right', fontWeight:800 }}>التقييم: {Number(payload[0].value).toFixed(2)}</div>
      </div>
    );
  }
  return null;
};

export default function UBA() {
  const qc = useQueryClient();
  const {
    tab,
    setTab,
    selectedUser,
    setSelectedUser,
    userSearch,
    setUserSearch,
    demoUsername,
    setDemoUsername,
    demoService,
    setDemoService,
    demoRiskScore,
    setDemoRiskScore,
    demoAccessResult,
    setDemoLabyrinthResult,
    demoLabyrinthResult,
    demoLoading,
    handleSimulateAccess,
    handleSimulateBaitInteraction,
    status,
    alerts,
    globalEvents,
    usersData,
    profile,
    userEvents,
    config,
    onResetUser,
    isResetting,
    onUpdateConfig,
    isConfigSaving,
  } = useUBA();

  const globalTrend = useMemo(() => {
    if(!globalEvents?.events) return [];
    return [...globalEvents.events].reverse().map(e => ({
      time: new Date(e.event_time).toLocaleTimeString('ar-SA',{hour:'2-digit',minute:'2-digit'}),
      risk: (e.anomaly_score*100).toFixed(1)
    }));
  }, [globalEvents]);

  const hrData = useMemo(() => {
    if(!profile?.hour_histogram) return [];
    return Object.entries(profile.hour_histogram).map(([h,c]) => ({ hour:`${h}:00`, count:c }));
  }, [profile]);

  const uRiskHist = useMemo(() => {
    if(!userEvents?.events) return [];
    return [...userEvents.events].reverse().map(e => ({
      time: new Date(e.event_time).toLocaleTimeString('ar-SA',{hour:'2-digit',minute:'2-digit'}),
      risk: (e.anomaly_score*100).toFixed(1)
    }));
  }, [userEvents]);

  const radarData = useMemo(() => {
    if(!userEvents?.events) return [];
    const counts = {};
    userEvents.events.forEach(e => {
      let ds = e.detectors_triggered;
      if(typeof ds==='string'){ try{ds=JSON.parse(ds);}catch{ds=[ds];} }
      (ds||[]).forEach(d => { counts[d] = (counts[d]||0)+1; });
    });
    const mx = Math.max(...Object.values(counts), 1);
    return Object.entries(counts).map(([name,val]) => ({ subject:name.replace('_detector',''), A:val, fullMark:mx+2 }));
  }, [userEvents]);

  return (
    <div className="uba-root" dir="rtl">
      {/* ── Hero ── */}
      <div className="uba-hero">
        <div className="uba-hero-glow" />
        <div className="uba-hero-inner">
          <div className="uba-hero-left">
            <div className="uba-hero-icon"><Activity size={26} style={{color:'#06b6d4'}} /></div>
            <div>
              <h1 className="uba-hero-title">تحليلات سلوك الكيانات (UBA) و AP-GDR</h1>
              <p className="uba-hero-sub">Deep Casual Inference · Threat Intelligence · Active Perturbation</p>
            </div>
          </div>
          <div className="uba-hero-right">
            <span className={`uba-status-badge ${status?.status==='active'?'uba-status-badge--active':'uba-status-badge--loading'}`}>
              <span style={{width:6,height:6,borderRadius:'50%',background:'currentColor'}}/>
              {status?.status==='active' ? 'المحرك نشط' : 'قيد التهيئة...'}
            </span>
            <span className="uba-version">الإصدار {status?.version ?? '2.0 (AP-GDR)'}</span>
          </div>
        </div>
      </div>

      {/* ── KPI Strip ── */}
      <div className="uba-kpi-strip">
        <div className="uba-kpi-card" style={{'--st-c':'#06b6d4'}}>
          <div className="uba-kpi-icon" style={{background:'rgba(6,182,212,0.1)',border:'1px solid rgba(6,182,212,0.2)'}}>
            <User size={18} style={{color:'#06b6d4'}} />
          </div>
          <div>
            <div className="uba-kpi-lbl">الكيانات المُراقبة</div>
            <div className="uba-kpi-val" style={{color:'#06b6d4'}}>{status?.profiles_total ?? 0}</div>
          </div>
        </div>
        <div className="uba-kpi-card" style={{'--st-c':'#ef4444'}}>
          <div className="uba-kpi-icon" style={{background:'rgba(239,68,68,0.1)',border:'1px solid rgba(239,68,68,0.2)'}}>
            <ShieldAlert size={18} style={{color:'#ef4444'}} />
          </div>
          <div>
            <div className="uba-kpi-lbl">تهديدات عالية الخطورة</div>
            <div className="uba-kpi-val" style={{color:'#ef4444'}}>{status?.high_risk_users ?? 0}</div>
          </div>
        </div>
        <div className="uba-kpi-card" style={{'--st-c':'#8b5cf6'}}>
          <div className="uba-kpi-icon" style={{background:'rgba(139,92,246,0.1)',border:'1px solid rgba(139,92,246,0.2)'}}>
            <Database size={18} style={{color:'#8b5cf6'}} />
          </div>
          <div>
            <div className="uba-kpi-lbl">الأحداث المقروءة</div>
            <div className="uba-kpi-val">{status?.events_total?.toLocaleString() ?? 0}</div>
          </div>
        </div>
        <div className="uba-kpi-card uba-kpi-card--apgdr">
          <div className="uba-kpi-icon" style={{background:'rgba(245,158,11,0.15)',border:'1px solid rgba(245,158,11,0.25)'}}>
            <Zap size={18} style={{color:'#f59e0b'}} />
          </div>
          <div>
            <div className="uba-kpi-lbl" style={{color:'rgba(245,158,11,0.6)'}}>الخداع السببي (AP-GDR)</div>
            <div className="uba-kpi-val" style={{color:'#f59e0b'}}>{config?.deception_enabled ? 'مُتأهب للعمل' : 'في وضع الخمول'}</div>
          </div>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="uba-tabs">
        {TABS.map(t => (
          <button key={t.id} className={`uba-tab ${tab===t.id?'uba-tab--active':''}`} onClick={()=>setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.div key={tab} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} exit={{opacity:0,y:-5}} transition={{duration:0.18}} style={{flex:1,display:'flex',flexDirection:'column',minHeight:0}}>
          {/* DASHBOARD */}
          {tab === 'dashboard' && (
            <div style={{display:'flex',flexDirection:'column',gap:14,flex:1,minHeight:0}}>
              <div className="uba-panel" style={{height:280,flexShrink:0}}>
                <div className="uba-panel-header">
                  <div className="uba-panel-title"><Activity size={14} style={{color:'#06b6d4'}}/> التباين التهديدي العام للشبكة</div>
                  <span className="uba-status-badge">آخر 50 حدث</span>
                </div>
                <div style={{flex:1,padding:'14px 18px 18px 0'}}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={globalTrend}>
                      <defs>
                        <linearGradient id="gRisk" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" fontSize={11} tickMargin={8} minTickGap={20} />
                      <YAxis stroke="rgba(255,255,255,0.3)" fontSize={11} tickFormatter={v=>`${v}%`} domain={[0,100]} orientation="right" />
                      <RechartsTooltip content={<CustomTooltip/>} />
                      <Area type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#gRisk)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:14,flex:1,minHeight:0}}>
                <div className="uba-panel">
                  <div className="uba-panel-header">
                    <div className="uba-panel-title"><AlertCircle size={14} style={{color:'#ef4444'}}/> الكيانات والملفات عالية المخاطر</div>
                  </div>
                  <div className="uba-table-wrap">
                    <table className="uba-table">
                      <thead>
                        <tr>
                          <th>الكيان (Profile)</th>
                          <th>مستوى الخطورة</th>
                          <th>التقييم (Score)</th>
                          <th>المرجع الأساسي</th>
                          <th>الحجم السببي</th>
                        </tr>
                      </thead>
                      <tbody>
                        {!usersData?.users?.length && <tr><td colSpan={5}><div className="uba-empty"><CheckCircle2 size={30} style={{opacity:0.2}}/>الوضع آمن. لا يوجد كيانات مسجلة حالياً.</div></td></tr>}
                        {usersData?.users?.slice(0,10).map(u => (
                          <tr key={u.username} className="uba-row" onClick={()=>{setSelectedUser(u.username);setTab('users');}}>
                            <td>
                              <div style={{display:'flex',alignItems:'center',gap:10}}>
                                <div style={{width:28,height:28,borderRadius:'50%',background:'rgba(255,255,255,0.05)',display:'flex',justifyContent:'center',alignItems:'center'}}>
                                  <User size={13} color="rgba(255,255,255,0.6)" />
                                </div>
                                <div style={{display:'flex',flexDirection:'column'}}>
                                  <span className="uba-mono" style={{fontWeight:800,color:'#f0f0f5',direction:'ltr',textAlign:'right'}}>{u.username}</span>
                                  <span style={{fontSize:'.68rem',color:'rgba(255,255,255,0.3)'}}>{u.peer_group||'Default'}</span>
                                </div>
                              </div>
                            </td>
                            <td><span className={`uba-risk-pill uba-risk-pill--${u.risk_level?.toUpperCase()||'LOW'}`}>{translateRiskLevel(u.risk_level)}</span></td>
                            <td>
                              <div className="uba-score-bar">
                                <span className="uba-score-val" style={{color:getRiskColor(u.risk_level)}} dir="ltr">{fmtScore(u.risk_score)}</span>
                                <div className="uba-score-track">
                                  <div style={{width:`${Math.min(u.risk_score*100,100)}%`,height:'100%',background:getRiskColor(u.risk_level)}}/>
                                </div>
                              </div>
                            </td>
                            <td>
                              {u.baseline_locked
                                ? <span className="uba-tag uba-tag-success"><UserCheck size={11}/> مرجعي ثابت</span>
                                : <span className="uba-tag uba-tag-warn"><Clock size={11}/> قيد التعلم</span>}
                            </td>
                            <td><span className="uba-mono" style={{color:'rgba(255,255,255,0.4)'}} dir="ltr">{u.event_count.toLocaleString()}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="uba-panel">
                  <div className="uba-panel-header">
                    <div className="uba-panel-title"><Zap size={14} style={{color:'#f59e0b'}}/> الإجراءات الحركية الأخيرة</div>
                  </div>
                  <div className="uba-feed">
                    {!alerts?.alerts?.length && <div className="uba-empty"><Clock size={26} style={{opacity:0.2}}/>سجل الأحداث نظيف.</div>}
                    {alerts?.alerts?.slice(0,10).map((a,i) => {
                      const c = getRiskColor(a.risk_level);
                      const isDecoy = a.action_taken===7 || String(a.action_taken).includes('DECOY');
                      const isPerturb = a.action_taken===6 || String(a.action_taken).includes('PERTURB');
                      return (
                        <div key={i} className="uba-alert-card" style={{borderRightColor:c}} onClick={()=>{setSelectedUser(a.username);setTab('users');}}>
                          <div className="uba-alert-head">
                            <span className="uba-mono uba-alert-user" dir="ltr">{a.username}</span>
                            <span className="uba-alert-time" dir="ltr">{new Date(a.event_time).toLocaleTimeString('ar-SA')}</span>
                          </div>
                          <div className="uba-alert-tags">
                            <span className="uba-tag" style={{borderColor:c,color:c}}>مخاطرة: {fmtScore(a.anomaly_score)}</span>
                            {isDecoy ? <span className="uba-tag uba-tag-danger"><Zap size={10}/> شبكة الإيقاع بالاعتمادية الذكية</span>
                            : isPerturb ? <span className="uba-tag uba-tag-warn"><Activity size={10}/> تشويش وعرقلة الاتجاه</span>
                            : <span className="uba-tag">{a.action_taken}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* USERS / PROFILE DEEP DIVE */}
          {tab === 'users' && (
            <div style={{display:'flex',gap:14,flex:1,minHeight:0}}>
              <div className="uba-userlist-panel">
                <div className="uba-search-bar">
                  <Search className="uba-search-icon" size={14}/>
                  <input className="uba-search-input" placeholder="ابحث عن كيان أو حساب..." value={userSearch} onChange={e=>setUserSearch(e.target.value)} />
                </div>
                <div style={{flex:1,overflowY:'auto',scrollbarWidth:'thin',scrollbarColor:'rgba(255,255,255,0.07) transparent'}}>
                  {usersData?.users?.map(u => (
                    <div key={u.username} className={`uba-user-row ${selectedUser===u.username?'uba-user-row--active':''}`} onClick={()=>setSelectedUser(u.username)}>
                      <div className="uba-ul-dot" style={{background:getRiskColor(u.risk_level),boxShadow:`0 0 8px ${getRiskColor(u.risk_level)}80`}}/>
                      <div className="uba-ul-info">
                        <div className="uba-ul-name">{u.username}</div>
                        <div className="uba-ul-meta"><span>R: {fmtScore(u.risk_score)}</span><span>{(u.event_count/1000).toFixed(1)}k احداث</span></div>
                      </div>
                    </div>
                  ))}
                  {!usersData?.users?.length && <div className="uba-empty"><User size={24} style={{opacity:0.2}}/>لم يتم العثور على أهداف.</div>}
                </div>
              </div>

              <div className="uba-profile-deep">
                <UserProfileCard
                  selectedUser={selectedUser}
                  profile={profile}
                  userEvents={userEvents}
                  onReset={onResetUser}
                  isResetting={isResetting}
                />
              </div>
            </div>
          )}

          {/* ALERTS */}
          {tab === 'alerts' && (
            <div className="uba-panel" style={{flex:1}}>
              <div className="uba-panel-header">
                <div>
                  <div className="uba-panel-title"><ShieldAlert size={15} style={{color:'#ef4444'}}/> سجلات التتبع الحرجة (AP-GDR)</div>
                  <div className="uba-panel-sub">الإجراءات والمسارات التي تمت السيطرة عليها بواسطة محرك الردع الاستباقي.</div>
                </div>
              </div>
              <div className="uba-table-wrap">
                <table className="uba-table">
                  <thead>
                    <tr>
                      <th>الطابع الزمني</th>
                      <th>الهوية / الخادم</th>
                      <th>يقين الخطر</th>
                      <th>العدسات الاستدلالية (Detectors)</th>
                      <th>القرار الاستراتيجي النهائي</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!alerts?.alerts?.length && <tr><td colSpan={5}><div className="uba-empty"><ShieldAlert size={36} style={{opacity:0.1}}/>لا توجد أحداث جسيمة تستدعي التدخل.</div></td></tr>}
                    {alerts?.alerts?.map((a,i)=>(
                      <tr key={i} className="uba-row">
                        <td className="uba-mono" style={{color:'rgba(255,255,255,0.4)',fontSize:'.75rem'}} dir="ltr">{new Date(a.event_time).toLocaleString('ar-SA')}</td>
                        <td className="uba-mono" style={{color:'#06b6d4',fontWeight:800,cursor:'pointer'}} onClick={()=>{setSelectedUser(a.username);setTab('users');}} dir="ltr">{a.username}</td>
                        <td className="uba-mono" style={{color:getRiskColor(a.risk_level),fontWeight:800,fontSize:'1rem'}} dir="ltr">{fmtScore(a.anomaly_score)}</td>
                        <td>
                          <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                            {(() => {
                              let ds = a.detectors_triggered;
                              if(typeof ds==='string'){try{ds=JSON.parse(ds);}catch{ds=[ds];}}
                              return (ds||[]).map(d=><span key={d} className="uba-tag uba-mono" style={{fontSize:'.68rem'}}>{d.replace('_detector','')}</span>);
                            })()}
                          </div>
                        </td>
                        <td>
                          {a.action_taken===7||String(a.action_taken).includes('DECOY') ? <span className="uba-tag uba-tag-danger"><Zap size={11}/> الإيقاع بـ Labyrinth</span>
                          : a.action_taken===6||String(a.action_taken).includes('PERTURB') ? <span className="uba-tag uba-tag-warn"><Activity size={11}/> حجب و Perturbation</span>
                          : <span className={`uba-tag ${a.blocked?'uba-tag-danger':'uba-tag-info'}`}>{a.blocked?'تم الحجب النهائي':'تتبع استكشافي'}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SETTINGS */}
          {tab === 'settings' && (
            <div style={{flex:1,overflowY:'auto',scrollbarWidth:'thin',scrollbarColor:'rgba(255,255,255,0.07) transparent'}}>
              <div className="uba-settings">
                <div className="uba-sets-card">
                  <div className="uba-sets-head">
                    <Settings size={24} style={{color:'#06b6d4'}} /> <h2>إعدادات السياسة السلوكية والانحراف (UBA)</h2>
                  </div>
                  
                  <div className="uba-set-row">
                    <div className="uba-set-info">
                      <div className="uba-set-title">التحليل المركزي للشذوذ (UBA Kernel)</div>
                      <div className="uba-set-desc">استكشاف الممارسات التهديدية تلقائياً عن طريق إنشاء أنماط وأسس سلوكية (Baselines) لكل كيان باستخدام خوارزميات إحصائية ديناميكية.</div>
                    </div>
                    <label className="uba-switch">
                      <input 
                        type="checkbox" 
                        checked={config?.enabled ?? true} 
                        onChange={(e) => onUpdateConfig({ ...config, enabled: e.target.checked })}
                      />
                      <span className="uba-switch-track" style={{'--sw-c':'#06b6d4'}}/>
                    </label>
                  </div>

                  <div className="uba-form-grid">
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">القرار الآلي للتخفيف التلقائي</label>
                      <select 
                        className="uba-select"
                        value={config?.alert_on_risk_level ?? 'critical'}
                        onChange={(e) => onUpdateConfig({ ...config, alert_on_risk_level: e.target.value })}
                      >
                        <option value="critical">مخاطر حرجة جداً فقط (&gt; 80%) [مُوصى به]</option>
                        <option value="high">عالية وحرجة (&gt; 55%) [تدقيق مكثف]</option>
                        <option value="medium">متوسطة فأكثر (&gt; 25%) [درع صلب]</option>
                        <option value="low">منخفضة فأكثر (تنبيه الكل)</option>
                      </select>
                      <div className="uba-form-sub">يقوم بتحديد متى يُنفذ أمر الفصل النهائي عبر جدار الحماية ضد المتلصصين الجدد.</div>
                    </div>
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">وضع تشغيل المحرك (Engine Mode)</label>
                      <select 
                        className="uba-select"
                        value={config?.mode ?? 'monitor'}
                        onChange={(e) => onUpdateConfig({ ...config, mode: e.target.value })}
                      >
                        <option value="learning">التعلم الذاتي المستمر (Learning)</option>
                        <option value="monitor">المراقبة وتسجيل الأنشطة (Monitor)</option>
                        <option value="enforce">التطبيق التلقائي الصارم (Enforce)</option>
                      </select>
                      <div className="uba-form-sub">تحديد سياسة التطبيق: إما التعلم المستمر للأنماط، أو مراقبة الانحرافات فقط، أو تطبيق تدابير الحجب التلقائي.</div>
                    </div>
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">الأحداث المرجعية للبصمة (Learning Limit)</label>
                      <input 
                        className="uba-input uba-mono" 
                        type="number" 
                        dir="ltr" 
                        value={config?.baseline_min_events ?? 50} 
                        onChange={(e) => {
                          const val = parseInt(e.target.value, 10);
                          if (!isNaN(val) && val >= 10 && val <= 1000) {
                            onUpdateConfig({ ...config, baseline_min_events: val });
                          }
                        }}
                        style={{textAlign:'right'}} 
                      />
                      <div className="uba-form-sub">الحد الأدنى لعدد الحركات والطلبات المطلوبة لقفل المرجع السلوكي للمستخدم قبل البدء بتدقيق الانحراف (بين 10 و 1000).</div>
                    </div>

                    <div className="uba-form-group">
                      <label className="uba-form-lbl">الحجر التلقائي للكيانات الشاذة (Auto-Quarantine)</label>
                      <select 
                        className="uba-select"
                        value={config?.enable_auto_quarantine ? 'true' : 'false'}
                        onChange={(e) => onUpdateConfig({ ...config, enable_auto_quarantine: e.target.value === 'true' })}
                      >
                        <option value="true">مفعل (عزل فوري للحسابات الخطرة)</option>
                        <option value="false">معطل (تسجيل وإنذار فقط)</option>
                      </select>
                      <div className="uba-form-sub">عزل وعرقلة الكيان التلقائية عند وصول خطورته لسقف العزل.</div>
                    </div>

                    <div className="uba-form-group">
                      <label className="uba-form-lbl">عتبة خطورة العزل الفوري (Score)</label>
                      <input 
                        className="uba-input uba-mono" 
                        type="number" 
                        dir="ltr" 
                        value={config?.auto_quarantine_risk_score ?? 85} 
                        onChange={(e) => {
                          const val = parseInt(e.target.value, 10);
                          if (!isNaN(val) && val >= 50 && val <= 100) {
                            onUpdateConfig({ ...config, auto_quarantine_risk_score: val });
                          }
                        }}
                        style={{textAlign:'right'}} 
                      />
                      <div className="uba-form-sub">درجة التهديد السلوكي (50 إلى 100) التي تؤدي لعزل الحساب مباشرة.</div>
                    </div>

                    <div className="uba-form-group">
                      <label className="uba-form-lbl">نصف عمر تلاشي الشذوذ (Decay Hours)</label>
                      <input 
                        className="uba-input uba-mono" 
                        type="number" 
                        dir="ltr" 
                        value={config?.anomaly_decay_hours ?? 24} 
                        onChange={(e) => {
                          const val = parseInt(e.target.value, 10);
                          if (!isNaN(val) && val >= 1 && val <= 168) {
                            onUpdateConfig({ ...config, anomaly_decay_hours: val });
                          }
                        }}
                        style={{textAlign:'right'}} 
                      />
                      <div className="uba-form-sub">عدد الساعات اللازمة لتلاشي نقاط الشذوذ تدريجياً للكيان الطبيعي.</div>
                    </div>
                  </div>
                </div>

                <div className="uba-apgdr-card">
                  <div className="uba-apgdr-head">
                    <div style={{background:'rgba(255,255,255,0.15)',padding:10,borderRadius:12,border:'1px solid rgba(255,255,255,0.1)'}}><Zap size={30} color="#fff"/></div>
                    <div>
                      <h2 className="uba-apgdr-title">نظام AP-GDR للاستخبارات والخداع الاستباقي</h2>
                      <p className="uba-apgdr-sub">الردع الابتكاري وكسر القواعد المعيارية للمهاجم</p>
                    </div>
                  </div>
                  <div className="uba-apgdr-body">
                    <div className="uba-apgdr-box">
                      <div className="uba-set-info">
                        <div className="uba-apgdr-btitle">تفعيل تقنيات Labyrinth للايقاع والتمويه</div>
                        <div className="uba-set-desc" style={{color:'rgba(255,255,255,0.6)'}}>بدلاً من الانعزال المباشر والفجّ الذي يُعلِم المهاجم بأنه اُكتشف، قم بتمرير الجلسات المهددة نحو فخ افتراضي شبكي يُصدر بيانات مُخلقة بالذكاء الاصطناعي ليزيد من استهلاك الموارد لدى المهاجم وكشف كامل نواياه التخريبية في بيئة آمنة محاطة.</div>
                      </div>
                      <label className="uba-switch" style={{transform:'scale(1.15)'}}>
                        <input type="checkbox" checked={config?.deception_enabled??true} onChange={()=>onUpdateConfig({...config, deception_enabled:!config?.deception_enabled})} />
                        <span className="uba-switch-track" style={{'--sw-c':'#f59e0b'}}/>
                      </label>
                    </div>

                    <div className="uba-res-box">
                      <div className="uba-res-p" style={{background:'rgba(239,68,68,0.03)',borderColor:'rgba(239,68,68,0.2)'}}>
                        <h5 style={{color:'#ef4444'}}><Activity size={16}/> الاستخبارات المضادة والتشويش الموجه</h5>
                        <p>براءة اختراع ابتكارية: بدلاً من الاستسلام للزيادة المستمرة في الإنذارات الخاطئة (False Positives)، يقوم المحرك بإنشاء جيوب زمنية من التشويش الدقيق على مستوى النقل. المهاجم البشري يكمل بصعوبة؛ البرامج الآلية تفشل فجأة متجاوزة مهلة الثواني فتسقط، ليتم حجبها للأبد بثقة يقينية تامة %100!</p>
                      </div>
                      <div className="uba-res-p" style={{background:'rgba(16,185,129,0.03)',borderColor:'rgba(16,185,129,0.2)'}}>
                        <h5 style={{color:'#10b981'}}><ShieldAlert size={16}/> التحييز السلوكي المستقل</h5>
                        <p>يخفف العبء التشغيلي لأطقم الـ SOC بنسبة 70%؛ حيث لا حاجة للمحلل لفحص سلوكيات متباينة مشكوك بها، محرك الذكاء سيتفاعل برمجياً مع الخصم ليكتشف أوتوماتيكياً ما إن كان الخصم إنساني معزول أم هجوم منظم شديد التوزيع.</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="uba-sets-card" style={{ marginTop: 20, border: '1px dashed rgba(245, 158, 11, 0.4)' }}>
                  <div className="uba-sets-head">
                    <Zap size={24} style={{ color: '#f59e0b' }} /> 
                    <h2>محاكاة الخداع الدفاعي والطعوم (AP-GDR Deception Sandbox)</h2>
                  </div>
                  <p className="uba-set-desc" style={{ marginBottom: 20 }}>
                    محاكاة هجوم سيبراني واختبار استجابة المحرك التلقائي عبر توليد الطعوم وحظر الحسابات.
                  </p>

                  <div className="uba-form-grid" style={{ marginBottom: 20 }}>
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">اسم المستخدم</label>
                      <input 
                        className="uba-input" 
                        type="text" 
                        value={demoUsername} 
                        onChange={(e) => setDemoUsername(e.target.value)} 
                        placeholder="Username"
                      />
                    </div>
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">الخادم / الخدمة</label>
                      <input 
                        className="uba-input" 
                        type="text" 
                        value={demoService} 
                        onChange={(e) => setDemoService(e.target.value)} 
                        placeholder="Service"
                      />
                    </div>
                    <div className="uba-form-group">
                      <label className="uba-form-lbl">درجة الخطورة المحاكاة: {demoRiskScore}</label>
                      <input 
                        type="range" 
                        min="0" 
                        max="1" 
                        step="0.05" 
                        value={demoRiskScore} 
                        onChange={(e) => setDemoRiskScore(parseFloat(e.target.value))} 
                        style={{ width: '100%', accentColor: '#f59e0b' }}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
                    <button 
                      className="uba-tab uba-tab--active" 
                      onClick={handleSimulateAccess}
                      disabled={demoLoading}
                      style={{ cursor: 'pointer' }}
                    >
                      {demoLoading ? 'جاري المحاكاة...' : '1. محاكاة وصول مشبوه للملفات'}
                    </button>

                    <button 
                      className="uba-tab uba-tab--active" 
                      onClick={handleSimulateBaitInteraction}
                      disabled={demoLoading || !demoAccessResult?.response_data}
                      style={{ 
                        cursor: demoAccessResult?.response_data ? 'pointer' : 'not-allowed',
                        opacity: demoAccessResult?.response_data ? 1 : 0.5,
                        borderColor: '#f59e0b',
                        color: '#f59e0b'
                      }}
                    >
                      {demoLoading ? 'جاري التفاعل...' : '2. محاكاة تفاعل الخصم مع الطعم'}
                    </button>
                  </div>

                  {demoAccessResult && (
                    <div className="card" style={{ padding: 14, background: 'var(--bg-overlay)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, marginBottom: 12 }}>
                      <h4 style={{ margin: '0 0 8px 0', fontSize: '.9rem', color: demoAccessResult.error ? '#ef4444' : '#10b981' }}>
                        {demoAccessResult.error ? 'فشل محاكاة الوصول' : 'نتيجة محاكاة الوصول'}
                      </h4>
                      {demoAccessResult.error ? (
                        <pre className="uba-mono" style={{ margin: 0, fontSize: '.75rem', color: '#ef4444' }}>{demoAccessResult.error}</pre>
                      ) : (
                        <div>
                          <div style={{ fontSize: '.8rem', marginBottom: 6 }}>الرد السلوكي: <strong>{demoAccessResult.verdict}</strong> (إجراء: {demoAccessResult.action_taken})</div>
                          {demoAccessResult.response_data && (
                            <pre className="uba-mono" style={{ margin: 0, padding: 8, background: 'rgba(0,0,0,0.15)', borderRadius: 4, fontSize: '.7rem', overflowX: 'auto', direction: 'ltr', textAlign: 'left' }}>
                              {JSON.stringify(demoAccessResult.response_data, null, 2)}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {demoLabyrinthResult && (
                    <div className="card" style={{ padding: 14, background: 'var(--bg-overlay)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8 }}>
                      <h4 style={{ margin: '0 0 8px 0', fontSize: '.9rem', color: demoLabyrinthResult.error ? '#ef4444' : '#f59e0b' }}>
                        {demoLabyrinthResult.error ? 'فشل تفاعل الطعم' : 'نتيجة تفاعل الطعم (Labyrinth Sandbox Hit)'}
                      </h4>
                      {demoLabyrinthResult.error ? (
                        <pre className="uba-mono" style={{ margin: 0, fontSize: '.75rem', color: '#ef4444' }}>{demoLabyrinthResult.error}</pre>
                      ) : (
                        <div>
                          <div style={{ fontSize: '.8rem', marginBottom: 6 }}>الحالة: <strong>{demoLabyrinthResult.status}</strong></div>
                          <div style={{ fontSize: '.75rem', color: 'rgba(255,255,255,0.6)' }}>{demoLabyrinthResult.message}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
