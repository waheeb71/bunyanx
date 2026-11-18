import { useEmailSecurityStore } from '../../stores/emailSecurityStore';
import { motion, AnimatePresence } from 'framer-motion';
import { BarChart2, List, Settings, ShieldCheck, ShieldX, Brain, ShieldAlert } from 'lucide-react';
import { useEmail } from './hooks/useEmail';

import EmailHeader from './components/EmailHeader';
import EmailStats from './components/EmailStats';
import EmailLogs from './components/EmailLogs';
import EmailSettings from './components/EmailSettings';
import EmailWhitelist from './components/EmailWhitelist';
import EmailAlerts from './components/EmailAlerts';
import EmailAIStats from './components/EmailAIStats';
import EmailQuarantine from './components/EmailQuarantine';

import '../email_security/Email.css';

const TABS = [
  { id: 'overview',   label: 'نظرة عامة',                 icon: BarChart2   },
  { id: 'quarantine', label: 'طابور الحجر الصحي (Quarantine)', icon: ShieldAlert },
  { id: 'alerts',     label: 'تنبيهات التهديدات',            icon: ShieldX     },
  { id: 'ai_stats',   label: 'محركات الذكاء الاصطناعي',      icon: Brain       },
  { id: 'logs',       label: 'السجلات الكاملة',             icon: List        },
  { id: 'config',     label: 'الإعدادات والمطابقة',         icon: Settings    },
  { id: 'whitelist',  label: 'القائمة البيضاء',             icon: ShieldCheck },
];

export default function EmailSecurity() {
  const tab = useEmailSecurityStore((s) => s.tab);
  const setTab = useEmailSecurityStore((s) => s.setTab);

  const {
    status, config, configSchema, stats, whitelist, modelMetrics,
    updateConfig, resetConfig, addToWhitelist, removeFromWhitelist,
  } = useEmail();

  return (
    <div className="em-root" dir="rtl">
      {/* Header + KPI */}
      <EmailHeader status={status} stats={stats} config={config} />

      {/* Tab bar */}
      <div className="em-tab-row">
        <div className="em-tabs">
          {TABS.map((t) => {
            const Icon = t.icon;
            const isActive = tab === t.id;
            return (
              <button
                key={t.id}
                className={`em-tab ${isActive ? 'em-tab--active' : ''}`}
                onClick={() => setTab(t.id)}
              >
                <Icon size={14} /> {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.18 }}
        >
          {tab === 'overview'   && <EmailStats stats={stats} />}
          {tab === 'quarantine' && <EmailQuarantine />}
          {tab === 'alerts'     && <EmailAlerts />}
          {tab === 'ai_stats'   && <EmailAIStats stats={stats} modelMetrics={modelMetrics} />}
          {tab === 'logs'       && <EmailLogs />}
          {tab === 'config'     && (
            <EmailSettings
              config={config}
              configSchema={configSchema}
              updateConfig={updateConfig}
              resetConfig={resetConfig}
            />
          )}
          {tab === 'whitelist'  && (
            <EmailWhitelist
              whitelist={whitelist}
              addToWhitelist={addToWhitelist}
              removeFromWhitelist={removeFromWhitelist}
            />
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
