import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, Search, Settings2, List, RefreshCw, Terminal, AlertTriangle, Info, AlertCircle, ShieldAlert, ExternalLink } from 'lucide-react';
import { logManagerApi } from '../../../services/api';
import './LogsExplorer.css';

const LEVEL_OPTIONS = [
  { value: '', label: 'كل المستويات' },
  { value: 'INFO', label: 'معلومات (INFO)' },
  { value: 'WARNING', label: 'تحذير (WARNING)' },
  { value: 'ERROR', label: 'خطأ (ERROR)' },
  { value: 'CRITICAL', label: 'حرج (CRITICAL)' },
];

const LogRow = ({ file, text }) => {
  // Parse standard bunyanx log: 2026-04-03 14:46:05 [ INFO] module.name: Message here
  const match = text.match(/^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+\[\s*(\w+)\s*\]\s+(.*?):\s+(.*)$/s);

  if (match) {
    const [_, time, level, comp, msg] = match;

    let icon = <Info size={14} />;
    let levelClass = level.toLowerCase();

    if (level === 'WARNING') {
      icon = <AlertTriangle size={14} />;
    } else if (level === 'ERROR') {
      icon = <AlertCircle size={14} />;
    } else if (level === 'CRITICAL') {
      icon = <ShieldAlert size={14} className="spin" style={{ animationDuration: '3s' }} />;
    } else if (level === 'DEBUG') {
      icon = <Settings2 size={14} />;
    }

    // Attempt to highlight IPs or Keywords inside the message
    const formattedMsg = msg.replace(/(\d{1,3}(?:\.\d{1,3}){3})/g, '<span class="ip-highlight">$1</span>')
      .replace(/(http[s]?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" class="url-highlight">$1</a>');

    return (
      <div className="log-row" dir="ltr">
        <div className="log-time">
          {time}
        </div>
        <div className="log-badge-wrapper">
          <div className={`log-badge badge-${levelClass}`}>
            {icon} {level}
          </div>
        </div>
        <div className="log-comp" title={comp}>
          {comp}
        </div>
        <div className="log-msg" dangerouslySetInnerHTML={{ __html: formattedMsg }} />

        <div className="log-filename">
          {file}
        </div>
      </div>
    );
  }

  // Fallback for unparsed text
  const isErr = text.includes('ERROR') || text.includes('CRITICAL');
  const isWarn = text.includes('WARNING');
  const fallbackColor = isErr ? 'text-red' : isWarn ? 'text-yellow' : 'text-default';

  return (
    <div className={`log-row-fallback ${fallbackColor}`} dir="ltr">
      <span className="file-prefix">[{file}]</span>
      {text}
    </div>
  );
};

import useDashboardStore from '../stores/useDashboardStore';

export default function LogsExplorer() {
  const logsState = useDashboardStore((s) => s.logsState);
  const setLogsState = useDashboardStore((s) => s.setLogsState);

  const [activeFile, setActiveFileState] = useState(logsState.activeFile);
  const [levelParam, setLevelParamState] = useState(logsState.levelParam);
  const [keywordParam, setKeywordParamState] = useState(logsState.keywordParam);

  const setActiveFile = (f) => {
    setActiveFileState(f);
    setLogsState({ activeFile: f });
  };

  const setLevelParam = (lvl) => {
    setLevelParamState(lvl);
    setLogsState({ levelParam: lvl });
  };

  const setKeywordParam = (kw) => {
    setKeywordParamState(kw);
    setLogsState({ keywordParam: kw });
  };

  const { data: files } = useQuery({
    queryKey: ['siem_log_files'],
    queryFn: () => logManagerApi.listFiles().then(r => r.data?.data || []),
  });

  useEffect(() => {
    if (!activeFile && files?.length > 0) {
      setActiveFile(files[0]);
    }
  }, [files, activeFile]);

  const { data: logsData, isFetching: logsLoading, refetch } = useQuery({
    queryKey: ['siem_raw_logs', activeFile, levelParam],
    queryFn: () => logManagerApi.searchLogs({ file_name: activeFile, level: levelParam, limit: 300 }).then(r => r.data),
    enabled: !!activeFile,
  });

  const displayLogs = (logsData?.data || []).filter(item => {
    const text = typeof item === 'string' ? item : (typeof item.content === 'string' ? item.content : JSON.stringify(item.content || item));
    return keywordParam === '' || text.toLowerCase().includes(keywordParam.toLowerCase());
  });

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="logs-container">

      {/* Side Panel */}
      <div className="logs-sidebar">
        <div className="logs-sidebar-header">
          <div className="logs-sidebar-icon">
            <Terminal size={20} />
          </div>
          <div className="logs-sidebar-title">
            <h3>مستكشف السجلات</h3>
            <p>SOC Log Terminal</p>
          </div>
        </div>

        <div className="logs-list custom-scrollbar">
          <div className="logs-list-title">Available Logs</div>
          {files?.length > 0 ? files.map(f => {
            const isLive = f.includes('Live Memory');
            return (
              <button
                key={f}
                onClick={() => setActiveFile(f)}
                className={`log-file-btn ${activeFile === f ? 'active' : ''}`}
              >
                {isLive ? <ActivityIcon active={activeFile === f} /> : <FileText size={16} />}
                <span className="log-file-btn-text" dir="ltr">{f}</span>
              </button>
            )
          }) : (
            <div className="logs-empty-msg">
              لا توجد ملفات متوفرة
            </div>
          )}
        </div>
      </div>

      {/* Main Terminal Window */}
      <div className="logs-terminal">

        {/* Terminal Header */}
        <div className="terminal-header">

          <div className="terminal-controls">
            <div className="active-file-badge">
              <span className="pulse-dot" />
              <span dir="ltr">
                {activeFile || 'No file selected'}
              </span>
            </div>

            <div className="terminal-select-wrap">
              <Settings2 size={16} style={{ color: '#94a3b8' }} />
              <select
                className="terminal-select"
                value={levelParam}
                onChange={e => setLevelParam(e.target.value)}
              >
                {LEVEL_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="terminal-controls">
            <div className="terminal-search-wrap">
              <Search size={16} style={{ color: '#94a3b8' }} />
              <input
                type="text"
                placeholder="بحث..."
                className="terminal-search-input"
                value={keywordParam}
                onChange={e => setKeywordParam(e.target.value)}
                dir="auto"
              />
            </div>

            <button
              className="refresh-btn"
              onClick={() => window.open('/logs-fullscreen', '_blank')}
              title="نافذة جديدة (Open in new window)"
            >
              <ExternalLink size={18} />
            </button>
            <button
              className="refresh-btn"
              onClick={() => refetch()}
              title="تحديث (Refresh)"
            >
              <RefreshCw size={18} className={logsLoading ? "spin" : ""} />
            </button>
          </div>
        </div>

        {/* Terminal Body */}
        <div className="terminal-body custom-scrollbar">
          <AnimatePresence mode='wait'>
            {logsLoading && displayLogs.length === 0 ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="terminal-overlay overlay-loading"
              >
                <RefreshCw size={32} className="spin" style={{ opacity: 0.5 }} />
                <span className="overlay-text">Fetching Logs...</span>
              </motion.div>
            ) : displayLogs.length > 0 ? (
              <motion.div
                key="content"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="logs-content"
              >
                {displayLogs.map((item, i) => {
                  const text = typeof item === 'string' ? item : (typeof item.content === 'string' ? item.content : JSON.stringify(item.content || item));
                  return <LogRow key={i} file={item.file || activeFile} text={text} />;
                })}
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="terminal-overlay overlay-empty"
              >
                <Terminal size={48} style={{ opacity: 0.2 }} />
                <div className="overlay-text">EOF — No logs match the criteria</div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}

// Micro-component for the Live indicator icon
function ActivityIcon({ active }) {
  return (
    <div className="activity-icon-wrapper">
      {active && <span className="activity-ping"></span>}
      <Terminal size={16} className={active ? "icon-active" : "icon-inactive"} />
    </div>
  );
}


