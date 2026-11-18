import { Globe, Layers, MapPin, Play, Pause, Volume2, VolumeX, Shield, Filter } from 'lucide-react';
import { useGlobeStore } from '../stores/useGlobeStore';

export function GlobeHeaderControls({ clockStr }) {
  const mapMode = useGlobeStore((s) => s.mapMode);
  const setMapMode = useGlobeStore((s) => s.setMapMode);

  const timeframe = useGlobeStore((s) => s.timeframe);
  const setTimeframe = useGlobeStore((s) => s.setTimeframe);

  const severityFilter = useGlobeStore((s) => s.severityFilter);
  const setSeverityFilter = useGlobeStore((s) => s.setSeverityFilter);

  const categoryFilter = useGlobeStore((s) => s.categoryFilter);
  const setCategoryFilter = useGlobeStore((s) => s.setCategoryFilter);

  const isFeedPaused = useGlobeStore((s) => s.isFeedPaused);
  const toggleFeedPause = useGlobeStore((s) => s.toggleFeedPause);

  const audioEnabled = useGlobeStore((s) => s.audioEnabled);
  const toggleAudio = useGlobeStore((s) => s.toggleAudio);

  return (
    <div className="gtm-top-controls-bar">
      {/* Brand / Mode Selector */}
      <div className="gtm-controls-group">
        <div className="gtm-brand-badge">
          <Shield size={18} className="gtm-brand-icon" />
          <span className="gtm-brand-text">رصد التهديدات 3D</span>
        </div>

        <div className="gtm-map-modes-inline">
          <button
            type="button"
            className={`gtm-mode-btn ${mapMode === 'global' ? 'active' : ''}`}
            onClick={() => setMapMode('global')}
            title="عرض عالمي"
          >
            <Globe size={15} />
            <span>عالمي</span>
          </button>
          <button
            type="button"
            className={`gtm-mode-btn ${mapMode === 'regional' ? 'active' : ''}`}
            onClick={() => setMapMode('regional')}
            title="عرض المناطق"
          >
            <Layers size={15} />
            <span>مناطق</span>
          </button>
          <button
            type="button"
            className={`gtm-mode-btn ${mapMode === 'country' ? 'active' : ''}`}
            onClick={() => setMapMode('country')}
            title="عرض الدول"
          >
            <MapPin size={15} />
            <span>دول</span>
          </button>
        </div>
      </div>

      {/* Filters (Timeframe, Severity, Category) */}
      <div className="gtm-controls-group">
        {/* Timeframe Select */}
        <div className="gtm-filter-item">
          <span className="gtm-filter-label">الإطار الزمني:</span>
          <select
            value={timeframe}
            onChange={(e) => setTimeframe(e.target.value)}
            className="gtm-control-select"
          >
            <option value="1h">آخر ساعة</option>
            <option value="12h">آخر 12 ساعة</option>
            <option value="24h">آخر 24 ساعة</option>
            <option value="7d">آخر 7 أيام</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="gtm-filter-item">
          <span className="gtm-filter-label">الخطورة:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="gtm-control-select"
          >
            <option value="all">الكل</option>
            <option value="critical">حرج</option>
            <option value="high">مرتفع</option>
            <option value="medium">متوسط</option>
            <option value="low">منخفض</option>
          </select>
        </div>

        {/* Category Filter */}
        <div className="gtm-filter-item">
          <span className="gtm-filter-label">النوع:</span>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="gtm-control-select"
          >
            <option value="all">الكل</option>
            <option value="malware">خبيثة</option>
            <option value="web">ويب</option>
            <option value="exploit">ثغرات</option>
            <option value="network">شبكة</option>
          </select>
        </div>
      </div>

      {/* Quick Action Toggles */}
      <div className="gtm-controls-group">
        <button
          type="button"
          className={`gtm-action-icon-btn ${isFeedPaused ? 'paused' : ''}`}
          onClick={toggleFeedPause}
          title={isFeedPaused ? 'استئناف التحديث المباشر' : 'إيقاف التحديث مؤقتاً'}
        >
          {isFeedPaused ? <Play size={15} /> : <Pause size={15} />}
        </button>

        <button
          type="button"
          className={`gtm-action-icon-btn ${audioEnabled ? 'active' : ''}`}
          onClick={toggleAudio}
          title={audioEnabled ? 'كتم التنبيهات الصوتية' : 'تفعيل التنبيهات الصوتية'}
        >
          {audioEnabled ? <Volume2 size={15} /> : <VolumeX size={15} />}
        </button>
      </div>
    </div>
  );
}

export default GlobeHeaderControls;
