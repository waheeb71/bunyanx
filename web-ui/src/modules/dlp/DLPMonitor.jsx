import React from 'react';
import DLPMonitorCard from './components/DLPMonitorCard';
import ERSTesterCard from './components/ERSTesterCard';
import FeedbackPanelCard from './components/FeedbackPanelCard';
import { useDLP } from './hooks/useDLP';

export default function DLPMonitor() {
  const { highRiskIps, isFetchingHighRisk, refetchHighRisk } = useDLP();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* High Risk IPs & Signal Legend */}
      <DLPMonitorCard
        highRisk={highRiskIps}
        isFetching={isFetchingHighRisk}
        refetch={refetchHighRisk}
      />

      {/* Live ERS Payload Simulator */}
      <ERSTesterCard />

      {/* Self-Learning Analyst Feedback & Admin Review Queue */}
      <FeedbackPanelCard />

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
