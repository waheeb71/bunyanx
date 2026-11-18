import { useGlobeStore } from '../stores/useGlobeStore';
import { useUnifiedMapData } from '../../../hooks/useUnifiedMapData';

export function useGlobe() {
  const timeframe = useGlobeStore((s) => s.timeframe);
  const severityFilter = useGlobeStore((s) => s.severityFilter);
  const categoryFilter = useGlobeStore((s) => s.categoryFilter);

  const mapData = useUnifiedMapData({
    timeframe,
    severityFilter,
    categoryFilter,
    refetchInterval: 3000,
  });

  return {
    threatFeed: mapData.arcs,
    liveStats: mapData.stats,
    statsSummary: {
      regions: mapData.regions,
      severity: mapData.severity,
      top_countries: mapData.topCountries,
      attack_types: mapData.attackTypes,
      timeline: mapData.timeline,
    },
    targets: mapData.targets,
    hqCoords: mapData.hqCoords,
    mapKpis: mapData.mapKpis,
    isLoading: mapData.isLoading,
  };
}

export default useGlobe;
