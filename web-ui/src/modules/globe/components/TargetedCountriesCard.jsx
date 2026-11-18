import { useMemo } from 'react';

export function TargetedCountriesCard({ topCountries = [] }) {
  const totalCountryAttacks = useMemo(
    () => topCountries.reduce((acc, c) => acc + (c.count || 0), 0),
    [topCountries]
  );

  return (
    <div className="gtm-card">
      <div className="gtm-card-header flex-row">
        <h3 className="gtm-card-title">أكثر الدول استهدافاً</h3>
      </div>

      <div className="gtm-countries-list">
        {topCountries.length === 0 ? (
          <div className="gtm-empty-state">لا توجد بيانات دول في هذا الإطار الزمني</div>
        ) : (
          topCountries.map((c) => {
            const pct = totalCountryAttacks > 0 ? Math.round(((c.count || 0) / totalCountryAttacks) * 100) : 0;
            return (
              <div key={c.name} className="gtm-country-row">
                <div className="gtm-country-info">
                  <span className="gtm-country-flag">{c.flag || '🌐'}</span>
                  <span className="gtm-country-name">{c.name}</span>
                </div>
                <div className="gtm-country-bar-container">
                  <div className="gtm-country-bar-track">
                    <div
                      className="gtm-country-bar-fill"
                      style={{ width: `${pct}%`, background: c.color || '#00d4ff' }}
                    />
                  </div>
                </div>
                <span className="gtm-country-pct">{pct}%</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default TargetedCountriesCard;
