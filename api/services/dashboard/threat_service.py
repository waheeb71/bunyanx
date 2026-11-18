import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import Request

from api.services.dashboard.geoip_service import GeoIPService
from api.services.dashboard.events_repository import EventsRepository

logger = logging.getLogger(__name__)

PORT_NAMES = {
    8080: "HTTP Proxy (8080)",
    80: "HTTP (80)",
    443: "HTTPS (443)",
    22: "SSH (22)",
    3389: "RDP (3389)",
    445: "SMB (445)",
    53: "DNS (53)",
}

PORT_COLORS = {
    8080: "#06b6d4",
    80: "#eab308",
    443: "#3b82f6",
    22: "#f97316",
    3389: "#ef4444",
    445: "#8b5cf6",
    53: "#10b981",
}

COUNTRY_FLAGS = {
    "United States": ("🇺🇸", "#ff4d6d"),
    "Germany": ("🇩🇪", "#00d4ff"),
    "United Kingdom": ("🇬🇧", "#ff9100"),
    "Russia": ("🇷🇺", "#a78bfa"),
    "China": ("🇨🇳", "#00e676"),
    "France": ("🇫🇷", "#3b82f6"),
    "Japan": ("🇯🇵", "#eab308"),
    "Brazil": ("🇧🇷", "#ec4899"),
}


class ThreatService:
    """Service layer for threat intelligence and dashboard analytics."""

    @staticmethod
    async def get_executive_trend(request: Request) -> List[Dict[str, Any]]:
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if not bunyanx or not hasattr(bunyanx, "db"):
            return []

        try:
            from system.database.database import SecurityEvent
            from sqlalchemy.future import select

            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            current_month = datetime.now().month

            async with bunyanx.db.session() as session:
                result = await session.execute(
                    select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
                )
                all_events = result.scalars().all()

            threat_trend = []
            for idx in range(6):
                m_idx = (current_month - 5 + idx + 12 - 1) % 12
                month_name = months[m_idx]
                target_month = m_idx + 1

                month_events = [ev for ev in all_events if ev.timestamp and ev.timestamp.month == target_month]
                blocked = len([ev for ev in month_events if ev.action == 'BLOCK'])
                detected = len(month_events)

                threat_trend.append({
                    "month": month_name,
                    "blocked": blocked,
                    "detected": detected,
                })

            return threat_trend

        except Exception as e:
            logger.error(f"Failed to fetch executive trend: {e}")
            return []

    @staticmethod
    async def get_globe_threats(
        request: Request,
        timeframe: str = "24h",
        severity: str = "all",
        category: str = "all",
    ) -> Dict[str, Any]:
        rows = await EventsRepository.fetch_recent_events(limit=100)
        geoip = GeoIPService.get_instance()

        feed = []
        unique_countries = set()
        blocked_count = 0

        for r in rows:
            ev_id, ts, src_ip, dst_ip, verdict, reason, ml_score = r
            src_ip = src_ip or "0.0.0.0"
            dst_ip = dst_ip or "0.0.0.0"
            verdict = (verdict or 'allow').lower()
            reason_str = (reason or '').lower()

            loc = geoip.resolve_ip_location(src_ip)
            country = loc["country"]
            flag = loc["flag"]
            src_lat = loc["lat"]
            src_lng = loc["lng"]

            dst_loc = geoip.resolve_ip_location(dst_ip)
            dst_lat = dst_loc["lat"] if dst_loc["lat"] != 0.0 else 13.5795
            dst_lng = dst_loc["lng"] if dst_loc["lng"] != 0.0 else 44.0206

            if country != "غير معروف" and country != "Unknown":
                unique_countries.add(country)

            if verdict in ['drop', 'block', 'quarantine']:
                blocked_count += 1

            sev_val = "medium"
            if ml_score is not None:
                sev_val = "critical" if ml_score >= 0.8 else "high" if ml_score >= 0.5 else "medium" if ml_score >= 0.2 else "low"
            elif 'sql' in reason_str or 'rce' in reason_str or 'score=0.9' in reason_str or 'score=0.8' in reason_str or verdict in ['drop', 'block']:
                sev_val = "critical"
            elif 'bot' in reason_str or 'score=0.7' in reason_str or 'quarantine' in verdict:
                sev_val = "high"
            elif 'anomaly' in reason_str:
                sev_val = "medium"

            if severity != "all" and sev_val.lower() != severity.lower():
                continue

            col = "#ff4d6d" if sev_val == "critical" else "#ff9100" if sev_val == "high" else "#00d4ff" if sev_val == "medium" else "#00e676"
            event_type = "WAF Intrusion" if "waf" in reason_str else "IDS Threat" if "ids" in reason_str or "ips" in reason_str else "Network Flow"

            feed.append({
                "id": str(ev_id),
                "type": event_type,
                "sev": sev_val,
                "severity": sev_val,
                "col": col,
                "color": col,
                "country": country,
                "flag": flag,
                "ip": src_ip,
                "src_ip": src_ip,
                "target_ip": dst_ip,
                "dst_ip": dst_ip,
                "time": ts or datetime.now().isoformat(),
                "src_lat": src_lat,
                "src_lng": src_lng,
                "dst_lat": dst_lat,
                "dst_lng": dst_lng,
            })

        total_count = len(feed)
        return {
            "feed": feed,
            "stats": {
                "total": total_count,
                "blocked": blocked_count,
                "countries": len(unique_countries),
                "rate": round(total_count / 60, 2) if total_count > 0 else 0.0,
            },
        }

    @staticmethod
    async def get_globe_stats(
        request: Request,
        timeframe: str = "24h",
        severity: str = "all",
        category: str = "all",
    ) -> Dict[str, Any]:
        rows = await EventsRepository.fetch_all_event_stats_rows()
        geoip = GeoIPService.get_instance()

        regions = {
            "الشرق الأوسط": 0,
            "أوروبا": 0,
            "أفريقيا": 0,
            "أمريكا الشمالية": 0,
            "أمريكا الجنوبية": 0,
            "آسيا": 0,
        }
        sev_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        country_counts = {}
        attack_types = {"malware": 0, "web": 0, "exploit": 0, "network": 0, "other": 0}

        timeline_bins = {}
        for h in range(0, 24, 2):
            lbl = f"{h:02d}:00"
            timeline_bins[lbl] = {"time": lbl, "attacks": 0, "blocked": 0, "pin": False, "pinColor": "", "pinIcon": ""}

        for r in rows:
            src_ip = r[0] or "0.0.0.0"
            verdict = (r[1] or 'allow').lower()
            reason_str = (r[2] or '').lower()
            ml_score = r[3]
            ts_str = r[4]

            # Severity
            if ml_score is not None:
                s = "critical" if ml_score >= 0.8 else "high" if ml_score >= 0.5 else "medium" if ml_score >= 0.2 else "low"
            elif 'sql' in reason_str or 'rce' in reason_str or 'score=0.9' in reason_str or 'score=0.8' in reason_str or verdict in ['drop', 'block']:
                s = "critical"
            elif 'bot' in reason_str or 'score=0.7' in reason_str or 'quarantine' in verdict:
                s = "high"
            elif 'anomaly' in reason_str:
                s = "medium"
            else:
                s = "low"
            sev_stats[s] += 1

            # GeoIP country
            loc = geoip.resolve_ip_location(src_ip)
            c_name = loc["country"]
            country_counts[c_name] = country_counts.get(c_name, 0) + 1

            # Region
            if c_name in ["United States", "Brazil", "Canada", "Mexico"]:
                regions["أمريكا الشمالية"] += 1
            elif c_name in ["Germany", "France", "United Kingdom", "Russia", "Italy", "Spain"]:
                regions["أوروبا"] += 1
            elif c_name in ["China", "Japan", "India", "South Korea"]:
                regions["آسيا"] += 1
            elif c_name in ["Egypt", "South Africa", "Nigeria", "Kenya"]:
                regions["أفريقيا"] += 1
            elif c_name in ["Brazil", "Argentina"]:
                regions["أمريكا الجنوبية"] += 1
            else:
                regions["الشرق الأوسط"] += 1

            # Attack type
            if "malware" in reason_str or "virus" in reason_str:
                attack_types["malware"] += 1
            elif "waf" in reason_str or "sql" in reason_str or "xss" in reason_str or "http" in reason_str:
                attack_types["web"] += 1
            elif "rce" in reason_str or "exploit" in reason_str or "shell" in reason_str:
                attack_types["exploit"] += 1
            elif "ids" in reason_str or "ips" in reason_str or "scan" in reason_str or "dos" in reason_str:
                attack_types["network"] += 1
            else:
                attack_types["other"] += 1

            # Timeline
            if ts_str:
                try:
                    dt_obj = datetime.fromisoformat(ts_str.replace('Z', ''))
                    hr_bin = f"{(dt_obj.hour // 2) * 2:02d}:00"
                    if hr_bin in timeline_bins:
                        timeline_bins[hr_bin]["attacks"] += 1
                        if verdict in ['drop', 'block', 'quarantine']:
                            timeline_bins[hr_bin]["blocked"] += 1
                except Exception:
                    pass

        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_countries = [
            {
                "name": c_name,
                "flag": COUNTRY_FLAGS.get(c_name, ("🌐", "#00d4ff"))[0],
                "count": count,
                "color": COUNTRY_FLAGS.get(c_name, ("🌐", "#00d4ff"))[1],
            }
            for c_name, count in sorted_countries
        ]

        return {
            "regions": regions,
            "severity": sev_stats,
            "top_countries": top_countries,
            "attack_types": attack_types,
            "timeline": list(timeline_bins.values()),
        }

    @staticmethod
    async def get_traffic_history(request: Request) -> List[Dict[str, Any]]:
        history = []
        now_utc = datetime.utcnow()
        now_local = datetime.now()

        for i in range(20):
            start_utc = now_utc - timedelta(seconds=10 * (20 - i))
            end_utc = now_utc - timedelta(seconds=10 * (19 - i))
            display_time = now_local - timedelta(seconds=10 * (20 - i))
            time_str = display_time.strftime("%H:%M:%S")

            sum_events, sum_blocked = await EventsRepository.fetch_traffic_interval(
                start_utc.isoformat(), end_utc.isoformat()
            )

            reqs = sum_events
            blocks = sum_blocked

            history.append({
                "time": time_str,
                "reqs": reqs,
                "blocks": blocks,
            })

        return history

    @staticmethod
    async def get_dashboard_location(request: Request) -> Dict[str, Any]:
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and hasattr(bunyanx, "config"):
            system_conf = bunyanx.config.get("system", {})
            location_conf = system_conf.get("location", {})
            if location_conf:
                return location_conf

        return {
            "headquarters": {
                "name": "المقر – تعز",
                "country": "اليمن",
                "flag": "🇾🇪",
                "lat": 13.5795,
                "lng": 44.0206,
            },
            "branches": [],
        }

    @staticmethod
    async def get_map_stats(request: Request) -> Dict[str, Any]:
        m = await EventsRepository.fetch_map_stats()
        attacks_today = m["attacks_today"]
        targeted_countries = m["targeted_countries"]
        active_attacks = m["active_attacks"]
        data_exfil_tb = m["data_exfil_tb"]

        return {
            "attacks_today": {
                "value": f"{attacks_today:,}",
                "change": f"+{min(attacks_today, 99)}%",
                "is_positive": True,
            },
            "targeted_countries": {
                "value": f"{targeted_countries}",
                "change": f"+{targeted_countries}",
                "is_positive": True,
            },
            "active_attacks": {
                "value": f"{active_attacks}",
                "change": f"+{active_attacks}",
                "is_positive": True,
            },
            "data_exfiltration": {
                "value": f"{data_exfil_tb:.2f} TB",
                "change": f"+{min(int(data_exfil_tb * 10), 99)}%",
                "is_positive": True,
            },
        }

    @staticmethod
    async def get_severity_breakdown(request: Request) -> Dict[str, Any]:
        rows = await EventsRepository.fetch_severity_rows()
        critical, high, medium, low = 0, 0, 0, 0

        for r in rows:
            verdict = (r[0] or '').lower()
            reason = (r[1] or '').lower()
            ml_score = r[2]

            if ml_score is not None:
                if ml_score >= 0.8: critical += 1
                elif ml_score >= 0.5: high += 1
                elif ml_score >= 0.2: medium += 1
                else: low += 1
            elif 'sql' in reason or 'rce' in reason or 'score=0.9' in reason or 'score=0.8' in reason or verdict in ['drop', 'block']:
                critical += 1
            elif 'bot' in reason or 'score=0.7' in reason or 'xss' in reason or 'quarantine' in verdict:
                high += 1
            elif 'anomaly' in reason or 'score=0.5' in reason or 'score=0.6' in reason or 'vip' in reason:
                medium += 1
            else:
                low += 1

        total = critical + high + medium + low

        return {
            "critical": {"value": critical, "percentage": round((critical / total) * 100, 1) if total > 0 else 0.0},
            "high": {"value": high, "percentage": round((high / total) * 100, 1) if total > 0 else 0.0},
            "medium": {"value": medium, "percentage": round((medium / total) * 100, 1) if total > 0 else 0.0},
            "low": {"value": low, "percentage": round((low / total) * 100, 1) if total > 0 else 0.0},
            "total": total,
        }

    @staticmethod
    async def get_alerts_trend_24h(request: Request) -> List[Dict[str, Any]]:
        rows = await EventsRepository.fetch_hourly_trends()
        trend_dict = {f"{h:02d}:00": 0 for h in range(24)}

        for r in rows:
            hr_str = r[0] if r[0] else '00'
            lbl = f"{int(hr_str):02d}:00"
            if lbl in trend_dict:
                trend_dict[lbl] = r[1]

        return [{"time": time_lbl, "val": val} for time_lbl, val in trend_dict.items()]

    @staticmethod
    async def get_top_services(request: Request) -> List[Dict[str, Any]]:
        rows = await EventsRepository.fetch_top_services()
        service_counts = []

        for r in rows:
            port = r[0]
            cnt = r[1]
            name = PORT_NAMES.get(port, f"Port ({port})")
            color = PORT_COLORS.get(port, "#a855f7")
            service_counts.append({"name": name, "count": cnt, "color": color})

        return service_counts
