import os
import logging
import random
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simulation: 192.168.1.x IPs are treated as external attackers from random
# countries. The last octet is used as a seed so the same IP always maps to
# the same country (deterministic), while different IPs get different origins.
# ---------------------------------------------------------------------------
_SIM_COUNTRIES = [
    {"country": "United States",  "flag": "🇺🇸", "lat": 37.0902,  "lng": -95.7129},
    {"country": "China",          "flag": "🇨🇳", "lat": 35.8617,  "lng": 104.1954},
    {"country": "Russia",         "flag": "🇷🇺", "lat": 61.5240,  "lng": 105.3188},
    {"country": "Iran",           "flag": "🇮🇷", "lat": 32.4279,  "lng": 53.6880},
    {"country": "North Korea",    "flag": "🇰🇵", "lat": 40.3399,  "lng": 127.5101},
    {"country": "Brazil",         "flag": "🇧🇷", "lat": -14.2350, "lng": -51.9253},
    {"country": "India",          "flag": "🇮🇳", "lat": 20.5937,  "lng": 78.9629},
    {"country": "Germany",        "flag": "🇩🇪", "lat": 51.1657,  "lng": 10.4515},
    {"country": "United Kingdom", "flag": "🇬🇧", "lat": 55.3781,  "lng": -3.4360},
    {"country": "France",         "flag": "🇫🇷", "lat": 46.2276,  "lng": 2.2137},
    {"country": "Turkey",         "flag": "🇹🇷", "lat": 38.9637,  "lng": 35.2433},
    {"country": "Ukraine",        "flag": "🇺🇦", "lat": 48.3794,  "lng": 31.1656},
    {"country": "Pakistan",       "flag": "🇵🇰", "lat": 30.3753,  "lng": 69.3451},
    {"country": "Indonesia",      "flag": "🇮🇩", "lat": -0.7893,  "lng": 113.9213},
    {"country": "Nigeria",        "flag": "🇳🇬", "lat": 9.0820,   "lng": 8.6753},
    {"country": "Romania",        "flag": "🇷🇴", "lat": 45.9432,  "lng": 24.9668},
    {"country": "Vietnam",        "flag": "🇻🇳", "lat": 14.0583,  "lng": 108.2772},
    {"country": "Netherlands",    "flag": "🇳🇱", "lat": 52.1326,  "lng": 5.2913},
    {"country": "South Korea",    "flag": "🇰🇷", "lat": 35.9078,  "lng": 127.7669},
    {"country": "Algeria",        "flag": "🇩🇿", "lat": 28.0339,  "lng": 1.6596},
]


def _sim_location_for_192(ip: str) -> Dict[str, Any]:
    """Deterministically map a 192.168.1.x IP to a simulated foreign country."""
    try:
        last_octet = int(ip.rsplit(".", 1)[-1])
    except (ValueError, IndexError):
        last_octet = 0
    entry = _SIM_COUNTRIES[last_octet % len(_SIM_COUNTRIES)]
    # Add a tiny random jitter so points don't stack exactly on top of each other
    rng = random.Random(last_octet)
    return {
        "country": entry["country"],
        "flag":    entry["flag"],
        "lat":     entry["lat"] + rng.uniform(-2.0, 2.0),
        "lng":     entry["lng"] + rng.uniform(-2.0, 2.0),
    }


class GeoIPService:
    _instance: Optional["GeoIPService"] = None

    def __init__(self):
        self.reader = None
        self._init_reader()

    def _init_reader(self):
        try:
            import geoip2.database
            project_root = Path(__file__).resolve().parents[3]
            candidate_paths = [
                os.environ.get("GEOIP_DB_PATH"),
                str(project_root / "data" / "GeoLite2-City.mmdb"),
                str(project_root / "system" / "data" / "GeoLite2-City.mmdb"),
                str(Path.cwd() / "data" / "GeoLite2-City.mmdb"),
                "/var/lib/geoip/GeoLite2-City.mmdb",
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
            ]
            found_path = None
            for p in candidate_paths:
                if p and os.path.exists(p):
                    found_path = p
                    break

            if found_path:
                self.reader = geoip2.database.Reader(found_path)
                logger.info(f"GeoIP reader initialized successfully from {found_path}")
            else:
                logger.warning(f"GeoIP database file not found in candidate paths. Checked: {project_root / 'data' / 'GeoLite2-City.mmdb'}")
        except Exception as e:
            logger.error(f"GeoIP reader initialization failed: {e}")

    @classmethod
    def get_instance(cls) -> "GeoIPService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        if not ip or ip == "0.0.0.0":
            return True
        return (
            ip.startswith("10.")
            or ip.startswith("127.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.2")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
        )

    def resolve_ip_location(self, ip: str) -> Dict[str, Any]:
        """
        Resolves IP address to country, flag, lat, and lng using MaxMind GeoIP.

        Simulation mode: 192.168.1.x IPs are treated as external attackers from
        randomised foreign countries (deterministic per last-octet) so they appear
        as realistic attack arcs on the globe/map.

        All other private IPs map to the local headquarters (Yemen).
        """
        # --- Simulation: 192.168.1.x → random foreign attacker country ---
        if ip and ip.startswith("192.168.1."):
            return _sim_location_for_192(ip)

        # --- Other private ranges → local HQ ---
        if self.is_private_ip(ip):
            return {
                "country": "اليمن (شبكة محلية)",
                "flag": "🇾🇪",
                "lat": 13.5795,
                "lng": 44.0206,
            }

        country = "غير معروف"
        flag = "🌐"
        lat, lng = 0.0, 0.0

        if self.reader:
            try:
                resp = self.reader.city(ip)
                country = resp.country.name or "غير معروف"
                iso = resp.country.iso_code or ""
                lat = resp.location.latitude or 0.0
                lng = resp.location.longitude or 0.0
                if iso:
                    flag = "".join(chr(127397 + ord(c)) for c in iso.upper())
            except Exception:
                pass

        return {
            "country": country,
            "flag": flag,
            "lat": lat,
            "lng": lng,
        }

