import logging
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Request
from api.core.auth import verify_token

from api.services.dashboard.kpi_service import KPIService
from api.services.dashboard.threat_service import ThreatService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["dashboard"])


@router.get("/executive/trend")
async def get_executive_trend(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Get the 6-month threat trend based on actual database events."""
    return await ThreatService.get_executive_trend(request)


@router.get("/globe/threats/live")
async def get_globe_threats(
    request: Request,
    timeframe: str = "24h",
    severity: str = "all",
    category: str = "all",
    token: dict = Depends(verify_token),
):
    """Fetch recent threats with real geo-coordinates, timeframe, severity, and category filtering."""
    return await ThreatService.get_globe_threats(
        request=request,
        timeframe=timeframe,
        severity=severity,
        category=category,
    )


@router.get("/globe/stats")
async def get_globe_stats(
    request: Request,
    timeframe: str = "24h",
    severity: str = "all",
    category: str = "all",
    token: dict = Depends(verify_token),
):
    """Retrieve authentic aggregated threat metrics from events.db."""
    return await ThreatService.get_globe_stats(
        request=request,
        timeframe=timeframe,
        severity=severity,
        category=category,
    )


@router.get("/stats/traffic/history")
async def get_traffic_history(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Fetch recent traffic history from actual database events."""
    return await ThreatService.get_traffic_history(request)


@router.get("/dashboard/location")
async def get_dashboard_location(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Get headquarters and branches geolocation coordinates configured in system settings."""
    return await ThreatService.get_dashboard_location(request)


@router.get("/dashboard/kpi")
async def get_dashboard_kpi(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Retrieve authentic KPI statistics from events.db and system database."""
    return await KPIService.get_kpis(request)


@router.get("/dashboard/map_stats")
async def get_dashboard_map_stats(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Retrieve real map statistics overlays from events.db."""
    return await ThreatService.get_map_stats(request)


@router.get("/dashboard/severity_breakdown")
async def get_dashboard_severity_breakdown(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Retrieve actual count breakdown of alerts by severity."""
    return await ThreatService.get_severity_breakdown(request)


@router.get("/dashboard/alerts_trend_24h")
async def get_dashboard_alerts_trend_24h(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Retrieve hourly alert distribution counts over the past 24 hours."""
    return await ThreatService.get_alerts_trend_24h(request)


@router.get("/dashboard/top_services")
async def get_dashboard_top_services(
    request: Request,
    token: dict = Depends(verify_token),
):
    """Retrieve top targeted destination ports/services."""
    return await ThreatService.get_top_services(request)
