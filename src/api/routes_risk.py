from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Any, Optional
import json
from src.database.db import get_connection
from src.engines.risk_engine import risk_engine
from src.engines.entity_graph import entity_graph
from src.models.risk import PostureMetrics

router = APIRouter(prefix="/api/risk", tags=["Risk & Posture"])

@router.get("/profile/{entity_id}")
def get_risk_profile(entity_id: str, tenant_id: str = "tenant-corp-acme"):
    """
    Returns the multi-dimensional risk score with plain-English explainability and mitigations.
    """
    profile = risk_engine.calculate_user_risk(entity_id, tenant_id)
    return profile

@router.get("/blast-radius/{entity_id}")
def get_blast_radius(entity_id: str, max_hops: int = 2):
    """
    Returns all directly and indirectly connected assets reachable from the target entity.
    """
    return entity_graph.compute_blast_radius(entity_id, max_hops)

@router.get("/graph")
def get_full_entity_graph():
    """
    Returns the complete entity-relationship graph formatted for Vis.js
    """
    return entity_graph.get_visjs_graph_data()

@router.get("/posture/metrics")
def get_posture_metrics(tenant_id: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()

    # Dynamic metrics from DB
    cursor.execute("SELECT COUNT(*) FROM events")
    event_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED'")
    active_incidents = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('CRITICAL', 'HIGH')")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM entities_user")
    avg_user_risk = cursor.fetchone()[0] or 15.0

    cursor.execute("SELECT AVG(risk_score) FROM entities_device")
    avg_device_risk = cursor.fetchone()[0] or 12.0

    conn.close()

    overall_health = round(100.0 - ((avg_user_risk * 0.5) + (avg_device_risk * 0.5)), 1)
    overall_health = max(10.0, min(98.0, overall_health))

    return {
        "overall_security_score": overall_health,
        "identity_hygiene": round(100.0 - avg_user_risk, 1),
        "endpoint_compliance": round(100.0 - avg_device_risk, 1),
        "cloud_exposure_score": 82.5,
        "mean_time_to_detect_mins": 3.8,
        "mean_time_to_respond_mins": 11.4,
        "total_events_processed": event_count,
        "active_incidents_count": active_incidents,
        "critical_alerts_last_24h": critical_alerts
    }
