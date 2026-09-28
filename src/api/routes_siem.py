from fastapi import APIRouter, Query, HTTPException, Body
from typing import List, Dict, Any, Optional
import json
from src.database.db import get_connection
from src.models.events import CommonEvent
from src.pipeline.event_bus import event_bus
from src.pipeline.normalizers import EventNormalizer
from src.engines.detection_rules import rule_engine
from src.engines.ueba_engine import ueba_engine
from src.engines.correlation_engine import correlation_engine
from src.engines.risk_engine import risk_engine

router = APIRouter(prefix="/api/siem", tags=["SIEM"])

@router.get("/events")
def get_events(
    q: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    actor_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if actor_id:
        query += " AND (actor_id LIKE ? OR actor_name LIKE ?)"
        params.extend([f"%{actor_id}%", f"%{actor_id}%"])
    if q:
        query += " AND (dest_name LIKE ? OR source_ip LIKE ? OR normalized_json LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    # Total count
    count_query = "SELECT COUNT(*) FROM events WHERE 1=1"
    cursor.execute(count_query)
    total_count = cursor.fetchone()[0]
    
    conn.close()

    events = [json.loads(r["normalized_json"]) for r in rows]
    return {
        "total": total_count,
        "returned": len(events),
        "events": events
    }

@router.post("/ingest")
async def ingest_event(payload: Dict[str, Any] = Body(...)):
    """
    Ingests raw vendor event (Windows, CloudTrail, or generic CEM),
    normalizes it, runs it through detection, and broadcasts live.
    """
    # Auto-detect format
    if "EventID" in payload:
        event = EventNormalizer.normalize_windows_event(payload)
    elif "eventName" in payload or "userIdentity" in payload:
        event = EventNormalizer.normalize_cloudtrail_event(payload)
    else:
        event = EventNormalizer.normalize_generic_cem(payload)

    # Publish to real-time bus
    await event_bus.publish(event)

    # Run detection rules
    alerts = rule_engine.evaluate(event)
    for a in alerts:
        _save_alert(a)

    # Run UEBA
    ueba_alt = ueba_engine.evaluate_behavior(event)
    if ueba_alt:
        _save_alert(ueba_alt)

    # Run Correlation
    incident = correlation_engine.track_event(event)

    # Recalculate Risk
    if event.actor and event.actor.id:
        risk_engine.calculate_user_risk(event.actor.id, tenant_id=event.tenant_id)

    return {
        "status": "INGESTED",
        "event_id": event.event_id,
        "alerts_triggered": len(alerts) + (1 if ueba_alt else 0),
        "incident_triggered": incident.incident_id if incident else None
    }

def _save_alert(alert):
    try:
        conn = get_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO alerts 
            (alert_id, tenant_id, title, rule_id, severity, category, summary, actor_id, device_id, source_ip, confidence, risk_impact, raw_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.tenant_id,
                alert.title,
                alert.rule_id,
                alert.severity.value,
                alert.category,
                alert.summary,
                alert.actor_id,
                alert.device_id,
                alert.source_ip,
                alert.confidence,
                alert.risk_impact,
                alert.model_dump_json(),
                alert.timestamp
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving alert: {e}")
