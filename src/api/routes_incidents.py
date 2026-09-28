from fastapi import APIRouter, Query, HTTPException, Body
from typing import List, Dict, Any, Optional
import json
from src.database.db import get_connection
from src.models.alerts import IncidentStatus
from src.engines.incident_engine import incident_engine

router = APIRouter(prefix="/api/incidents", tags=["Incidents & SOAR"])

@router.get("")
def list_incidents(status: Optional[str] = None, tenant_id: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    incidents = []
    for r in rows:
        data = json.loads(r["raw_json"])
        incidents.append(data)
    return incidents

@router.get("/alerts")
def list_alerts(limit: int = 50, tenant_id: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [json.loads(r["raw_json"]) for r in rows]

@router.get("/{incident_id}")
def get_incident(incident_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_json FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")
    
    inc_data = json.loads(row["raw_json"])
    # Fetch containment actions
    cursor.execute("SELECT raw_json FROM containment_actions WHERE incident_id = ?", (incident_id,))
    act_rows = cursor.fetchall()
    inc_data["containment_actions"] = [json.loads(ar["raw_json"]) for ar in act_rows]
    conn.close()
    return inc_data

@router.post("/{incident_id}/status")
def update_status(incident_id: str, payload: Dict[str, Any] = Body(...)):
    new_status = payload.get("status")
    analyst = payload.get("analyst", "Marcus Vance (SecOps)")
    try:
        st_enum = IncidentStatus(new_status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status {new_status}")

    updated = incident_engine.update_incident_status(incident_id, st_enum, analyst)
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return updated

@router.post("/actions/{action_id}/execute")
def approve_and_execute_action(action_id: str, payload: Dict[str, Any] = Body(...)):
    """
    Authorizes and executes an automated containment action
    """
    analyst = payload.get("approved_by", "Marcus Vance (Lead Analyst)")
    result = incident_engine.execute_containment_action(action_id, analyst)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Execution failed"))
    return result
