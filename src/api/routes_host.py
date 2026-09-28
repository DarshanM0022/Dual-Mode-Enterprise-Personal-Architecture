from fastapi import APIRouter
from typing import Dict, Any
from src.services.live_host_collector import live_collector

router = APIRouter(prefix="/api/host", tags=["Real Host Telemetry"])

@router.post("/audit")
async def run_live_host_audit():
    """
    Executes a real-time live security scan of the actual host machine,
    auditing Windows Defender, listening ports, active processes, and event logs.
    """
    result = await live_collector.run_full_host_audit_and_ingest()
    return result

@router.get("/status")
def get_host_summary():
    """
    Returns high-level metadata about the physical host environment.
    """
    return {
        "hostname": live_collector.hostname,
        "username": live_collector.username,
        "device_id": live_collector.get_host_device_id()
    }
