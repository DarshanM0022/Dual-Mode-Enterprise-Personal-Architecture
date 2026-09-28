from fastapi import APIRouter, HTTPException, Path
from typing import Dict, Any
from src.services.simulation_service import simulation_service

router = APIRouter(prefix="/api/simulations", tags=["Simulations"])

@router.post("/run/{scenario_type}")
async def run_scenario(scenario_type: str = Path(...)):
    """
    Triggers a live multi-stage attack scenario through the ingestion, detection,
    risk calculation, and incident creation pipeline.
    """
    valid_scenarios = ["CREDENTIAL_STUFFING", "RANSOMWARE_DEFENSE", "EXFILTRATION"]
    if scenario_type not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario. Choose from: {', '.join(valid_scenarios)}"
        )

    result = await simulation_service.run_scenario(scenario_type)
    return result
