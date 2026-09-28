from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Any, Optional
import json
from src.database.db import get_connection
from src.services.identity_service import identity_service
from src.services.device_service import device_service
from src.services.exposure_service import exposure_service

router = APIRouter(prefix="/api/entities", tags=["Entities"])

@router.get("/users")
def list_users(tenant_id: Optional[str] = None):
    return identity_service.get_identities(tenant_id)

@router.get("/users/{user_id}")
def get_user(user_id: str):
    user = identity_service.get_identity_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/devices")
def list_devices(tenant_id: Optional[str] = None):
    return device_service.get_devices(tenant_id)

@router.get("/devices/{device_id}")
def get_device(device_id: str):
    device = device_service.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@router.get("/exposures")
def list_exposures(tenant_id: Optional[str] = None):
    return exposure_service.get_exposures(tenant_id)

@router.post("/exposures/{item_id}/resolve")
def resolve_exposure(item_id: str):
    success = exposure_service.resolve_exposure(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Exposure item not found")
    return {"status": "RESOLVED", "item_id": item_id}
