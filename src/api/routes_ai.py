from fastapi import APIRouter, Body, HTTPException
from typing import Dict, Any
from src.services.ai_copilot import ai_copilot

router = APIRouter(prefix="/api/ai", tags=["AI Copilot"])

@router.post("/query")
def ask_copilot(payload: Dict[str, Any] = Body(...)):
    prompt = payload.get("prompt", "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    user_role = payload.get("role", "SecOps Analyst")
    tenant_id = payload.get("tenant_id", "tenant-corp-acme")

    response = ai_copilot.process_query(prompt, user_role=user_role, tenant_id=tenant_id)
    return response
