from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class RiskDriver(BaseModel):
    category: str  # "IDENTITY", "DEVICE", "BEHAVIOR", "THREAT_INTEL", "EXPOSURE"
    factor: str
    impact_points: float
    evidence: str

class EntityRiskProfile(BaseModel):
    entity_id: str
    entity_type: str  # "USER", "DEVICE", "APPLICATION", "ORGANIZATION"
    tenant_id: str = "tenant-corp-acme"
    overall_risk: float = 0.0  # 0 to 100
    risk_level: str = "LOW"    # "LOW" (0-39), "MEDIUM" (40-69), "HIGH" (70-89), "CRITICAL" (90-100)
    identity_subscore: float = 0.0
    device_subscore: float = 0.0
    behavior_subscore: float = 0.0
    threat_subscore: float = 0.0
    exposure_subscore: float = 0.0
    confidence_multiplier: float = 1.0
    primary_drivers: List[RiskDriver] = Field(default_factory=list)
    plain_english_explanation: str = "Entity behavior is within expected baseline boundaries."
    recommended_mitigations: List[str] = Field(default_factory=list)
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class PostureMetrics(BaseModel):
    overall_security_score: float = 84.0  # 0-100
    identity_hygiene: float = 88.0
    endpoint_compliance: float = 91.0
    cloud_exposure_score: float = 78.0
    mean_time_to_detect_mins: float = 4.2
    mean_time_to_respond_mins: float = 12.8
    total_events_processed: int = 158200
    active_incidents_count: int = 2
    critical_alerts_last_24h: int = 4
