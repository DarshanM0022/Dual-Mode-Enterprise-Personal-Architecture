from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid

class AlertSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    CLOSED = "CLOSED"

class ActionType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    REVOKE_SESSION = "REVOKE_SESSION"
    ENFORCE_MFA = "ENFORCE_MFA"
    BLOCK_IP = "BLOCK_IP"
    KILL_PROCESS = "KILL_PROCESS"
    PASSWORD_RESET = "PASSWORD_RESET"

class ActionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"

class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    tenant_id: str = "tenant-corp-acme"
    title: str
    rule_id: str
    severity: AlertSeverity
    category: str  # "IDENTITY", "MALWARE", "ANOMALY", "NETWORK", "EXFILTRATION", "EXPOSURE"
    summary: str
    actor_id: Optional[str] = None
    device_id: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    related_event_ids: List[str] = Field(default_factory=list)
    confidence: float = 0.85
    risk_impact: float = 25.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ContainmentAction(BaseModel):
    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    action_type: ActionType
    target_entity_type: str  # "DEVICE", "USER", "IP", "PROCESS"
    target_entity_id: str
    description: str
    status: ActionStatus = ActionStatus.PENDING_APPROVAL
    requested_by: str = "AI Security Copilot"
    approved_by: Optional[str] = None
    executed_at: Optional[str] = None
    requires_human_approval: bool = True
    impact_level: str = "HIGH"  # "LOW", "MEDIUM", "HIGH"

class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    tenant_id: str = "tenant-corp-acme"
    title: str
    severity: AlertSeverity
    status: IncidentStatus = IncidentStatus.NEW
    lead_analyst: str = "Unassigned"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    affected_entities: List[Dict[str, str]] = Field(default_factory=list)  # [{"type": "USER", "id": "u1"}, ...]
    associated_alert_ids: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)  # ["Initial Access", "Privilege Escalation", "Exfiltration"]
    blast_radius_score: float = 30.0
    ai_summary: Optional[str] = None
    ai_recommendations: List[str] = Field(default_factory=list)
    containment_actions: List[ContainmentAction] = Field(default_factory=list)
