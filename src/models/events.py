from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
import uuid

class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    PRIVILEGE = "privilege"
    EXPOSURE = "exposure"
    VULNERABILITY = "vulnerability"
    ENDPOINT_TELEMETRY = "endpoint_telemetry"

class EventAction(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    PRIVILEGE_ESCALATE = "privilege_escalate"
    NETWORK_CONNECT = "network_connect"
    PROCESS_SPAWN = "process_spawn"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    CREDENTIAL_EXPOSED = "credential_exposed"
    PORT_SCAN = "port_scan"
    POLICY_VIOLATION = "policy_violation"

class Actor(BaseModel):
    type: str = "user"  # "user", "service_account", "system", "attacker"
    id: str
    name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None

class Source(BaseModel):
    type: str = "device"  # "device", "ip", "external"
    id: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    os: Optional[str] = None

class Destination(BaseModel):
    type: str = "application"  # "application", "server", "cloud_resource", "ip"
    id: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    resource_type: Optional[str] = None

class NetworkDetails(BaseModel):
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    bytes_sent: Optional[int] = 0
    bytes_received: Optional[int] = 0

class AuthDetails(BaseModel):
    method: Optional[str] = "password"  # "password", "mfa_push", "sso", "kerberos", "ssh_key"
    mfa_completed: bool = False
    failure_reason: Optional[str] = None

class CommonEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "tenant-corp-acme"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: EventType
    action: EventAction
    severity: str = "LOW"  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    actor: Actor
    source: Source
    destination: Optional[Destination] = None
    network: Optional[NetworkDetails] = None
    authentication: Optional[AuthDetails] = None
    result: str = "success"  # "success", "failure", "blocked", "challenge"
    raw_source_vendor: str = "AetherisCollector"  # "WindowsSecurity", "AWSCloudTrail", "Sysmon", "PaloAltoFirewall"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    normalized: bool = True
