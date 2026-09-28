from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class UserEntity(BaseModel):
    user_id: str
    tenant_id: str = "tenant-corp-acme"
    username: str
    full_name: str
    email: str
    role: str = "Analyst"  # "Global Admin", "SecOps Analyst", "Developer", "HR Specialist", "VIP Executive"
    department: str = "Security"
    privilege_level: str = "STANDARD"  # "STANDARD", "ELEVATED", "DOMAIN_ADMIN", "ROOT"
    mfa_enabled: bool = True
    mfa_method: str = "Hardware Token"  # "Hardware Token", "Authenticator App", "SMS", "None"
    status: str = "ACTIVE"  # "ACTIVE", "SUSPENDED", "LOCKED", "UNDER_INVESTIGATION"
    risk_score: float = 15.0
    known_devices: List[str] = Field(default_factory=list)
    typical_login_hours: List[int] = Field(default_factory=lambda: [9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
    typical_countries: List[str] = Field(default_factory=lambda: ["US"])
    last_login: Optional[str] = None
    created_at: Optional[str] = None

class DeviceEntity(BaseModel):
    device_id: str
    tenant_id: str = "tenant-corp-acme"
    hostname: str
    owner_user_id: str
    os_type: str  # "Windows 11 Enterprise", "macOS Sonoma", "Ubuntu 22.04 LTS"
    ip_address: str
    mac_address: str
    patch_status: str = "COMPLIANT"  # "COMPLIANT", "PENDING_REBOOT", "CRITICAL_MISSING"
    disk_encryption: bool = True
    firewall_active: bool = True
    edr_agent_active: bool = True
    edr_version: str = "2.4.1"
    risk_score: float = 10.0
    status: str = "ACTIVE"  # "ACTIVE", "ISOLATED", "COMPROMISED", "OFFLINE"
    critical_vulnerabilities: int = 0
    last_heartbeat: Optional[str] = None

class ApplicationEntity(BaseModel):
    app_id: str
    name: str
    category: str  # "Identity Provider", "Database", "Source Code", "Cloud Infrastructure", "CRM"
    criticality: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "TIER_0"
    mfa_required: bool = True
    allowed_roles: List[str] = Field(default_factory=list)
    risk_score: float = 10.0

class ExposureItem(BaseModel):
    item_id: str
    tenant_id: str = "tenant-corp-acme"
    category: str  # "CREDENTIAL_LEAK", "CLOUD_EXPOSURE", "OPEN_PORT", "PRIVACY_RISK", "DATA_BROKER"
    title: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    target_entity: str
    details: str
    remediation_steps: str
    status: str = "OPEN"  # "OPEN", "RESOLVED", "IGNORED"
    discovered_at: str
