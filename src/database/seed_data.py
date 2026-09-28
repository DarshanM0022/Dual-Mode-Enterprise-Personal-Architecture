import json
from datetime import datetime, timezone, timedelta
import uuid
from src.database.db import get_connection, init_db
from src.models.events import CommonEvent, EventType, EventAction, Actor, Source, Destination, NetworkDetails, AuthDetails
from src.models.entities import UserEntity, DeviceEntity, ApplicationEntity, ExposureItem
from src.models.alerts import Alert, AlertSeverity, Incident, IncidentStatus, ContainmentAction, ActionType, ActionStatus
from src.models.risk import EntityRiskProfile, RiskDriver

def seed_database():
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    # Check if already seeded
    cursor.execute("SELECT COUNT(*) FROM entities_user")
    if cursor.fetchone()[0] > 0:
        conn.close()
        return

    now = datetime.now(timezone.utc)

    # 1. USERS
    users = [
        UserEntity(
            user_id="usr-sarah-ciso",
            tenant_id="tenant-corp-acme",
            username="sarah.chen",
            full_name="Sarah Chen",
            email="sarah.chen@acmecorp.internal",
            role="Chief Information Security Officer",
            department="Executive",
            privilege_level="VIP Executive",
            mfa_enabled=True,
            mfa_method="Hardware Token (YubiKey)",
            status="ACTIVE",
            risk_score=12.0,
            known_devices=["dev-ciso-mac"],
            typical_countries=["US"],
            last_login=(now - timedelta(hours=2)).isoformat()
        ),
        UserEntity(
            user_id="usr-marcus-sec",
            tenant_id="tenant-corp-acme",
            username="marcus.vance",
            full_name="Marcus Vance",
            email="m.vance@acmecorp.internal",
            role="Lead SecOps Analyst",
            department="Security Operations",
            privilege_level="DOMAIN_ADMIN",
            mfa_enabled=True,
            mfa_method="Hardware Token (YubiKey)",
            status="ACTIVE",
            risk_score=18.0,
            known_devices=["dev-secops-win"],
            typical_countries=["US"],
            last_login=(now - timedelta(minutes=25)).isoformat()
        ),
        UserEntity(
            user_id="usr-elena-finance",
            tenant_id="tenant-corp-acme",
            username="elena.rostova",
            full_name="Elena Rostova",
            email="e.rostova@acmecorp.internal",
            role="VP of Finance",
            department="Finance",
            privilege_level="VIP Executive",
            mfa_enabled=True,
            mfa_method="SMS (Vulnerable)",
            status="UNDER_INVESTIGATION",
            risk_score=78.0,
            known_devices=["dev-elena-win"],
            typical_countries=["US"],
            last_login=(now - timedelta(minutes=5)).isoformat()
        ),
        UserEntity(
            user_id="usr-alex-dev",
            tenant_id="tenant-corp-acme",
            username="alex.mercer",
            full_name="Alex Mercer",
            email="a.mercer@acmecorp.internal",
            role="Senior Platform Architect",
            department="Engineering",
            privilege_level="ELEVATED",
            mfa_enabled=True,
            mfa_method="Authenticator App",
            status="ACTIVE",
            risk_score=32.0,
            known_devices=["dev-dev-linux"],
            typical_countries=["US", "CA"],
            last_login=(now - timedelta(hours=4)).isoformat()
        ),
        # Personal mode user
        UserEntity(
            user_id="usr-darsh-personal",
            tenant_id="tenant-personal-darsh",
            username="darsh.user",
            full_name="Darsh Sharma",
            email="darsh.personal@mail.net",
            role="Personal Identity",
            department="Home",
            privilege_level="STANDARD",
            mfa_enabled=True,
            mfa_method="Authenticator App",
            status="ACTIVE",
            risk_score=22.0,
            known_devices=["dev-personal-iphone", "dev-personal-laptop"],
            typical_countries=["IN"],
            last_login=(now - timedelta(minutes=10)).isoformat()
        )
    ]

    for u in users:
        cursor.execute(
            "INSERT INTO entities_user VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (u.user_id, u.tenant_id, u.username, u.full_name, u.email, u.role, u.department,
             u.privilege_level, 1 if u.mfa_enabled else 0, u.status, u.risk_score, u.model_dump_json())
        )

    # 2. DEVICES
    devices = [
        DeviceEntity(
            device_id="dev-ciso-mac",
            tenant_id="tenant-corp-acme",
            hostname="ACME-CISO-MBP16",
            owner_user_id="usr-sarah-ciso",
            os_type="macOS Sonoma 14.4",
            ip_address="10.20.10.45",
            mac_address="3C:22:FB:45:90:11",
            patch_status="COMPLIANT",
            disk_encryption=True,
            firewall_active=True,
            edr_agent_active=True,
            risk_score=10.0,
            status="ACTIVE",
            last_heartbeat=now.isoformat()
        ),
        DeviceEntity(
            device_id="dev-secops-win",
            tenant_id="tenant-corp-acme",
            hostname="ACME-SOC-WS01",
            owner_user_id="usr-marcus-sec",
            os_type="Windows 11 Enterprise (23H2)",
            ip_address="10.20.10.12",
            mac_address="A4:BB:6D:88:21:40",
            patch_status="COMPLIANT",
            disk_encryption=True,
            firewall_active=True,
            edr_agent_active=True,
            risk_score=12.0,
            status="ACTIVE",
            last_heartbeat=now.isoformat()
        ),
        DeviceEntity(
            device_id="dev-elena-win",
            tenant_id="tenant-corp-acme",
            hostname="ACME-FIN-LAT9440",
            owner_user_id="usr-elena-finance",
            os_type="Windows 11 Enterprise (22H2)",
            ip_address="10.20.40.89",
            mac_address="88:A4:C2:55:71:02",
            patch_status="CRITICAL_MISSING",
            disk_encryption=True,
            firewall_active=True,
            edr_agent_active=True,
            risk_score=76.0,
            status="ACTIVE",
            critical_vulnerabilities=2,
            last_heartbeat=(now - timedelta(minutes=3)).isoformat()
        ),
        DeviceEntity(
            device_id="dev-rogue-external",
            tenant_id="tenant-corp-acme",
            hostname="UNKNOWN-HOST-X99",
            owner_user_id="usr-elena-finance",
            os_type="Kali Linux 2024.1",
            ip_address="185.220.101.44",
            mac_address="00:15:5D:89:C3:A1",
            patch_status="CRITICAL_MISSING",
            disk_encryption=False,
            firewall_active=False,
            edr_agent_active=False,
            risk_score=94.0,
            status="COMPROMISED",
            critical_vulnerabilities=7,
            last_heartbeat=(now - timedelta(minutes=4)).isoformat()
        ),
        # Personal devices
        DeviceEntity(
            device_id="dev-personal-iphone",
            tenant_id="tenant-personal-darsh",
            hostname="Darsh-iPhone15Pro",
            owner_user_id="usr-darsh-personal",
            os_type="iOS 17.5.1",
            ip_address="192.168.1.104",
            mac_address="70:3E:AC:12:34:56",
            patch_status="COMPLIANT",
            disk_encryption=True,
            firewall_active=True,
            edr_agent_active=True,
            risk_score=14.0,
            status="ACTIVE",
            last_heartbeat=now.isoformat()
        ),
        DeviceEntity(
            device_id="dev-personal-laptop",
            tenant_id="tenant-personal-darsh",
            hostname="DARSH-LEGION-PRO",
            owner_user_id="usr-darsh-personal",
            os_type="Windows 11 Pro",
            ip_address="192.168.1.105",
            mac_address="B0:4E:26:77:88:99",
            patch_status="PENDING_REBOOT",
            disk_encryption=True,
            firewall_active=True,
            edr_agent_active=True,
            risk_score=26.0,
            status="ACTIVE",
            last_heartbeat=now.isoformat()
        )
    ]

    for d in devices:
        cursor.execute(
            "INSERT INTO entities_device VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (d.device_id, d.tenant_id, d.hostname, d.owner_user_id, d.os_type, d.ip_address,
             d.patch_status, 1 if d.disk_encryption else 0, 1 if d.firewall_active else 0,
             1 if d.edr_agent_active else 0, d.risk_score, d.status, d.model_dump_json())
        )

    # 3. APPLICATIONS
    apps = [
        ApplicationEntity(app_id="app-okta-idp", name="Okta Identity Cloud", category="Identity Provider", criticality="TIER_0", mfa_required=True, risk_score=15.0),
        ApplicationEntity(app_id="app-aws-prod", name="AWS GovCloud Production", category="Cloud Infrastructure", criticality="TIER_0", mfa_required=True, risk_score=25.0),
        ApplicationEntity(app_id="app-vault", name="HashiCorp Vault Secrets", category="Secrets Management", criticality="TIER_0", mfa_required=True, risk_score=20.0),
        ApplicationEntity(app_id="app-github-ent", name="GitHub Enterprise Cloud", category="Source Code", criticality="HIGH", mfa_required=True, risk_score=15.0),
        ApplicationEntity(app_id="app-netsuite", name="NetSuite Enterprise ERP", category="Finance / ERP", criticality="TIER_0", mfa_required=True, risk_score=35.0),
    ]

    for a in apps:
        cursor.execute(
            "INSERT INTO entities_app VALUES (?, ?, ?, ?, ?, ?, ?)",
            (a.app_id, a.name, a.category, a.criticality, 1 if a.mfa_required else 0, a.risk_score, a.model_dump_json())
        )

    # 4. EXPOSURES
    exposures = [
        ExposureItem(
            item_id="exp-ent-01",
            tenant_id="tenant-corp-acme",
            category="CLOUD_EXPOSURE",
            title="Publicly Readable S3 Bucket Containing CloudTrail Backups",
            severity="HIGH",
            target_entity="s3://acme-audit-logs-backup-2025",
            details="AWS S3 bucket policy allows GetObject actions from Principal '*' without IP condition enforcement.",
            remediation_steps="Apply AWS S3 Block Public Access at the account level and restrict bucket policy to the SecOps IAM role.",
            status="OPEN",
            discovered_at=(now - timedelta(hours=6)).isoformat()
        ),
        ExposureItem(
            item_id="exp-ent-02",
            tenant_id="tenant-corp-acme",
            category="CREDENTIAL_LEAK",
            title="Production GitHub Token Found in Public Pastebin Dump",
            severity="CRITICAL",
            target_entity="token:ghp_98a7sd********************",
            details="Automated dark web scanner discovered an active fine-grained GitHub PAT with read/write access to acme-core repos.",
            remediation_steps="Immediately revoke token ghp_98a7sd... in GitHub Org settings, inspect audit log for cloned repos, and rotate credentials.",
            status="OPEN",
            discovered_at=(now - timedelta(hours=2)).isoformat()
        ),
        ExposureItem(
            item_id="exp-ent-03",
            tenant_id="tenant-corp-acme",
            category="OPEN_PORT",
            title="Exposed Management Port 3389 (RDP) on Edge Gateway",
            severity="MEDIUM",
            target_entity="gateway-ext.acmecorp.com:3389",
            details="Direct Remote Desktop Protocol listener discovered exposed without VPN or Zero-Trust bastion gateway.",
            remediation_steps="Disable direct public RDP. Route administrative ingress through Cloudflare Access or wireguard mesh.",
            status="OPEN",
            discovered_at=(now - timedelta(days=1)).isoformat()
        ),
        # Personal Mode exposures
        ExposureItem(
            item_id="exp-pers-01",
            tenant_id="tenant-personal-darsh",
            category="CREDENTIAL_LEAK",
            title="Master Password Exposed in Breached Combo-List",
            severity="HIGH",
            target_entity="darsh.personal@mail.net",
            details="Password hash found in compilation breach leak with 12,000 other compromised accounts.",
            remediation_steps="Change master password immediately, enable Passkey/Hardware 2FA on primary email and banking accounts.",
            status="OPEN",
            discovered_at=(now - timedelta(days=2)).isoformat()
        ),
        ExposureItem(
            item_id="exp-pers-02",
            tenant_id="tenant-personal-darsh",
            category="PRIVACY_RISK",
            title="Third-Party Quiz App Retains Full Google Drive Read Access",
            severity="MEDIUM",
            target_entity="OAuth Grant: 'MindTest Quiz App'",
            details="Application requested and holds 'https://www.googleapis.com/auth/drive.readonly' permission.",
            remediation_steps="Revoke OAuth access in Google Account Security Settings -> Third-party apps with account access.",
            status="OPEN",
            discovered_at=(now - timedelta(days=5)).isoformat()
        )
    ]

    for exp in exposures:
        cursor.execute(
            "INSERT INTO exposures VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (exp.item_id, exp.tenant_id, exp.category, exp.title, exp.severity,
             exp.target_entity, exp.details, exp.remediation_steps, exp.status, exp.discovered_at)
        )

    # 5. RISK PROFILES
    elena_risk = EntityRiskProfile(
        entity_id="usr-elena-finance",
        entity_type="USER",
        tenant_id="tenant-corp-acme",
        overall_risk=78.0,
        risk_level="HIGH",
        identity_subscore=82.0,
        device_subscore=76.0,
        behavior_subscore=84.0,
        threat_subscore=90.0,
        exposure_subscore=65.0,
        confidence_multiplier=0.95,
        primary_drivers=[
            RiskDriver(
                category="IDENTITY",
                factor="Impossible Travel Anomaly",
                impact_points=35.0,
                evidence="User authenticated from New York (IP 108.35.12.9) and 14 minutes later from Moscow (IP 185.220.101.44) (Velocity: 4,800 mph)."
            ),
            RiskDriver(
                category="DEVICE",
                factor="Unrecognized Endpoint & Missing EDR",
                impact_points=25.0,
                evidence="Authentication initiated from UNKNOWN-HOST-X99 running Kali Linux without company certificate."
            ),
            RiskDriver(
                category="BEHAVIOR",
                factor="Off-Hours Privileged Financial Record Access",
                impact_points=18.0,
                evidence="Session initiated at 03:17 UTC (deviates 3.4 standard deviations from regular business hours)."
            )
        ],
        plain_english_explanation="Risk increased from 24 -> 78 because an unmanaged external device successfully authenticated via SMS MFA outside normal working hours, followed by an impossible geographical displacement from New York to Moscow, and immediate access to sensitive NetSuite financial ledgers.",
        recommended_mitigations=[
            "Revoke all active user sessions for Elena Rostova across Okta and Azure.",
            "Enforce hardware-bound FIDO2 YubiKey requirement on the account.",
            "Isolate unknown device 185.220.101.44 at perimeter firewall."
        ]
    )

    cursor.execute(
        "INSERT INTO risk_profiles VALUES (?, ?, ?, ?, ?, ?, ?)",
        (elena_risk.entity_id, elena_risk.entity_type, elena_risk.tenant_id, elena_risk.overall_risk,
         elena_risk.risk_level, elena_risk.model_dump_json(), elena_risk.last_updated)
    )

    # 6. ALERTS
    alert_1 = Alert(
        alert_id="ALT-GEO-8812",
        tenant_id="tenant-corp-acme",
        title="Impossible Travel Velocity Detected",
        rule_id="RULE-IDP-004",
        severity=AlertSeverity.HIGH,
        category="IDENTITY",
        summary="Elena Rostova logged in from New York, then 14 minutes later from Moscow.",
        actor_id="usr-elena-finance",
        device_id="dev-rogue-external",
        source_ip="185.220.101.44",
        confidence=0.98,
        risk_impact=35.0,
        timestamp=(now - timedelta(minutes=14)).isoformat()
    )

    alert_2 = Alert(
        alert_id="ALT-DEV-9021",
        tenant_id="tenant-corp-acme",
        title="Unmanaged & Unverified Device Authentication",
        rule_id="RULE-DEV-009",
        severity=AlertSeverity.MEDIUM,
        category="DEVICE",
        summary="Authentication request originated from unmanaged Linux device with missing corporate certificate.",
        actor_id="usr-elena-finance",
        device_id="dev-rogue-external",
        source_ip="185.220.101.44",
        confidence=0.92,
        risk_impact=20.0,
        timestamp=(now - timedelta(minutes=13)).isoformat()
    )

    alert_3 = Alert(
        alert_id="ALT-BEH-3341",
        tenant_id="tenant-corp-acme",
        title="Abnormal Batch Data Download from NetSuite",
        rule_id="RULE-UEBA-012",
        severity=AlertSeverity.CRITICAL,
        category="ANOMALY",
        summary="Download volume 4.8 GB exceeds 30-day baseline average (12 MB) by 400x.",
        actor_id="usr-elena-finance",
        device_id="dev-rogue-external",
        source_ip="185.220.101.44",
        confidence=0.95,
        risk_impact=40.0,
        timestamp=(now - timedelta(minutes=8)).isoformat()
    )

    for alt in [alert_1, alert_2, alert_3]:
        cursor.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alt.alert_id, alt.tenant_id, alt.title, alt.rule_id, alt.severity.value,
             alt.category, alt.summary, alt.actor_id, alt.device_id, alt.source_ip,
             alt.confidence, alt.risk_impact, alt.model_dump_json(), alt.timestamp)
        )

    # 7. INCIDENTS & CONTAINMENT ACTIONS
    act_1 = ContainmentAction(
        action_id="ACT-REV-101",
        incident_id="INC-CRIT-901",
        action_type=ActionType.REVOKE_SESSION,
        target_entity_type="USER",
        target_entity_id="usr-elena-finance",
        description="Invalidate all active OAuth refresh tokens and Okta sessions for Elena Rostova.",
        status=ActionStatus.PENDING_APPROVAL,
        requested_by="AI Security Copilot",
        requires_human_approval=True,
        impact_level="MEDIUM"
    )

    act_2 = ContainmentAction(
        action_id="ACT-ISO-102",
        incident_id="INC-CRIT-901",
        action_type=ActionType.BLOCK_IP,
        target_entity_type="IP",
        target_entity_id="185.220.101.44",
        description="Push firewall block rule to drop all ingress and egress packets for IP 185.220.101.44.",
        status=ActionStatus.PENDING_APPROVAL,
        requested_by="AI Security Copilot",
        requires_human_approval=True,
        impact_level="HIGH"
    )

    inc_1 = Incident(
        incident_id="INC-CRIT-901",
        tenant_id="tenant-corp-acme",
        title="Multi-Stage VIP Account Takeover & Rapid Exfiltration",
        severity=AlertSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        lead_analyst="marcus.vance",
        created_at=(now - timedelta(minutes=15)).isoformat(),
        updated_at=now.isoformat(),
        affected_entities=[
            {"type": "USER", "id": "usr-elena-finance", "name": "Elena Rostova"},
            {"type": "DEVICE", "id": "dev-rogue-external", "name": "UNKNOWN-HOST-X99"},
            {"type": "IP", "id": "185.220.101.44", "name": "External TOR Exit / C2 IP"},
            {"type": "APPLICATION", "id": "app-netsuite", "name": "NetSuite Enterprise ERP"}
        ],
        associated_alert_ids=["ALT-GEO-8812", "ALT-DEV-9021", "ALT-BEH-3341"],
        timeline=[
            {"time": (now - timedelta(minutes=14)).isoformat(), "event": "Impossible travel alert: US to Moscow login within 14m"},
            {"time": (now - timedelta(minutes=13)).isoformat(), "event": "Unenrolled Linux device completed SMS MFA challenge"},
            {"time": (now - timedelta(minutes=10)).isoformat(), "event": "Session accessed high-criticality NetSuite ERP customer invoices"},
            {"time": (now - timedelta(minutes=8)).isoformat(), "event": "Data export triggered: 4.8 GB encrypted archive stream started"}
        ],
        mitre_tactics=["Initial Access (T1078.004)", "Defense Evasion (T1556)", "Collection (T1560)", "Exfiltration (T1048)"],
        blast_radius_score=68.5,
        ai_summary="High-confidence account takeover targeting VP of Finance. An attacker obtained credentials and bypassed SMS 2FA from a rogue IP address (185.220.101.44), established an unauthorized session, and extracted financial records. Two automated containment actions have been queued and are awaiting analyst sign-off.",
        ai_recommendations=[
            "Authorize ACT-REV-101 immediately to kill active session tokens.",
            "Authorize ACT-ISO-102 to block attacker IP on perimeter firewalls.",
            "Temporarily lock account Elena Rostova and verify identity out-of-band via phone/Slack.",
            "Initiate forensic audit on NetSuite export access logs to ascertain exact data exposure."
        ],
        containment_actions=[act_1, act_2]
    )

    cursor.execute(
        "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (inc_1.incident_id, inc_1.tenant_id, inc_1.title, inc_1.severity.value,
         inc_1.status.value, inc_1.lead_analyst, inc_1.blast_radius_score,
         inc_1.model_dump_json(), inc_1.created_at, inc_1.updated_at)
    )

    for act in [act_1, act_2]:
        cursor.execute(
            "INSERT INTO containment_actions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (act.action_id, act.incident_id, act.action_type.value, act.target_entity_type,
             act.target_entity_id, act.description, act.status.value, act.requested_by,
             act.approved_by, act.executed_at, act.model_dump_json())
        )

    # 8. EVENTS (Realistic SIEM events)
    events_data = [
        CommonEvent(
            event_id="EVT-10001",
            tenant_id="tenant-corp-acme",
            timestamp=(now - timedelta(minutes=15)).isoformat(),
            event_type=EventType.AUTHENTICATION,
            action=EventAction.LOGIN,
            severity="LOW",
            actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
            source=Source(id="dev-elena-win", hostname="ACME-FIN-LAT9440", ip="108.35.12.9", country="US", city="New York"),
            destination=Destination(id="app-okta-idp", name="Okta Identity Cloud"),
            network=NetworkDetails(source_ip="108.35.12.9", destination_ip="52.84.14.88", destination_port=443),
            authentication=AuthDetails(method="sso", mfa_completed=True),
            result="success",
            raw_source_vendor="OktaSystemLog"
        ),
        CommonEvent(
            event_id="EVT-10002",
            tenant_id="tenant-corp-acme",
            timestamp=(now - timedelta(minutes=14)).isoformat(),
            event_type=EventType.AUTHENTICATION,
            action=EventAction.LOGIN,
            severity="HIGH",
            actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
            source=Source(id="dev-rogue-external", hostname="UNKNOWN-HOST-X99", ip="185.220.101.44", country="RU", city="Moscow"),
            destination=Destination(id="app-okta-idp", name="Okta Identity Cloud"),
            network=NetworkDetails(source_ip="185.220.101.44", destination_ip="52.84.14.88", destination_port=443),
            authentication=AuthDetails(method="password", mfa_completed=True),
            result="success",
            raw_source_vendor="OktaSystemLog"
        ),
        CommonEvent(
            event_id="EVT-10003",
            tenant_id="tenant-corp-acme",
            timestamp=(now - timedelta(minutes=10)).isoformat(),
            event_type=EventType.NETWORK,
            action=EventAction.NETWORK_CONNECT,
            severity="MEDIUM",
            actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
            source=Source(id="dev-rogue-external", hostname="UNKNOWN-HOST-X99", ip="185.220.101.44"),
            destination=Destination(id="app-netsuite", name="NetSuite Enterprise ERP", ip="199.19.12.50", port=443),
            network=NetworkDetails(source_ip="185.220.101.44", destination_ip="199.19.12.50", destination_port=443, bytes_sent=12000, bytes_received=850000),
            result="success",
            raw_source_vendor="PaloAltoNextGenFW"
        ),
        CommonEvent(
            event_id="EVT-10004",
            tenant_id="tenant-corp-acme",
            timestamp=(now - timedelta(minutes=8)).isoformat(),
            event_type=EventType.FILE,
            action=EventAction.FILE_MODIFY,
            severity="CRITICAL",
            actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
            source=Source(id="dev-rogue-external", hostname="UNKNOWN-HOST-X99", ip="185.220.101.44"),
            destination=Destination(id="app-netsuite", name="CustomerLedgers_2025_Q3.enc"),
            network=NetworkDetails(source_ip="185.220.101.44", destination_ip="185.220.101.44", bytes_sent=4800000000),
            result="success",
            raw_source_vendor="NetSuiteAuditTrail",
            metadata={"file_size_bytes": 4800000000, "operation": "BULK_EXPORT"}
        ),
        CommonEvent(
            event_id="EVT-10005",
            tenant_id="tenant-corp-acme",
            timestamp=(now - timedelta(minutes=5)).isoformat(),
            event_type=EventType.ENDPOINT_TELEMETRY,
            action=EventAction.PROCESS_SPAWN,
            severity="LOW",
            actor=Actor(id="usr-marcus-sec", name="Marcus Vance", role="Lead SecOps Analyst"),
            source=Source(id="dev-secops-win", hostname="ACME-SOC-WS01", ip="10.20.10.12"),
            metadata={"process_name": "chrome.exe", "command_line": "chrome.exe --profile-directory=Default", "parent_pid": 4120},
            result="success",
            raw_source_vendor="MicrosoftSysmon"
        )
    ]

    for ev in events_data:
        cursor.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev.event_id, ev.tenant_id, ev.timestamp, ev.event_type.value, ev.action.value,
             ev.severity, ev.actor.id, ev.actor.name, ev.source.id if ev.source else None,
             ev.source.ip if ev.source else None, ev.destination.name if ev.destination else None,
             ev.result, ev.raw_source_vendor, ev.model_dump_json())
        )

    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_database()
    print("Database successfully initialized and seeded with enterprise and personal datasets.")
