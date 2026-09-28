import asyncio
from datetime import datetime, timezone
import uuid
from typing import Dict, Any, List
from src.models.events import CommonEvent, EventType, EventAction, Actor, Source, Destination, NetworkDetails, AuthDetails
from src.pipeline.event_bus import event_bus
from src.engines.detection_rules import rule_engine
from src.engines.ueba_engine import ueba_engine
from src.engines.correlation_engine import correlation_engine
from src.engines.risk_engine import risk_engine
from src.database.db import get_connection

class SimulationService:
    async def run_scenario(self, scenario_type: str) -> Dict[str, Any]:
        """
        Executes an interactive attack simulation through the entire real-time pipeline.
        """
        now = datetime.now(timezone.utc)
        events_generated: List[CommonEvent] = []

        if scenario_type == "CREDENTIAL_STUFFING":
            # Stage 1: Brute Force Failed Attempts
            for i in range(5):
                evt = CommonEvent(
                    tenant_id="tenant-corp-acme",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type=EventType.AUTHENTICATION,
                    action=EventAction.FAILED_LOGIN,
                    severity="MEDIUM",
                    actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
                    source=Source(id="dev-external-attacker", hostname="TOR-EXIT-NODE-89", ip="194.26.29.11", country="RO"),
                    destination=Destination(name="Okta Identity Cloud"),
                    network=NetworkDetails(source_ip="194.26.29.11", destination_port=443),
                    authentication=AuthDetails(method="password", mfa_completed=False, failure_reason="BadPassword"),
                    result="failure",
                    raw_source_vendor="OktaSystemLog"
                )
                events_generated.append(evt)

            # Stage 2: Successful Login from new geo
            evt_success = CommonEvent(
                tenant_id="tenant-corp-acme",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=EventType.AUTHENTICATION,
                action=EventAction.LOGIN,
                severity="HIGH",
                actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
                source=Source(id="dev-external-attacker", hostname="TOR-EXIT-NODE-89", ip="194.26.29.11", country="RO"),
                destination=Destination(name="Okta Identity Cloud"),
                network=NetworkDetails(source_ip="194.26.29.11", destination_port=443),
                authentication=AuthDetails(method="password", mfa_completed=True),
                result="success",
                raw_source_vendor="OktaSystemLog"
            )
            events_generated.append(evt_success)

            # Stage 3: High-Value Financial Record Access
            evt_access = CommonEvent(
                tenant_id="tenant-corp-acme",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=EventType.NETWORK,
                action=EventAction.NETWORK_CONNECT,
                severity="HIGH",
                actor=Actor(id="usr-elena-finance", name="Elena Rostova", role="VP of Finance"),
                source=Source(id="dev-external-attacker", ip="194.26.29.11"),
                destination=Destination(name="NetSuite ERP Financial Ledgers"),
                network=NetworkDetails(source_ip="194.26.29.11", destination_port=443, bytes_sent=15000, bytes_received=890000),
                result="success",
                raw_source_vendor="PaloAltoNextGenFW"
            )
            events_generated.append(evt_access)

        elif scenario_type == "RANSOMWARE_DEFENSE":
            # Stage 1: Encoded PowerShell Process
            evt_ps = CommonEvent(
                tenant_id="tenant-corp-acme",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=EventType.ENDPOINT_TELEMETRY,
                action=EventAction.PROCESS_SPAWN,
                severity="HIGH",
                actor=Actor(id="usr-marcus-sec", name="Marcus Vance"),
                source=Source(id="dev-secops-win", hostname="ACME-SOC-WS01", ip="10.20.10.12"),
                metadata={
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
                    "parent_process": "WINWORD.EXE"
                },
                result="success",
                raw_source_vendor="MicrosoftSysmon"
            )
            events_generated.append(evt_ps)

            # Stage 2: Shadow Copy Deletion (vssadmin)
            evt_vss = CommonEvent(
                tenant_id="tenant-corp-acme",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=EventType.ENDPOINT_TELEMETRY,
                action=EventAction.PROCESS_SPAWN,
                severity="CRITICAL",
                actor=Actor(id="usr-marcus-sec", name="Marcus Vance"),
                source=Source(id="dev-secops-win", hostname="ACME-SOC-WS01", ip="10.20.10.12"),
                metadata={
                    "process_name": "vssadmin.exe",
                    "command_line": "vssadmin.exe delete shadows /all /quiet",
                    "parent_process": "powershell.exe"
                },
                result="success",
                raw_source_vendor="MicrosoftSysmon"
            )
            events_generated.append(evt_vss)

        elif scenario_type == "EXFILTRATION":
            # Stage 1: Rapid 1.2 GB Egress Connection
            evt_exfil = CommonEvent(
                tenant_id="tenant-corp-acme",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=EventType.NETWORK,
                action=EventAction.NETWORK_CONNECT,
                severity="CRITICAL",
                actor=Actor(id="usr-alex-dev", name="Alex Mercer"),
                source=Source(id="dev-dev-linux", hostname="ACME-ENG-DEV01", ip="10.20.20.55"),
                destination=Destination(name="MegaUpload / DropPoint C2", ip="45.33.32.156"),
                network=NetworkDetails(
                    source_ip="10.20.20.55",
                    destination_ip="45.33.32.156",
                    destination_port=443,
                    bytes_sent=1280000000  # 1.2 GB
                ),
                result="success",
                raw_source_vendor="PaloAltoNextGenFW"
            )
            events_generated.append(evt_exfil)

        else:
            return {"success": False, "error": f"Unknown scenario {scenario_type}"}

        # Process each simulated event through the complete live engine
        alerts_created = []
        incidents_created = []

        for evt in events_generated:
            # 1. Publish to EventBus (saves to DB and broadcasts over WebSocket)
            await event_bus.publish(evt)

            # 2. Rule evaluation
            rule_alerts = rule_engine.evaluate(evt)
            for ra in rule_alerts:
                self._save_alert(ra)
                alerts_created.append(ra.title)

            # 3. UEBA evaluation
            ueba_alert = ueba_engine.evaluate_behavior(evt)
            if ueba_alert:
                self._save_alert(ueba_alert)
                alerts_created.append(ueba_alert.title)

            # 4. Correlation evaluation
            inc = correlation_engine.track_event(evt)
            if inc:
                incidents_created.append(inc.incident_id)

            # 5. Dynamic Risk update
            if evt.actor and evt.actor.id:
                risk_engine.calculate_user_risk(evt.actor.id, tenant_id=evt.tenant_id)

            await asyncio.sleep(0.15)  # slight pause for smooth stream demonstration

        return {
            "success": True,
            "scenario": scenario_type,
            "events_streamed": len(events_generated),
            "alerts_triggered": alerts_created,
            "incidents_created": incidents_created
        }

    def _save_alert(self, alert):
        try:
            conn = get_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts 
                (alert_id, tenant_id, title, rule_id, severity, category, summary, actor_id, device_id, source_ip, confidence, risk_impact, raw_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.tenant_id,
                    alert.title,
                    alert.rule_id,
                    alert.severity.value,
                    alert.category,
                    alert.summary,
                    alert.actor_id,
                    alert.device_id,
                    alert.source_ip,
                    alert.confidence,
                    alert.risk_impact,
                    alert.model_dump_json(),
                    alert.timestamp
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Simulation] Alert save error: {e}")

simulation_service = SimulationService()
