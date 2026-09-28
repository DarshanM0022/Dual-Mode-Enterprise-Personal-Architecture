from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from src.models.events import CommonEvent, EventType, EventAction
from src.models.alerts import Alert, AlertSeverity, Incident, IncidentStatus, ContainmentAction, ActionType, ActionStatus
from src.database.db import get_connection

class StatefulCorrelationEngine:
    def __init__(self, window_seconds: int = 900):
        self.window_seconds = window_seconds
        # Entity-keyed event chain: entity_id -> list of event records
        self.entity_chains: Dict[str, List[Dict[str, Any]]] = {}

    def track_event(self, event: CommonEvent) -> Optional[Incident]:
        """
        Maintains an entity-centric attack trajectory and triggers an Incident
        when multi-stage kill-chain progression is observed.
        """
        entity_key = event.actor.id if event.actor and event.actor.id else (event.source.ip if event.source else None)
        if not entity_key:
            return None

        event_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        
        if entity_key not in self.entity_chains:
            self.entity_chains[entity_key] = []

        # Prune events outside window
        self.entity_chains[entity_key] = [
            e for e in self.entity_chains[entity_key] 
            if (event_time - e["time"]).total_seconds() <= self.window_seconds
        ]

        # Record this event in the trajectory
        self.entity_chains[entity_key].append({
            "event_id": event.event_id,
            "time": event_time,
            "type": event.event_type,
            "action": event.action,
            "severity": event.severity,
            "summary": f"{event.action.value} on {event.destination.name if event.destination else (event.source.hostname if event.source else 'unknown')}",
            "device": event.source.hostname if event.source else None,
            "ip": event.source.ip if event.source else None
        })

        # Check for multi-stage Kill Chain:
        # Stage 1: Auth (failed or impossible)
        # Stage 2: Access/Network to sensitive asset
        # Stage 3: High-impact file/process activity
        chain = self.entity_chains[entity_key]
        has_auth = any(e["type"] == EventType.AUTHENTICATION for e in chain)
        has_network_or_access = any(e["type"] in [EventType.NETWORK, EventType.PRIVILEGE] for e in chain)
        has_file_or_exfil = any(e["type"] in [EventType.FILE, EventType.PROCESS, EventType.EXPOSURE] or e["severity"] in ["HIGH", "CRITICAL"] for e in chain)

        if len(chain) >= 3 and has_auth and (has_network_or_access or has_file_or_exfil):
            # We have a correlated multi-stage attack incident!
            return self._synthesize_incident(entity_key, chain, event)

        return None

    def _synthesize_incident(self, entity_key: str, chain: List[Dict[str, Any]], triggering_event: CommonEvent) -> Incident:
        now = datetime.now(timezone.utc)
        timeline = [
            {"time": e["time"].isoformat(), "event": e["summary"]}
            for e in chain
        ]

        act_revoke = ContainmentAction(
            incident_id="",
            action_type=ActionType.REVOKE_SESSION,
            target_entity_type="USER",
            target_entity_id=entity_key,
            description=f"Revoke all active sessions and refresh tokens for {entity_key}",
            status=ActionStatus.PENDING_APPROVAL,
            requires_human_approval=True,
            impact_level="HIGH"
        )
        
        act_isolate = ContainmentAction(
            incident_id="",
            action_type=ActionType.ISOLATE_HOST,
            target_entity_type="DEVICE",
            target_entity_id=triggering_event.source.id or "device-unknown",
            description=f"Network isolation of host {triggering_event.source.hostname or triggering_event.source.ip}",
            status=ActionStatus.PENDING_APPROVAL,
            requires_human_approval=True,
            impact_level="HIGH"
        )

        incident = Incident(
            tenant_id=triggering_event.tenant_id,
            title=f"Coordinated Multi-Stage Attack Pattern Detected: {entity_key}",
            severity=AlertSeverity.CRITICAL if any(e["severity"] == "CRITICAL" for e in chain) else AlertSeverity.HIGH,
            status=IncidentStatus.NEW,
            lead_analyst="SecOps Automation",
            affected_entities=[
                {"type": "USER", "id": entity_key, "name": entity_key},
                {"type": "DEVICE", "id": triggering_event.source.id or "dev-unknown", "name": triggering_event.source.hostname or "Host"}
            ],
            associated_alert_ids=[],
            timeline=timeline,
            mitre_tactics=["Initial Access (T1078)", "Lateral Movement (T1021)", "Exfiltration (T1041)"],
            blast_radius_score=72.0,
            ai_summary=f"Automated correlation pipeline linked {len(chain)} sequential actions within {self.window_seconds // 60} minutes across authentication, network reachability, and high-impact resource access involving entity '{entity_key}'.",
            ai_recommendations=[
                "Confirm analyst sign-off for emergency session revocation.",
                "Inspect network firewall logs for outbound C2 beacons.",
                "Review device security posture and quarantine host."
            ],
            containment_actions=[act_revoke, act_isolate]
        )
        
        # Link action incident IDs
        act_revoke.incident_id = incident.incident_id
        act_isolate.incident_id = incident.incident_id

        # Persist incident to DB
        self._persist_incident(incident)
        return incident

    def _persist_incident(self, incident: Incident):
        try:
            conn = get_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents 
                (incident_id, tenant_id, title, severity, status, lead_analyst, blast_radius_score, raw_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.tenant_id,
                    incident.title,
                    incident.severity.value,
                    incident.status.value,
                    incident.lead_analyst,
                    incident.blast_radius_score,
                    incident.model_dump_json(),
                    incident.created_at,
                    incident.updated_at
                )
            )
            for act in incident.containment_actions:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO containment_actions
                    (action_id, incident_id, action_type, target_entity_type, target_entity_id, description, status, requested_by, approved_by, executed_at, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        act.action_id,
                        incident.incident_id,
                        act.action_type.value,
                        act.target_entity_type,
                        act.target_entity_id,
                        act.description,
                        act.status.value,
                        act.requested_by,
                        act.approved_by,
                        act.executed_at,
                        act.model_dump_json()
                    )
                )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[CorrelationEngine] DB save error: {e}")

correlation_engine = StatefulCorrelationEngine()
