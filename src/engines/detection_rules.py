from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
import math
from src.models.events import CommonEvent, EventType, EventAction
from src.models.alerts import Alert, AlertSeverity
from src.database.db import get_connection

class RuleEngine:
    def __init__(self):
        # In-memory sliding window cache for fast stateful checks
        self.recent_auth_failures: Dict[str, List[datetime]] = {}
        self.last_user_logins: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, event: CommonEvent) -> List[Alert]:
        alerts: List[Alert] = []

        # 1. BRUTE FORCE / PASSWORD SPRAY RULE
        if event.event_type == EventType.AUTHENTICATION and event.action == EventAction.FAILED_LOGIN:
            actor_key = event.actor.id if event.actor else (event.source.ip if event.source else "UNKNOWN")
            now = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            
            if actor_key not in self.recent_auth_failures:
                self.recent_auth_failures[actor_key] = []
            
            # Prune failures older than 10 mins
            self.recent_auth_failures[actor_key] = [
                t for t in self.recent_auth_failures[actor_key] if (now - t).total_seconds() < 600
            ]
            self.recent_auth_failures[actor_key].append(now)

            if len(self.recent_auth_failures[actor_key]) >= 5:
                alerts.append(Alert(
                    tenant_id=event.tenant_id,
                    title="Brute-Force / Credential Spraying Attack Detected",
                    rule_id="RULE-AUTH-001",
                    severity=AlertSeverity.HIGH,
                    category="IDENTITY",
                    summary=f"Detected {len(self.recent_auth_failures[actor_key])} consecutive authentication failures within 10 minutes for {actor_key}.",
                    actor_id=event.actor.id if event.actor else None,
                    device_id=event.source.id if event.source else None,
                    source_ip=event.source.ip if event.source else None,
                    related_event_ids=[event.event_id],
                    confidence=0.96,
                    risk_impact=30.0
                ))

        # 2. IMPOSSIBLE TRAVEL VELOCITY RULE
        if event.event_type == EventType.AUTHENTICATION and event.action == EventAction.LOGIN and event.result == "success":
            actor_id = event.actor.id if event.actor else None
            country = event.source.country if event.source else None
            current_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))

            if actor_id and country:
                if actor_id in self.last_user_logins:
                    last_record = self.last_user_logins[actor_id]
                    last_time = last_record["time"]
                    last_country = last_record["country"]
                    elapsed_minutes = (current_time - last_time).total_seconds() / 60.0

                    # Different country within less than 60 minutes
                    if last_country and country != last_country and 0 < elapsed_minutes < 60:
                        alerts.append(Alert(
                            tenant_id=event.tenant_id,
                            title="Impossible Geographic Travel Detected",
                            rule_id="RULE-IDP-004",
                            severity=AlertSeverity.HIGH,
                            category="IDENTITY",
                            summary=f"User {actor_id} authenticated from {last_country} and subsequently from {country} within {int(elapsed_minutes)} minutes (physically impossible speed).",
                            actor_id=actor_id,
                            device_id=event.source.id if event.source else None,
                            source_ip=event.source.ip if event.source else None,
                            related_event_ids=[event.event_id],
                            confidence=0.98,
                            risk_impact=35.0
                        ))

                self.last_user_logins[actor_id] = {"time": current_time, "country": country}

        # 3. LIVING OFF THE LAND / SUSPICIOUS PROCESS CREATION
        if event.event_type in [EventType.PROCESS, EventType.ENDPOINT_TELEMETRY]:
            cmd = (event.metadata.get("command_line") or "").lower()
            proc = (event.metadata.get("process_name") or "").lower()
            suspicious_patterns = [
                ("vssadmin", "delete shadows", "Ransomware Defense Evasion - Shadow Copies Deleted"),
                ("powershell", "-enc", "Suspicious Base64 Encoded PowerShell Execution"),
                ("certutil", "-urlcache", "Living-off-the-Land Ingress Tool Transfer via Certutil"),
                ("mimikatz", "", "Credential Dumping Utility Detected")
            ]
            for tool, pattern, description in suspicious_patterns:
                if tool in proc or tool in cmd:
                    if not pattern or pattern in cmd:
                        alerts.append(Alert(
                            tenant_id=event.tenant_id,
                            title=f"Malicious Execution: {description}",
                            rule_id="RULE-EDR-007",
                            severity=AlertSeverity.CRITICAL,
                            category="MALWARE",
                            summary=f"Endpoint execution detected suspicious pattern '{tool} {pattern}' in command: {cmd[:120]}...",
                            actor_id=event.actor.id if event.actor else None,
                            device_id=event.source.id if event.source else None,
                            source_ip=event.source.ip if event.source else None,
                            related_event_ids=[event.event_id],
                            confidence=0.99,
                            risk_impact=45.0
                        ))

        # 4. MASS DATA EXFILTRATION DETECTED
        if event.network and (event.network.bytes_sent or 0) > 500 * 1024 * 1024:  # > 500 MB
            mb = (event.network.bytes_sent or 0) / (1024 * 1024)
            alerts.append(Alert(
                tenant_id=event.tenant_id,
                title="Mass Outbound Data Exfiltration Detected",
                rule_id="RULE-NET-015",
                severity=AlertSeverity.CRITICAL,
                category="EXFILTRATION",
                summary=f"Mass data egress ({mb:.1f} MB) directed from {event.source.ip if event.source else 'host'} to external destination {event.network.destination_ip}.",
                actor_id=event.actor.id if event.actor else None,
                device_id=event.source.id if event.source else None,
                source_ip=event.source.ip if event.source else None,
                dest_ip=event.network.destination_ip,
                related_event_ids=[event.event_id],
                confidence=0.94,
                risk_impact=40.0
            ))

        return alerts

rule_engine = RuleEngine()
