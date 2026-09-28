from datetime import datetime, timezone
from typing import Dict, Any, Optional
import uuid
from src.models.events import CommonEvent, EventType, EventAction, Actor, Source, Destination, NetworkDetails, AuthDetails

class EventNormalizer:
    @staticmethod
    def normalize_windows_event(raw: Dict[str, Any], tenant_id: str = "tenant-corp-acme") -> CommonEvent:
        """
        Normalizes Windows Event Logs (e.g., 4624 Logon, 4625 Failed Logon, 4688 Process Creation)
        """
        event_id = raw.get("EventID") or raw.get("event_id")
        user = raw.get("TargetUserName") or raw.get("username") or "UNKNOWN_USER"
        workstation = raw.get("WorkstationName") or raw.get("computer_name") or "WIN-UNKNOWN"
        ip = raw.get("IpAddress") or raw.get("source_ip") or "127.0.0.1"
        
        if event_id in [4624, "4624"]:
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.AUTHENTICATION,
                action=EventAction.LOGIN,
                severity="LOW",
                actor=Actor(id=user, name=user, role="User"),
                source=Source(id=workstation, hostname=workstation, ip=ip),
                authentication=AuthDetails(method=raw.get("LogonType", "Network"), mfa_completed=True),
                result="success",
                raw_source_vendor="WindowsSecurity",
                metadata={"LogonGuid": raw.get("LogonGuid"), "ProcessId": raw.get("ProcessId")}
            )
        elif event_id in [4625, "4625"]:
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.AUTHENTICATION,
                action=EventAction.FAILED_LOGIN,
                severity="MEDIUM",
                actor=Actor(id=user, name=user, role="User"),
                source=Source(id=workstation, hostname=workstation, ip=ip),
                authentication=AuthDetails(method="password", mfa_completed=False, failure_reason=raw.get("SubStatus", "BadPassword")),
                result="failure",
                raw_source_vendor="WindowsSecurity",
                metadata={"Status": raw.get("Status")}
            )
        elif event_id in [4688, "4688"]:
            cmd = raw.get("CommandLine", "")
            proc = raw.get("NewProcessName", "unknown.exe")
            # Living off the land or suspicious command line detection flag
            suspicious = any(flag in cmd.lower() for flag in ["-enc", "bypass", "vssadmin", "downloadstring", "mimikatz", "certutil"])
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.PROCESS,
                action=EventAction.PROCESS_SPAWN,
                severity="HIGH" if suspicious else "LOW",
                actor=Actor(id=user, name=user),
                source=Source(id=workstation, hostname=workstation, ip=ip),
                result="success",
                raw_source_vendor="WindowsSysmon",
                metadata={"process_name": proc, "command_line": cmd, "parent_process": raw.get("ParentProcessName")}
            )
        else:
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.AUTHENTICATION,
                action=EventAction.LOGIN,
                severity="INFORMATIONAL",
                actor=Actor(id=user),
                source=Source(id=workstation, ip=ip),
                result="success",
                raw_source_vendor="WindowsSecurity",
                metadata=raw
            )

    @staticmethod
    def normalize_cloudtrail_event(raw: Dict[str, Any], tenant_id: str = "tenant-corp-acme") -> CommonEvent:
        """
        Normalizes AWS CloudTrail records (ConsoleLogin, AssumeRole, etc.)
        """
        event_name = raw.get("eventName", "UnknownCloudAction")
        user_identity = raw.get("userIdentity", {})
        actor_name = user_identity.get("userName") or user_identity.get("arn", "UnknownCloudActor")
        source_ip = raw.get("sourceIPAddress", "0.0.0.0")
        
        is_error = "errorCode" in raw or raw.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        
        if event_name == "ConsoleLogin":
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.AUTHENTICATION,
                action=EventAction.FAILED_LOGIN if is_error else EventAction.LOGIN,
                severity="MEDIUM" if is_error else "LOW",
                actor=Actor(id=actor_name, name=actor_name, role="CloudIdentity"),
                source=Source(ip=source_ip, country=raw.get("awsRegion")),
                destination=Destination(name="AWS Management Console"),
                network=NetworkDetails(source_ip=source_ip),
                authentication=AuthDetails(method="CloudSSO", mfa_completed=raw.get("additionalEventData", {}).get("MFAUsed") == "Yes"),
                result="failure" if is_error else "success",
                raw_source_vendor="AWSCloudTrail",
                metadata={"userAgent": raw.get("userAgent"), "requestID": raw.get("requestID")}
            )
        else:
            return CommonEvent(
                tenant_id=tenant_id,
                event_type=EventType.NETWORK,
                action=EventAction.NETWORK_CONNECT,
                severity="LOW",
                actor=Actor(id=actor_name, name=actor_name),
                source=Source(ip=source_ip),
                destination=Destination(name=raw.get("eventSource", "AWS")),
                result="failure" if is_error else "success",
                raw_source_vendor="AWSCloudTrail",
                metadata=raw
            )

    @staticmethod
    def normalize_generic_cem(data: Dict[str, Any]) -> CommonEvent:
        """
        Validates or casts directly to standard CommonEvent
        """
        if isinstance(data, CommonEvent):
            return data
        return CommonEvent(**data)
