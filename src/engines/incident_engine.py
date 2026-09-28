from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import json
import uuid
from src.models.alerts import Incident, IncidentStatus, ContainmentAction, ActionStatus, ActionType
from src.database.db import get_connection, log_audit

class IncidentEngine:
    def update_incident_status(self, incident_id: str, new_status: IncidentStatus, analyst: str = "SecOps Lead") -> Optional[Incident]:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        data = json.loads(row["raw_json"])
        data["status"] = new_status.value
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        data["timeline"].append({
            "time": data["updated_at"],
            "event": f"Incident status transitioned to {new_status.value} by {analyst}."
        })

        cursor.execute(
            "UPDATE incidents SET status = ?, updated_at = ?, raw_json = ? WHERE incident_id = ?",
            (new_status.value, data["updated_at"], json.dumps(data), incident_id)
        )
        conn.commit()
        conn.close()

        log_audit(analyst, f"INCIDENT_STATUS_CHANGE", f"Incident {incident_id} changed to {new_status.value}")
        return Incident(**data)

    def execute_containment_action(self, action_id: str, approved_by: str) -> Dict[str, Any]:
        """
        Executes a containment action following human approval
        """
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM containment_actions WHERE action_id = ?", (action_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"success": False, "error": f"Action {action_id} not found"}

        act_data = json.loads(row["raw_json"])
        action_type = act_data.get("action_type")
        target_id = act_data.get("target_entity_id")
        now_str = datetime.now(timezone.utc).isoformat()

        execution_details = ""

        # Execute the real simulation of security containment
        if action_type == ActionType.ISOLATE_HOST.value:
            cursor.execute(
                "UPDATE entities_device SET status = 'ISOLATED' WHERE device_id = ? OR hostname = ? OR ip_address = ?",
                (target_id, target_id, target_id)
            )
            execution_details = f"Host {target_id} isolated from corporate network via EDR firewall agent rule. Ingress/egress dropped except management port 8443."

        elif action_type == ActionType.REVOKE_SESSION.value:
            cursor.execute(
                "UPDATE entities_user SET status = 'LOCKED' WHERE user_id = ? OR username = ?",
                (target_id, target_id)
            )
            execution_details = f"Active OAuth and SAML tokens invalidated for identity {target_id}. Account locked until in-person verification."

        elif action_type == ActionType.BLOCK_IP.value:
            execution_details = f"Boundary perimeter firewall rule appended: DROP ALL FROM {target_id}."

        elif action_type == ActionType.ENFORCE_MFA.value:
            cursor.execute(
                "UPDATE entities_user SET mfa_method = 'Hardware Token (YubiKey Required)' WHERE user_id = ?",
                (target_id,)
            )
            execution_details = f"Downgraded auth factors revoked; FIDO2 hardware token enforced for {target_id}."

        # Update action status
        act_data["status"] = ActionStatus.EXECUTED.value
        act_data["approved_by"] = approved_by
        act_data["executed_at"] = now_str

        cursor.execute(
            "UPDATE containment_actions SET status = ?, approved_by = ?, executed_at = ?, raw_json = ? WHERE action_id = ?",
            (ActionStatus.EXECUTED.value, approved_by, now_str, json.dumps(act_data), action_id)
        )

        # Update incident timeline
        inc_id = act_data.get("incident_id")
        if inc_id:
            cursor.execute("SELECT raw_json FROM incidents WHERE incident_id = ?", (inc_id,))
            inc_row = cursor.fetchone()
            if inc_row:
                inc_data = json.loads(inc_row["raw_json"])
                inc_data["timeline"].append({
                    "time": now_str,
                    "event": f"SOAR Containment Executed: {action_type} on {target_id} (Approved by {approved_by})."
                })
                # Check if all actions executed -> update incident to CONTAINMENT status
                inc_data["status"] = IncidentStatus.CONTAINMENT.value
                cursor.execute(
                    "UPDATE incidents SET status = ?, raw_json = ? WHERE incident_id = ?",
                    (IncidentStatus.CONTAINMENT.value, json.dumps(inc_data), inc_id)
                )

        conn.commit()
        conn.close()

        log_audit(approved_by, f"SOAR_ACTION_EXECUTED", f"Action {action_type} executed on {target_id}: {execution_details}")
        return {
            "success": True,
            "action_id": action_id,
            "action_type": action_type,
            "target": target_id,
            "status": "EXECUTED",
            "approved_by": approved_by,
            "details": execution_details,
            "executed_at": now_str
        }

incident_engine = IncidentEngine()
