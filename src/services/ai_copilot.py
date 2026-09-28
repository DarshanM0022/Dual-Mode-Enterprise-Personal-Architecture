import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid
from src.database.db import get_connection, log_audit
from src.engines.risk_engine import risk_engine
from src.engines.entity_graph import entity_graph
from src.models.alerts import ContainmentAction, ActionType, ActionStatus

class GuardrailedSecurityCopilot:
    def __init__(self):
        self.injection_blacklist = [
            r"ignore previous instructions",
            r"override policy",
            r"bypass approval",
            r"drop database",
            r"delete from",
            r"rm -rf",
            r"execute without authorization"
        ]

    def process_query(self, user_prompt: str, user_role: str = "SecOps Analyst", tenant_id: str = "tenant-corp-acme") -> Dict[str, Any]:
        """
        Processes an analyst or personal user query through the Guardrail & Security Tool Router.
        """
        # 1. Guardrail: Prompt Injection & Adversarial Filter
        for pattern in self.injection_blacklist:
            if re.search(pattern, user_prompt, re.IGNORECASE):
                log_audit(user_role, "AI_GUARDRAIL_BLOCKED", f"Suspicious prompt pattern blocked: {pattern}", "BLOCKED")
                return {
                    "role": "assistant",
                    "status": "GUARDRAIL_TRIGGERED",
                    "content": "⚠️ **Security Guardrail Active**: The submitted query contains unauthorized override or injection patterns. Request has been logged to the SIEM audit trail.",
                    "citations": [],
                    "tool_invocations": []
                }

        # 2. Tool Routing based on Semantic Intent
        prompt_lower = user_prompt.lower()
        tools_called = []
        citations = []
        response_text = ""
        action_request = None

        # Intent A: Why is user X high risk / explain user risk
        if any(w in prompt_lower for w in ["why", "risk", "elena", "sarah", "marcus", "alex", "darsh"]) and ("user" in prompt_lower or "elena" in prompt_lower or "risk" in prompt_lower):
            target_user = "usr-elena-finance"
            if "sarah" in prompt_lower: target_user = "usr-sarah-ciso"
            elif "marcus" in prompt_lower: target_user = "usr-marcus-sec"
            elif "alex" in prompt_lower: target_user = "usr-alex-dev"
            elif "darsh" in prompt_lower: target_user = "usr-darsh-personal"

            tools_called.append(f"get_user_risk('{target_user}')")
            profile = risk_engine.calculate_user_risk(target_user, tenant_id=tenant_id)
            
            drivers_md = "\n".join([f"- **{d.category}** (+{int(d.impact_points)} pts): {d.factor} — *{d.evidence}*" for d in profile.primary_drivers[:5]])
            mitigations_md = "\n".join([f"1. {m}" for m in profile.recommended_mitigations])

            response_text = (
                f"### Risk Assessment for Entity `{profile.entity_id}`\n\n"
                f"**Overall Risk Score**: `{profile.overall_risk}/100` ({profile.risk_level})\n"
                f"**Confidence**: `{int(profile.confidence_multiplier * 100)}%`\n\n"
                f"#### Subscore Breakdown:\n"
                f"- **Identity Hygiene**: `{profile.identity_subscore}/100` (Weight 30%)\n"
                f"- **Device Posture**: `{profile.device_subscore}/100` (Weight 25%)\n"
                f"- **Behavioral Deviation**: `{profile.behavior_subscore}/100` (Weight 20%)\n"
                f"- **Threat Signals**: `{profile.threat_subscore}/100` (Weight 15%)\n"
                f"- **Exposure Points**: `{profile.exposure_subscore}/100` (Weight 10%)\n\n"
                f"#### Primary Risk Contributors:\n{drivers_md if drivers_md else '- No abnormal deviations recorded.'}\n\n"
                f"#### Recommended Mitigations:\n{mitigations_md}"
            )
            citations.append(f"EntityRiskProfile:{profile.entity_id}")

        # Intent B: Incident Investigation & Blast Radius
        elif any(w in prompt_lower for w in ["incident", "blast radius", "investigate", "attack", "inc-"]):
            tools_called.append("get_active_incidents()")
            tools_called.append("calculate_blast_radius('usr-elena-finance')")
            
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT raw_json FROM incidents ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            conn.close()

            blast = entity_graph.compute_blast_radius("usr-elena-finance", max_hops=2)

            if row:
                inc_data = json.loads(row["raw_json"])
                citations.append(f"Incident:{inc_data['incident_id']}")
                timeline_md = "\n".join([f"- `{t['time'][11:19]}`: {t['event']}" for t in inc_data.get("timeline", [])])

                response_text = (
                    f"### Incident Investigation: `{inc_data['incident_id']}`\n\n"
                    f"**Title**: {inc_data['title']}\n"
                    f"**Severity**: `{inc_data['severity']}` | **Status**: `{inc_data['status']}`\n"
                    f"**Blast Radius Score**: `{blast['blast_radius_score']}/100` ({blast['exposed_asset_count']} reachable entities)\n\n"
                    f"#### Correlated Kill Chain Timeline:\n{timeline_md}\n\n"
                    f"#### AI Forensic Synthesis:\n{inc_data.get('ai_summary')}\n\n"
                    f"#### Recommended Immediate Actions:\n"
                    f"1. Isolate the external host `UNKNOWN-HOST-X99` (`185.220.101.44`).\n"
                    f"2. Revoke active OAuth and Okta tokens for `Elena Rostova`."
                )
            else:
                response_text = "No active incidents currently require immediate remediation."

        # Intent C: Isolate / Lock / Respond (Write Action Guardrail)
        elif any(w in prompt_lower for w in ["isolate", "lock", "block", "revoke", "remediate", "kill"]):
            tools_called.append("propose_containment_action()")
            
            # GUARDRAIL: High impact actions REQUIRE Human Sign-off
            action_request = {
                "action_id": f"ACT-GUARD-{uuid.uuid4().hex[:6].upper()}",
                "action_type": "ISOLATE_HOST" if "isolate" in prompt_lower else "REVOKE_SESSION",
                "target_entity": "dev-rogue-external (185.220.101.44)" if "isolate" in prompt_lower else "usr-elena-finance",
                "impact": "CRITICAL (Disrupts network/access)",
                "status": "PENDING_ANALYST_AUTHORIZATION"
            }

            response_text = (
                f"### 🛡️ Guardrail Policy Triggered: Human-in-the-Loop Required\n\n"
                f"The AI Copilot does not have authority to autonomously execute destructive or high-impact actions.\n\n"
                f"**Proposed Containment Action**: `{action_request['action_type']}`\n"
                f"**Target Asset**: `{action_request['target_entity']}`\n"
                f"**Impact Level**: `{action_request['impact']}`\n\n"
                f"An authorization token (`{action_request['action_id']}`) has been created. Please review and click **'Authorize Containment'** in the Incident Response panel to execute."
            )

        # Default: General Security Intelligence
        else:
            tools_called.append("search_security_telemetry()")
            response_text = (
                "### Aetheris Unified Security Copilot\n\n"
                "I am your guardrailed SecOps & Personal Security Assistant. You can query me on:\n\n"
                "- **Entity Risk**: *'Why is Elena Rostova high risk?'* or *'Explain Darsh's security health'*.\n"
                "- **Incident Triage**: *'Investigate the active incident and show blast radius'*.\n"
                "- **Containment Playbooks**: *'Isolate rogue host 185.220.101.44'* or *'Revoke user session'*.\n"
                "- **SIEM Telemetry**: *'Search recent brute force attacks or anomalous data egress'*.\n\n"
                "All high-impact responses adhere to strict read/write separation and require analyst authorization."
            )

        log_audit(user_role, "AI_QUERY_PROCESSED", f"Query: {user_prompt[:80]}... | Tools: {tools_called}", "SUCCESS")

        return {
            "role": "assistant",
            "status": "COMPLETED",
            "content": response_text,
            "citations": citations,
            "tool_invocations": tools_called,
            "action_request": action_request
        }

ai_copilot = GuardrailedSecurityCopilot()
