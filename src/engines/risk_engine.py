from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import json
from src.models.risk import EntityRiskProfile, RiskDriver
from src.database.db import get_connection

class ExplainableRiskEngine:
    def calculate_user_risk(self, user_id: str, tenant_id: str = "tenant-corp-acme") -> EntityRiskProfile:
        conn = get_connection()
        cursor = conn.cursor()

        # 1. Fetch user entity
        cursor.execute("SELECT raw_json, risk_score FROM entities_user WHERE user_id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            conn.close()
            return EntityRiskProfile(entity_id=user_id, entity_type="USER", plain_english_explanation="Entity not found")
        
        user_data = json.loads(user_row["raw_json"])
        
        # 2. Fetch owned devices risk
        cursor.execute("SELECT hostname, risk_score, status, raw_json FROM entities_device WHERE owner_user_id = ?", (user_id,))
        device_rows = cursor.fetchall()
        max_device_risk = 10.0
        for dr in device_rows:
            if dr["risk_score"] > max_device_risk:
                max_device_risk = dr["risk_score"]

        # 3. Fetch recent alerts for user
        cursor.execute("SELECT raw_json FROM alerts WHERE actor_id = ?", (user_id,))
        alert_rows = cursor.fetchall()
        alerts = [json.loads(r["raw_json"]) for r in alert_rows]

        # 4. Fetch user exposures
        cursor.execute("SELECT * FROM exposures WHERE target_entity LIKE ? AND status = 'OPEN'", (f"%{user_data.get('email', user_id)}%",))
        exposure_rows = cursor.fetchall()

        # 5. Fetch incidents involving user
        cursor.execute("SELECT raw_json FROM incidents WHERE raw_json LIKE ? AND status != 'CLOSED'", (f"%{user_id}%",))
        incident_rows = cursor.fetchall()

        conn.close()

        # Dimension Calculations
        identity_points = 10.0
        device_points = max_device_risk
        behavior_points = 10.0
        threat_points = 10.0 if not incident_rows else 60.0
        exposure_points = 10.0
        drivers: List[RiskDriver] = []
        mitigations: List[str] = []

        if max_device_risk > 50.0:
            drivers.append(RiskDriver(
                category="DEVICE",
                factor="Compromised or Unpatched Endpoint Associated",
                impact_points=max_device_risk * 0.4,
                evidence=f"Associated endpoint exhibits elevated risk ({max_device_risk}/100) and unpatched vulnerabilities."
            ))

        # Analyze Privilege & MFA
        if user_data.get("privilege_level") in ["DOMAIN_ADMIN", "VIP Executive", "ROOT"]:
            identity_points += 20.0
            drivers.append(RiskDriver(
                category="IDENTITY",
                factor=f"High-Value Target Asset: {user_data.get('privilege_level')}",
                impact_points=20.0,
                evidence="Entity holds elevated administrative or executive access to sensitive company systems."
            ))

        if not user_data.get("mfa_enabled") or "SMS" in str(user_data.get("mfa_method")):
            identity_points += 25.0
            drivers.append(RiskDriver(
                category="IDENTITY",
                factor="Weak or Vulnerable Authentication Factor (SMS 2FA)",
                impact_points=25.0,
                evidence="Account relies on SMS-based verification susceptible to SIM-swapping and SS7 interception."
            ))
            mitigations.append("Upgrade account to hardware FIDO2 / WebAuthn security key.")

        # Analyze Alerts
        for alt in alerts:
            cat = alt.get("category", "")
            sev = alt.get("severity", "LOW")
            sev_weight = {"CRITICAL": 35.0, "HIGH": 25.0, "MEDIUM": 15.0, "LOW": 5.0}.get(sev, 5.0)

            if cat == "IDENTITY":
                identity_points += sev_weight
                drivers.append(RiskDriver(
                    category="IDENTITY",
                    factor=alt.get("title", "Identity Alert"),
                    impact_points=sev_weight,
                    evidence=alt.get("summary", "")
                ))
            elif cat in ["DEVICE", "MALWARE"]:
                device_points += sev_weight
                drivers.append(RiskDriver(
                    category="DEVICE",
                    factor=alt.get("title", "Endpoint Threat"),
                    impact_points=sev_weight,
                    evidence=alt.get("summary", "")
                ))
            elif cat in ["BEHAVIOR", "ANOMALY"]:
                behavior_points += sev_weight
                drivers.append(RiskDriver(
                    category="BEHAVIOR",
                    factor=alt.get("title", "Behavioral Deviation"),
                    impact_points=sev_weight,
                    evidence=alt.get("summary", "")
                ))
            elif cat in ["EXFILTRATION", "NETWORK"]:
                threat_points += sev_weight
                drivers.append(RiskDriver(
                    category="THREAT_INTEL",
                    factor=alt.get("title", "Threat & Egress Signal"),
                    impact_points=sev_weight,
                    evidence=alt.get("summary", "")
                ))

        # Analyze Exposures
        for exp in exposure_rows:
            exposure_points += 30.0
            drivers.append(RiskDriver(
                category="EXPOSURE",
                factor=exp["title"],
                impact_points=30.0,
                evidence=f"Discovered {exp['discovered_at']}: {exp['details']}"
            ))
            mitigations.append(exp["remediation_steps"])

        # Cap subscores
        identity_sub = min(identity_points, 100.0)
        device_sub = min(device_points, 100.0)
        behavior_sub = min(behavior_points, 100.0)
        threat_sub = min(threat_points, 100.0)
        exposure_sub = min(exposure_points, 100.0)

        # Sort drivers by highest impact
        drivers.sort(key=lambda d: d.impact_points, reverse=True)

        # Weighted calculation
        overall_risk = (
            (identity_sub * 0.30) +
            (device_sub * 0.25) +
            (behavior_sub * 0.20) +
            (threat_sub * 0.15) +
            (exposure_sub * 0.10)
        )
        overall_risk = round(min(max(overall_risk, 0.0), 100.0), 1)

        risk_level = "CRITICAL" if overall_risk >= 85.0 else (
            "HIGH" if overall_risk >= 65.0 else (
                "MEDIUM" if overall_risk >= 35.0 else "LOW"
            )
        )

        # Explainability synthesis
        if drivers:
            top_factors = [f"'{d.factor}' (+{int(d.impact_points)} pts)" for d in drivers[:3]]
            explanation = (
                f"Overall risk is evaluated at {overall_risk}/100 ({risk_level}). Primary risk drivers: "
                f"{'; '.join(top_factors)}. Immediate investigation is advised."
            )
        else:
            explanation = f"Overall risk is low ({overall_risk}/100). All telemetry parameters conform to standard operational baseline."

        if not mitigations:
            mitigations = ["Maintain periodic identity access reviews and standard baseline monitoring."]

        profile = EntityRiskProfile(
            entity_id=user_id,
            entity_type="USER",
            tenant_id=tenant_id,
            overall_risk=overall_risk,
            risk_level=risk_level,
            identity_subscore=round(identity_sub, 1),
            device_subscore=round(device_sub, 1),
            behavior_subscore=round(behavior_sub, 1),
            threat_subscore=round(threat_sub, 1),
            exposure_subscore=round(exposure_sub, 1),
            confidence_multiplier=0.95,
            primary_drivers=drivers,
            plain_english_explanation=explanation,
            recommended_mitigations=mitigations,
            last_updated=datetime.now(timezone.utc).isoformat()
        )

        # Persist updated profile
        self._persist_profile(profile)
        return profile

    def _persist_profile(self, profile: EntityRiskProfile):
        try:
            conn = get_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO risk_profiles 
                (entity_id, entity_type, tenant_id, overall_risk, risk_level, raw_json, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.entity_id,
                    profile.entity_type,
                    profile.tenant_id,
                    profile.overall_risk,
                    profile.risk_level,
                    profile.model_dump_json(),
                    profile.last_updated
                )
            )
            # Also update user risk in entities_user
            if profile.entity_type == "USER":
                conn.execute(
                    "UPDATE entities_user SET risk_score = ? WHERE user_id = ?",
                    (profile.overall_risk, profile.entity_id)
                )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[RiskEngine] Save error: {e}")

risk_engine = ExplainableRiskEngine()
