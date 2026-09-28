from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import math
from src.models.events import CommonEvent, EventType
from src.models.alerts import Alert, AlertSeverity

class UEBAEngine:
    def __init__(self):
        # Baseline store for entities: historical normal profiles
        self.baselines: Dict[str, Dict[str, Any]] = {
            "usr-sarah-ciso": {
                "typical_hours_mean": 13.5,  # 1:30 PM UTC
                "typical_hours_std": 3.0,
                "known_devices": ["dev-ciso-mac"],
                "known_countries": ["US"],
                "avg_data_transfer_mb": 25.0
            },
            "usr-marcus-sec": {
                "typical_hours_mean": 14.0,
                "typical_hours_std": 4.0,
                "known_devices": ["dev-secops-win"],
                "known_countries": ["US"],
                "avg_data_transfer_mb": 50.0
            },
            "usr-elena-finance": {
                "typical_hours_mean": 14.0,
                "typical_hours_std": 2.5,   # Strictly 9am-5pm EST (14:00-22:00 UTC)
                "known_devices": ["dev-elena-win"],
                "known_countries": ["US"],
                "avg_data_transfer_mb": 15.0
            },
            "usr-alex-dev": {
                "typical_hours_mean": 15.0,
                "typical_hours_std": 5.0,
                "known_devices": ["dev-dev-linux"],
                "known_countries": ["US", "CA"],
                "avg_data_transfer_mb": 120.0
            },
            "usr-darsh-personal": {
                "typical_hours_mean": 15.0,
                "typical_hours_std": 5.0,
                "known_devices": ["dev-personal-iphone", "dev-personal-laptop"],
                "known_countries": ["IN"],
                "avg_data_transfer_mb": 40.0
            }
        }

    def evaluate_behavior(self, event: CommonEvent) -> Optional[Alert]:
        actor_id = event.actor.id if event.actor else None
        if not actor_id or actor_id not in self.baselines:
            return None

        baseline = self.baselines[actor_id]
        event_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        current_hour = event_time.hour + (event_time.minute / 60.0)

        deviation_reasons = []
        anomaly_score = 0.0

        # 1. Time-of-Day Z-Score Anomaly
        mean_hr = baseline["typical_hours_mean"]
        std_hr = max(baseline["typical_hours_std"], 1.0)
        # Circular difference on a 24-hr clock
        hr_diff = min(abs(current_hour - mean_hr), 24 - abs(current_hour - mean_hr))
        z_score = hr_diff / std_hr

        if z_score > 2.5:
            anomaly_score += min(z_score * 12.0, 35.0)
            deviation_reasons.append(
                f"Authentication at {event_time.strftime('%H:%M UTC')} exhibits high temporal deviation (Z-score: {z_score:.2f} > 2.5 threshold)."
            )

        # 2. Unrecognized Endpoint / Device Novelty
        if event.source and event.source.id:
            if event.source.id not in baseline["known_devices"]:
                anomaly_score += 30.0
                deviation_reasons.append(
                    f"New, previously unseen device '{event.source.id}' (hostname: {event.source.hostname or 'unknown'}) used for authentication."
                )

        # 3. Foreign Country Discrepancy
        if event.source and event.source.country:
            if event.source.country not in baseline["known_countries"]:
                anomaly_score += 30.0
                deviation_reasons.append(
                    f"Origin country '{event.source.country}' is outside established behavioral profile ({', '.join(baseline['known_countries'])})."
                )

        # 4. Data Transfer Volume Surge
        if event.network and event.network.bytes_sent:
            current_mb = event.network.bytes_sent / (1024 * 1024)
            avg_mb = baseline["avg_data_transfer_mb"]
            if current_mb > avg_mb * 5.0 and current_mb > 50.0:
                anomaly_score += 35.0
                deviation_reasons.append(
                    f"Network transfer volume ({current_mb:.1f} MB) is {current_mb / avg_mb:.1f}x higher than entity baseline average ({avg_mb:.1f} MB)."
                )

        if anomaly_score >= 45.0:
            severity = AlertSeverity.CRITICAL if anomaly_score >= 80.0 else (
                AlertSeverity.HIGH if anomaly_score >= 60.0 else AlertSeverity.MEDIUM
            )
            return Alert(
                tenant_id=event.tenant_id,
                title=f"Statistical Behavioral Anomaly: {actor_id}",
                rule_id="UEBA-ANOMALY-001",
                severity=severity,
                category="BEHAVIOR",
                summary="; ".join(deviation_reasons),
                actor_id=actor_id,
                device_id=event.source.id if event.source else None,
                source_ip=event.source.ip if event.source else None,
                related_event_ids=[event.event_id],
                confidence=round(min(0.70 + (anomaly_score / 300.0), 0.98), 2),
                risk_impact=round(anomaly_score * 0.8, 1)
            )

        return None

ueba_engine = UEBAEngine()
