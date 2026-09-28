from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timezone
from src.database.db import get_connection

class DeviceService:
    def get_devices(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute("SELECT raw_json FROM entities_device WHERE tenant_id = ?", (tenant_id,))
        else:
            cursor.execute("SELECT raw_json FROM entities_device")
        rows = cursor.fetchall()
        conn.close()
        return [json.loads(r["raw_json"]) for r in rows]

    def get_device_by_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM entities_device WHERE device_id = ?", (device_id,))
        row = cursor.fetchone()
        conn.close()
        return json.loads(row["raw_json"]) if row else None

    def trigger_isolate(self, device_id: str) -> bool:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM entities_device WHERE device_id = ?", (device_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False
        data = json.loads(row["raw_json"])
        data["status"] = "ISOLATED"
        cursor.execute(
            "UPDATE entities_device SET status = 'ISOLATED', raw_json = ? WHERE device_id = ?",
            (json.dumps(data), device_id)
        )
        conn.commit()
        conn.close()
        return True

device_service = DeviceService()
