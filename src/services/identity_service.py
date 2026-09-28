from typing import List, Dict, Any, Optional
import json
from src.database.db import get_connection
from src.models.entities import UserEntity

class IdentityService:
    def get_identities(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute("SELECT raw_json FROM entities_user WHERE tenant_id = ?", (tenant_id,))
        else:
            cursor.execute("SELECT raw_json FROM entities_user")
        rows = cursor.fetchall()
        conn.close()
        return [json.loads(r["raw_json"]) for r in rows]

    def get_identity_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM entities_user WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        return json.loads(row["raw_json"]) if row else None

    def update_user_status(self, user_id: str, status: str) -> bool:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM entities_user WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False
        data = json.loads(row["raw_json"])
        data["status"] = status
        cursor.execute(
            "UPDATE entities_user SET status = ?, raw_json = ? WHERE user_id = ?",
            (status, json.dumps(data), user_id)
        )
        conn.commit()
        conn.close()
        return True

identity_service = IdentityService()
