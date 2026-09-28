from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from src.database.db import get_connection
from src.models.entities import ExposureItem

class ExposureService:
    def get_exposures(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute("SELECT * FROM exposures WHERE tenant_id = ? ORDER BY discovered_at DESC", (tenant_id,))
        else:
            cursor.execute("SELECT * FROM exposures ORDER BY discovered_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def resolve_exposure(self, item_id: str) -> bool:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE exposures SET status = 'RESOLVED' WHERE item_id = ?", (item_id,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0

exposure_service = ExposureService()
