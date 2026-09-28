import asyncio
from typing import List, Callable, Dict, Any
from datetime import datetime, timezone
from src.models.events import CommonEvent
from src.database.db import get_connection

class EventBus:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EventBus, cls).__new__(cls)
            cls._instance._subscribers = []
            cls._instance._ws_broadcaster = None
        return cls._instance

    def register_subscriber(self, handler: Callable[[CommonEvent], Any]):
        self._subscribers.append(handler)

    def set_websocket_broadcaster(self, broadcaster: Callable[[Dict[str, Any]], Any]):
        self._ws_broadcaster = broadcaster

    async def publish(self, event: CommonEvent):
        # 1. Persist to DB
        self._save_event_to_db(event)

        # 2. Broadcast via WebSocket if registered
        if self._ws_broadcaster:
            try:
                await self._ws_broadcaster({
                    "type": "NEW_EVENT",
                    "event": event.model_dump()
                })
            except Exception as e:
                print(f"[EventBus] WS broadcast error: {e}")

        # 3. Notify all subscribers (Detection Engine, Graph, UEBA)
        for sub in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(sub):
                    await sub(event)
                else:
                    sub(event)
            except Exception as e:
                print(f"[EventBus] Subscriber error: {e}")

    def _save_event_to_db(self, event: CommonEvent):
        try:
            conn = get_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO events 
                (event_id, tenant_id, timestamp, event_type, action, severity, actor_id, actor_name, source_id, source_ip, dest_name, result, raw_source_vendor, normalized_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.timestamp,
                    event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                    event.action.value if hasattr(event.action, "value") else str(event.action),
                    event.severity,
                    event.actor.id if event.actor else None,
                    event.actor.name if event.actor else None,
                    event.source.id if event.source else None,
                    event.source.ip if event.source else None,
                    event.destination.name if event.destination else None,
                    event.result,
                    event.raw_source_vendor,
                    event.model_dump_json()
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[EventBus] DB Persist error: {e}")

event_bus = EventBus()
