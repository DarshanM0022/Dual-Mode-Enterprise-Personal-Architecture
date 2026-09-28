import sqlite3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from src.config import settings

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        action TEXT NOT NULL,
        severity TEXT NOT NULL,
        actor_id TEXT,
        actor_name TEXT,
        source_id TEXT,
        source_ip TEXT,
        dest_name TEXT,
        result TEXT NOT NULL,
        raw_source_vendor TEXT,
        normalized_json TEXT NOT NULL
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);")

    # 2. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS entities_user (
        user_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        username TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT,
        privilege_level TEXT,
        mfa_enabled INTEGER DEFAULT 1,
        status TEXT DEFAULT 'ACTIVE',
        risk_score REAL DEFAULT 10.0,
        raw_json TEXT NOT NULL
    );
    """)

    # 3. Devices Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS entities_device (
        device_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        owner_user_id TEXT,
        os_type TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        patch_status TEXT DEFAULT 'COMPLIANT',
        disk_encryption INTEGER DEFAULT 1,
        firewall_active INTEGER DEFAULT 1,
        edr_agent_active INTEGER DEFAULT 1,
        risk_score REAL DEFAULT 10.0,
        status TEXT DEFAULT 'ACTIVE',
        raw_json TEXT NOT NULL
    );
    """)

    # 4. Applications Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS entities_app (
        app_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        criticality TEXT NOT NULL,
        mfa_required INTEGER DEFAULT 1,
        risk_score REAL DEFAULT 10.0,
        raw_json TEXT NOT NULL
    );
    """)

    # 5. Exposures Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS exposures (
        item_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        details TEXT,
        remediation_steps TEXT,
        status TEXT DEFAULT 'OPEN',
        discovered_at TEXT NOT NULL
    );
    """)

    # 6. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        title TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        summary TEXT,
        actor_id TEXT,
        device_id TEXT,
        source_ip TEXT,
        confidence REAL,
        risk_impact REAL,
        raw_json TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """)

    # 7. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        lead_analyst TEXT,
        blast_radius_score REAL DEFAULT 20.0,
        raw_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # 8. Containment Actions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS containment_actions (
        action_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_entity_type TEXT NOT NULL,
        target_entity_id TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL,
        requested_by TEXT,
        approved_by TEXT,
        executed_at TEXT,
        raw_json TEXT NOT NULL
    );
    """)

    # 9. Risk Profiles Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_profiles (
        entity_id TEXT PRIMARY KEY,
        entity_type TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        overall_risk REAL NOT NULL,
        risk_level TEXT NOT NULL,
        raw_json TEXT NOT NULL,
        last_updated TEXT NOT NULL
    );
    """)

    # 10. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        status TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

def log_audit(actor: str, action: str, details: str, status: str = "SUCCESS"):
    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO audit_logs (log_id, timestamp, actor, action, details, status) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(), actor, action, details, status)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit: {e}")
