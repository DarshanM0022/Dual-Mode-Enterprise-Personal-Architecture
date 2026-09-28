import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "aetheris.db"

class PlatformConfig(BaseModel):
    app_name: str = "Aetheris — Unified Adaptive Security Platform"
    app_version: str = "1.0.0-enterprise"
    host: str = "127.0.0.1"
    port: int = 8000
    db_path: str = str(DB_PATH)
    default_tenant: str = "tenant-corp-acme"
    personal_tenant: str = "tenant-personal-darsh"
    
    # Risk weights
    weight_identity: float = 0.30
    weight_device: float = 0.25
    weight_behavior: float = 0.20
    weight_threat: float = 0.15
    weight_exposure: float = 0.10
    
    # Anomaly detection Z-score threshold
    anomaly_z_threshold: float = 2.5
    
    # Correlation window in seconds
    correlation_window_seconds: int = 900  # 15 minutes

settings = PlatformConfig()
