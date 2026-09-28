from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from src.config import settings
from src.database.seed_data import seed_database
from src.api.routes_siem import router as siem_router
from src.api.routes_entities import router as entities_router
from src.api.routes_risk import router as risk_router
from src.api.routes_incidents import router as incidents_router
from src.api.routes_ai import router as ai_router
from src.api.routes_simulations import router as simulations_router
from src.api.routes_host import router as host_router
from src.api.websocket import router as ws_router

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Enterprise-grade unified adaptive security platform with explainable multi-dimensional risk, stateful correlation, behavioral baselines, blast radius mapping, and guardrailed AI copilot."
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize and seed database
    seed_database()

    # Register API routers
    app.include_router(siem_router)
    app.include_router(entities_router)
    app.include_router(risk_router)
    app.include_router(incidents_router)
    app.include_router(ai_router)
    app.include_router(simulations_router)
    app.include_router(host_router)
    app.include_router(ws_router)

    # Static files & UI Mount
    static_dir = Path(__file__).resolve().parent.parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    def index():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/health")
    def health():
        return {"status": "HEALTHY", "platform": settings.app_name, "version": settings.app_version}

    return app

app = create_app()
