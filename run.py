import uvicorn
import webbrowser
import sys
import time
from src.config import settings

def main():
    print("=" * 70)
    print(f"  {settings.app_name}")
    print(f"  Version: {settings.app_version}")
    print("=" * 70)
    print(f"  [+] Starting Web Interface: http://{settings.host}:{settings.port}")
    print(f"  [+] Real-time WebSocket:    ws://{settings.host}:{settings.port}/ws/telemetry")
    print(f"  [+] API Swagger Docs:       http://{settings.host}:{settings.port}/docs")
    print("=" * 70)

    # Launch uvicorn
    uvicorn.run("src.app:app", host=settings.host, port=settings.port, reload=False)

if __name__ == "__main__":
    main()
