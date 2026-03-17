"""
correlation_api.py - API REST del Motor de Correlación Multi-Evento
AUT_SOC - Fase 2.1.D

FastAPI en puerto 8747. N8N lo llama tras el IOC Engine para detectar
patrones de ataque en ventanas de tiempo.

Endpoints:
  POST /correlate        - Ingesta evento y evalúa patrones
  GET  /super-alerts     - Lista super-alertas recientes
  GET  /stats            - Estadísticas del motor
  POST /cleanup          - Limpia eventos antiguos
  GET  /health           - Health check
"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import threading
import time

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Any, Optional
from correlation_engine import CorrelationEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("correlation_api")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_URL = os.getenv(
    "CORRELATION_DB_URL",
    "postgresql://soporte:soporte@localhost:5432/tia"
)
PORT = int(os.getenv("CORRELATION_PORT", "8747"))

engine = CorrelationEngine(DB_URL)


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class EventRequest(BaseModel):
    event: dict[str, Any]

class CleanupRequest(BaseModel):
    days: int = 3


# ---------------------------------------------------------------------------
# Lifespan: limpieza periódica en background
# ---------------------------------------------------------------------------

def _cleanup_loop():
    """Limpia eventos de correlación antiguos cada 6 horas."""
    while True:
        time.sleep(6 * 3600)
        try:
            deleted = engine.cleanup_old_events(days=3)
            logger.info(f"Cleanup automático: {deleted} eventos eliminados")
        except Exception as e:
            logger.error(f"Error en cleanup: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    stats = engine.get_stats()
    logger.info(f"✅ Correlation Engine listo — {stats['events_last_24h']} eventos (24h)")
    thread = threading.Thread(target=_cleanup_loop, daemon=True)
    thread.start()
    yield
    logger.info("🛑 Correlation Engine apagado")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AUT_SOC Correlation Engine",
    description="Motor de correlación multi-evento para detección de patrones de ataque - Fase 2.1.D",
    version="2.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/correlate")
def correlate(req: EventRequest):
    """
    Ingesta un evento normalizado del pipeline N8N y evalúa patrones.
    Retorna si se generaron super-alertas y el bonus de riesgo a aplicar.
    """
    return engine.ingest_event(req.event)


@app.get("/super-alerts")
def get_super_alerts(hours: int = 24):
    """Lista super-alertas generadas en las últimas N horas."""
    alerts = engine.get_recent_super_alerts(hours=hours)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/stats")
def get_stats():
    """Estadísticas del motor de correlación."""
    return {
        **engine.get_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/cleanup")
def cleanup(req: CleanupRequest):
    """Limpia eventos de correlación más antiguos que N días."""
    deleted = engine.cleanup_old_events(days=req.days)
    return {"deleted_events": deleted, "older_than_days": req.days}


@app.get("/health")
def health():
    try:
        stats = engine.get_stats()
        return {
            "status": "ok",
            "service": "correlation-engine",
            "version": "2.1.0",
            "events_24h": stats["events_last_24h"],
            "super_alerts_24h": stats["super_alerts_last_24h"],
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("correlation_api:app", host="0.0.0.0", port=PORT,
                reload=False, log_level="info")
