"""
ioc_api.py - API REST del IOC Engine
AUT_SOC - Fase 2.1.C

FastAPI server que expone el motor de IOCs como microservicio HTTP (puerto 8746).
N8N lo llama después del enriquecimiento externo para verificar IOCs contra feeds.

Endpoints:
  POST /check/event      - Verifica todos los IOCs de un evento N8N
  POST /check/ip         - Verifica una IP específica
  POST /check/hash       - Verifica un hash de archivo
  POST /check/url        - Verifica una URL
  POST /check/auto       - Detecta tipo y verifica
  POST /feeds/update     - Actualiza todos los feeds (cron/manual)
  GET  /health           - Health check
  GET  /stats            - Estadísticas de la BD
"""

import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from ioc_fetcher import IOCDatabase, IOCFetcher, DB_PATH
from ioc_checker import IOCChecker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ioc_api")

# ---------------------------------------------------------------------------
# Instancias globales
# ---------------------------------------------------------------------------
db = IOCDatabase(DB_PATH)
fetcher = IOCFetcher(db)
checker = IOCChecker(DB_PATH)

# Timestamp de la última actualización de feeds
_last_feed_update: float = 0
_feed_update_lock = threading.Lock()
_update_in_progress = False


# ---------------------------------------------------------------------------
# Modelos Pydantic
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    value: str

class EventCheckRequest(BaseModel):
    event: dict[str, Any]

class FeedUpdateResponse(BaseModel):
    status: str
    results: Optional[dict] = None
    message: str = ""


# ---------------------------------------------------------------------------
# Lifespan: carga inicial de feeds si BD está vacía
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    stats = db.get_stats()
    total_iocs = sum(v for k, v in stats.items() if k != "feeds" and isinstance(v, int))

    if total_iocs == 0:
        logger.info("BD vacía — descargando feeds iniciales en background...")
        thread = threading.Thread(target=_run_feed_update, daemon=True)
        thread.start()
    else:
        logger.info(f"✅ IOC Engine listo — {total_iocs:,} IOCs en base de datos")

    yield
    logger.info("🛑 IOC Engine apagado")


def _run_feed_update():
    global _last_feed_update, _update_in_progress
    with _feed_update_lock:
        if _update_in_progress:
            return
        _update_in_progress = True
    try:
        logger.info("⬇️  Actualizando feeds IOC...")
        results = fetcher.fetch_all()
        _last_feed_update = time.time()
        logger.info(f"✅ Feeds actualizados: {results}")
    except Exception as e:
        logger.error(f"Error actualizando feeds: {e}")
    finally:
        _update_in_progress = False


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AUT_SOC IOC Engine",
    description="Motor de verificación de IOCs contra feeds open-source - Fase 2.1.C",
    version="2.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints de verificación
# ---------------------------------------------------------------------------

@app.post("/check/event")
def check_event(req: EventCheckRequest):
    """
    Verifica todos los IOCs de un evento normalizado de N8N.
    Comprueba: IPs externas, hashes, URLs, dominios.
    """
    return checker.check_event(req.event)


@app.post("/check/ip")
def check_ip(req: CheckRequest):
    """Verifica si una IP está en listas negras."""
    return checker.check_ip(req.value)


@app.post("/check/hash")
def check_hash(req: CheckRequest):
    """Verifica si un hash (MD5/SHA1/SHA256) corresponde a malware conocido."""
    return checker.check_hash(req.value)


@app.post("/check/url")
def check_url(req: CheckRequest):
    """Verifica si una URL está en listas de URLs maliciosas."""
    return checker.check_url(req.value)


@app.post("/check/domain")
def check_domain(req: CheckRequest):
    """Verifica si un dominio está en listas de amenazas."""
    return checker.check_domain(req.value)


@app.post("/check/auto")
def check_auto(req: CheckRequest):
    """Detecta automáticamente el tipo de IOC y consulta la tabla correcta."""
    return checker.check_auto(req.value)


# ---------------------------------------------------------------------------
# Endpoints de gestión de feeds
# ---------------------------------------------------------------------------

@app.post("/feeds/update", response_model=FeedUpdateResponse)
def update_feeds(background_tasks: BackgroundTasks):
    """
    Actualiza todos los feeds en background.
    No bloquea la respuesta — retorna inmediatamente.
    """
    global _update_in_progress
    if _update_in_progress:
        return FeedUpdateResponse(status="in_progress", message="Actualización ya en curso")

    background_tasks.add_task(_run_feed_update)
    return FeedUpdateResponse(status="started", message="Actualización de feeds iniciada en background")


@app.post("/feeds/update/sync")
def update_feeds_sync():
    """
    Actualiza todos los feeds de forma síncrona.
    Puede tardar varios segundos. Usar solo para debug/cron.
    """
    global _update_in_progress
    if _update_in_progress:
        return {"status": "in_progress"}
    results = fetcher.fetch_all()
    return {"status": "ok", "results": results}


# ---------------------------------------------------------------------------
# Health & Stats
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    stats = db.get_stats()
    total = sum(v for k, v in stats.items() if k != "feeds" and isinstance(v, int))
    return {
        "status": "ok",
        "service": "ioc-engine",
        "version": "2.1.0",
        "total_iocs": total,
        "last_feed_update": datetime.fromtimestamp(_last_feed_update, timezone.utc).isoformat() if _last_feed_update else None,
        "update_in_progress": _update_in_progress,
    }


@app.get("/stats")
def stats():
    return {
        **db.get_stats(),
        "last_feed_update": _last_feed_update,
        "update_in_progress": _update_in_progress,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ioc_api:app", host="0.0.0.0", port=8746, reload=False, log_level="info")
