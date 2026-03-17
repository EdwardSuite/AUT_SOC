"""
playbook_api.py - API REST del Motor de Playbooks
AUT_SOC - Fase 2.1.E

FastAPI en puerto 8748. N8N lo llama cuando detecta una alerta que
requiere respuesta automatizada (score >= 75 o patrón crítico).

Endpoints:
  POST /execute          - Ejecuta el playbook apropiado para la alerta
  POST /execute/{name}   - Fuerza un playbook específico
  GET  /incidents        - Lista incidentes abiertos
  PATCH /incidents/{id}  - Cierra/actualiza un incidente
  GET  /stats            - Estadísticas de playbooks ejecutados
  GET  /playbooks        - Lista todos los playbooks disponibles
  GET  /health           - Health check
"""

import logging
import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from playbook_engine import PlaybookEngine, PLAYBOOK_DEFINITIONS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("playbook_api")

PORT = int(os.getenv("PLAYBOOK_PORT", "8748"))
engine = PlaybookEngine()


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    alert: dict[str, Any]
    force_playbook: Optional[str] = None

class UpdateIncidentRequest(BaseModel):
    status: str  # OPEN, RESOLVED, FALSE_POSITIVE
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AUT_SOC Playbook Engine",
    description="Motor de playbooks de respuesta automatizada - Fase 2.1.E",
    version="2.1.0",
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/execute")
def execute_playbook(req: ExecuteRequest):
    """
    Selecciona y ejecuta el playbook apropiado para la alerta.
    Si force_playbook está definido, usa ese playbook directamente.
    """
    playbook_name = req.force_playbook or None
    result = engine.execute(req.alert, playbook_name)
    logger.info(f"Playbook ejecutado: {result['playbook_executed']} | ID: {result['execution_id']}")
    return result


@app.post("/execute/{playbook_name}")
def execute_specific_playbook(playbook_name: str, req: ExecuteRequest):
    """Ejecuta un playbook específico por nombre."""
    if playbook_name.upper() not in PLAYBOOK_DEFINITIONS:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_name}' no encontrado. Disponibles: {list(PLAYBOOK_DEFINITIONS.keys())}"
        )
    result = engine.execute(req.alert, playbook_name.upper())
    return result


@app.get("/incidents")
def get_open_incidents(limit: int = 50):
    """Lista los incidentes abiertos (playbooks ejecutados pendientes de resolución)."""
    incidents = engine.get_open_executions(limit=limit)
    return {"count": len(incidents), "incidents": incidents}


@app.patch("/incidents/{execution_id}")
def update_incident(execution_id: str, req: UpdateIncidentRequest):
    """Actualiza el estado de un incidente (cierre, falso positivo, etc.)."""
    valid_statuses = ["OPEN", "RESOLVED", "FALSE_POSITIVE", "IN_PROGRESS"]
    if req.status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Status inválido. Válidos: {valid_statuses}")

    import psycopg2
    try:
        with engine._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE playbook_executions
                    SET status = %s,
                        resolved_at = CASE WHEN %s IN ('RESOLVED','FALSE_POSITIVE') THEN NOW() ELSE resolved_at END
                    WHERE execution_id = %s
                    RETURNING id
                """, (req.status.upper(), req.status.upper(), execution_id))
                result = cur.fetchone()
            conn.commit()
        if not result:
            raise HTTPException(status_code=404, detail=f"Incidente {execution_id} no encontrado")
        return {"execution_id": execution_id, "status": req.status.upper(), "updated": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/playbooks")
def list_playbooks():
    """Lista todos los playbooks disponibles con sus definiciones."""
    return {
        name: {
            "name": pb["name"],
            "description": pb["description"],
            "priority": pb["priority"],
            "sla_minutes": pb["sla_minutes"],
            "steps_count": len(pb["steps"]),
            "auto_actions": pb["auto_actions"],
        }
        for name, pb in PLAYBOOK_DEFINITIONS.items()
    }


@app.get("/stats")
def get_stats():
    """Estadísticas de ejecución de playbooks."""
    return {
        **engine.get_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    try:
        stats = engine.get_stats()
        return {
            "status": "ok",
            "service": "playbook-engine",
            "version": "2.1.0",
            "open_incidents": stats["open_incidents"],
            "executions_24h": stats["executions_24h"],
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("playbook_api:app", host="0.0.0.0", port=PORT,
                reload=False, log_level="info")
