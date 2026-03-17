"""
sigma_api.py - API REST del Motor Sigma
AUT_SOC - Fase 2.1.A

FastAPI server que expone el motor Sigma como microservicio HTTP.
N8N llama a este servicio vía HTTP Request node después de normalizar el evento.

Endpoints:
  POST /evaluate         - Evalúa un evento contra todas las reglas
  GET  /health           - Health check
  GET  /rules            - Lista reglas cargadas
  GET  /reload           - Recarga reglas desde disco
  GET  /stats            - Estadísticas del motor
"""

import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from rules_loader import RulesLoader

# ---------------------------------------------------------------------------
# Configuración de logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sigma_api")

# ---------------------------------------------------------------------------
# Modelos Pydantic
# ---------------------------------------------------------------------------

class EvaluateRequest(BaseModel):
    """Cuerpo de la petición de evaluación."""
    event: dict[str, Any]
    max_rules: Optional[int] = None       # Limitar nº de reglas evaluadas (debug)
    min_severity: Optional[str] = None    # Filtrar: solo reglas >= esta severidad


class RuleMatch(BaseModel):
    rule_id: str
    rule_title: str
    rule_file: str
    severity: str
    risk_score: int
    description: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    tags: list[str]
    false_positives: list[str]


class EvaluateResponse(BaseModel):
    """Respuesta de la evaluación para N8N."""
    # ¿Hubo algún match?
    sigma_matched: bool
    match_count: int

    # Detalle de cada regla que hizo match
    matches: list[RuleMatch]

    # Resumen agregado para enriquecer el evento
    highest_severity: str
    sigma_risk_score: int            # Score de riesgo basado en la regla más grave
    mitre_tactics: list[str]        # Tácticas únicas de todos los matches
    mitre_techniques: list[str]     # Técnicas únicas de todos los matches
    sigma_tags: list[str]           # Tags únicos de todos los matches

    # Para el prompt de IA
    sigma_context_summary: str

    # Metadatos
    rules_evaluated: int
    evaluation_time_ms: float


SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# ---------------------------------------------------------------------------
# Instancia global del loader (se inicializa en el lifespan)
# ---------------------------------------------------------------------------
loader = RulesLoader(rules_dir="./rules")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Cargar reglas al arrancar el servicio."""
    count = loader.load_all()
    logger.info(f"✅ Sigma Engine listo - {count} reglas cargadas")
    yield
    logger.info("🛑 Sigma Engine apagado")


# ---------------------------------------------------------------------------
# App FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AUT_SOC Sigma Engine",
    description="Motor de reglas Sigma para detección de amenazas - Fase 2.1.A",
    version="2.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Health check — usado por N8N y el ping_service."""
    return {
        "status": "ok",
        "service": "sigma-engine",
        "version": "2.1.0",
        "rules_loaded": len(loader.rules),
        "last_loaded_ts": loader.last_loaded,
    }


@app.get("/stats")
def stats():
    """Estadísticas de la carga de reglas."""
    severity_counts = {}
    for level in SEVERITY_ORDER:
        severity_counts[level] = len(loader.get_rules_by_severity(level))

    return {
        **loader.get_stats(),
        "severity_distribution": severity_counts,
    }


@app.get("/rules")
def list_rules(severity: Optional[str] = None, limit: int = 100):
    """Lista las reglas cargadas (opcionalmente filtradas por severidad)."""
    rules = loader.rules
    if severity:
        rules = loader.get_rules_by_severity(severity)

    return {
        "total": len(rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.level,
                "mitre_techniques": r.mitre_techniques,
                "tags": r.tags,
                "file": r.filename,
            }
            for r in rules[:limit]
        ],
    }


@app.post("/reload")
def reload_rules():
    """Recarga las reglas desde disco sin reiniciar el servicio (hot-reload)."""
    count = loader.load_all()
    return {
        "status": "reloaded",
        "rules_loaded": count,
        "errors": len(loader.load_errors),
        "load_errors": loader.load_errors[:5],
    }


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate_event(req: EvaluateRequest):
    """
    Evalúa un evento normalizado de QRadar contra todas las reglas Sigma.

    El evento debe estar normalizado por N8N (campos en minúsculas, etc.)
    Retorna todos los matches con contexto MITRE ATT&CK y score de riesgo.
    """
    if not loader.rules:
        raise HTTPException(status_code=503, detail="No hay reglas cargadas. Llama a /reload.")

    start_time = time.perf_counter()

    # Auto-reload si las reglas tienen más de 5 min
    loader.reload_if_needed(max_age_seconds=300)

    # Filtrar por severidad mínima si se especifica
    rules_to_eval = loader.rules
    if req.min_severity and req.min_severity in SEVERITY_ORDER:
        min_idx = SEVERITY_ORDER.index(req.min_severity)
        rules_to_eval = [r for r in rules_to_eval if SEVERITY_ORDER.index(r.level) >= min_idx]

    if req.max_rules:
        rules_to_eval = rules_to_eval[:req.max_rules]

    # Evaluar cada regla
    matches = []
    for rule in rules_to_eval:
        try:
            if rule.matches(req.event):
                matches.append(rule)
        except Exception as e:
            logger.warning(f"Error evaluando regla '{rule.title}': {e}")

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # -----------------------------------------------------------------------
    # Construir respuesta agregada
    # -----------------------------------------------------------------------
    if not matches:
        return EvaluateResponse(
            sigma_matched=False,
            match_count=0,
            matches=[],
            highest_severity="none",
            sigma_risk_score=0,
            mitre_tactics=[],
            mitre_techniques=[],
            sigma_tags=[],
            sigma_context_summary="No se encontraron coincidencias con reglas Sigma.",
            rules_evaluated=len(rules_to_eval),
            evaluation_time_ms=round(elapsed_ms, 2),
        )

    # Determinar severidad más alta
    match_levels = [m.level for m in matches]
    highest_severity = max(match_levels, key=lambda x: SEVERITY_ORDER.index(x) if x in SEVERITY_ORDER else 0)
    max_risk_score = max(m.risk_score for m in matches)

    # Consolidar MITRE ATT&CK
    all_tactics = list(dict.fromkeys(t for m in matches for t in m.mitre_tactics))
    all_techniques = list(dict.fromkeys(t for m in matches for t in m.mitre_techniques))
    all_tags = list(dict.fromkeys(t for m in matches for t in m.tags))

    # Resumen para el prompt de IA
    context_parts = [f"🚨 Sigma detectó {len(matches)} regla(s) coincidente(s):"]
    for m in matches[:5]:  # Top 5 para no saturar el prompt
        context_parts.append(
            f"  • [{m.level.upper()}] {m.title}"
            + (f" | MITRE: {', '.join(m.mitre_techniques)}" if m.mitre_techniques else "")
        )
    if len(matches) > 5:
        context_parts.append(f"  ... y {len(matches) - 5} reglas más.")
    if all_tactics:
        context_parts.append(f"  Tácticas ATT&CK: {', '.join(all_tactics)}")
    if all_techniques:
        context_parts.append(f"  Técnicas ATT&CK: {', '.join(all_techniques)}")

    sigma_summary = "\n".join(context_parts)

    logger.info(
        f"Evaluación completada: {len(matches)} matches en {elapsed_ms:.1f}ms "
        f"| Severidad máx: {highest_severity} | Técnicas: {all_techniques[:3]}"
    )

    return EvaluateResponse(
        sigma_matched=True,
        match_count=len(matches),
        matches=[RuleMatch(**m.to_match_result()) for m in matches],
        highest_severity=highest_severity,
        sigma_risk_score=max_risk_score,
        mitre_tactics=all_tactics,
        mitre_techniques=all_techniques,
        sigma_tags=all_tags,
        sigma_context_summary=sigma_summary,
        rules_evaluated=len(rules_to_eval),
        evaluation_time_ms=round(elapsed_ms, 2),
    )


# ---------------------------------------------------------------------------
# Entry point para ejecución directa
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "sigma_api:app",
        host="0.0.0.0",
        port=8745,
        reload=False,
        log_level="info",
    )
