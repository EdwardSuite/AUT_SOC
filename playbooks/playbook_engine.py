"""
playbook_engine.py - Motor de Playbooks de Respuesta Automatizada
AUT_SOC - Fase 2.1.E

Ejecuta playbooks de respuesta según el tipo de amenaza detectada.
Diseñado para ser llamado desde N8N después del análisis de IA.

Playbooks disponibles:
  - BRUTE_FORCE    : Notificación CSIRT + recomendación de bloqueo de IP
  - MALWARE        : Alerta urgente + cuarentena de endpoint recomendada
  - DATA_EXFIL     : Escalación inmediata + reporte de incidente
  - KILL_CHAIN     : Activación de respuesta completa multi-equipo
  - LATERAL_SPREAD : Aislamiento de segmento recomendado
  - GENERIC_HIGH   : Playbook genérico para alertas de alta severidad
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

DB_URL = os.getenv("PLAYBOOK_DB_URL", "postgresql://soporte:soporte@localhost:5432/tia")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
QRADAR_URL = os.getenv("QRADAR_URL", "https://192.168.71.54")
QRADAR_TOKEN = os.getenv("QRADAR_TOKEN", "")

SEVERITY_EMOJI = {
    "low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"
}

# ---------------------------------------------------------------------------
# Definición de Playbooks
# ---------------------------------------------------------------------------

PLAYBOOK_DEFINITIONS = {
    "BRUTE_FORCE": {
        "name": "Brute Force Response",
        "description": "Respuesta a ataque de fuerza bruta detectado",
        "priority": "HIGH",
        "sla_minutes": 30,
        "steps": [
            "Identificar IP origen y bloquear en firewall perimetral",
            "Verificar cuentas afectadas y resetear credenciales si hubo éxito",
            "Revisar logs de autenticación en las últimas 24h para la IP",
            "Notificar al propietario del sistema objetivo",
            "Documentar en sistema de tickets",
        ],
        "auto_actions": ["notify_csirt", "log_incident", "qradar_note"],
        "escalate_if": "event_count >= 20 OR sigma_highest_severity == critical",
    },
    "MALWARE": {
        "name": "Malware Incident Response",
        "description": "Respuesta a detección de malware / IOC conocido",
        "priority": "CRITICAL",
        "sla_minutes": 15,
        "steps": [
            "Aislar el endpoint afectado de la red inmediatamente",
            "Preservar evidencia (imagen forense del sistema)",
            "Identificar el vector de infección (email, web, USB)",
            "Escanear otros sistemas en el mismo segmento",
            "Abrir caso P1 en sistema de tickets",
            "Notificar a CISO y equipo de IR",
        ],
        "auto_actions": ["notify_csirt", "log_incident", "qradar_note", "urgent_telegram"],
        "escalate_if": "always",
    },
    "DATA_EXFIL": {
        "name": "Data Exfiltration Response",
        "description": "Respuesta a posible exfiltración de datos",
        "priority": "CRITICAL",
        "sla_minutes": 15,
        "steps": [
            "Bloquear conexión de red saliente identificada",
            "Capturar tráfico para análisis forense de red",
            "Identificar qué datos pudieron haberse exfiltrado",
            "Evaluar obligaciones de notificación (GDPR/regulatorias)",
            "Contactar a CISO y asesoría legal",
            "Preservar logs de todos los sistemas involucrados",
        ],
        "auto_actions": ["notify_csirt", "log_incident", "qradar_note", "urgent_telegram"],
        "escalate_if": "always",
    },
    "KILL_CHAIN": {
        "name": "Full Kill Chain Response",
        "description": "Respuesta a ataque multi-etapa detectado (kill chain completo)",
        "priority": "CRITICAL",
        "sla_minutes": 10,
        "steps": [
            "ACTIVAR PLAN DE RESPUESTA A INCIDENTES MAYOR",
            "Convocar equipo de IR inmediatamente",
            "Aislar segmento de red afectado",
            "Preservar toda evidencia antes de cualquier remediación",
            "Mapear el alcance completo del compromiso",
            "Notificar cadena de mando completa",
            "Considerar notificación a autoridades (si aplica regulación)",
        ],
        "auto_actions": ["notify_csirt", "log_incident", "qradar_note", "urgent_telegram"],
        "escalate_if": "always",
    },
    "LATERAL_SPREAD": {
        "name": "Lateral Movement Response",
        "description": "Respuesta a movimiento lateral detectado en red interna",
        "priority": "HIGH",
        "sla_minutes": 20,
        "steps": [
            "Identificar todos los hosts involucrados",
            "Aislar hosts comprometidos del segmento",
            "Analizar credenciales usadas para el movimiento lateral",
            "Verificar si el origen fue comprometido desde exterior",
            "Revocar credenciales potencialmente comprometidas",
        ],
        "auto_actions": ["notify_csirt", "log_incident", "qradar_note"],
        "escalate_if": "unique_hosts >= 5 OR correlation_max_severity == critical",
    },
    "GENERIC_HIGH": {
        "name": "High Severity Alert Response",
        "description": "Respuesta estándar a alerta de alta severidad",
        "priority": "HIGH",
        "sla_minutes": 60,
        "steps": [
            "Revisar el contexto completo del evento",
            "Verificar si es falso positivo",
            "Si es real: identificar sistemas afectados",
            "Aplicar controles de mitigación según tipo de ataque",
            "Documentar en sistema de tickets",
        ],
        "auto_actions": ["notify_csirt", "log_incident"],
        "escalate_if": "final_score >= 90",
    },
}


# ---------------------------------------------------------------------------
# PlaybookEngine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """Motor de ejecución de playbooks de respuesta."""

    def __init__(self):
        self._ensure_tables()

    def _conn(self):
        return psycopg2.connect(DB_URL)

    def _ensure_tables(self):
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id              SERIAL PRIMARY KEY,
                    execution_id    VARCHAR(32) UNIQUE NOT NULL,
                    playbook        VARCHAR(64) NOT NULL,
                    priority        VARCHAR(16),
                    sla_minutes     INTEGER,
                    alert_id        VARCHAR(64),
                    src_ip          VARCHAR(45),
                    dst_ip          VARCHAR(45),
                    final_score     INTEGER,
                    trigger_reason  TEXT,
                    steps           JSONB,
                    actions_taken   JSONB,
                    status          VARCHAR(32) DEFAULT 'OPEN',
                    created_at      TIMESTAMPTZ DEFAULT NOW(),
                    resolved_at     TIMESTAMPTZ
                );
                CREATE INDEX IF NOT EXISTS idx_pb_exec_created ON playbook_executions(created_at);
                CREATE INDEX IF NOT EXISTS idx_pb_exec_status ON playbook_executions(status);
                """)
            conn.commit()
        logger.info("Tablas de playbooks verificadas")

    # -------------------------------------------------------------------------
    # Selección de playbook
    # -------------------------------------------------------------------------

    def select_playbook(self, alert: dict) -> str:
        """Determina qué playbook ejecutar según los datos del alert."""
        # Prioridad: KILL_CHAIN > MALWARE > DATA_EXFIL > LATERAL_SPREAD > BRUTE_FORCE > GENERIC_HIGH
        patterns = alert.get("correlation_super_alerts", [])
        pattern_names = [p.get("pattern", "") for p in patterns]

        sigma_rules = [m.get("title", "") for m in alert.get("sigma_top_matches", [])]
        sigma_summary = (alert.get("sigma_context_summary") or "").lower()
        ioc_found = alert.get("ioc_found", False)
        ioc_threat = (alert.get("ioc_worst", {}) or {}).get("threat", "") if ioc_found else ""

        if "KILL_CHAIN" in pattern_names:
            return "KILL_CHAIN"
        if ioc_found and any(t in (ioc_threat or "").lower() for t in ["ransomware", "malware", "trojan", "rat"]):
            return "MALWARE"
        if "DATA_EXFIL" in pattern_names or any("exfil" in r.lower() for r in sigma_rules):
            return "DATA_EXFIL"
        if "LATERAL_SPREAD" in pattern_names or any("lateral" in r.lower() for r in sigma_rules):
            return "LATERAL_SPREAD"
        if "BRUTE_FORCE" in pattern_names or any("brute" in r.lower() for r in sigma_rules):
            return "BRUTE_FORCE"
        if ioc_found:
            return "MALWARE"
        return "GENERIC_HIGH"

    # -------------------------------------------------------------------------
    # Ejecución
    # -------------------------------------------------------------------------

    def execute(self, alert: dict, playbook_name: Optional[str] = None) -> dict:
        """Ejecuta el playbook correspondiente para la alerta."""
        if not playbook_name:
            playbook_name = self.select_playbook(alert)

        pb = PLAYBOOK_DEFINITIONS.get(playbook_name, PLAYBOOK_DEFINITIONS["GENERIC_HIGH"])
        execution_id = self._gen_id(alert, playbook_name)

        trigger_reason = self._build_trigger_reason(alert)
        actions_taken = []

        # --- Ejecutar auto-acciones ---
        if "log_incident" in pb["auto_actions"]:
            self._log_to_db(execution_id, playbook_name, pb, alert, trigger_reason)
            actions_taken.append("incident_logged")

        if "notify_csirt" in pb["auto_actions"]:
            self._notify_telegram(alert, pb, execution_id, urgent=False)
            actions_taken.append("csirt_notified")

        if "urgent_telegram" in pb["auto_actions"]:
            self._notify_telegram(alert, pb, execution_id, urgent=True)
            actions_taken.append("urgent_alert_sent")

        if "qradar_note" in pb["auto_actions"] and alert.get("offense_id"):
            self._add_qradar_note(alert, pb, execution_id)
            actions_taken.append("qradar_note_added")

        return {
            "playbook_executed": playbook_name,
            "execution_id": execution_id,
            "priority": pb["priority"],
            "sla_minutes": pb["sla_minutes"],
            "actions_taken": actions_taken,
            "steps": pb["steps"],
            "trigger_reason": trigger_reason,
            "playbook_summary": (
                f"🎯 Playbook [{playbook_name}] ejecutado | "
                f"Prioridad: {pb['priority']} | SLA: {pb['sla_minutes']}min\n"
                f"Razón: {trigger_reason}"
            ),
        }

    # -------------------------------------------------------------------------
    # Acciones
    # -------------------------------------------------------------------------

    def _notify_telegram(self, alert: dict, pb: dict, execution_id: str, urgent: bool):
        """Envía notificación estructurada a Telegram."""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            logger.warning("Telegram no configurado — saltando notificación")
            return

        severity = (alert.get("priority") or alert.get("severity_label") or "high").lower()
        emoji = SEVERITY_EMOJI.get(severity, "🔴")
        prefix = "🚨 *URGENTE*" if urgent else "⚠️ *ALERTA*"

        score = alert.get("final_score", alert.get("risk_score", 0))
        src_ip = alert.get("src_ip", "N/A")
        src_ip_safe = re.sub(r'[^\d\.]', '', src_ip) if src_ip != "N/A" else "N/A"

        lines = [
            f"{prefix} — Playbook {pb['name']}",
            f"",
            f"{emoji} *Severidad:* {severity.upper()} | *Score:* {score}/100",
            f"🌐 *IP Origen:* `{src_ip_safe}`",
            f"🕐 *SLA:* {pb['sla_minutes']} minutos",
            f"📋 *Execution ID:* `{execution_id}`",
            f"",
            f"*Acciones inmediatas:*",
        ]
        for i, step in enumerate(pb["steps"][:3], 1):
            lines.append(f"  {i}. {step}")

        if alert.get("correlation_triggered"):
            lines.append(f"\n🔗 *Correlación:* {alert.get('correlation_summary', '')[:200]}")
        if alert.get("ioc_found"):
            lines.append(f"\n☠️ *IOC:* {alert.get('ioc_summary', '')[:200]}")
        if alert.get("sigma_matched"):
            lines.append(f"\n🔍 *Sigma:* {alert.get('sigma_context_summary', '')[:200]}")

        message = "\n".join(lines)

        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": message,
                      "parse_mode": "Markdown", "disable_web_page_preview": True},
                timeout=10
            )
            logger.info(f"Telegram enviado: {pb['name']} ({execution_id})")
        except Exception as e:
            logger.error(f"Error enviando Telegram: {e}")

    def _add_qradar_note(self, alert: dict, pb: dict, execution_id: str):
        """Añade nota al offense de QRadar."""
        offense_id = alert.get("offense_id") or alert.get("id")
        if not offense_id or not QRADAR_TOKEN:
            return
        note = (
            f"[AUT_SOC Playbook] {pb['name']} ejecutado | ID: {execution_id}\n"
            f"Score: {alert.get('final_score', 0)} | SLA: {pb['sla_minutes']}min\n"
            f"Pasos: {'; '.join(pb['steps'][:3])}"
        )
        try:
            requests.post(
                f"{QRADAR_URL}/api/siem/offenses/{offense_id}/notes",
                headers={"SEC": QRADAR_TOKEN, "Content-Type": "application/json",
                         "Version": "14.0"},
                json={"note_text": note},
                verify=False, timeout=10
            )
            logger.info(f"Nota QRadar añadida al offense {offense_id}")
        except Exception as e:
            logger.error(f"Error añadiendo nota a QRadar: {e}")

    def _log_to_db(self, execution_id: str, playbook_name: str, pb: dict,
                   alert: dict, trigger_reason: str):
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO playbook_executions
                            (execution_id, playbook, priority, sla_minutes, alert_id,
                             src_ip, dst_ip, final_score, trigger_reason, steps, actions_taken)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (execution_id) DO NOTHING
                    """, (
                        execution_id, playbook_name, pb["priority"], pb["sla_minutes"],
                        alert.get("unified_id", ""),
                        alert.get("src_ip", ""), alert.get("dst_ip", ""),
                        int(alert.get("final_score", 0)),
                        trigger_reason, json.dumps(pb["steps"]),
                        json.dumps([])
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error guardando ejecución en BD: {e}")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _gen_id(self, alert: dict, playbook: str) -> str:
        key = f"{playbook}{alert.get('src_ip','')}{alert.get('unified_id','')}{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def _build_trigger_reason(self, alert: dict) -> str:
        parts = []
        if alert.get("sigma_matched"):
            parts.append(f"Sigma:{alert.get('sigma_highest_severity','?').upper()}")
        if alert.get("ioc_found"):
            parts.append(f"IOC:{alert.get('ioc_risk_score',0)}")
        if alert.get("correlation_triggered"):
            patterns = [p.get("pattern") for p in alert.get("correlation_super_alerts", [])]
            parts.append(f"Correlation:{'+'.join(patterns)}")
        score = alert.get("final_score", 0)
        parts.append(f"Score:{score}")
        return " | ".join(parts) if parts else f"Score:{score}"

    def get_open_executions(self, limit: int = 50) -> list:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM playbook_executions
                    WHERE status = 'OPEN'
                    ORDER BY created_at DESC LIMIT %s
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]

    def get_stats(self) -> dict:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) as total FROM playbook_executions WHERE created_at >= NOW() - INTERVAL '24 hours'")
                total_24h = cur.fetchone()["total"]
                cur.execute("SELECT COUNT(*) as open FROM playbook_executions WHERE status = 'OPEN'")
                open_count = cur.fetchone()["open"]
                cur.execute("SELECT playbook, COUNT(*) as cnt FROM playbook_executions GROUP BY playbook ORDER BY cnt DESC")
                by_playbook = {r["playbook"]: r["cnt"] for r in cur.fetchall()}
        return {"executions_24h": total_24h, "open_incidents": open_count, "by_playbook": by_playbook}
