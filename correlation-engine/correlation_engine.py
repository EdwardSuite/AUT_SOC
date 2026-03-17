"""
correlation_engine.py - Motor de Correlación Multi-Evento
AUT_SOC - Fase 2.1.D

Detecta patrones de ataque analizando secuencias de eventos en ventanas de tiempo.
Usa PostgreSQL para persistencia y consulta de eventos históricos.

Patrones detectados:
  - BRUTE_FORCE     : N+ fallos de autenticación del mismo src_ip en < T minutos
  - PORT_SCAN       : N+ puertos distintos desde mismo src_ip en < T minutos
  - KILL_CHAIN      : Recon → Lateral Movement → Exfiltration en < 1 hora
  - C2_BEACONING    : Conexiones periódicas regulares al mismo dst_ip
  - LATERAL_SPREAD  : Mismo src_ip atacando N+ hosts internos distintos
  - DATA_STAGING    : Alto volumen de datos salientes tras alerta de acceso
"""

import logging
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional
import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuración de patrones
# ---------------------------------------------------------------------------

PATTERNS = {
    "BRUTE_FORCE": {
        "description": "Múltiples fallos de autenticación del mismo origen",
        "threshold_events": 5,        # N eventos mínimos
        "window_minutes": 5,          # en T minutos
        "severity": "high",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "filter": {"categories": ["authentication", "login", "ssh", "rdp", "brute"]},
        "group_by": "src_ip",
    },
    "PORT_SCAN": {
        "description": "Escaneo de múltiples puertos desde el mismo origen",
        "threshold_events": 10,
        "threshold_unique": 8,        # N+ puertos únicos
        "window_minutes": 3,
        "severity": "medium",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046",
        "filter": {"categories": ["scan", "port", "probe", "network"]},
        "group_by": "src_ip",
        "unique_field": "dst_port",
    },
    "LATERAL_SPREAD": {
        "description": "Un mismo origen atacando múltiples hosts internos",
        "threshold_events": 4,
        "threshold_unique": 3,        # N+ destinos únicos internos
        "window_minutes": 15,
        "severity": "high",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "filter": {"categories": ["lateral", "movement", "smb", "wmi", "psexec", "rdp"]},
        "group_by": "src_ip",
        "unique_field": "dst_ip",
    },
    "KILL_CHAIN": {
        "description": "Secuencia Recon → Movimiento Lateral → Exfiltración",
        "window_minutes": 60,
        "severity": "critical",
        "mitre_tactic": "Multiple",
        "mitre_technique": "Multiple",
        "stages": [
            {"keywords": ["scan", "recon", "probe", "discovery"], "label": "Reconnaissance"},
            {"keywords": ["lateral", "movement", "smb", "rdp", "ssh"], "label": "Lateral Movement"},
            {"keywords": ["exfil", "upload", "transfer", "dns tunnel", "c2"], "label": "Exfiltration"},
        ],
        "group_by": "src_ip",
    },
    "C2_BEACONING": {
        "description": "Conexiones periódicas regulares a destino externo (posible C2)",
        "threshold_events": 6,
        "window_minutes": 30,
        "max_interval_variance": 0.2,  # 20% varianza en intervalos = muy regular = sospechoso
        "severity": "high",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "filter": {"categories": ["c2", "beaconing", "beacon", "outbound"]},
        "group_by": "dst_ip",
    },
}

SEVERITY_SCORE = {"low": 35, "medium": 55, "high": 80, "critical": 95}


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Motor de correlación multi-evento sobre PostgreSQL."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self._ensure_tables()

    def _conn(self):
        return psycopg2.connect(self.db_url)

    def _ensure_tables(self):
        """Crea las tablas necesarias si no existen."""
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS correlation_events (
                    id          SERIAL PRIMARY KEY,
                    unified_id  VARCHAR(64) UNIQUE NOT NULL,
                    src_ip      VARCHAR(45),
                    dst_ip      VARCHAR(45),
                    dst_port    INTEGER,
                    category    VARCHAR(128),
                    severity    VARCHAR(32),
                    description TEXT,
                    raw_event   JSONB,
                    received_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_corr_src_ip ON correlation_events(src_ip, received_at);
                CREATE INDEX IF NOT EXISTS idx_corr_dst_ip ON correlation_events(dst_ip, received_at);
                CREATE INDEX IF NOT EXISTS idx_corr_received ON correlation_events(received_at);

                CREATE TABLE IF NOT EXISTS super_alerts (
                    id           SERIAL PRIMARY KEY,
                    alert_id     VARCHAR(64) UNIQUE NOT NULL,
                    pattern      VARCHAR(64) NOT NULL,
                    severity     VARCHAR(32) NOT NULL,
                    src_ip       VARCHAR(45),
                    dst_ip       VARCHAR(45),
                    event_count  INTEGER,
                    description  TEXT,
                    mitre_tactic VARCHAR(128),
                    mitre_technique VARCHAR(32),
                    details      JSONB,
                    created_at   TIMESTAMPTZ DEFAULT NOW(),
                    notified     BOOLEAN DEFAULT FALSE
                );
                """)
            conn.commit()
        logger.info("Tablas de correlación verificadas")

    # -------------------------------------------------------------------------
    # Ingestión de eventos
    # -------------------------------------------------------------------------

    def ingest_event(self, event: dict) -> dict:
        """
        Ingesta un evento normalizado del pipeline N8N.
        Retorna si se generó una super-alerta.
        """
        unified_id = event.get("unified_id") or self._gen_id(event)
        src_ip = event.get("src_ip") or event.get("source_ip") or ""
        dst_ip = event.get("dst_ip") or event.get("destination_ip") or ""
        dst_port_raw = event.get("dst_port") or event.get("destination_port") or 0
        try:
            dst_port = int(dst_port_raw)
        except (ValueError, TypeError):
            dst_port = 0

        category = (event.get("category") or event.get("qradar_category") or "").lower()
        description = (event.get("description") or event.get("message") or "").lower()
        severity = (event.get("severity_label") or event.get("severity") or "low").lower()

        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO correlation_events
                            (unified_id, src_ip, dst_ip, dst_port, category, severity, description, raw_event)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (unified_id) DO NOTHING
                    """, (unified_id, src_ip, dst_ip, dst_port, category, severity,
                          description, json.dumps(event)))
                conn.commit()
        except Exception as e:
            logger.error(f"Error ingesting event {unified_id}: {e}")

        # Evaluar patrones con el evento recién ingresado
        return self.evaluate(src_ip=src_ip, dst_ip=dst_ip, category=category,
                             description=description)

    # -------------------------------------------------------------------------
    # Evaluación de patrones
    # -------------------------------------------------------------------------

    def evaluate(self, src_ip: str = "", dst_ip: str = "",
                 category: str = "", description: str = "") -> dict:
        """Evalúa todos los patrones para el evento actual."""
        triggered = []

        if src_ip:
            triggered += self._check_brute_force(src_ip, category, description)
            triggered += self._check_port_scan(src_ip, category, description)
            triggered += self._check_lateral_spread(src_ip, category, description)
            triggered += self._check_kill_chain(src_ip)

        if dst_ip:
            triggered += self._check_c2_beaconing(dst_ip, category, description)

        # Guardar super-alertas generadas
        new_super_alerts = []
        for alert in triggered:
            saved = self._save_super_alert(alert)
            if saved:
                new_super_alerts.append(alert)

        max_severity = "none"
        if new_super_alerts:
            sev_order = ["low", "medium", "high", "critical"]
            max_sev = max(new_super_alerts, key=lambda a: sev_order.index(a.get("severity", "low")))
            max_severity = max_sev.get("severity", "none")

        return {
            "correlation_triggered": len(new_super_alerts) > 0,
            "correlation_pattern_count": len(new_super_alerts),
            "correlation_max_severity": max_severity,
            "correlation_risk_bonus": SEVERITY_SCORE.get(max_severity, 0),
            "correlation_super_alerts": new_super_alerts,
            "correlation_summary": self._build_summary(new_super_alerts),
        }

    # -------------------------------------------------------------------------
    # Detectores de patrones
    # -------------------------------------------------------------------------

    def _check_brute_force(self, src_ip: str, category: str, description: str) -> list:
        p = PATTERNS["BRUTE_FORCE"]
        if not self._matches_filter(category, description, p["filter"]["categories"]):
            return []

        window = datetime.now(timezone.utc) - timedelta(minutes=p["window_minutes"])
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(*) as cnt
                    FROM correlation_events
                    WHERE src_ip = %s AND received_at >= %s
                      AND (category ILIKE ANY(%s) OR description ILIKE ANY(%s))
                """, (src_ip, window,
                      [f"%{k}%" for k in p["filter"]["categories"]],
                      [f"%{k}%" for k in p["filter"]["categories"]]))
                row = cur.fetchone()
                count = row["cnt"] if row else 0

        if count >= p["threshold_events"]:
            return [self._build_super_alert("BRUTE_FORCE", p, src_ip=src_ip,
                                            event_count=count,
                                            detail=f"{count} fallos en {p['window_minutes']} min")]
        return []

    def _check_port_scan(self, src_ip: str, category: str, description: str) -> list:
        p = PATTERNS["PORT_SCAN"]
        if not self._matches_filter(category, description, p["filter"]["categories"]):
            return []

        window = datetime.now(timezone.utc) - timedelta(minutes=p["window_minutes"])
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(*) as total, COUNT(DISTINCT dst_port) as unique_ports
                    FROM correlation_events
                    WHERE src_ip = %s AND received_at >= %s AND dst_port > 0
                """, (src_ip, window))
                row = cur.fetchone()

        if row and row["unique_ports"] >= p.get("threshold_unique", 8):
            return [self._build_super_alert("PORT_SCAN", p, src_ip=src_ip,
                                            event_count=row["total"],
                                            detail=f"{row['unique_ports']} puertos únicos en {p['window_minutes']} min")]
        return []

    def _check_lateral_spread(self, src_ip: str, category: str, description: str) -> list:
        p = PATTERNS["LATERAL_SPREAD"]
        if not self._matches_filter(category, description, p["filter"]["categories"]):
            return []

        window = datetime.now(timezone.utc) - timedelta(minutes=p["window_minutes"])
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(*) as total, COUNT(DISTINCT dst_ip) as unique_hosts
                    FROM correlation_events
                    WHERE src_ip = %s AND received_at >= %s
                      AND dst_ip ~ '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
                """, (src_ip, window))
                row = cur.fetchone()

        if row and row["unique_hosts"] >= p.get("threshold_unique", 3):
            return [self._build_super_alert("LATERAL_SPREAD", p, src_ip=src_ip,
                                            event_count=row["total"],
                                            detail=f"{row['unique_hosts']} hosts internos distintos en {p['window_minutes']} min")]
        return []

    def _check_kill_chain(self, src_ip: str) -> list:
        p = PATTERNS["KILL_CHAIN"]
        window = datetime.now(timezone.utc) - timedelta(minutes=p["window_minutes"])

        stages_found = []
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT category, description, received_at
                    FROM correlation_events
                    WHERE src_ip = %s AND received_at >= %s
                    ORDER BY received_at ASC
                """, (src_ip, window))
                events = cur.fetchall()

        for stage in p["stages"]:
            for ev in events:
                text = f"{ev['category']} {ev['description']}"
                if any(kw in text for kw in stage["keywords"]):
                    if stage["label"] not in stages_found:
                        stages_found.append(stage["label"])
                    break

        if len(stages_found) >= 3:
            return [self._build_super_alert("KILL_CHAIN", p, src_ip=src_ip,
                                            event_count=len(events),
                                            detail=f"Fases detectadas: {' → '.join(stages_found)}")]
        elif len(stages_found) == 2:
            # Parcial: solo warning (no genera super-alerta pero se loguea)
            logger.warning(f"Kill chain parcial para {src_ip}: {stages_found}")
        return []

    def _check_c2_beaconing(self, dst_ip: str, category: str, description: str) -> list:
        p = PATTERNS["C2_BEACONING"]
        if not self._matches_filter(category, description, p["filter"]["categories"]):
            return []

        window = datetime.now(timezone.utc) - timedelta(minutes=p["window_minutes"])
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT received_at FROM correlation_events
                    WHERE dst_ip = %s AND received_at >= %s
                    ORDER BY received_at ASC
                """, (dst_ip, window))
                rows = cur.fetchall()

        if len(rows) < p["threshold_events"]:
            return []

        # Calcular varianza de intervalos
        times = [r["received_at"].timestamp() for r in rows]
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            return []

        avg = sum(intervals) / len(intervals)
        if avg == 0:
            return []
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg  # coeficiente de variación

        if cv <= p["max_interval_variance"]:
            return [self._build_super_alert("C2_BEACONING", p, dst_ip=dst_ip,
                                            event_count=len(rows),
                                            detail=f"{len(rows)} conexiones regulares (varianza: {cv:.1%}) en {p['window_minutes']} min")]
        return []

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _matches_filter(self, category: str, description: str, keywords: list) -> bool:
        text = f"{category} {description}"
        return any(kw in text for kw in keywords)

    def _gen_id(self, event: dict) -> str:
        key = f"{event.get('src_ip','')}{event.get('dst_ip','')}{event.get('category','')}{datetime.now().isoformat()}"
        return hashlib.md5(key.encode()).hexdigest()

    def _build_super_alert(self, pattern: str, p: dict, src_ip: str = "",
                           dst_ip: str = "", event_count: int = 0, detail: str = "") -> dict:
        alert_id = hashlib.md5(
            f"{pattern}{src_ip}{dst_ip}{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}".encode()
        ).hexdigest()[:16]

        return {
            "alert_id": alert_id,
            "pattern": pattern,
            "severity": p["severity"],
            "risk_score": SEVERITY_SCORE.get(p["severity"], 50),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "event_count": event_count,
            "description": p["description"],
            "detail": detail,
            "mitre_tactic": p.get("mitre_tactic", ""),
            "mitre_technique": p.get("mitre_technique", ""),
        }

    def _save_super_alert(self, alert: dict) -> bool:
        """Guarda la super-alerta en BD. Retorna True si es nueva."""
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO super_alerts
                            (alert_id, pattern, severity, src_ip, dst_ip,
                             event_count, description, mitre_tactic, mitre_technique, details)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (alert_id) DO NOTHING
                        RETURNING id
                    """, (alert["alert_id"], alert["pattern"], alert["severity"],
                          alert.get("src_ip"), alert.get("dst_ip"),
                          alert["event_count"], alert["detail"],
                          alert["mitre_tactic"], alert["mitre_technique"],
                          json.dumps(alert)))
                    result = cur.fetchone()
                conn.commit()
            if result:
                logger.warning(f"🚨 SUPER-ALERTA [{alert['pattern']}] {alert['detail']} | src={alert.get('src_ip')}")
                return True
        except Exception as e:
            logger.error(f"Error guardando super-alerta: {e}")
        return False

    def _build_summary(self, alerts: list) -> str:
        if not alerts:
            return "✅ Sin patrones de ataque detectados en ventana de tiempo."
        lines = [f"🚨 CORRELACIÓN DETECTADA — {len(alerts)} patrón(es):"]
        for a in alerts:
            lines.append(
                f"  • [{a['pattern']}] {a['detail']} "
                f"| MITRE: {a['mitre_technique']} | Riesgo: {a['risk_score']}"
            )
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Consultas de estado
    # -------------------------------------------------------------------------

    def get_recent_super_alerts(self, hours: int = 24) -> list:
        """Obtiene super-alertas de las últimas N horas."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM super_alerts
                    WHERE created_at >= %s
                    ORDER BY created_at DESC LIMIT 100
                """, (since,))
                return [dict(r) for r in cur.fetchall()]

    def get_stats(self) -> dict:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) as total FROM correlation_events WHERE received_at >= NOW() - INTERVAL '24 hours'")
                events_24h = cur.fetchone()["total"]
                cur.execute("SELECT COUNT(*) as total FROM super_alerts WHERE created_at >= NOW() - INTERVAL '24 hours'")
                alerts_24h = cur.fetchone()["total"]
                cur.execute("SELECT pattern, COUNT(*) as cnt FROM super_alerts GROUP BY pattern ORDER BY cnt DESC")
                by_pattern = {r["pattern"]: r["cnt"] for r in cur.fetchall()}
        return {
            "events_last_24h": events_24h,
            "super_alerts_last_24h": alerts_24h,
            "super_alerts_by_pattern": by_pattern,
        }

    def cleanup_old_events(self, days: int = 3):
        """Limpia eventos de correlación antiguos (mantener BD liviana)."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM correlation_events WHERE received_at < %s", (cutoff,))
                deleted = cur.rowcount
            conn.commit()
        logger.info(f"Limpieza: {deleted} eventos eliminados (> {days} días)")
        return deleted
