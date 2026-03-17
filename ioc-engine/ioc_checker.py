"""
ioc_checker.py - Motor de consulta de IOCs
AUT_SOC - Fase 2.1.C

Consulta la base de datos SQLite para verificar si un IP/URL/hash/dominio
es un IOC conocido. Diseñado para ser llamado desde N8N en tiempo real.
"""

import hashlib
import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from ioc_fetcher import DB_PATH

logger = logging.getLogger(__name__)

# Umbral: IOC mayor a N días se considera "posiblemente desactualizado"
IOC_STALE_DAYS = 7

RISK_MULTIPLIER = {
    "C2":           95,
    "malware":      90,
    "botnet":       88,
    "ransomware":   95,
    "phishing":     75,
    "spam":         40,
    "scanning":     55,
    "exploit":      85,
    "trojan":       88,
    "rat":          85,
    "stealer":      80,
}


class IOCChecker:
    """Consulta la base de datos de IOCs para validar indicadores en tiempo real."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _is_stale(self, updated_at: str) -> bool:
        try:
            dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt) > timedelta(days=IOC_STALE_DAYS)
        except Exception:
            return False

    def _calc_risk(self, threat: str, confidence: int = 75) -> int:
        threat_lower = (threat or "").lower()
        base = 60
        for keyword, score in RISK_MULTIPLIER.items():
            if keyword in threat_lower:
                base = max(base, score)
        return min(100, int(base * (confidence / 100)))

    # -------------------------------------------------------------------------
    # Consultas públicas
    # -------------------------------------------------------------------------

    def check_ip(self, ip: str) -> dict:
        """Verifica si una IP está en alguna lista negra."""
        clean_ip = ip.strip().split(":")[0]  # quitar puerto si viene
        if not clean_ip:
            return self._not_found("ip", ip)

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_ips WHERE ip = ?", (clean_ip,)
            ).fetchone()

        if not row:
            return self._not_found("ip", clean_ip)

        return self._build_result(
            ioc_type="ip", value=clean_ip, found=True,
            feed=row["feed"], threat=row["threat"], malware=row["malware"],
            confidence=row["confidence"] or 75,
            updated_at=row["updated_at"],
            extra={"first_seen": row["first_seen"], "last_seen": row["last_seen"]}
        )

    def check_url(self, url: str) -> dict:
        """Verifica si una URL está en listas de URLs maliciosas."""
        url = url.strip()
        if not url:
            return self._not_found("url", url)

        with self._conn() as conn:
            # Match exacto primero
            row = conn.execute("SELECT * FROM ioc_urls WHERE url = ?", (url,)).fetchone()
            if not row:
                # Match por host
                try:
                    host = url.split("/")[2]
                    row = conn.execute("SELECT * FROM ioc_urls WHERE host = ? LIMIT 1", (host,)).fetchone()
                except Exception:
                    pass

        if not row:
            return self._not_found("url", url)

        return self._build_result(
            ioc_type="url", value=url, found=True,
            feed=row["feed"], threat=row["threat"], malware="",
            confidence=80, updated_at=row["updated_at"],
            extra={"matched_url": row["url"], "host": row["host"], "tags": row["tags"]}
        )

    def check_hash(self, hash_value: str) -> dict:
        """Verifica si un hash MD5/SHA1/SHA256 es malware conocido."""
        h = hash_value.strip().lower()
        if not h:
            return self._not_found("hash", hash_value)

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_hashes WHERE hash_value = ?", (h,)
            ).fetchone()

        if not row:
            return self._not_found("hash", h)

        return self._build_result(
            ioc_type="hash", value=h, found=True,
            feed=row["feed"], threat=row["malware"], malware=row["malware"],
            confidence=95, updated_at=row["updated_at"],
            extra={"file_name": row["file_name"], "hash_type": row["hash_type"], "tags": row["tags"]}
        )

    def check_domain(self, domain: str) -> dict:
        """Verifica si un dominio está en listas de amenazas."""
        d = domain.strip().lower()
        if not d:
            return self._not_found("domain", domain)

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_domains WHERE domain = ?", (d,)
            ).fetchone()
            if not row:
                # Buscar subdominio
                parts = d.split(".")
                if len(parts) > 2:
                    parent = ".".join(parts[-2:])
                    row = conn.execute(
                        "SELECT * FROM ioc_domains WHERE domain = ?", (parent,)
                    ).fetchone()

        if not row:
            return self._not_found("domain", d)

        return self._build_result(
            ioc_type="domain", value=d, found=True,
            feed=row["feed"], threat=row["threat"], malware=row["malware"],
            confidence=row["confidence"] or 75,
            updated_at=row["updated_at"],
        )

    def check_auto(self, value: str) -> dict:
        """
        Detecta automáticamente el tipo de IOC y consulta la tabla correcta.
        Ideal para usar desde N8N cuando el tipo no está claro.
        """
        v = value.strip()
        # IP
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", v):
            return self.check_ip(v)
        # Hash (MD5=32, SHA1=40, SHA256=64)
        if re.match(r"^[0-9a-fA-F]{32}$", v):
            return self.check_hash(v)
        if re.match(r"^[0-9a-fA-F]{40}$", v):
            return self.check_hash(v)
        if re.match(r"^[0-9a-fA-F]{64}$", v):
            return self.check_hash(v)
        # URL
        if v.startswith(("http://", "https://", "ftp://")):
            return self.check_url(v)
        # Dominio
        if "." in v and not v.startswith("/"):
            return self.check_domain(v)
        return self._not_found("unknown", v)

    def check_event(self, event: dict) -> dict:
        """
        Verifica todos los IOCs relevantes de un evento N8N en una sola llamada.
        Retorna el resultado más grave encontrado + detalles de todos los checks.
        """
        checks = {}
        found_any = False
        max_risk = 0
        worst_result = None

        # IPs
        for field in ["src_ip", "dst_ip", "source_ip", "destination_ip"]:
            val = event.get(field, "")
            if val and not self._is_private_ip(val):
                result = self.check_ip(val)
                checks[field] = result
                if result["found"] and result["risk_score"] > max_risk:
                    max_risk = result["risk_score"]
                    worst_result = result
                    found_any = True

        # Hashes
        for field in ["md5", "sha1", "sha256", "file_hash", "hash"]:
            val = event.get(field, "")
            if val and len(val) in (32, 40, 64):
                result = self.check_hash(val)
                checks[field] = result
                if result["found"] and result["risk_score"] > max_risk:
                    max_risk = result["risk_score"]
                    worst_result = result
                    found_any = True

        # URLs
        for field in ["url", "uri", "http_url", "request_url"]:
            val = event.get(field, "")
            if val and val.startswith("http"):
                result = self.check_url(val)
                checks[field] = result
                if result["found"] and result["risk_score"] > max_risk:
                    max_risk = result["risk_score"]
                    worst_result = result
                    found_any = True

        # Resumen para N8N
        summary_lines = []
        if found_any:
            summary_lines.append(f"🚨 IOC DETECTADO en {len([c for c in checks.values() if c['found']])} campo(s):")
            for field, res in checks.items():
                if res["found"]:
                    summary_lines.append(
                        f"  • {field}={res['value']} → {res['threat']} "
                        f"(Feed: {res['feed']}, Riesgo: {res['risk_score']})"
                    )
        else:
            summary_lines.append("✅ Ningún IOC encontrado en las fuentes consultadas.")

        return {
            "ioc_found": found_any,
            "ioc_risk_score": max_risk,
            "ioc_risk_bonus": min(max_risk, 40),  # bonus máx 40 para el scoring
            "ioc_worst": worst_result,
            "ioc_checks": checks,
            "ioc_summary": "\n".join(summary_lines),
        }

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
            return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
        except ValueError:
            return False

    def _not_found(self, ioc_type: str, value: str) -> dict:
        return {
            "found": False, "ioc_type": ioc_type, "value": value,
            "feed": None, "threat": None, "malware": None,
            "risk_score": 0, "confidence": 0, "stale": False, "details": {}
        }

    def _build_result(self, ioc_type: str, value: str, found: bool,
                      feed: str, threat: str, malware: str,
                      confidence: int, updated_at: str, extra: dict = None) -> dict:
        risk = self._calc_risk(threat or malware or "", confidence)
        return {
            "found": found,
            "ioc_type": ioc_type,
            "value": value,
            "feed": feed,
            "threat": threat or malware or "malicious",
            "malware": malware,
            "risk_score": risk,
            "confidence": confidence,
            "stale": self._is_stale(updated_at),
            "updated_at": updated_at,
            "details": extra or {},
        }
