"""
ioc_fetcher.py - Descargador de feeds IOC
AUT_SOC - Fase 2.1.C

Descarga y actualiza listas de IOCs desde fuentes open-source gratuitas:
  - URLhaus    (abuse.ch) - URLs maliciosas activas
  - Feodo      (abuse.ch) - IPs de botnets C2 (Emotet, Dridex, TrickBot...)
  - MalwareBazaar (abuse.ch) - Hashes de malware
  - Threat Fox (abuse.ch) - IOCs multitipos
  - OTX Pulse  (AlienVault) - Opcional (requiere API key)
"""

import csv
import gzip
import io
import json
import logging
import sqlite3
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("./ioc_database.db")

FEEDS = {
    "urlhaus_online": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "type": "url",
        "format": "csv",
        "description": "URLhaus - URLs maliciosas activas",
        "field_map": {"url": 2, "threat": 5, "tags": 8},
        "comment_char": "#",
    },
    "feodo_ipblocklist": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "ip",
        "format": "json",
        "description": "Feodo Tracker - IPs C2 de botnets",
    },
    "malwarebazaar_recent": {
        "url": "https://mb-api.abuse.ch/api/v1/",
        "type": "hash",
        "format": "json_post",
        "post_data": {"query": "get_recent", "selector": "100"},
        "description": "MalwareBazaar - Hashes recientes",
    },
    "threatfox_iocs": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "multi",
        "format": "json_post",
        "post_data": {"query": "get_iocs", "days": 3},
        "description": "ThreatFox - IOCs recientes (3 días)",
    },
}


class IOCDatabase:
    """Base de datos SQLite para almacenar IOCs."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ioc_ips (
                    ip          TEXT PRIMARY KEY,
                    feed        TEXT NOT NULL,
                    threat      TEXT,
                    malware     TEXT,
                    confidence  INTEGER DEFAULT 50,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ioc_urls (
                    url         TEXT PRIMARY KEY,
                    feed        TEXT NOT NULL,
                    threat      TEXT,
                    host        TEXT,
                    tags        TEXT,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ioc_hashes (
                    hash_value  TEXT PRIMARY KEY,
                    hash_type   TEXT DEFAULT 'sha256',
                    feed        TEXT NOT NULL,
                    file_name   TEXT,
                    malware     TEXT,
                    tags        TEXT,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ioc_domains (
                    domain      TEXT PRIMARY KEY,
                    feed        TEXT NOT NULL,
                    threat      TEXT,
                    malware     TEXT,
                    confidence  INTEGER DEFAULT 50,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS feed_metadata (
                    feed_name   TEXT PRIMARY KEY,
                    last_update TEXT,
                    record_count INTEGER DEFAULT 0,
                    status      TEXT DEFAULT 'pending'
                );

                CREATE INDEX IF NOT EXISTS idx_ioc_ips_updated ON ioc_ips(updated_at);
                CREATE INDEX IF NOT EXISTS idx_ioc_hashes_type ON ioc_hashes(hash_type);
            """)
        logger.info(f"Base de datos IOC inicializada: {self.db_path}")

    def upsert_ips(self, ips: list[dict], feed: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """INSERT INTO ioc_ips (ip, feed, threat, malware, confidence, first_seen, last_seen, updated_at)
                   VALUES (:ip, :feed, :threat, :malware, :confidence, :first_seen, :last_seen, :updated_at)
                   ON CONFLICT(ip) DO UPDATE SET
                     threat=excluded.threat, malware=excluded.malware,
                     confidence=excluded.confidence, last_seen=excluded.last_seen,
                     updated_at=excluded.updated_at""",
                [{**ip, "feed": feed, "updated_at": now} for ip in ips]
            )
        logger.info(f"[{feed}] {len(ips)} IPs insertadas/actualizadas")

    def upsert_urls(self, urls: list[dict], feed: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """INSERT INTO ioc_urls (url, feed, threat, host, tags, updated_at)
                   VALUES (:url, :feed, :threat, :host, :tags, :updated_at)
                   ON CONFLICT(url) DO UPDATE SET
                     threat=excluded.threat, tags=excluded.tags, updated_at=excluded.updated_at""",
                [{**u, "feed": feed, "updated_at": now} for u in urls]
            )
        logger.info(f"[{feed}] {len(urls)} URLs insertadas/actualizadas")

    def upsert_hashes(self, hashes: list[dict], feed: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """INSERT INTO ioc_hashes (hash_value, hash_type, feed, file_name, malware, tags, updated_at)
                   VALUES (:hash_value, :hash_type, :feed, :file_name, :malware, :tags, :updated_at)
                   ON CONFLICT(hash_value) DO UPDATE SET
                     malware=excluded.malware, tags=excluded.tags, updated_at=excluded.updated_at""",
                [{**h, "feed": feed, "updated_at": now} for h in hashes]
            )

    def upsert_domains(self, domains: list[dict], feed: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                """INSERT INTO ioc_domains (domain, feed, threat, malware, confidence, updated_at)
                   VALUES (:domain, :feed, :threat, :malware, :confidence, :updated_at)
                   ON CONFLICT(domain) DO UPDATE SET
                     threat=excluded.threat, malware=excluded.malware, updated_at=excluded.updated_at""",
                [{**d, "feed": feed, "updated_at": now} for d in domains]
            )

    def update_feed_metadata(self, feed: str, count: int, status: str):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO feed_metadata (feed_name, last_update, record_count, status)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(feed_name) DO UPDATE SET
                     last_update=excluded.last_update,
                     record_count=excluded.record_count,
                     status=excluded.status""",
                (feed, now, count, status)
            )

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            for table in ["ioc_ips", "ioc_urls", "ioc_hashes", "ioc_domains"]:
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                stats[table] = row[0] if row else 0
            feeds = conn.execute("SELECT feed_name, last_update, record_count, status FROM feed_metadata").fetchall()
            stats["feeds"] = [{"name": f[0], "last_update": f[1], "records": f[2], "status": f[3]} for f in feeds]
        return stats


class IOCFetcher:
    """Descarga y procesa feeds de IOCs de múltiples fuentes."""

    def __init__(self, db: IOCDatabase, otx_api_key: str = ""):
        self.db = db
        self.otx_api_key = otx_api_key
        self.headers = {
            "User-Agent": "AUT_SOC-IOC-Engine/2.1 (github.com/EdwardSuite/AUT_SOC)",
            "Accept": "application/json",
        }

    def _get(self, url: str, timeout: int = 30) -> bytes:
        req = urllib.request.Request(url, headers=self.headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def _post_json(self, url: str, data: dict, timeout: int = 30) -> dict:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={**self.headers, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    # -------------------------------------------------------------------------

    def fetch_feodo(self) -> int:
        """Descarga IPs C2 de Feodo Tracker (botnets: Emotet, Dridex, TrickBot, Cobalt Strike)."""
        feed = "feodo_ipblocklist"
        try:
            data = json.loads(self._get("https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
            ips = []
            for entry in data:
                ips.append({
                    "ip": entry.get("ip_address", ""),
                    "threat": "C2",
                    "malware": entry.get("malware", ""),
                    "confidence": 90,
                    "first_seen": entry.get("first_seen", ""),
                    "last_seen": entry.get("last_seen", ""),
                })
            ips = [i for i in ips if i["ip"]]
            self.db.upsert_ips(ips, feed)
            self.db.update_feed_metadata(feed, len(ips), "ok")
            logger.info(f"[Feodo] {len(ips)} IPs C2 descargadas")
            return len(ips)
        except Exception as e:
            logger.error(f"[Feodo] Error: {e}")
            self.db.update_feed_metadata(feed, 0, f"error: {e}")
            return 0

    def fetch_urlhaus(self) -> int:
        """Descarga URLs maliciosas activas de URLhaus."""
        feed = "urlhaus_online"
        try:
            raw = self._get("https://urlhaus.abuse.ch/downloads/csv_online/").decode("utf-8", errors="ignore")
            urls = []
            for line in raw.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split('","')
                if len(parts) < 6:
                    continue
                url_val = parts[2].strip('"')
                threat = parts[5].strip('"') if len(parts) > 5 else ""
                host = url_val.split("/")[2] if "/" in url_val else url_val
                tags = parts[8].strip('"') if len(parts) > 8 else ""
                if url_val.startswith("http"):
                    urls.append({"url": url_val[:500], "threat": threat, "host": host[:255], "tags": tags[:255]})
            self.db.upsert_urls(urls, feed)
            self.db.update_feed_metadata(feed, len(urls), "ok")
            logger.info(f"[URLhaus] {len(urls)} URLs descargadas")
            return len(urls)
        except Exception as e:
            logger.error(f"[URLhaus] Error: {e}")
            self.db.update_feed_metadata(feed, 0, f"error: {e}")
            return 0

    def fetch_malwarebazaar(self) -> int:
        """Descarga hashes de malware recientes de MalwareBazaar."""
        feed = "malwarebazaar_recent"
        try:
            resp = self._post_json(
                "https://mb-api.abuse.ch/api/v1/",
                {"query": "get_recent", "selector": "100"}
            )
            hashes = []
            for sample in resp.get("data", []):
                hashes.append({
                    "hash_value": sample.get("sha256_hash", ""),
                    "hash_type": "sha256",
                    "file_name": (sample.get("file_name") or "")[:255],
                    "malware": (sample.get("signature") or "")[:255],
                    "tags": json.dumps(sample.get("tags", []))[:255],
                })
            hashes = [h for h in hashes if h["hash_value"]]
            self.db.upsert_hashes(hashes, feed)
            # También MD5 y SHA1 como índice secundario
            for sample in resp.get("data", []):
                for h_type in ["md5_hash", "sha1_hash"]:
                    h_val = sample.get(h_type, "")
                    if h_val:
                        self.db.upsert_hashes([{
                            "hash_value": h_val,
                            "hash_type": h_type.replace("_hash", ""),
                            "file_name": (sample.get("file_name") or "")[:255],
                            "malware": (sample.get("signature") or "")[:255],
                            "tags": "",
                        }], feed)
            self.db.update_feed_metadata(feed, len(hashes), "ok")
            logger.info(f"[MalwareBazaar] {len(hashes)} hashes descargados")
            return len(hashes)
        except Exception as e:
            logger.error(f"[MalwareBazaar] Error: {e}")
            self.db.update_feed_metadata(feed, 0, f"error: {e}")
            return 0

    def fetch_threatfox(self) -> int:
        """Descarga IOCs multi-tipo de ThreatFox (últimos 3 días)."""
        feed = "threatfox_iocs"
        try:
            resp = self._post_json(
                "https://threatfox-api.abuse.ch/api/v1/",
                {"query": "get_iocs", "days": 3}
            )
            ips, domains, urls_list, hashes = [], [], [], []

            for ioc in (resp.get("data") or []):
                ioc_type = ioc.get("ioc_type", "")
                value = ioc.get("ioc", "")
                threat = ioc.get("threat_type", "")
                malware = ioc.get("malware_printable", "")
                confidence = ioc.get("confidence_level", 50)

                if ioc_type in ("ip:port",):
                    ip = value.split(":")[0]
                    ips.append({"ip": ip, "threat": threat, "malware": malware,
                                "confidence": confidence, "first_seen": "", "last_seen": ""})
                elif ioc_type == "domain":
                    domains.append({"domain": value[:255], "threat": threat,
                                    "malware": malware, "confidence": confidence})
                elif ioc_type == "url":
                    host = value.split("/")[2] if "/" in value else value
                    urls_list.append({"url": value[:500], "threat": threat,
                                      "host": host[:255], "tags": malware[:255]})
                elif ioc_type in ("sha256_hash", "md5_hash", "sha1_hash"):
                    hashes.append({"hash_value": value, "hash_type": ioc_type.replace("_hash", ""),
                                   "file_name": "", "malware": malware, "tags": threat[:255]})

            if ips:      self.db.upsert_ips(ips, feed)
            if domains:  self.db.upsert_domains(domains, feed)
            if urls_list: self.db.upsert_urls(urls_list, feed)
            if hashes:   self.db.upsert_hashes(hashes, feed)

            total = len(ips) + len(domains) + len(urls_list) + len(hashes)
            self.db.update_feed_metadata(feed, total, "ok")
            logger.info(f"[ThreatFox] {total} IOCs: {len(ips)} IPs, {len(domains)} dominios, {len(urls_list)} URLs, {len(hashes)} hashes")
            return total
        except Exception as e:
            logger.error(f"[ThreatFox] Error: {e}")
            self.db.update_feed_metadata(feed, 0, f"error: {e}")
            return 0

    def fetch_all(self) -> dict:
        """Ejecuta todos los feeds y retorna resumen."""
        results = {}
        start = time.time()
        for name, fn in [
            ("feodo", self.fetch_feodo),
            ("urlhaus", self.fetch_urlhaus),
            ("malwarebazaar", self.fetch_malwarebazaar),
            ("threatfox", self.fetch_threatfox),
        ]:
            try:
                results[name] = fn()
            except Exception as e:
                results[name] = f"error: {e}"
        results["elapsed_seconds"] = round(time.time() - start, 1)
        results["total_iocs"] = sum(v for v in results.values() if isinstance(v, int))
        return results
