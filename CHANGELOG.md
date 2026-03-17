# Changelog

## [2.2.0] - 2026-03-17

### Added - Fase 2.1.D: Correlation Engine (Multi-Event Pattern Detection)
- **Correlation Engine** - Microservicio FastAPI (puerto 8747) para detección de patrones de ataque
  - `correlation_engine.py`: Motor de correlación sobre PostgreSQL con ventanas de tiempo
  - 5 patrones detectados: BRUTE_FORCE, PORT_SCAN, LATERAL_SPREAD, KILL_CHAIN, C2_BEACONING
  - Genera "Super Alertas" cuando detecta secuencias sospechosas
  - Aporta: `correlation_triggered`, `correlation_risk_bonus`, `correlation_summary` al pipeline
  - Limpieza automática de eventos de correlación (retención 3 días)
- **Sistema de Backup automático** - `scripts/backup_n8n.sh` + `scripts/setup_backup.sh`
  - Backup diario 03:00 AM de: N8N data volume + PostgreSQL dump + microservicios
  - Rotación automática (retención 7 días) en `/opt/backups/aut_soc/`
  - Manifiesto de cada backup con tamaños y resultado
- **VirusTotal condicional** - Nodo IF en N8N que salta VirusTotal en alertas low/medium sin IOC
  - Condición: `severity == high/critical` OR `ioc_found == true`
  - Reducción ~70% de llamadas a la API de VirusTotal
- **N8N workflow actualizado** (54 nodos):
  - Pipeline completo: Normalize → Sigma → IOC → Correlation → MD5 → Enrich → Scoring → LLM
  - Dynamic Scoring acumula bonuses de Sigma + IOC + Correlación
  - Build AI Prompt incluye contexto Sigma, MITRE, IOC y correlación

## [2.1.0] - 2026-03-17

### Added - Fase 2.1.C: IOC Engine (abuse.ch + ThreatFox)
- **IOC Engine** - Microservicio FastAPI (puerto 8746) para verificación de IOCs en tiempo real
  - `ioc_fetcher.py`: Descarga feeds de URLhaus, Feodo Tracker, MalwareBazaar, ThreatFox
  - `ioc_checker.py`: Verificación de IPs, URLs, hashes, dominios contra base SQLite
  - Auto-detección de tipo de IOC (IP/hash/URL/dominio) en `/check/auto`
  - Verificación completa de evento N8N en una sola llamada `/check/event`
  - Cron diario automático (02:00 AM) para actualización de feeds
  - Aporta: `ioc_found`, `ioc_risk_score`, `ioc_risk_bonus`, `ioc_summary` al pipeline

### Added - Fase 2.1.B: MITRE ATT&CK Enricher
- **MitreEnricher** integrado en el Sigma Engine (puerto 8745)
  - Base embebida: 35 técnicas + 14 tácticas de MITRE ATT&CK Enterprise
  - Descarga automática en background del JSON oficial MITRE (700+ técnicas)
  - Nuevos endpoints: `/mitre/technique/{id}`, `/mitre/tactic/{name}`, `/mitre/enrich`
  - Genera `attack_summary` textual listo para incluir en el prompt del LLM

### Added - Fase 2.1.A: Motor de Reglas Sigma
- **Sigma Engine** - Microservicio FastAPI (puerto 8745) que evalúa eventos contra reglas Sigma
  - Motor de matching implementado desde cero en Python (sigma_matcher.py)
  - Soporte completo de: AND/OR/NOT, wildcards, modificadores (contains/startswith/endswith/re)
  - Condiciones complejas: '1 of', 'all of', wildcards en bloques
  - Hot-reload de reglas sin reiniciar el servicio
- **10 reglas Sigma curadas** para el contexto SOC:
  - SSH Brute Force (High), Port Scanning (Medium), C2 Beaconing (High)
  - Data Exfiltration (High), Lateral Movement (High), Privilege Escalation (High)
  - Ransomware Activity (Critical), Credential Dumping (Critical)
  - Web Application Attack (High), Insider Threat (Medium)
- **Mapeo MITRE ATT&CK automático** - Extracción de tácticas y técnicas desde tags Sigma
- **Integración N8N** - Nodos listos para importar en el workflow existente:
  - Nodo HTTP que llama al Sigma Engine post-normalización
  - Nodo Code que mergea resultados y calcula sigma_score_bonus
  - Contexto Sigma incluido automáticamente en prompt del LLM
- **Script de instalación** (setup.sh) con descarga automática de reglas SigmaHQ
- **Servicio systemd** (sigma-engine.service) para gestión del proceso
- **MEMORIA_PROYECTO.md** - Documento de continuidad entre sesiones

### Added - Infraestructura
- `sigma-engine/` - Directorio completo del motor con README detallado
- `docs/MEMORIA_PROYECTO.md` - Memoria persistente del proyecto para continuidad

## [2.0] - 2026-03-16

### Added
- **SOC Pipeline v2 - Mejorado** - Complete workflow redesign
- Dual LLM analysis with Qwen2.5 (Junior) and DeepSeek R1 (Senior)
- Dynamic risk scoring algorithm
- Multi-source threat intelligence enrichment
  - AbuseIPDB integration
  - GreyNoise integration
  - VirusTotal integration
- Internal enrichment with asset inventory and VIP user lookup
- Duplicate alert detection with MD5 hashing
- Telegram critical alert notifications
- Event memory and historical correlation
- Comprehensive metrics collection

### Changed
- Refactored alert processing pipeline for better performance
- Improved error handling and logging
- Enhanced documentation with architecture diagrams

### Fixed
- Alert deduplication issues
- IP classification logic
- Response parsing from LLM models

## [1.0] - 2025-12-01

### Added
- Initial SOC automation pipeline
- QRadar SIEM integration
- Basic alert filtering and processing
- Database storage for alerts
- n8n workflow engine setup
- Ollama local LLM integration
