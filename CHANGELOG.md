# Changelog

## [2.1.0] - 2026-03-17

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
