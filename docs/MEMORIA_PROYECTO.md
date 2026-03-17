# 🧠 MEMORIA DEL PROYECTO - AUT_SOC

> **Documento de continuidad**: Este archivo es la fuente de verdad del estado actual del proyecto.
> Se actualiza en cada sesión de trabajo. Claude lo lee al iniciar para retomar contexto.

---

## 📌 INFORMACIÓN BASE

| Campo | Valor |
|-------|-------|
| **Repo GitHub** | https://github.com/EdwardSuite/AUT_SOC |
| **Workflow N8N** | http://192.168.118.64:5678/workflow/UkEdz3PlAeB5HgI2 |
| **Servidor** | Ubuntu 24.04 @ 192.168.118.64 (SSH puerto 5551, user: soporte) |
| **Dashboard NocoDB** | http://192.168.118.64:8080 |
| **Ollama API** | http://192.168.118.64:11434 |

---

## 🏗️ ARQUITECTURA ACTUAL (v2.0)

```
QRadar SIEM (192.168.71.54)
    ↓ [GET offenses API]
N8N Schedule Trigger (cada X min)
    ↓
Health Check (SSH) → Port Validation
    ↓
Filter: Noise Reduction v2
    ↓
Normalize → MD5 Hash → Dedup Check
    ↓
┌─────────────────┬──────────────────┐
│   IP Privada    │    IP Pública    │
│ Asset Inventory │  AbuseIPDB       │
│ VIP Users       │  GreyNoise       │
│                 │  VirusTotal      │
└────────┬────────┴────────┬─────────┘
         └────────┬────────┘
                  ↓
    Query Event Memory (PostgreSQL)
    Dynamic Scoring (Fase 3)
    Update Event Memory
                  ↓
    Build AI Prompt v2
                  ↓
    Qwen2.5:14b (Junior LLM)
         ↓ [Si falla]
    DeepSeek R1:14b (Senior LLM)
                  ↓
    Save Enriched Alerts (PostgreSQL)
    Is Critical? → Telegram Alert
    Collect & Save Metrics
```

### Modelos LLM activos en servidor:
- `qwen:latest` → 2.3 GB (usado como Junior)
- `deepseek-r1:7b` → 4.7 GB (usado como Senior)
> ⚠️ El README menciona :14b pero el servidor tiene :latest y :7b

### Servicios Docker activos:
| Contenedor | Puerto | Estado |
|-----------|--------|--------|
| n8n_modulo_a | 5678 | ✅ Up |
| tia_dashboard (NocoDB) | 8080 | ✅ Up |
| tia_postgres | 5432 | ✅ Up |
| tia_redis | 6379 | ✅ Up |

---

## 📊 HISTORIAL DE VERSIONES

### v1.0 (2025-12-01) - MVP
- Pipeline básico QRadar → N8N
- Filtrado simple y almacenamiento DB
- LLM básico con Ollama

### v2.0 (2026-03-16) - Producción
- Dual LLM (Qwen2.5 Junior + DeepSeek R1 Senior)
- Scoring dinámico de riesgo
- Enriquecimiento multi-fuente (AbuseIPDB, GreyNoise, VirusTotal)
- Deduplicación por MD5
- Alertas Telegram para críticos
- 45+ nodos en N8N
- Documentación completa en repo

---

## 🚧 FASE 2.1 - EN DESARROLLO

**Estado**: 🔄 En ejecución (2026-03-17)
**Objetivo**: Integrar capacidades de detección avanzada inspiradas en proyectos de referencia

### Proyectos de referencia analizados:
1. **[DetectFlow (SOC Prime)](https://github.com/socprime/detectflow-main)**
   - Motor de reglas Sigma en streaming (Kafka + Flink)
   - Pre-filtering para reducción de falsos positivos
   - Dashboard en tiempo real de métricas de pipeline
   - Hot-reload de reglas sin reiniciar pipeline
   - → *Concepto adaptable*: Motor Sigma ligero + pre-filtros dinámicos en N8N

2. **[SigmaHQ](https://github.com/SigmaHQ/sigma)**
   - Estándar abierto de reglas de detección (YAML)
   - Miles de reglas para distintos SIEMs/plataformas
   - → *Adaptable*: Evaluar alertas QRadar contra reglas Sigma relevantes

3. **[Sigma CLI / pySigma](https://github.com/SigmaHQ/pySigma)**
   - Librería Python para procesar reglas Sigma
   - → *Adaptable*: Nodo Python en N8N que evalúe reglas contra eventos

### Mejoras Planificadas para Fase 2.1:

#### 🔴 PRIORIDAD ALTA

**2.1.A - Motor de Reglas Sigma**
- FastAPI microservicio en puerto 8745 (`sigma-engine/sigma_api.py`)
- Motor de matching completo con AND/OR/NOT, wildcards, modificadores (`sigma_matcher.py`)
- 10 reglas curadas + descarga automática de SigmaHQ en setup
- Nodos N8N listos para importar (`sigma-engine/n8n_sigma_nodes.json`)
- `setup.sh` + systemd service para deploy en servidor
- **Pendiente: ejecutar setup.sh en 192.168.118.64 y agregar nodos en N8N**
- Estado: ✅ CÓDIGO COMPLETO — ⬜ DEPLOY EN SERVIDOR PENDIENTE

**2.1.B - Mapeo MITRE ATT&CK**
- Enriquecer cada alerta con táctica/técnica MITRE
- Fuente: mapeo de reglas Sigma + categoría de QRadar
- Output: campos `mitre_tactic`, `mitre_technique`, `mitre_id`
- Integración: añadir al prompt de IA para mejor contexto
- Estado: ⬜ Pendiente

**2.1.C - Feed de IOCs Gratuitos (Abuse.ch + OTX)**
- Integrar feeds: URLhaus, MalwareBazaar, Feodo Tracker
- Consulta en tiempo real: ¿el IOC aparece en algún feed?
- Comparar IPs, dominios, hashes contra listas negras actualizadas
- Actualización diaria automática vía cron
- Estado: ⬜ Pendiente

#### 🟡 PRIORIDAD MEDIA

**2.1.D - Correlación Multi-Evento (Patrones)**
- Detectar secuencias de eventos sospechosas
  - Ej: múltiples alertas del mismo src_ip en < 5 min = posible brute force
  - Ej: alert tipo "recon" seguida de "lateral movement" = kill chain
- Usar PostgreSQL para ventanas de tiempo
- Generar "Super Alert" cuando se detecta patrón
- Estado: ✅ COMPLETO — puerto 8747, 5 patrones, integrado en N8N

**2.1.E - Playbooks de Respuesta Automatizada**
- Sub-workflows N8N según tipo de amenaza:
  - `playbook_brute_force.json` → bloqueo temporal + notificación CSIRT
  - `playbook_malware.json` → cuarentena endpoint + ticket urgente
  - `playbook_data_exfil.json` → bloqueo red + escalación inmediata
- Trigger: scoring > threshold + categoría específica
- Estado: ✅ COMPLETO — puerto 8748, 6 playbooks, integrado en N8N (56 nodos)

**2.1.F - Dashboard NocoDB Mejorado**
- Aprovechar NocoDB en puerto 8080 (ya activo)
- Vistas: Alertas por severidad, Top IPs, Tendencias temporales
- KPIs: MTTD, MTTR, Alertas por día, Efectividad IA
- Estado: ⬜ Pendiente

#### 🟢 PRIORIDAD BAJA

**2.1.G - Retroalimentación al SIEM**
- Cerrar el loop: enviar análisis de vuelta a QRadar
- Actualizar offense con notas del análisis IA
- Cambiar status en QRadar si se confirma FP
- Estado: ⬜ Pendiente

**2.1.H - Ajuste de Modelos LLM**
- Evaluar si actualizar a versiones :14b de modelos
- Pruebas de latencia: qwen vs deepseek en alertas reales
- Prompt engineering mejorado con contexto MITRE
- Estado: ⬜ Pendiente

---

## ✅ TAREAS COMPLETADAS

| Fecha | Tarea | Resultado |
|-------|-------|-----------|
| 2026-03-16 | Diagnóstico completo servidor | Mapeados todos los servicios |
| 2026-03-16 | Optimización storage | +6GB libres (71%→67%) |
| 2026-03-16 | Swap llama3 → qwen:latest | qwen:latest instalado (2.3GB) |
| 2026-03-16 | Documentación v2.0 | README + N8N_WORKFLOW.md |
| 2026-03-17 | Análisis DetectFlow & Sigma | Plan Fase 2.1 definido |
| 2026-03-17 | Creación MEMORIA_PROYECTO.md | Este documento |
| 2026-03-17 | **Sigma Engine completo (2.1.A)** | sigma_api.py + sigma_matcher.py + 10 reglas + setup.sh + n8n_sigma_nodes.json |
| 2026-03-17 | **MITRE ATT&CK Enricher (2.1.B)** | mitre_enricher.py + endpoints /mitre/* en sigma_api.py |
| 2026-03-17 | **IOC Engine completo (2.1.C)** | ioc_api.py + ioc_fetcher.py + ioc_checker.py + setup.sh (puerto 8746) |
| 2026-03-17 | **deploy_server.sh** | Script unico para instalar todo en el servidor |
| 2026-03-17 | **Backup automático (scripts/)** | backup_n8n.sh + setup_backup.sh, cron 03:00 AM |
| 2026-03-17 | **Correlation Engine (2.1.D)** | correlation_engine.py + correlation_api.py, 5 patrones, puerto 8747 |
| 2026-03-17 | **VirusTotal condicional** | IF node en N8N, skip en low/medium sin IOC |
| 2026-03-17 | **N8N 54 nodos** | Pipeline completo con Sigma+IOC+Correlación integrados |
| 2026-03-17 | **Playbook Engine (2.1.E)** | playbook_engine.py + playbook_api.py, 6 playbooks, puerto 8748 |
| 2026-03-17 | **N8N 56 nodos** | IF: Playbook Needed? + Playbook Engine - Execute integrados |
| 2026-03-17 | **deploy_server.sh v2** | Script único para 4 microservicios + backup |

---

## 🔴 PROBLEMAS CONOCIDOS / DEUDA TÉCNICA

| # | Problema | Impacto | Estado |
|---|---------|---------|--------|
| 1 | N8N database.sqlite = 2.2GB (crece) | Puede afectar performance | ⚠️ Monitorear |
| 2 | Modelos en servidor son :latest/:7b, no :14b | Capacidad IA menor | ⚠️ Evaluar upgrade |
| 3 | Sin rate limiting en SSH (puerto 5551) | Riesgo de brute force | ⚠️ Pendiente |
| 4 | APIs externas sin timeout/retry | Pipeline puede colgarse | ⚠️ Pendiente |
| 5 | Sin backup de n8n database.sqlite | Pérdida de workflows | ✅ Resuelto (scripts/backup_n8n.sh) |

---

## 🗺️ ROADMAP GENERAL

```
v1.0 (dic 2025) ✅ → MVP básico
v2.0 (mar 2026) ✅ → Pipeline completo dual-LLM
v2.1 (en curso) 🔄 → Sigma + MITRE + IOC feeds + Correlación
v2.2 (futuro)   ⬜ → Playbooks + Dashboard + Retroalimentación SIEM
v3.0 (futuro)   ⬜ → ML propio + Threat Hunting automatizado
```

---

## 📋 INSTRUCCIONES PARA CLAUDE (PRÓXIMA SESIÓN)

Al iniciar una nueva sesión sobre este proyecto:

1. **Leer este archivo primero**: `docs/MEMORIA_PROYECTO.md`
2. **Verificar estado del servidor**: SSH a 192.168.118.64:5551 (user: soporte)
3. **Revisar workflow N8N**: http://192.168.118.64:5678/workflow/UkEdz3PlAeB5HgI2
4. **Continuar por**: la primera tarea con estado ⬜ Pendiente en Fase 2.1
5. **Actualizar este doc**: al final de cada sesión registrar avances

---

*Última actualización: 2026-03-17 sesión 3 | Por: Claude Code (Anthropic)*
