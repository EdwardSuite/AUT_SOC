# SOC Pipeline v2 - Guía del Flujo n8n

## 📋 Descripción General

El flujo **SOC Pipeline v2 - Mejorado** es un pipeline automatizado de seguridad con:

- **Ingesta**: Obtiene alertas en tiempo real del SIEM QRadar (192.168.71.54)
- **Procesamiento**: Filtra, deduplicación y normalización automática
- **Enriquecimiento**: Consulta múltiples fuentes de inteligencia (AbuseIPDB, GreyNoise, VirusTotal)
- **Análisis IA**: Análisis dual con modelos locales (Qwen2.5 + DeepSeek R1)
- **Escalación**: Escala casos complejos a análisis avanzado
- **Notificación**: Envía alertas críticas a Telegram
- **Logging**: Registra métricas en base de datos

## 🏗️ Estructura del Flujo

### Fases Principales
1. **Trigger & Validación** - Schedule, Health Check, Port Open
2. **Obtención de Alertas** - QRadar API
3. **Filtrado y Deduplicación** - Noise Reduction, Hash MD5
4. **Clasificación** - Private vs Public IP
5. **Enriquecimiento** - Internal o External según IP
6. **Análisis Dual** - Qwen2.5 → DeepSeek R1 (si falla)
7. **Almacenamiento** - Save enriched alerts
8. **Notificación** - Telegram critical alerts
9. **Métricas** - Collect & save metrics
10. **Finalización** - Log errors

## 🔌 Integraciones

### SIEM
- **QRadar**: 192.168.71.54 (alertas en tiempo real)

### APIs Externas
- **AbuseIPDB**: Reputación de IPs
- **GreyNoise**: Inteligencia de IPs  
- **VirusTotal**: Análisis de amenazas

### Modelos LLM (Ollama)
- **Qwen2.5:14b** - Análisis rápido (Junior)
- **DeepSeek R1:14b** - Razonamiento profundo (Senior)

### Notificaciones
- **Telegram Bot** - Alertas críticas

### Base de Datos
- **PostgreSQL** - Almacenamiento de alertas, métricas, eventos

## 📊 Nodos Principales (45+)

| # | Nodo | Tipo | Función |
|----|------|------|---------|
| 1 | Schedule Trigger | Trigger | Ejecución programada |
| 2 | Health Check | SSH | Validación servidor |
| 3 | Port Open? | Condicional | Validación puertos |
| 4 | Fetch Alerts | HTTP GET | QRadar offenses |
| 5 | Filter: Noise Reduction | Lógica | Elimina ruido |
| 6 | Has Valid Alerts? | Condicional | Valida alertas |
| 7 | Split Alerts | Loop | Procesa 1 x 1 |
| 8 | Normalize Data | JS | Estandariza formato |
| 9 | Generate MD5 Hash | Función | Hash único |
| 10 | Check for Duplicates | DB Select | Consulta histórico |
| ... | +35 nodos más | | |

## ⚙️ Configuración Requerida

### Credenciales en n8n

1. **QRadar API Key**
   ```
   Settings → Credentials → QRadar
   API_KEY: tu_api_key_aqui
   ```

2. **External APIs**
   - AbuseIPDB API Key
   - GreyNoise API Key
   - VirusTotal API Key

3. **Telegram Bot**
   - Bot Token: obtener de @BotFather
   - Chat ID: enviar /start al bot

### Variables de Entorno

Ver `config/env.example` para lista completa.

## 🔍 Validación del Flujo

✅ **45+ nodos** - Todos operativos
✅ **10 fases** - Pipeline completado
✅ **Dual LLM** - Qwen2.5 + DeepSeek R1
✅ **Multi-source** - 8 integraciones
✅ **Database** - PostgreSQL configurada
✅ **Notifications** - Telegram activo

## 📖 Más Información

- [README.md](../README.md) - Documentación completa
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribuir al proyecto
- GitHub Issues - Reportar problemas

---

**Última actualización**: 2026-03-16
**Versión**: 2.0 - Mejorado
