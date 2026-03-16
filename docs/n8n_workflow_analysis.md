# SOC Pipeline v2 - Mejorado - Análisis Detallado

## Información General del Flujo
- **Nombre:** SOC Pipeline v2 - Mejorado
- **ID:** UkEdz3PlAeB5HgI2
- **URL:** http://192.168.118.64:5678/workflow/UkEdz3PlAeB5HgI2
- **Estado:** Activo
- **Tipo:** Security Operations Center (SOC) Automation Pipeline
- **Última Actualización:** 2026-03-16

## Descripción del Flujo
Pipeline automatizado de seguridad que:
1. Obtiene alertas de QRadar (SIEM)
2. Filtra ruido y duplicados
3. Enriquece datos con múltiples inteligencias de amenazas (AbuseIPDB, GreyNoise, VirusTotal)
4. Normaliza y valida datos
5. Aplica scoring dinámico
6. Utiliza análisis dual con LLMs (Qwen2.5 Junior + DeepSeek R1 Senior)
7. Genera alertas críticas a Telegram
8. Registra métricas y anomalías

## Estructura del Flujo (45+ Nodos)

### 1. Trigger & Validación Inicial
- **Schedule Trigger:** Ejecución programada
- **Health Check (SSH):** Verifica disponibilidad del servidor
- **Port Open?:** Valida puertos abiertos

### 2. Obtención de Alertas
- **Fetch Alerts (API):** GET desde QRadar (192.168.71.54)
  - Endpoint: `/api/siem/offenses?filter=status=OPEN&sort=-last_updated_time`
  - Filtra solo alertas abiertas ordenadas por actualización

### 3. Filtrado y Deduplicación
- **Filter: Noise Reduction v2:** Elimina alertas conocidas (ruido)
- **Has Valid Alerts?:** Condicional - valida que haya alertas
- **Split Alerts (1 por 1):** Procesa alertas de forma individual
- **Normalize Data (JS):** Estandariza formato
- **Generate MD5 Hash:** Crea hash único de alerta
- **Check for Duplicates:** Consulta evento anterior
- **Is Duplicate Alert?:** Condicional - salta procesamiento si es duplicado

### 4. Procesamiento Base
- **Restore Data:** Recupera datos originales
- **Mark as Processed:** Registra en DB (insert)
- **Is Private IP?:** Condicional para determinar si es IP privada

### 5. Enriquecimiento Interno (Private IPs)
- **Enrich: Internal Context Prep:** Prepara contexto
- **Lookup: Asset Inventory:** Consulta inventario de activos
- **Lookup: VIP Users:** Busca usuarios VIP
- **Merge: Internal Enrichment:** Combina enriquecimiento interno

### 6. Enriquecimiento Externo (Public IPs)
- **API Configuration Loader:** Carga configuraciones de APIs
- **Enrich: AbuseIPDB:** Consulta reputación de IPs
- **Enrich: GreyNoise:** Obtiene inteligencia de GreyNoise
- **Consolidate External Enrichment:** Consolida datos externos
- **Enrich: VirusTotal Real:** Análisis en VirusTotal
- **Extract & Validate IPs:** Valida IPs extraídas
- **Correlate: IP Risk Analysis:** Análisis de riesgo de IP

### 7. Análisis con Inteligencia Interna
- **Join: Internal + External:** Combina enriquecimiento
- **Query: Event Memory:** Consulta histórico de eventos
- **Dynamic Scoring (Fase 3):** Calcula score dinámico
- **Update: Event Memory:** Actualiza en DB (insert)

### 8. Análisis Dual con LLMs
- **Build AI Prompt v2:** Construye prompt para IA
- **LLM: Qwen2.5 (Junior):** Análisis inicial
  - Modelo: Qwen2.5:14b (ejecutable localmente)
- **Model: Qwen2.5:14b:** Display de modelo
- **Parse & Validate AI Response:** Valida respuesta
- **Is AI Response Valid?:** Condicional de validación

### 9. Escalación (Si falla análisis junior)
- **Escalation: DeepSeek R1:** Análisis profundo
  - Modelo: DeepSeek R1:14b (razonamiento avanzado)
- **Model: DeepSeek R1:14b:** Display de modelo
- **Clean DeepSeek Response:** Limpia formato
- **Merge Junior & Senior:** Combina análisis

### 10. Almacenamiento y Alertas
- **Save Enriched Alerts:** Guarda en DB (insert)
- **Is Critical Alert?:** Condicional de severidad
- **Telegram: Critical Alert:** Envía alerta crítica a Telegram
- **Collect Metrics:** Recopila métricas
- **Save Metrics:** Guarda métricas en DB
- **Send Alert to Telegram:** Notificación general
- **Log Error to Database:** Registro de errores (insert)

## Integraciones
- **QRadar SIEM:** 192.168.71.54 (alertas en tiempo real)
- **Ollama Local (Qwen2.5:14b):** Análisis iniciales
- **Ollama Local (DeepSeek R1:14b):** Análisis avanzados
- **AbuseIPDB:** Reputación de IPs
- **GreyNoise:** Inteligencia de IPs
- **VirusTotal:** Análisis de amenazas
- **Telegram:** Notificaciones críticas

## Base de Datos
- Múltiples operaciones insert/select/update
- Almacena: Alertas, Métricas, Eventos, Histórico

## Validaciones y Condicionales
1. Has Valid Alerts?
2. Is Duplicate Alert?
3. Is Private IP?
4. Is AI Response Valid?
5. Is Critical Alert?

## Flujo de Lógica
```
Schedule → Health Check → Fetch Alerts → Filter Noise → 
Has Alerts? → Split (1x1) → Normalize → Hash → Check Dup →
Is Dup? → [If Yes: Mark Processed | If No: Restore]
→ Is Private IP?
  → [If Yes: Internal Enrichment | If No: External Enrichment]
→ Join Data → Query Memory → Dynamic Score → Update Memory
→ Build Prompt → Qwen2.5 (Junior) → Validate
  → [If Valid: Proceed | If Invalid: DeepSeek R1 (Senior)]
→ Clean Response → Merge Analysis
→ Save Enriched → Is Critical?
  → [If Critical: Telegram Alert]
→ Collect Metrics → Save Metrics
→ Send Telegram → Log Errors
```

## Estado de Modelos LLM
- ✅ **Qwen2.5:14b** - Instalado y operativo
- ✅ **DeepSeek R1:14b** - Instalado y operativo
- ❌ **Llama 3.2** - PENDIENTE DE DESINSTALAR
- ⏳ **Qwen 2.1** - PENDIENTE DE INSTALAR

## Recomendaciones
1. Implementar timeouts en consultas a APIs externas
2. Agregar retry logic para integraciones
3. Documentar mapeo de severidades dinámicas
4. Implementar alertas de fallos en lógica de scoring
5. Crear dashboard de métricas de ejecución
6. Validar permisos en Telegram Bot
7. Verificar quota de APIs externas (AbuseIPDB, GreyNoise)
8. Implementar rate limiting en consultas
