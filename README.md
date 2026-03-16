# AUT_SOC - Automated SOC Security Operations Center

![Status](https://img.shields.io/badge/status-Active-green)
![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Descripción General

**AUT_SOC** es una solución de automatización integral para un **Security Operations Center (SOC)** que integra:

- 🔍 **SIEM Integration** (QRadar) - Obtención y correlación de alertas en tiempo real
- 🤖 **Inteligencia Artificial Dual** - Análisis con Qwen2.5 (Junior) y escalación con DeepSeek R1 (Senior)
- 🌐 **Enriquecimiento de Datos** - AbuseIPDB, GreyNoise, VirusTotal, Inventario interno
- 📊 **Scoring Dinámico** - Evaluación automática de riesgo y severidad
- 🔔 **Notificaciones Inteligentes** - Alertas críticas vía Telegram
- 📈 **Métricas y Análisis** - Registro y seguimiento de eventos

El sistema automatiza el ciclo completo de investigación de incidentes de seguridad, desde la detección inicial hasta la escalación y notificación.

## 📋 Características Principales

### 🔐 Seguridad
- ✅ Integración con QRadar SIEM
- ✅ Deduplicación automática de alertas
- ✅ Filtrado de ruido (Noise Reduction v2)
- ✅ Detección de IPs privadas vs públicas
- ✅ Validación de duplicados con hash MD5

### 🧠 Análisis Inteligente
- ✅ Análisis primario con **Qwen2.5:14b**
- ✅ Escalación a **DeepSeek R1:14b** para casos complejos
- ✅ Razonamiento de cadena de pensamiento
- ✅ Parsing y validación automática de respuestas IA

### 📚 Enriquecimiento de Datos
- ✅ Inventario de activos interno
- ✅ Búsqueda de usuarios VIP
- ✅ Consulta de reputación en AbuseIPDB
- ✅ Inteligencia de GreyNoise
- ✅ Análisis de archivos en VirusTotal
- ✅ Correlación de riesgo de IP

## 📦 Requisitos

### Hardware Mínimo
- **CPU**: 4 cores (recomendado 8+)
- **RAM**: 16 GB (para los modelos LLM)
- **Disco**: 50 GB (modelos + base de datos)

### Software Requerido
```
✅ Docker & Docker Compose 2.0+
✅ n8n 1.60+
✅ Ollama (para Qwen2.5 y DeepSeek R1)
✅ PostgreSQL 14+
✅ Python 3.9+
✅ Git 2.30+
```

## 🚀 Instalación Rápida

### 1. Clonar Repositorio
```bash
git clone https://github.com/EdwardSuite/AUT_SOC.git
cd AUT_SOC
```

### 2. Preparar Entorno
```bash
cp config/env.example .env
nano .env  # Editar con tus credenciales
```

### 3. Arrancar Servicios
```bash
docker-compose up -d
```

### 4. Descargar Modelos LLM
```bash
ollama pull qwen2.5:14b
ollama pull deepseek-r1:14b
```

### 5. Acceder a n8n
```
URL: http://192.168.118.64:5678
```

## 📊 Estado del Sistema

| Componente | Puerto | Status |
|-----------|--------|--------|
| n8n | 5678 | ✅ Activo |
| PostgreSQL | 5432 | ✅ Activo |
| Ollama | 11434 | ✅ Activo |

## 📚 Documentación

- **[N8N_WORKFLOW.md](docs/N8N_WORKFLOW.md)** - Guía detallada del flujo
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guía para contribuyentes
- **[CHANGELOG.md](CHANGELOG.md)** - Historial de cambios

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Ver [LICENSE](LICENSE) para más detalles.

## 📞 Contacto

- **GitHub**: [@EdwardSuite](https://github.com/EdwardSuite)
- **Issues**: [AUT_SOC Issues](https://github.com/EdwardSuite/AUT_SOC/issues)

---

**Versión**: 2.0 - Mejorado  
**Estado**: ✅ En Producción  
**Última actualización**: 2026-03-16
