#!/bin/bash
# ============================================================================
# backup_n8n.sh - Backup automático de N8N + PostgreSQL
# AUT_SOC - Sistema SOC Automatizado
#
# Uso:
#   sudo bash backup_n8n.sh          # backup manual
#   (instalado via setup: cron diario 03:00 AM)
#
# Qué respalda:
#   1. Volumen n8n (workflows, credenciales, configuración)
#   2. Base de datos PostgreSQL (alertas, métricas, historial)
#   3. Configuración de microservicios (sigma, ioc)
#
# Retención: 7 días por defecto (configurable)
# ============================================================================
set -euo pipefail

# --- Configuración -----------------------------------------------------------
BACKUP_DIR="/opt/backups/aut_soc"
RETENTION_DAYS=7
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"

# Contenedores (ajustar si cambian los nombres)
N8N_CONTAINER="n8n_modulo_a"
POSTGRES_CONTAINER="tia_postgres"

# PostgreSQL (ajustar credenciales si es necesario)
PG_USER="soporte"
PG_DB="tia"

# Directorios de microservicios a respaldar
SIGMA_DIR="/opt/docker/sigma-engine"
IOC_DIR="/opt/docker/ioc-engine"

# Colores
GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
log()   { echo -e "${GREEN}[✓] $(date '+%H:%M:%S')${NC} $1"; }
step()  { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
error() { echo -e "${RED}[✗] $1${NC}" >&2; }

# --- Inicialización ----------------------------------------------------------
mkdir -p "$BACKUP_PATH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔒 AUT_SOC BACKUP — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Destino: $BACKUP_PATH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BACKUP_OK=0
BACKUP_FAIL=0

# --- 1. Backup N8N Data Volume -----------------------------------------------
step "1. Backup N8N (workflows + credenciales)"

if docker ps --format '{{.Names}}' | grep -q "^${N8N_CONTAINER}$"; then
    # Obtener la ruta del volumen montado
    N8N_DATA=$(docker inspect "$N8N_CONTAINER" \
        --format '{{range .Mounts}}{{if eq .Destination "/home/node/.n8n"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || echo "")

    if [ -n "$N8N_DATA" ] && [ -d "$N8N_DATA" ]; then
        tar -czf "$BACKUP_PATH/n8n_data.tar.gz" -C "$(dirname "$N8N_DATA")" "$(basename "$N8N_DATA")" 2>/dev/null
        SIZE=$(du -sh "$BACKUP_PATH/n8n_data.tar.gz" | cut -f1)
        log "N8N data: $SIZE (fuente: $N8N_DATA)"
        BACKUP_OK=$((BACKUP_OK + 1))
    else
        # Fallback: backup directo desde el contenedor
        docker cp "$N8N_CONTAINER:/home/node/.n8n" "$BACKUP_PATH/n8n_home" 2>/dev/null && \
        tar -czf "$BACKUP_PATH/n8n_data.tar.gz" -C "$BACKUP_PATH" "n8n_home" && \
        rm -rf "$BACKUP_PATH/n8n_home"
        log "N8N data (via docker cp): OK"
        BACKUP_OK=$((BACKUP_OK + 1))
    fi
else
    error "Contenedor $N8N_CONTAINER no encontrado. Saltando."
    BACKUP_FAIL=$((BACKUP_FAIL + 1))
fi

# --- 2. Backup PostgreSQL ----------------------------------------------------
step "2. Backup PostgreSQL (alertas + métricas)"

if docker ps --format '{{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
    # Dump completo con pg_dumpall para incluir roles
    docker exec "$POSTGRES_CONTAINER" pg_dumpall -U "$PG_USER" 2>/dev/null \
        | gzip > "$BACKUP_PATH/postgres_full.sql.gz"

    SIZE=$(du -sh "$BACKUP_PATH/postgres_full.sql.gz" | cut -f1)
    log "PostgreSQL dump: $SIZE"
    BACKUP_OK=$((BACKUP_OK + 1))
else
    error "Contenedor $POSTGRES_CONTAINER no encontrado. Intentando pg_dump local..."
    if command -v pg_dump &>/dev/null; then
        pg_dump -U "$PG_USER" "$PG_DB" 2>/dev/null | gzip > "$BACKUP_PATH/postgres_dump.sql.gz" && \
        log "PostgreSQL dump local: OK" && BACKUP_OK=$((BACKUP_OK + 1)) || \
        { error "pg_dump falló"; BACKUP_FAIL=$((BACKUP_FAIL + 1)); }
    else
        BACKUP_FAIL=$((BACKUP_FAIL + 1))
    fi
fi

# --- 3. Backup Microservicios ------------------------------------------------
step "3. Backup microservicios (Sigma + IOC)"

for DIR in "$SIGMA_DIR" "$IOC_DIR"; do
    if [ -d "$DIR" ]; then
        NAME=$(basename "$DIR")
        # Excluir venv (muy pesado) y la base SQLite de IOC (se regenera de feeds)
        tar -czf "$BACKUP_PATH/${NAME}.tar.gz" \
            --exclude="${DIR}/venv" \
            --exclude="${DIR}/ioc_database.db" \
            "$DIR" 2>/dev/null
        SIZE=$(du -sh "$BACKUP_PATH/${NAME}.tar.gz" | cut -f1)
        log "$NAME: $SIZE"
        BACKUP_OK=$((BACKUP_OK + 1))
    else
        error "Directorio $DIR no encontrado. Saltando."
    fi
done

# --- 4. Crear manifiesto del backup ------------------------------------------
step "4. Generando manifiesto"

cat > "$BACKUP_PATH/MANIFEST.txt" << EOF
AUT_SOC Backup Manifest
=======================
Timestamp : $TIMESTAMP
Date      : $(date '+%Y-%m-%d %H:%M:%S')
Host      : $(hostname)
Uptime    : $(uptime -p)

Archivos:
$(ls -lh "$BACKUP_PATH"/*.gz "$BACKUP_PATH"/*.txt 2>/dev/null | awk '{print $5, $9}')

Resultado : $BACKUP_OK OK / $BACKUP_FAIL FAIL
EOF

log "Manifiesto creado"

# --- 5. Rotación de backups antiguos ----------------------------------------
step "5. Rotación (retención: ${RETENTION_DAYS} días)"

DELETED=$(find "$BACKUP_DIR" -maxdepth 1 -type d -mtime +$RETENTION_DAYS | wc -l)
find "$BACKUP_DIR" -maxdepth 1 -type d -mtime +$RETENTION_DAYS -exec rm -rf {} + 2>/dev/null || true
log "Backups eliminados (> ${RETENTION_DAYS} días): $DELETED"

# --- Resumen -----------------------------------------------------------------
TOTAL_SIZE=$(du -sh "$BACKUP_PATH" | cut -f1)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ BACKUP COMPLETADO"
echo "  Ubicación : $BACKUP_PATH"
echo "  Tamaño    : $TOTAL_SIZE"
echo "  Resultado : $BACKUP_OK OK / $BACKUP_FAIL FAIL"
echo "  Retención : últimos ${RETENTION_DAYS} días en $BACKUP_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Salir con error si algún backup crítico falló
[ $BACKUP_FAIL -gt 0 ] && exit 1 || exit 0
