#!/bin/bash
# ============================================================================
# backup_n8n.sh - Script de respaldo automatizado para n8n
# Realiza una copia de seguridad de la base de datos database.sqlite de n8n
# Recomendado para ejecutar diariamente vía cron
# ============================================================================

set -e

# Configuración
N8N_CONTAINER_NAME="soc_n8n"
BACKUP_DIR="/opt/docker/backups/n8n"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/n8n_backup_${TIMESTAMP}.sqlite"
DB_PATH_IN_CONTAINER="/home/node/.n8n/database.sqlite"
RETENTION_DAYS=7

# Colores para salida
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "======================================================================"
echo "Iniciando proceso de respaldo de n8n - $(date)"
echo "======================================================================"

# 1. Crear directorio de respaldo si no existe
mkdir -p "$BACKUP_DIR"

# 2. Verificar si el contenedor de n8n está en ejecución
if ! docker ps --format '{{.Names}}' | grep -q "^${N8N_CONTAINER_NAME}$"; then
    echo -e "${RED}[ERROR]${NC} El contenedor ${N8N_CONTAINER_NAME} no está en ejecución."
    exit 1
fi

# 3. Realizar el respaldo copiando el archivo desde el contenedor
echo "Copiando base de datos desde el contenedor ${N8N_CONTAINER_NAME}..."
if docker cp "${N8N_CONTAINER_NAME}:${DB_PATH_IN_CONTAINER}" "$BACKUP_FILE"; then
    echo -e "${GREEN}[ÉXITO]${NC} Respaldo completado correctamente."
    echo "Archivo guardado en: $BACKUP_FILE"

    # Mostrar el tamaño del archivo de respaldo
    FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Tamaño del respaldo: $FILE_SIZE"
else
    echo -e "${RED}[ERROR]${NC} Falló la copia de seguridad de la base de datos."
    exit 1
fi

# 4. Limpieza de respaldos antiguos (retención)
echo "Ejecutando limpieza de respaldos antiguos (más de ${RETENTION_DAYS} días)..."
find "$BACKUP_DIR" -name "n8n_backup_*.sqlite" -type f -mtime +${RETENTION_DAYS} -exec rm {} \;
echo -e "${GREEN}[INFO]${NC} Limpieza completada."

echo "======================================================================"
echo "Proceso finalizado con éxito - $(date)"
echo "======================================================================"
