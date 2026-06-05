#!/bin/bash
# ============================================================================
# secure_ssh.sh - Script para proteger el puerto SSH
# Configura rate limiting usando UFW para evitar ataques de fuerza bruta
# ============================================================================

set -e

# Configuración
SSH_PORT=5551

# Colores para salida
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "======================================================================"
echo "Iniciando configuración de seguridad SSH (Rate Limiting) - $(date)"
echo "======================================================================"

# Verificar privilegios de root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[ADVERTENCIA]${NC} Este script requiere privilegios de root. Ejecute: sudo bash $0"
    exit 1
fi

# Verificar si ufw está instalado
if ! command -v ufw &> /dev/null; then
    echo "UFW no está instalado. Instalando..."
    apt-get update -qq
    apt-get install -y ufw
fi

# 1. Asegurar que el puerto base esté permitido antes de limitar
echo "Asegurando el puerto SSH ${SSH_PORT}..."
ufw allow ${SSH_PORT}/tcp >/dev/null 2>&1

# 2. Aplicar rate limiting
echo "Aplicando Rate Limiting en el puerto ${SSH_PORT}..."
# limit bloquea conexiones si un IP intenta más de 6 conexiones en 30 segundos
ufw limit ${SSH_PORT}/tcp

# 3. Mostrar estado
echo "======================================================================"
echo "Estado actual de UFW para el puerto ${SSH_PORT}:"
ufw status | grep "${SSH_PORT}/tcp" || echo "UFW inactivo. Active UFW con 'sudo ufw enable' si es seguro."
echo "======================================================================"
echo -e "${GREEN}[ÉXITO]${NC} Configuración completada."
