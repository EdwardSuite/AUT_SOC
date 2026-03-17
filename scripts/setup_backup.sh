#!/bin/bash
# ============================================================================
# setup_backup.sh - Instala el sistema de backup automático de AUT_SOC
# Uso: sudo bash setup_backup.sh
# ============================================================================
set -e

BACKUP_DIR="/opt/backups/aut_soc"
SCRIPT_SRC="$(dirname "$0")/backup_n8n.sh"
SCRIPT_DEST="/usr/local/bin/aut_soc_backup.sh"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root: sudo bash setup_backup.sh"; exit 1; }

step "1. Creando directorio de backups"
mkdir -p "$BACKUP_DIR"
chmod 750 "$BACKUP_DIR"
log "Directorio: $BACKUP_DIR"

step "2. Instalando script de backup"
cp "$SCRIPT_SRC" "$SCRIPT_DEST"
chmod +x "$SCRIPT_DEST"
log "Script instalado en: $SCRIPT_DEST"

step "3. Configurando cron (diario 03:00 AM)"
cat > /etc/cron.d/aut-soc-backup << 'EOF'
# AUT_SOC - Backup automático diario a las 03:00 AM
0 3 * * * root /usr/local/bin/aut_soc_backup.sh >> /var/log/aut_soc_backup.log 2>&1
EOF
chmod 644 /etc/cron.d/aut-soc-backup
log "Cron configurado: diario 03:00 AM"

step "4. Ejecutando backup inicial"
bash "$SCRIPT_DEST"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ BACKUP SYSTEM INSTALADO"
echo "  Backups en : $BACKUP_DIR"
echo "  Cron       : diario 03:00 AM"
echo "  Logs       : /var/log/aut_soc_backup.log"
echo "  Manual     : sudo aut_soc_backup.sh"
echo "  Listar     : ls -lh $BACKUP_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
