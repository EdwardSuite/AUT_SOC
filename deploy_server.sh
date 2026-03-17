#!/bin/bash
# ============================================================================
# deploy_server.sh - Deploy completo AUT_SOC en servidor Ubuntu
# Ejecutar directamente en el servidor: sudo bash deploy_server.sh
#
# Instala:
#   - Sigma Engine        (puerto 8745) - Reglas Sigma + MITRE ATT&CK
#   - IOC Engine          (puerto 8746) - Feeds abuse.ch
#   - Correlation Engine  (puerto 8747) - Detección de patrones multi-evento
#   - Playbook Engine     (puerto 8748) - Respuesta automatizada a incidentes
#   - Backup automático   (cron 03:00 AM)
#
# Variables opcionales:
#   TELEGRAM_BOT_TOKEN  - Para notificaciones de playbooks
#   TELEGRAM_CHAT_ID    - Chat ID del canal SOC
#   QRADAR_TOKEN        - Token API QRadar para añadir notas
# ============================================================================

set -e
REPO="https://github.com/EdwardSuite/AUT_SOC.git"
DEPLOY_BASE="/opt/docker"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root: sudo bash deploy_server.sh"; exit 1; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🚀 AUT_SOC - DEPLOY COMPLETO"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

step "1. Clonando/actualizando repo AUT_SOC"
cd /tmp
rm -rf AUT_SOC_deploy
git clone "$REPO" AUT_SOC_deploy
log "Repo clonado desde GitHub"

step "2. Instalando Sigma Engine (puerto 8745)"
bash /tmp/AUT_SOC_deploy/sigma-engine/setup.sh

step "3. Instalando IOC Engine (puerto 8746)"
bash /tmp/AUT_SOC_deploy/ioc-engine/setup.sh

step "4. Instalando Correlation Engine (puerto 8747)"
bash /tmp/AUT_SOC_deploy/correlation-engine/setup.sh

step "5. Instalando Playbook Engine (puerto 8748)"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}" \
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}" \
QRADAR_TOKEN="${QRADAR_TOKEN:-}" \
bash /tmp/AUT_SOC_deploy/playbooks/setup.sh

step "6. Configurando backup automático"
bash /tmp/AUT_SOC_deploy/scripts/setup_backup.sh

step "7. Verificando servicios"
sleep 5
SERVICES=("sigma-engine" "ioc-engine" "correlation-engine" "playbook-engine")
ALL_OK=true
for svc in "${SERVICES[@]}"; do
  if systemctl is-active --quiet "$svc"; then
    log "$svc ACTIVO"
  else
    fail "$svc no inició — ver: journalctl -u $svc -n 20"
    ALL_OK=false
  fi
done

step "8. Verificando APIs"
declare -A PORTS=(
  [8745]="Sigma Engine"
  [8746]="IOC Engine"
  [8747]="Correlation Engine"
  [8748]="Playbook Engine"
)
for port in 8745 8746 8747 8748; do
  resp=$(curl -sf "http://localhost:$port/health" 2>/dev/null || echo "")
  if [ -n "$resp" ]; then
    log "Puerto $port (${PORTS[$port]}): OK"
  else
    warn "Puerto $port (${PORTS[$port]}): Sin respuesta"
  fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if $ALL_OK; then
  echo "  ✅ DEPLOY COMPLETADO EXITOSAMENTE"
else
  echo "  ⚠️  DEPLOY COMPLETADO CON ADVERTENCIAS"
fi
echo ""
echo "  Sigma Engine       : http://192.168.118.64:8745/health"
echo "  IOC Engine         : http://192.168.118.64:8746/health"
echo "  Correlation Engine : http://192.168.118.64:8747/health"
echo "  Playbook Engine    : http://192.168.118.64:8748/health"
echo ""
echo "  Backups            : /opt/backups/aut_soc/"
echo "  Logs               : journalctl -u <servicio> -f"
echo ""
echo "  Para configurar Telegram en playbooks:"
echo "  TELEGRAM_BOT_TOKEN=<token> TELEGRAM_CHAT_ID=<id> sudo bash deploy_server.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
