#!/bin/bash
# ============================================================================
# deploy_server.sh - Deploy completo AUT_SOC en servidor Ubuntu
# Ejecutar directamente en el servidor: bash deploy_server.sh
#
# Instala: Sigma Engine (8745) + IOC Engine (8746)
# ============================================================================

set -e
REPO="https://github.com/EdwardSuite/AUT_SOC.git"
DEPLOY_BASE="/opt/docker"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

step "1. Clonando/actualizando repo AUT_SOC"
cd /tmp
rm -rf AUT_SOC_deploy
git clone "$REPO" AUT_SOC_deploy
log "Repo clonado"

step "2. Instalando Sigma Engine"
sudo bash /tmp/AUT_SOC_deploy/sigma-engine/setup.sh

step "3. Instalando IOC Engine"
sudo bash /tmp/AUT_SOC_deploy/ioc-engine/setup.sh

step "4. Verificando servicios"
sleep 3
for svc in sigma-engine ioc-engine; do
  if systemctl is-active --quiet "$svc"; then
    log "$svc ACTIVO"
  else
    echo -e "${YELLOW}[!]${NC} $svc no inició — ver: journalctl -u $svc -n 20"
  fi
done

step "5. Verificando APIs"
for port in 8745 8746; do
  resp=$(curl -sf "http://localhost:$port/health" 2>/dev/null && echo "OK" || echo "NO_RESP")
  log "Puerto $port: $resp"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ DEPLOY COMPLETADO"
echo "  Sigma Engine : http://192.168.118.64:8745"
echo "  IOC Engine   : http://192.168.118.64:8746"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
