#!/bin/bash
# ============================================================================
# setup.sh - Instalador del IOC Engine para AUT_SOC (Fase 2.1.C)
# Uso: sudo bash setup.sh
# ============================================================================
set -e

INSTALL_DIR="/opt/docker/ioc-engine"
SERVICE_USER="soporte"
PORT=8746
VENV_DIR="$INSTALL_DIR/venv"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root: sudo bash setup.sh"; exit 1; }

step "1. Instalando dependencias"
apt-get install -y python3 python3-pip python3-venv curl 2>/dev/null | tail -1
log "Python: $(python3 --version)"

step "2. Copiando archivos"
mkdir -p "$INSTALL_DIR"
cp -r "$(dirname "$0")/." "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
log "Instalado en: $INSTALL_DIR"

step "3. Entorno virtual Python"
sudo -u "$SERVICE_USER" python3 -m venv "$VENV_DIR"
sudo -u "$SERVICE_USER" "$VENV_DIR/bin/pip" install --upgrade pip -q
sudo -u "$SERVICE_USER" "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
log "Dependencias instaladas"

step "4. Creando servicio systemd"
cat > /etc/systemd/system/ioc-engine.service << EOF
[Unit]
Description=AUT_SOC IOC Engine - Verificador de Indicadores de Compromiso
Documentation=https://github.com/EdwardSuite/AUT_SOC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python ioc_api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ioc-engine
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

step "5. Creando cron para actualización diaria de feeds"
# Actualizar feeds todos los días a las 02:00 AM
CRON_JOB="0 2 * * * $SERVICE_USER curl -sf -X POST http://localhost:$PORT/feeds/update/sync > /var/log/ioc-engine-cron.log 2>&1"
echo "$CRON_JOB" > /etc/cron.d/ioc-engine-feeds
chmod 644 /etc/cron.d/ioc-engine-feeds
log "Cron configurado (actualización diaria 02:00 AM)"

step "6. Iniciando servicio"
systemctl daemon-reload
systemctl enable ioc-engine.service
systemctl start ioc-engine.service
sleep 4

if systemctl is-active --quiet ioc-engine.service; then
    log "Servicio ioc-engine ACTIVO"
else
    echo "❌ El servicio no inició"; journalctl -u ioc-engine -n 20 --no-pager; exit 1
fi

step "7. Verificando API y descarga inicial de feeds"
sleep 3
HEALTH=$(curl -sf "http://localhost:$PORT/health" 2>/dev/null || echo "ERROR")
echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ IOC ENGINE INSTALADO"
echo "  Health:  http://192.168.118.64:$PORT/health"
echo "  Check:   POST http://192.168.118.64:$PORT/check/event"
echo "  Feeds:   POST http://192.168.118.64:$PORT/feeds/update"
echo "  Logs:    journalctl -u ioc-engine -f"
echo "  (Los feeds se descargan en background al iniciar)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
