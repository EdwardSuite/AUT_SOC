#!/bin/bash
# ============================================================================
# setup.sh - Instalador del Correlation Engine (Fase 2.1.D)
# Uso: sudo bash setup.sh
# ============================================================================
set -e

INSTALL_DIR="/opt/docker/correlation-engine"
SERVICE_USER="soporte"
PORT=8747
VENV_DIR="$INSTALL_DIR/venv"

# PostgreSQL (ajustar si cambian las credenciales)
PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-soporte}"
PG_PASS="${PG_PASS:-soporte}"
PG_DB="${PG_DB:-tia}"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root: sudo bash setup.sh"; exit 1; }

step "1. Dependencias"
apt-get install -y python3 python3-pip python3-venv libpq-dev 2>/dev/null | tail -1
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
cat > /etc/systemd/system/correlation-engine.service << EOF
[Unit]
Description=AUT_SOC Correlation Engine - Detección de patrones multi-evento
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=CORRELATION_DB_URL=postgresql://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PG_DB}
Environment=CORRELATION_PORT=$PORT
ExecStart=$VENV_DIR/bin/python correlation_api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlation-engine

[Install]
WantedBy=multi-user.target
EOF

step "5. Iniciando servicio"
systemctl daemon-reload
systemctl enable correlation-engine.service
systemctl start correlation-engine.service
sleep 4

if systemctl is-active --quiet correlation-engine.service; then
    log "Servicio correlation-engine ACTIVO"
else
    echo "❌ El servicio no inició"
    journalctl -u correlation-engine -n 20 --no-pager
    exit 1
fi

step "6. Verificando API"
sleep 2
HEALTH=$(curl -sf "http://localhost:$PORT/health" 2>/dev/null || echo "ERROR")
echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ CORRELATION ENGINE INSTALADO"
echo "  Health:       http://192.168.118.64:$PORT/health"
echo "  Correlate:    POST http://192.168.118.64:$PORT/correlate"
echo "  Super-Alerts: GET  http://192.168.118.64:$PORT/super-alerts"
echo "  Logs:         journalctl -u correlation-engine -f"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
