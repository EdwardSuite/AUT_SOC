#!/bin/bash
# ============================================================================
# setup.sh - Instalador del Playbook Engine (Fase 2.1.E)
# Uso: sudo bash setup.sh
# Variables de entorno opcionales:
#   TELEGRAM_BOT_TOKEN  - Token del bot de Telegram para notificaciones
#   TELEGRAM_CHAT_ID    - Chat ID del canal SOC
#   QRADAR_TOKEN        - Token API de QRadar para añadir notas
# ============================================================================
set -e

INSTALL_DIR="/opt/docker/playbook-engine"
SERVICE_USER="soporte"
PORT=8748
VENV_DIR="$INSTALL_DIR/venv"

PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-soporte}"
PG_PASS="${PG_PASS:-soporte}"
PG_DB="${PG_DB:-tia}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
QRADAR_URL="${QRADAR_URL:-https://192.168.71.54}"
QRADAR_TOKEN="${QRADAR_TOKEN:-}"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

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

step "4. Configurando variables de entorno"
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    warn "TELEGRAM_BOT_TOKEN no definido — las notificaciones Telegram estarán desactivadas"
    warn "Puedes configurarlo después en: /etc/systemd/system/playbook-engine.service"
fi

step "5. Creando servicio systemd"
cat > /etc/systemd/system/playbook-engine.service << EOF
[Unit]
Description=AUT_SOC Playbook Engine - Respuesta automatizada a incidentes
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PLAYBOOK_DB_URL=postgresql://${PG_USER}:${PG_PASS}@${PG_HOST}:${PG_PORT}/${PG_DB}
Environment=PLAYBOOK_PORT=$PORT
Environment=TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
Environment=TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
Environment=QRADAR_URL=${QRADAR_URL}
Environment=QRADAR_TOKEN=${QRADAR_TOKEN}
ExecStart=$VENV_DIR/bin/python playbook_api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=playbook-engine

[Install]
WantedBy=multi-user.target
EOF

step "6. Iniciando servicio"
systemctl daemon-reload
systemctl enable playbook-engine.service
systemctl start playbook-engine.service
sleep 4

if systemctl is-active --quiet playbook-engine.service; then
    log "Servicio playbook-engine ACTIVO"
else
    echo "❌ El servicio no inició"
    journalctl -u playbook-engine -n 20 --no-pager
    exit 1
fi

step "7. Verificando API"
sleep 2
HEALTH=$(curl -sf "http://localhost:$PORT/health" 2>/dev/null || echo "ERROR")
echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ PLAYBOOK ENGINE INSTALADO"
echo "  Health:     http://192.168.118.64:$PORT/health"
echo "  Execute:    POST http://192.168.118.64:$PORT/execute"
echo "  Playbooks:  GET  http://192.168.118.64:$PORT/playbooks"
echo "  Incidents:  GET  http://192.168.118.64:$PORT/incidents"
echo "  Logs:       journalctl -u playbook-engine -f"
echo ""
echo "  Para configurar Telegram (si no lo hiciste antes):"
echo "  Editar: /etc/systemd/system/playbook-engine.service"
echo "  Añadir: Environment=TELEGRAM_BOT_TOKEN=<tu_token>"
echo "          Environment=TELEGRAM_CHAT_ID=<tu_chat_id>"
echo "  Luego:  systemctl daemon-reload && systemctl restart playbook-engine"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
