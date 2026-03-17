#!/bin/bash
# ============================================================================
# setup.sh - Instalador del Sigma Engine para AUT_SOC
# Fase 2.1.A - Motor de Reglas Sigma
#
# Uso: sudo bash setup.sh
# Servidor: Ubuntu 24.04 @ 192.168.118.64
# ============================================================================

set -e

INSTALL_DIR="/opt/docker/sigma-engine"
SERVICE_USER="soporte"
PORT=8745
PYTHON_BIN="python3"
VENV_DIR="$INSTALL_DIR/venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }

# ─── Verificar root ───────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    log_error "Ejecutar como root: sudo bash setup.sh"
    exit 1
fi

log_step "1. Verificando dependencias del sistema"
apt-get install -y python3 python3-pip python3-venv curl 2>/dev/null | tail -2
log_info "Python: $($PYTHON_BIN --version)"

log_step "2. Creando directorio de instalación"
mkdir -p "$INSTALL_DIR/rules"
cp -r "$(dirname "$0")/." "$INSTALL_DIR/"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
log_info "Instalado en: $INSTALL_DIR"

log_step "3. Creando entorno virtual Python"
sudo -u "$SERVICE_USER" $PYTHON_BIN -m venv "$VENV_DIR"
sudo -u "$SERVICE_USER" "$VENV_DIR/bin/pip" install --upgrade pip -q
sudo -u "$SERVICE_USER" "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
log_info "Dependencias instaladas"

log_step "4. Descargando reglas Sigma adicionales de SigmaHQ"
RULES_DIR="$INSTALL_DIR/rules"
SIGMA_RULES_URL="https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"

# Descargar y extraer reglas relevantes (network + linux)
if command -v curl &> /dev/null; then
    log_info "Descargando reglas SigmaHQ (esto puede tomar un momento)..."
    TEMP_DIR=$(mktemp -d)

    curl -sL "$SIGMA_RULES_URL" -o "$TEMP_DIR/sigma.zip" 2>/dev/null && {
        cd "$TEMP_DIR"
        unzip -q sigma.zip 2>/dev/null || true

        # Copiar categorías más relevantes para el SOC
        for category in network linux proxy firewall web; do
            SIGMA_PATH="$TEMP_DIR/sigma-master/rules/$category"
            if [ -d "$SIGMA_PATH" ]; then
                mkdir -p "$RULES_DIR/$category"
                cp "$SIGMA_PATH"/*.yml "$RULES_DIR/$category/" 2>/dev/null | true
                RULE_COUNT=$(ls "$RULES_DIR/$category/" 2>/dev/null | wc -l)
                log_info "  $category: $RULE_COUNT reglas copiadas"
            fi
        done

        rm -rf "$TEMP_DIR"
        log_info "Reglas SigmaHQ descargadas"
    } || {
        log_warn "No se pudo descargar SigmaHQ. Usando solo reglas locales."
    }
else
    log_warn "curl no disponible, usando solo reglas locales"
fi

TOTAL_RULES=$(find "$RULES_DIR" -name "*.yml" | wc -l)
log_info "Total reglas disponibles: $TOTAL_RULES"
chown -R "$SERVICE_USER:$SERVICE_USER" "$RULES_DIR"

log_step "5. Creando servicio systemd"
cat > /etc/systemd/system/sigma-engine.service << EOF
[Unit]
Description=AUT_SOC Sigma Engine - Motor de Reglas de Detección
Documentation=https://github.com/EdwardSuite/AUT_SOC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python sigma_api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sigma-engine

# Límites de recursos
LimitNOFILE=65536
TimeoutStartSec=30
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

log_step "6. Activando e iniciando el servicio"
systemctl daemon-reload
systemctl enable sigma-engine.service
systemctl start sigma-engine.service

# Esperar a que inicie
sleep 3

if systemctl is-active --quiet sigma-engine.service; then
    log_info "✅ Servicio sigma-engine ACTIVO"
else
    log_error "❌ El servicio no inició correctamente"
    journalctl -u sigma-engine.service --no-pager -n 20
    exit 1
fi

log_step "7. Verificando API"
sleep 2
HEALTH=$(curl -sf "http://localhost:$PORT/health" 2>/dev/null || echo "ERROR")
if echo "$HEALTH" | grep -q "ok"; then
    log_info "✅ API respondiendo en puerto $PORT"
    echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
else
    log_warn "API no responde aún. Verificar con: curl http://localhost:$PORT/health"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ SIGMA ENGINE INSTALADO CORRECTAMENTE"
echo ""
echo "  Endpoints disponibles:"
echo "  • Health:   http://192.168.118.64:$PORT/health"
echo "  • Evaluar:  POST http://192.168.118.64:$PORT/evaluate"
echo "  • Reglas:   http://192.168.118.64:$PORT/rules"
echo "  • Stats:    http://192.168.118.64:$PORT/stats"
echo "  • Reload:   POST http://192.168.118.64:$PORT/reload"
echo ""
echo "  Gestión del servicio:"
echo "  • Estado:   systemctl status sigma-engine"
echo "  • Logs:     journalctl -u sigma-engine -f"
echo "  • Reinicio: systemctl restart sigma-engine"
echo ""
echo "  Siguiente paso: Agregar nodos en N8N"
echo "  Workflow: http://192.168.118.64:5678/workflow/UkEdz3PlAeB5HgI2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
