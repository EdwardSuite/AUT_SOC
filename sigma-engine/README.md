# ⚡ Sigma Engine — AUT_SOC Fase 2.1.A

Motor de evaluación de reglas **Sigma** para el pipeline SOC. Evalúa eventos normalizados de QRadar contra reglas de detección estándar y retorna contexto **MITRE ATT&CK** + score de riesgo.

---

## Arquitectura

```
N8N Pipeline
    │
    ├─ Normalize Data (JS)
    │       ↓
    ├─ [NUEVO] Sigma Engine - Evaluate Event (HTTP POST :8745/evaluate)
    │       ↓
    ├─ [NUEVO] Sigma - Merge Results (Code Node)
    │       ↓
    ├─ Dynamic Scoring (Fase 3) ← recibe sigma_score_bonus
    │       ↓
    └─ Build AI Prompt v2 ← recibe sigma_context_summary + mitre_*
```

## Instalación rápida

```bash
# En el servidor (192.168.118.64)
scp -P 5551 -r sigma-engine/ soporte@192.168.118.64:/tmp/
ssh -p 5551 soporte@192.168.118.64
sudo bash /tmp/sigma-engine/setup.sh
```

## Endpoints

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/health` | Estado del servicio |
| `GET` | `/stats` | Estadísticas de reglas |
| `GET` | `/rules` | Lista de reglas cargadas |
| `POST` | `/evaluate` | **Evaluar un evento** |
| `POST` | `/reload` | Hot-reload de reglas |

## Ejemplo de uso

```bash
curl -X POST http://192.168.118.64:8745/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "EventName": "SSH Authentication Failed multiple times",
      "src_ip": "203.0.113.42",
      "dst_port": "5551",
      "category": "Authentication"
    }
  }'
```

**Respuesta:**
```json
{
  "sigma_matched": true,
  "match_count": 1,
  "highest_severity": "high",
  "sigma_risk_score": 75,
  "mitre_tactics": ["Credential Access"],
  "mitre_techniques": ["T1110.001"],
  "sigma_context_summary": "🚨 Sigma detectó 1 regla(s) coincidente(s):\n  • [HIGH] SSH Brute Force Attack | MITRE: T1110.001\n  Tácticas ATT&CK: Credential Access\n  Técnicas ATT&CK: T1110.001",
  "rules_evaluated": 9,
  "evaluation_time_ms": 1.23
}
```

## Reglas incluidas

| Categoría | Regla | Severidad | MITRE |
|-----------|-------|-----------|-------|
| network | SSH Brute Force Attack | High | T1110.001 |
| network | Network Port Scanning | Medium | T1046 |
| network | Potential C2 Beaconing | High | T1071 |
| network | Potential Data Exfiltration | High | T1041, T1048 |
| network | Lateral Movement | High | T1021 |
| generic | Privilege Escalation | High | T1548 |
| generic | Ransomware Activity | Critical | T1486, T1490 |
| generic | Credential Dumping | Critical | T1003 |
| generic | Web Application Attack | High | T1190 |
| generic | Insider Threat Indicators | Medium | T1078 |

*+ reglas adicionales descargadas de SigmaHQ durante la instalación*

## Integración N8N

Ver `n8n_sigma_nodes.json` para los nodos a importar en el workflow.

**Qué aporta al pipeline:**
- `sigma_matched` → boolean si hubo algún match
- `sigma_risk_score` → score numérico (0-95) para el Dynamic Scoring
- `sigma_score_bonus` → bonus a sumar al score existente
- `sigma_mitre_tactics` → lista de tácticas MITRE detectadas
- `sigma_mitre_techniques` → lista de técnicas (T1046, T1110.001, etc.)
- `sigma_context_summary` → texto listo para el prompt del LLM

## Gestión del servicio

```bash
systemctl status sigma-engine    # Estado
systemctl restart sigma-engine   # Reiniciar
journalctl -u sigma-engine -f    # Logs en tiempo real
```

---
*AUT_SOC Fase 2.1.A | Puerto: 8745 | Versión: 2.1.0*
