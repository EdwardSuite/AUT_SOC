"""
mitre_enricher.py - Enriquecedor MITRE ATT&CK
AUT_SOC - Fase 2.1.B

Mapea IDs de técnicas/tácticas MITRE a descripciones completas.
Se integra al Sigma Engine: /mitre/technique/{id} y /mitre/tactic/{name}
Fuente: MITRE ATT&CK Enterprise (embebido + actualizable desde GitHub).
"""

import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base de datos MITRE embebida (subset enterprise - las más relevantes en SOC)
# Se complementa con descarga del JSON oficial en setup
# ---------------------------------------------------------------------------

MITRE_TACTICS = {
    "reconnaissance": {
        "id": "TA0043", "name": "Reconnaissance",
        "description": "El adversario intenta recopilar información sobre el objetivo antes del ataque.",
        "url": "https://attack.mitre.org/tactics/TA0043/"
    },
    "resource_development": {
        "id": "TA0042", "name": "Resource Development",
        "description": "El adversario intenta establecer recursos para soportar las operaciones.",
        "url": "https://attack.mitre.org/tactics/TA0042/"
    },
    "initial_access": {
        "id": "TA0001", "name": "Initial Access",
        "description": "El adversario intenta entrar en la red de la víctima.",
        "url": "https://attack.mitre.org/tactics/TA0001/"
    },
    "execution": {
        "id": "TA0002", "name": "Execution",
        "description": "El adversario intenta ejecutar código malicioso.",
        "url": "https://attack.mitre.org/tactics/TA0002/"
    },
    "persistence": {
        "id": "TA0003", "name": "Persistence",
        "description": "El adversario intenta mantener acceso al sistema comprometido.",
        "url": "https://attack.mitre.org/tactics/TA0003/"
    },
    "privilege_escalation": {
        "id": "TA0004", "name": "Privilege Escalation",
        "description": "El adversario intenta obtener permisos de mayor nivel.",
        "url": "https://attack.mitre.org/tactics/TA0004/"
    },
    "defense_evasion": {
        "id": "TA0005", "name": "Defense Evasion",
        "description": "El adversario intenta evitar ser detectado.",
        "url": "https://attack.mitre.org/tactics/TA0005/"
    },
    "credential_access": {
        "id": "TA0006", "name": "Credential Access",
        "description": "El adversario intenta robar credenciales de cuentas.",
        "url": "https://attack.mitre.org/tactics/TA0006/"
    },
    "discovery": {
        "id": "TA0007", "name": "Discovery",
        "description": "El adversario intenta descubrir el entorno del objetivo.",
        "url": "https://attack.mitre.org/tactics/TA0007/"
    },
    "lateral_movement": {
        "id": "TA0008", "name": "Lateral Movement",
        "description": "El adversario intenta moverse a través del entorno.",
        "url": "https://attack.mitre.org/tactics/TA0008/"
    },
    "collection": {
        "id": "TA0009", "name": "Collection",
        "description": "El adversario intenta recopilar datos de interés para su objetivo.",
        "url": "https://attack.mitre.org/tactics/TA0009/"
    },
    "command_and_control": {
        "id": "TA0011", "name": "Command and Control",
        "description": "El adversario intenta comunicarse con sistemas comprometidos.",
        "url": "https://attack.mitre.org/tactics/TA0011/"
    },
    "exfiltration": {
        "id": "TA0010", "name": "Exfiltration",
        "description": "El adversario intenta robar datos del entorno de la víctima.",
        "url": "https://attack.mitre.org/tactics/TA0010/"
    },
    "impact": {
        "id": "TA0040", "name": "Impact",
        "description": "El adversario intenta manipular, interrumpir o destruir sistemas y datos.",
        "url": "https://attack.mitre.org/tactics/TA0040/"
    },
}

MITRE_TECHNIQUES = {
    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "credential_access",
               "description": "Uso de fuerza bruta para ganar acceso a cuentas.", "url": "https://attack.mitre.org/techniques/T1110/"},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential_access",
                   "description": "Intentos sistemáticos de adivinar contraseñas de cuentas.", "url": "https://attack.mitre.org/techniques/T1110/001/"},
    "T1110.002": {"name": "Password Cracking", "tactic": "credential_access",
                   "description": "Uso de técnicas criptográficas para descifrar hashes de contraseñas.", "url": "https://attack.mitre.org/techniques/T1110/002/"},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential_access",
                   "description": "Uso de una contraseña común contra muchas cuentas diferentes.", "url": "https://attack.mitre.org/techniques/T1110/003/"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access",
               "description": "Volcado de credenciales del sistema operativo.", "url": "https://attack.mitre.org/techniques/T1003/"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential_access",
                   "description": "Acceso a credenciales desde la memoria del proceso LSASS.", "url": "https://attack.mitre.org/techniques/T1003/001/"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "credential_access",
               "description": "Robo o falsificación de tickets Kerberos.", "url": "https://attack.mitre.org/techniques/T1558/"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential_access",
               "description": "Búsqueda de credenciales almacenadas de forma insegura.", "url": "https://attack.mitre.org/techniques/T1552/"},

    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery",
               "description": "Escaneo de red para descubrir servicios accesibles.", "url": "https://attack.mitre.org/techniques/T1046/"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery",
               "description": "Recopilación de información sobre el sistema comprometido.", "url": "https://attack.mitre.org/techniques/T1082/"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "discovery",
               "description": "Búsqueda de información de red del sistema.", "url": "https://attack.mitre.org/techniques/T1016/"},

    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "lateral_movement",
               "description": "Uso de servicios remotos legítimos para movimiento lateral.", "url": "https://attack.mitre.org/techniques/T1021/"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral_movement",
                   "description": "Uso de RDP para movimiento lateral.", "url": "https://attack.mitre.org/techniques/T1021/001/"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral_movement",
                   "description": "Uso de SMB y shares administrativos de Windows.", "url": "https://attack.mitre.org/techniques/T1021/002/"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "lateral_movement",
               "description": "Transferencia de herramientas entre sistemas comprometidos.", "url": "https://attack.mitre.org/techniques/T1570/"},

    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "command_and_control",
               "description": "Uso de protocolos de capa de aplicación para C2.", "url": "https://attack.mitre.org/techniques/T1071/"},
    "T1071.001": {"name": "Web Protocols (HTTP/S)", "tactic": "command_and_control",
                   "description": "Uso de HTTP/HTTPS para comunicaciones C2.", "url": "https://attack.mitre.org/techniques/T1071/001/"},
    "T1071.004": {"name": "DNS", "tactic": "command_and_control",
                   "description": "Uso de DNS para comunicaciones C2.", "url": "https://attack.mitre.org/techniques/T1071/004/"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "command_and_control",
               "description": "Uso de protocolos de red de capas inferiores para C2.", "url": "https://attack.mitre.org/techniques/T1095/"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "command_and_control",
               "description": "Tunneling de comunicaciones a través de protocolos legítimos.", "url": "https://attack.mitre.org/techniques/T1572/"},

    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration",
               "description": "Exfiltración de datos a través del canal C2.", "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration",
               "description": "Exfiltración usando un protocolo diferente al C2.", "url": "https://attack.mitre.org/techniques/T1048/"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration",
               "description": "Uso de servicios web externos para exfiltrar datos.", "url": "https://attack.mitre.org/techniques/T1567/"},

    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access",
               "description": "Explotación de vulnerabilidades en aplicaciones expuestas a Internet.", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1133": {"name": "External Remote Services", "tactic": "initial_access",
               "description": "Abuso de servicios remotos externos legítimos.", "url": "https://attack.mitre.org/techniques/T1133/"},
    "T1078": {"name": "Valid Accounts", "tactic": "persistence",
               "description": "Uso de credenciales legítimas comprometidas.", "url": "https://attack.mitre.org/techniques/T1078/"},

    # Privilege Escalation
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation",
               "description": "Abuso de mecanismos de control de elevación de privilegios.", "url": "https://attack.mitre.org/techniques/T1548/"},
    "T1548.001": {"name": "Setuid and Setgid", "tactic": "privilege_escalation",
                   "description": "Abuso de binarios SUID/SGID para escalación.", "url": "https://attack.mitre.org/techniques/T1548/001/"},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": "privilege_escalation",
                   "description": "Bypass del control de cuentas de usuario de Windows.", "url": "https://attack.mitre.org/techniques/T1548/002/"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "privilege_escalation",
               "description": "Manipulación de tokens de acceso para escalar privilegios.", "url": "https://attack.mitre.org/techniques/T1134/"},

    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact",
               "description": "Cifrado de datos para interrumpir la disponibilidad (ransomware).", "url": "https://attack.mitre.org/techniques/T1486/"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact",
               "description": "Eliminación de opciones de recuperación del sistema.", "url": "https://attack.mitre.org/techniques/T1490/"},
    "T1489": {"name": "Service Stop", "tactic": "impact",
               "description": "Detención de servicios legítimos del sistema.", "url": "https://attack.mitre.org/techniques/T1489/"},

    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution",
               "description": "Uso de intérpretes de comandos para ejecución de código malicioso.", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution",
                   "description": "Uso de PowerShell para ejecución maliciosa.", "url": "https://attack.mitre.org/techniques/T1059/001/"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution",
                   "description": "Uso de cmd.exe para ejecución maliciosa.", "url": "https://attack.mitre.org/techniques/T1059/003/"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution",
                   "description": "Uso de shells Unix para ejecución maliciosa.", "url": "https://attack.mitre.org/techniques/T1059/004/"},
}


class MitreEnricher:
    """Enriquece técnicas MITRE ATT&CK con descripciones completas."""

    def __init__(self, cache_dir: str = "./mitre_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self._extended: dict = {}
        self._load_extended_cache()

    def _load_extended_cache(self):
        """Carga el cache extendido de MITRE si existe."""
        cache_file = self.cache_dir / "mitre_enterprise.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    self._extended = json.load(f)
                logger.info(f"Cache MITRE cargado: {len(self._extended)} técnicas")
            except Exception as e:
                logger.warning(f"No se pudo cargar cache MITRE: {e}")

    def download_mitre_data(self) -> int:
        """
        Descarga el JSON oficial de MITRE ATT&CK Enterprise desde GitHub.
        Retorna el número de técnicas indexadas.
        """
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        cache_file = self.cache_dir / "mitre_enterprise.json"
        index_file = self.cache_dir / "mitre_index.json"

        logger.info("Descargando MITRE ATT&CK Enterprise...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AUT_SOC/2.1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = json.loads(resp.read())

            # Indexar técnicas por ID
            index = {}
            for obj in raw.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                ext_refs = obj.get("external_references", [])
                mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
                if not mitre_ref:
                    continue

                tech_id = mitre_ref.get("external_id", "")
                if not tech_id:
                    continue

                # Extraer tácticas
                tactics = [
                    p.get("phase_name", "").replace("-", "_")
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ]

                index[tech_id.upper()] = {
                    "id": tech_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:300],
                    "tactics": tactics,
                    "url": mitre_ref.get("url", ""),
                    "deprecated": obj.get("x_mitre_deprecated", False),
                }

            with open(index_file, "w") as f:
                json.dump(index, f)

            self._extended = index
            logger.info(f"MITRE indexado: {len(index)} técnicas")
            return len(index)

        except Exception as e:
            logger.error(f"Error descargando MITRE: {e}")
            return 0

    def get_technique(self, tech_id: str) -> Optional[dict]:
        """Retorna info completa de una técnica por ID (ej: T1046, T1110.001)."""
        tid = tech_id.upper().replace("ATT&CK.", "").replace("ATTACK.", "")

        # 1. Cache extendido (MITRE oficial)
        if tid in self._extended:
            return self._extended[tid]

        # 2. Base embebida
        if tid in MITRE_TECHNIQUES:
            t = MITRE_TECHNIQUES[tid]
            return {
                "id": tid,
                "name": t["name"],
                "description": t["description"],
                "tactics": [t.get("tactic", "unknown")],
                "url": t["url"],
                "source": "embedded",
            }

        return None

    def get_tactic(self, tactic_name: str) -> Optional[dict]:
        """Retorna info de una táctica por nombre (ej: 'Credential Access')."""
        key = tactic_name.lower().replace(" ", "_").replace("-", "_")
        return MITRE_TACTICS.get(key)

    def enrich_techniques(self, technique_ids: list[str]) -> list[dict]:
        """Enriquece una lista de IDs de técnicas con info completa."""
        results = []
        for tid in technique_ids:
            info = self.get_technique(tid)
            if info:
                results.append(info)
            else:
                results.append({"id": tid, "name": "Unknown Technique", "description": "", "tactics": []})
        return results

    def build_attack_summary(self, tactics: list[str], techniques: list[str]) -> str:
        """
        Construye un resumen textual del contexto ATT&CK para incluir en el prompt IA.
        """
        lines = ["=== MITRE ATT&CK CONTEXT ==="]

        if tactics:
            lines.append(f"Tácticas identificadas: {', '.join(tactics)}")
            for tac in tactics[:3]:
                info = self.get_tactic(tac)
                if info:
                    lines.append(f"  • {info['name']} ({info['id']}): {info['description'][:120]}...")

        if techniques:
            lines.append(f"\nTécnicas detectadas: {', '.join(techniques)}")
            for tid in techniques[:5]:
                info = self.get_technique(tid)
                if info:
                    name = info.get('name', 'Unknown')
                    desc = info.get('description', '')[:100]
                    lines.append(f"  • {tid} - {name}: {desc}...")

        lines.append("=== FIN CONTEXTO ATT&CK ===")
        return "\n".join(lines)

    def get_stats(self) -> dict:
        return {
            "embedded_techniques": len(MITRE_TECHNIQUES),
            "embedded_tactics": len(MITRE_TACTICS),
            "extended_cache": len(self._extended),
            "total_available": len(self._extended) or len(MITRE_TECHNIQUES),
        }
