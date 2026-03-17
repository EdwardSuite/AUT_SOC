"""
rules_loader.py - Cargador e índice de reglas Sigma
AUT_SOC - Fase 2.1.A

Carga todas las reglas YAML desde el directorio de reglas,
las parsea y las indexa para evaluación eficiente.
"""

import yaml
import logging
import time
from pathlib import Path
from typing import Optional
from sigma_matcher import SigmaRule

logger = logging.getLogger(__name__)


class RulesLoader:
    """
    Carga, valida e indexa reglas Sigma desde disco.
    Soporta hot-reload sin reiniciar el servicio.
    """

    def __init__(self, rules_dir: str = "./rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: list[SigmaRule] = []
        self.last_loaded: float = 0
        self.load_errors: list[dict] = []
        self._stats: dict = {}

    def load_all(self) -> int:
        """
        Carga todas las reglas .yml/.yaml del directorio.
        Retorna el número de reglas cargadas exitosamente.
        """
        self.rules = []
        self.load_errors = []
        loaded = 0
        skipped = 0

        rule_files = list(self.rules_dir.rglob("*.yml")) + list(self.rules_dir.rglob("*.yaml"))

        if not rule_files:
            logger.warning(f"No se encontraron reglas en {self.rules_dir}")
            return 0

        for rule_file in rule_files:
            try:
                rule = self._load_rule(rule_file)
                if rule:
                    self.rules.append(rule)
                    loaded += 1
                else:
                    skipped += 1
            except Exception as e:
                self.load_errors.append({"file": str(rule_file), "error": str(e)})
                logger.error(f"Error cargando {rule_file}: {e}")

        self.last_loaded = time.time()
        self._stats = {
            "total_files": len(rule_files),
            "loaded": loaded,
            "skipped": skipped,
            "errors": len(self.load_errors),
        }

        logger.info(
            f"Reglas cargadas: {loaded}/{len(rule_files)} "
            f"({skipped} omitidas, {len(self.load_errors)} errores)"
        )
        return loaded

    def _load_rule(self, rule_path: Path) -> Optional[SigmaRule]:
        """Parsea un archivo de regla YAML. Retorna None si no es válida."""
        with open(rule_path, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)

        if not isinstance(content, dict):
            return None

        # Validación mínima
        if not content.get("title"):
            logger.debug(f"Regla sin título, omitiendo: {rule_path}")
            return None

        if not content.get("detection"):
            logger.debug(f"Regla sin detection, omitiendo: {rule_path}")
            return None

        # Filtrar reglas en estado 'deprecated' o 'unsupported'
        status = content.get("status", "").lower()
        if status in ("deprecated", "unsupported"):
            return None

        return SigmaRule(content, filename=rule_path.name)

    def reload_if_needed(self, max_age_seconds: int = 300) -> bool:
        """
        Recarga las reglas si han pasado más de max_age_seconds desde la última carga.
        Retorna True si se recargó.
        """
        if time.time() - self.last_loaded > max_age_seconds:
            self.load_all()
            return True
        return False

    def get_stats(self) -> dict:
        """Retorna estadísticas de la carga actual."""
        return {
            **self._stats,
            "rules_loaded": len(self.rules),
            "last_loaded_ts": self.last_loaded,
            "load_errors": self.load_errors[:10],  # Max 10 errores en respuesta
        }

    def get_rules_by_severity(self, level: str) -> list[SigmaRule]:
        return [r for r in self.rules if r.level == level.lower()]

    def get_rules_by_tag(self, tag: str) -> list[SigmaRule]:
        return [r for r in self.rules if tag.lower() in [t.lower() for t in r.tags]]
