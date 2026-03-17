"""
sigma_matcher.py - Motor de evaluación de reglas Sigma
AUT_SOC - Fase 2.1.A

Evalúa eventos normalizados (de QRadar/N8N) contra reglas Sigma YAML.
Implementa las construcciones de detección más comunes de la especificación Sigma.
"""

import re
import yaml
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SigmaRule:
    """Representa una regla Sigma parseada y lista para evaluar eventos."""

    SEVERITY_SCORE = {
        "informational": 5,
        "low": 20,
        "medium": 50,
        "high": 75,
        "critical": 95,
    }

    def __init__(self, rule_dict: dict, filename: str = ""):
        self.filename = filename
        self.title = rule_dict.get("title", "Unknown Rule")
        self.id = rule_dict.get("id", "")
        self.status = rule_dict.get("status", "experimental")
        self.description = rule_dict.get("description", "")
        self.level = rule_dict.get("level", "medium").lower()
        self.tags = rule_dict.get("tags", [])
        self.logsource = rule_dict.get("logsource", {})
        self.detection = rule_dict.get("detection", {})
        self.falsepositives = rule_dict.get("falsepositives", [])
        self.category = rule_dict.get("logsource", {}).get("category", "")
        self.product = rule_dict.get("logsource", {}).get("product", "")

        # Extraer contexto MITRE ATT&CK de los tags
        self.mitre_techniques = []
        self.mitre_tactics = []
        for tag in self.tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.t") and "." in tag_lower[7:]:
                self.mitre_techniques.append(tag.replace("attack.", "").upper())
            elif tag_lower.startswith("attack."):
                tactic = tag.replace("attack.", "").replace("_", " ").title()
                self.mitre_tactics.append(tactic)

    @property
    def risk_score(self) -> int:
        return self.SEVERITY_SCORE.get(self.level, 50)

    def matches(self, event: dict) -> bool:
        """
        Evalúa si el evento cumple la lógica de detección de la regla.
        Retorna True si hay match, False en caso contrario.
        """
        detection = self.detection
        if not detection:
            return False

        condition = detection.get("condition", "")
        if not condition:
            return False

        # Evaluar todos los bloques de detección
        block_results: dict[str, bool] = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            try:
                block_results[key] = self._evaluate_block(value, event)
            except Exception as e:
                logger.debug(f"Error evaluando bloque '{key}' en regla '{self.title}': {e}")
                block_results[key] = False

        # Resolver la condición
        try:
            return self._evaluate_condition(condition.lower().strip(), block_results)
        except Exception as e:
            logger.debug(f"Error evaluando condición en regla '{self.title}': {e}")
            return False

    # -------------------------------------------------------------------------
    # Evaluación de bloques de detección
    # -------------------------------------------------------------------------

    def _evaluate_block(self, block: Any, event: dict) -> bool:
        """Despacha la evaluación según el tipo del bloque."""
        if isinstance(block, list):
            return self._match_keywords(block, event)
        elif isinstance(block, dict):
            return self._match_selection(block, event)
        return False

    def _match_keywords(self, keywords: list, event: dict) -> bool:
        """Busca keywords en la representación en texto de todos los campos del evento."""
        event_text = " ".join(str(v) for v in event.values() if v is not None).lower()
        for kw in keywords:
            if isinstance(kw, list):
                # AND implícito dentro de una sub-lista
                if all(str(k).lower() in event_text for k in kw):
                    return True
            else:
                if str(kw).lower() in event_text:
                    return True
        return False

    def _match_selection(self, selection: dict, event: dict) -> bool:
        """
        Evalúa un bloque de selección.
        Todos los campos deben coincidir (AND implícito entre campos).
        """
        for field_expr, rule_values in selection.items():
            parts = field_expr.split("|")
            field = parts[0]
            modifiers = [m.lower() for m in parts[1:]]

            event_value = self._get_field(event, field)

            # Si el campo no existe en el evento → no match
            if event_value is None:
                # Excepción: si el valor esperado es null/None, sí es match
                if rule_values is None:
                    continue
                return False

            if not self._match_field(event_value, rule_values, modifiers):
                return False

        return True

    # -------------------------------------------------------------------------
    # Resolución de campos y valores
    # -------------------------------------------------------------------------

    def _get_field(self, event: dict, field: str) -> Any:
        """
        Obtiene el valor de un campo del evento.
        Soporta búsqueda case-insensitive y campo comodín '_'.
        """
        if field == "_":
            return " ".join(str(v) for v in event.values() if v is not None)

        # Match exacto
        if field in event:
            return event[field]

        # Match case-insensitive
        field_lower = field.lower()
        for k, v in event.items():
            if k.lower() == field_lower:
                return v

        return None

    def _match_field(self, event_value: Any, rule_values: Any, modifiers: list) -> bool:
        """Compara el valor del evento contra el/los valores de la regla con modificadores."""
        event_str = str(event_value).lower()

        if isinstance(rule_values, list):
            if "all" in modifiers:
                return all(self._match_single(event_str, str(v), modifiers) for v in rule_values)
            return any(self._match_single(event_str, str(v), modifiers) for v in rule_values)

        if rule_values is None:
            return event_value is None or event_str in ("none", "null", "")

        return self._match_single(event_str, str(rule_values), modifiers)

    def _match_single(self, event_str: str, rule_val: str, modifiers: list) -> bool:
        """Aplica un modificador individual al comparar dos strings."""
        rule_lower = rule_val.lower()

        if "re" in modifiers:
            try:
                return bool(re.search(rule_lower, event_str, re.IGNORECASE))
            except re.error:
                return False
        elif "contains" in modifiers:
            return rule_lower in event_str
        elif "startswith" in modifiers:
            return event_str.startswith(rule_lower)
        elif "endswith" in modifiers:
            return event_str.endswith(rule_lower)
        else:
            # Match exacto con soporte de wildcard '*'
            if "*" in rule_val or "?" in rule_val:
                pattern = re.escape(rule_lower).replace(r"\*", ".*").replace(r"\?", ".")
                return bool(re.fullmatch(pattern, event_str))
            return event_str == rule_lower

    # -------------------------------------------------------------------------
    # Evaluación de condiciones
    # -------------------------------------------------------------------------

    def _evaluate_condition(self, condition: str, blocks: dict[str, bool]) -> bool:
        """
        Interpreta la condición de la regla Sigma.
        Soporta: AND, OR, NOT, 'all of', '1 of', 'X of', wildcards (*).
        """
        cond = condition.strip()

        # Caso trivial: bloque único
        if cond in blocks:
            return blocks[cond]

        # 'all of them'
        if cond == "all of them":
            return all(blocks.values())

        # 'any of them' / '1 of them'
        if cond in ("any of them", "1 of them"):
            return any(blocks.values())

        # 'N of selection*'
        m = re.match(r"(\d+|all)\s+of\s+(\w+\*?)", cond)
        if m:
            count_str, pattern = m.group(1), m.group(2)
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                matched = [v for k, v in blocks.items() if k.startswith(prefix)]
            else:
                matched = [blocks.get(pattern, False)]

            if count_str == "all":
                return all(matched) if matched else False
            return sum(matched) >= int(count_str)

        # Operadores booleanos: parsear respetando paréntesis
        return self._parse_boolean(cond, blocks)

    def _parse_boolean(self, expr: str, blocks: dict[str, bool]) -> bool:
        """Parser simple de expresiones booleanas: AND, OR, NOT, paréntesis."""
        expr = expr.strip()

        # Eliminar paréntesis externos si los hay
        if expr.startswith("(") and expr.endswith(")"):
            # Verificar que realmente envuelvan toda la expresión
            depth = 0
            for i, c in enumerate(expr):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                if depth == 0 and i < len(expr) - 1:
                    break
            else:
                return self._parse_boolean(expr[1:-1], blocks)

        # OR (menor precedencia)
        for part in self._split_by_operator(expr, " or "):
            if self._parse_boolean(part, blocks):
                return True
        if " or " in expr:
            return False

        # AND
        parts = self._split_by_operator(expr, " and ")
        if len(parts) > 1:
            return all(self._parse_boolean(p, blocks) for p in parts)

        # NOT
        if expr.startswith("not "):
            return not self._parse_boolean(expr[4:], blocks)

        # Término hoja
        return blocks.get(expr, False)

    @staticmethod
    def _split_by_operator(expr: str, operator: str) -> list[str]:
        """Divide una expresión por un operador, respetando paréntesis."""
        parts = []
        depth = 0
        start = 0
        op_len = len(operator)
        i = 0
        while i <= len(expr) - op_len:
            if expr[i] == "(":
                depth += 1
            elif expr[i] == ")":
                depth -= 1
            elif depth == 0 and expr[i:i + op_len] == operator:
                parts.append(expr[start:i].strip())
                start = i + op_len
                i += op_len
                continue
            i += 1
        parts.append(expr[start:].strip())
        return parts if len(parts) > 1 else [expr]

    def to_match_result(self) -> dict:
        """Serializa la información de la regla como resultado de match."""
        return {
            "rule_id": self.id,
            "rule_title": self.title,
            "rule_file": self.filename,
            "severity": self.level,
            "risk_score": self.risk_score,
            "description": self.description,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "false_positives": self.falsepositives,
        }
