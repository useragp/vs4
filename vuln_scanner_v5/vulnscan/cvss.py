"""CVSS helpers: v3.x base score calculator and severity mapping."""

import math
from typing import Dict, Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup (spec appendix A)."""
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    metrics = {}  # type: Dict[str, str]
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()
    try:
        scope_changed = metrics["S"] == "C"
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
