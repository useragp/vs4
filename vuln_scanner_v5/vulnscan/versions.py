"""Version comparison, version-constraint parsing and CPE 2.3 helpers (stdlib only)."""

import re
from typing import Dict, List, Optional, Tuple

CPE_KEYS = ("part", "vendor", "product", "version", "update", "edition", "language",
            "sw_edition", "target_sw", "target_hw", "other")

# Pre-release markers sort *before* the release (3.8.0rc1 < 3.8.0).
_PRE_RELEASE = {"dev": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "pre": -2,
                "preview": -2, "c": -1, "rc": -1}
_WORD_PRE = {"dev", "alpha", "beta", "pre", "preview", "rc"}
# Words that mean "the release itself" and carry no ordering information.
_NEUTRAL = {"final", "release", "ga", "stable", "lts"}
# Words used for post-release patch levels (OpenSSH 9.3p1, bash 5.1 patch 8).
_POST = {"p", "patch", "pl", "post", "sp", "update", "u", "r", "rev"}

Token = Tuple[int, int, str]
_EMPTY = ("*", "-", "")


class VersionError(ValueError):
    pass


def _tokens(version: str) -> List[Token]:
    v = version.strip().lower()
    v = re.sub(r"^\d+:(?=\d)", "", v)          # Debian epoch 1:2.3 -> 2.3
    v = v.split("+", 1)[0]                      # build metadata 3.8.10+dfsg -> 3.8.10
    v = re.sub(r"^(?:version\s*|v(?=\d))", "", v)
    raw = re.findall(r"\d+|[a-z]+", v)
    if not raw or not raw[0].isdigit():
        raise VersionError("Unparseable version: {!r}".format(version))
    out = []  # type: List[Token]
    for i, tok in enumerate(raw):
        if tok.isdigit():
            out.append((2, int(tok), ""))
            continue
        if tok in _NEUTRAL:
            continue
        nxt_is_digit = i + 1 < len(raw) and raw[i + 1].isdigit()
        # 'a'/'b'/'c' are pre-releases only when followed by a number (3.8.0a1),
        # otherwise they are post-release letters (OpenSSL 1.1.1w).
        if tok in _WORD_PRE or (tok in _PRE_RELEASE and nxt_is_digit):
            out.append((-1, _PRE_RELEASE[tok], ""))
        elif tok in _POST and nxt_is_digit:
            out.append((1, 0, "~post"))
        else:
            out.append((1, 0, tok))
    while out and out[-1] == (2, 0, ""):        # 5.1.0 == 5.1
        out.pop()
    return out


def is_version(text: str) -> bool:
    try:
        _tokens(text)
        return True
    except ValueError:
        return False


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1. Raises ValueError for unparseable input."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x is None or y is None:
            # Missing component: equals numeric 0 (5.1 == 5.1.0); a post-release
            # letter is newer (1.1.1w > 1.1.1); a pre-release is older (3.8.0rc1 < 3.8.0).
            tok, sign = (y, -1) if x is None else (x, 1)
            if tok[0] == 2:
                if tok[1] != 0:
                    return sign
                continue
            return sign if tok[0] == 1 else -sign
        if x != y:
            # A numeric part is newer than a letter at the same position (1.2.10 > 1.2.b).
            return -1 if x < y else 1
    return 0


def version_in_range(version: str, start_incl: str = "", start_excl: str = "",
                     end_incl: str = "", end_excl: str = "") -> bool:
    if start_incl and start_incl not in ("0", "*") and compare_versions(version, start_incl) < 0:
        return False
    if start_excl and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl and compare_versions(version, end_incl) > 0:
        return False
    if end_excl and compare_versions(version, end_excl) >= 0:
        return False
    return True


def same_branch(version: str, other: str, depth: int = 2) -> bool:
    """True when both versions share the first `depth` numeric parts (3.10.4 ~ 3.10.16)."""
    try:
        a = [t[1] for t in _tokens(version) if t[0] == 2][:depth]
        b = [t[1] for t in _tokens(other) if t[0] == 2][:depth]
    except ValueError:
        return False
    a += [0] * (depth - len(a))
    b += [0] * (depth - len(b))
    return a == b


def with_cpe_update(version: str, update: str) -> str:
    """Combine a CPE version with a numeric update field (bash 5.1 + patch8 -> 5.1.8)."""
    m = re.fullmatch(r"(?:patch|p|pl|update|u)?[_.-]?(\d+)", (update or "").strip().lower())
    if update in _EMPTY or not m:
        return version
    return "{}.{}".format(version, int(m.group(1)))


# ---- version constraint expressions (CVE.org / CNA style) -----------------------
_OP_RE = re.compile(r"(<=|>=|<|>|=|==)\s*v?([0-9][\w.\-+]*)")


def parse_constraint(expr: str) -> Optional[Dict[str, str]]:
    """'< 3.1.41' / '>= 1.0, < 2.0' / '3.8.*' / '2.x' -> range dict, or None when not a constraint.

    Keys: start_incl, start_excl, end_incl, end_excl, exact.
    """
    text = (expr or "").strip().lower()
    if not text or text in ("*", "all", "all versions"):
        return {}
    ops = _OP_RE.findall(text)
    if ops:
        out = {}  # type: Dict[str, str]
        for op, ver in ops:
            ver = ver.rstrip(".,;")
            key = {"<": "end_excl", "<=": "end_incl", ">": "start_excl", ">=": "start_incl",
                   "=": "exact", "==": "exact"}[op]
            out[key] = ver
        return out
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)\.(?:\*|x)", text)
    if m:  # 3.8.* -> [3.8, 3.9)
        parts = m.group(1).split(".")
        upper = parts[:-1] + [str(int(parts[-1]) + 1)]
        return {"start_incl": m.group(1), "end_excl": ".".join(upper)}
    m = re.fullmatch(r"(?:up to|through|until)\s+v?([0-9][\w.\-]*)", text)
    if m:
        return {"end_incl": m.group(1)}
    m = re.fullmatch(r"(?:before|prior to|earlier than|below)\s+v?([0-9][\w.\-]*)", text)
    if m:
        return {"end_excl": m.group(1)}
    return None


def in_constraint(version: str, rng: Dict[str, str]) -> bool:
    if "exact" in rng:
        return compare_versions(version, rng["exact"]) == 0
    return version_in_range(version, rng.get("start_incl", ""), rng.get("start_excl", ""),
                            rng.get("end_incl", ""), rng.get("end_excl", ""))


def describe_constraint(rng: Dict[str, str]) -> str:
    if not rng:
        return "all versions"
    if "exact" in rng:
        return "= " + rng["exact"]
    parts = []
    for key, sym in (("start_incl", ">="), ("start_excl", ">"), ("end_incl", "<="), ("end_excl", "<")):
        if rng.get(key) and not (key == "start_incl" and rng[key] in ("0", "*")):
            parts.append("{} {}".format(sym, rng[key]))
    return ", ".join(parts) or "all versions"


# ---- CPE ---------------------------------------------------------------------------
def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def split_cpe(cpe: str) -> List[str]:
    return re.split(r"(?<!\\):", cpe.strip())


def parse_cpe(cpe: str) -> Optional[Dict[str, str]]:
    """Parse a CPE 2.3 formatted string into a dict (lower-cased, unescaped)."""
    if not cpe:
        return None
    parts = split_cpe(cpe)
    if len(parts) < 5 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    parts = parts + ["*"] * (13 - len(parts))
    parsed = dict(zip(CPE_KEYS, [_unescape(p).lower() for p in parts[2:13]]))
    parsed["raw"] = cpe.strip()
    return parsed


def validate_cpe(cpe: str) -> Tuple[bool, str]:
    parsed = parse_cpe(cpe)
    if parsed is None:
        return False, "Not a CPE 2.3 string (expected cpe:2.3:part:vendor:product:version:...)"
    if parsed["part"] not in ("a", "o", "h"):
        return False, "CPE part must be a (application), o (OS/firmware) or h (hardware)"
    if parsed["vendor"] in ("*", "-", "") or parsed["product"] in ("*", "-", ""):
        return False, "CPE vendor and product must be specific (no wildcards)"
    if len(split_cpe(cpe)) != 13:
        return False, "CPE 2.3 must have 13 colon-separated fields"
    return True, ""


def product_match_string(cpe: str) -> Optional[str]:
    """cpe:2.3:part:vendor:product (escaping kept) for NVD virtualMatchString."""
    parts = split_cpe(cpe)
    if len(parts) < 5:
        return None
    return ":".join(parts[:5])


def normalize_product(term: str) -> str:
    """'J-Link Software' -> 'j-link_software' (NVD product naming style)."""
    return re.sub(r"\s+", "_", term.strip().lower())


def squash(term: str) -> str:
    """Loose name key: 'J-Link', 'jlink', 'J_Link' -> 'jlink'."""
    return re.sub(r"[^a-z0-9]", "", (term or "").lower())
