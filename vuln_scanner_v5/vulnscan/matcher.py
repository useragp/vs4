"""Applicability assessment - the false-positive filter.

Every candidate CVE is checked against the component with the strongest evidence
available, in this order:

1. NVD CPE configurations (analysed CVEs): product + version range.
2. CVE.org CNA "affected" data (vendor-supplied product + versions; available for
   most recent CVEs that NVD has not analysed yet).
3. The CVE description text: product/vendor mentions, version ranges such as
   "before 5.1.8" and wording that reveals a third-party library/plugin.

Applicability
-------------
HIGH            product and version confirmed inside an affected range (NVD CPE,
                CVE.org CNA data or an exact OSV.dev package+version match).
MEDIUM          product confirmed but the version cannot be verified, or the CVE is
                not analysed yet and product + vendor / version range are named.
LOW             weak or indirect evidence (keyword only; ecosystem item).
NOT APPLICABLE  the version is outside every affected range, an exclude keyword
                matched, the keyword only matched as a substring, or the CVE is
                about a different product. Reported only with "ALL".

Scope
-----
core       the vulnerability is in the product itself (runtime, compiler, Git, Bash).
ecosystem  it is in something built on/for the product: library, plugin, framework,
           API, wrapper, distribution that merely bundles it, app running on it.
unknown    text evidence does not tell.
"""

import re
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

from .models import (NOT_APPLICABLE, SCOPE_CORE, SCOPE_RELATED, SCOPE_UNKNOWN, Component)
from .versions import (compare_versions, describe_constraint, in_constraint, is_version,
                       parse_constraint, parse_cpe, same_branch, squash, version_in_range,
                       with_cpe_update)

AFFECTED = "AFFECTED"
VERSION_UNKNOWN = "VERSION_UNKNOWN"
NOT_AFFECTED = "NOT_AFFECTED"
PLATFORM_ONLY = "PLATFORM_ONLY"
PRODUCT_NOT_LISTED = "PRODUCT_NOT_LISTED"
NO_CONFIGURATION = "NO_CONFIGURATION"
OTHER_PRODUCT = "OTHER_PRODUCT"
NO_INFO = "NO_INFO"

_EMPTY = ("*", "-", "")
_RANGE_KEYS = ("versionStartIncluding", "versionStartExcluding",
               "versionEndIncluding", "versionEndExcluding")


class Assessment(NamedTuple):
    applicability: Optional[str]   # HIGH / MEDIUM / LOW, None = not applicable
    reason: str
    scope: str = SCOPE_UNKNOWN
    evidence: str = ""             # how it was found (exact search term, matched words)

    @property
    def label(self) -> str:
        return self.applicability or NOT_APPLICABLE


SCOPE_OTHER = "other"       # internal: a different product that merely mentions ours
CnaLookup = Callable[[str], Optional[List[Dict[str, Any]]]]


# ---------------------------------------------------------------------------
# Terms
# ---------------------------------------------------------------------------
# Extra knowledge about common "platform" products whose name appears in many
# unrelated CVEs (libraries, plugins, bindings). Keys are squashed product names.
PROFILES = {
    "python": {"aliases": ["CPython"],
               "core": [r"\bCPython\b", r"python/cpython", r"\bPython interpreter\b",
                        r"\bPython(?:'s)? standard library\b", r"\bpython\.org\b"]},
    "cpython": {"aliases": ["CPython"], "core": [r"\bCPython\b", r"python/cpython"]},
    "git": {"aliases": [], "core": [r"\bgit-scm\b", r"\bgit/git\b", r"\bGit for Windows\b",
                                    r"\bgit (?:clone|fetch|push|submodule|config|apply)\b.*\b(?:in|of) Git\b"]},
    "bash": {"aliases": ["GNU Bash"], "core": [r"\bGNU Bash\b"]},
    "nodejs": {"aliases": ["Node.js"], "core": [r"\bnodejs/node\b"]},
    "perl": {"aliases": [], "core": [r"\bPerl interpreter\b", r"\bPerl5\b"]},
    "ruby": {"aliases": ["CRuby", "MRI"], "core": [r"\bCRuby\b", r"\bruby/ruby\b"]},
    "php": {"aliases": [], "core": [r"\bphp-src\b", r"\bPHP interpreter\b"]},
    "openssl": {"aliases": [], "core": [r"\bopenssl/openssl\b"]},
    "linuxkernel": {"aliases": ["Linux kernel"], "core": [r"\bLinux kernel\b"]},
}


def mentions(text: str, terms: Sequence[str]) -> List[str]:
    """Terms appearing in text as whole words (case-insensitive)."""
    hits = []
    for term in terms:
        term = term.strip()
        if len(term) < 2:
            continue
        pattern = r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])"
        if re.search(pattern, text, flags=re.IGNORECASE) and term not in hits:
            hits.append(term)
    return hits


def component_cpes(comp: Component) -> List[Dict[str, str]]:
    return [p for p in (parse_cpe(c) for c in comp.cpe) if p]


def _profiles(comp: Component) -> List[Dict[str, Any]]:
    keys = {squash(t) for t in [comp.name] + comp.keywords + comp.aliases}
    keys.update(squash(c["product"]) for c in component_cpes(comp))
    return [PROFILES[k] for k in keys if k in PROFILES]


def product_terms(comp: Component) -> List[str]:
    """Name, keywords, aliases (+ well known aliases) - the words that identify the product."""
    out = []  # type: List[str]
    for t in [comp.name] + comp.keywords + comp.aliases + [a for p in _profiles(comp) for a in p["aliases"]]:
        t = re.sub(r"\s*\((?:python|npm|java|ruby|rust|go)? ?package\)\s*$", "", t.strip(), flags=re.I)
        if t and t.lower() not in [x.lower() for x in out]:
            out.append(t)
    return out


def _name_keys(comp: Component) -> set:
    keys = {squash(t) for t in product_terms(comp)}
    keys.update(squash(c["product"]) for c in component_cpes(comp))
    if comp.purl.startswith("pkg:"):
        keys.add(squash(comp.purl.split("/")[-1].split("@")[0]))
    if comp.osv_package:
        keys.add(squash(comp.osv_package))
    keys.discard("")
    return keys


def vendor_terms(comp: Component) -> List[str]:
    """Vendor / manufacturer names that are not also product names (avoid 'python' == 'python')."""
    products = {squash(t) for t in product_terms(comp)}
    out = []
    for t in (comp.vendor, comp.manufacturer):
        t = (t or "").strip()
        if len(t) >= 3 and squash(t) not in products and t not in out:
            out.append(t)
    return out


def _vendor_keys(comp: Component) -> set:
    keys = {squash(t) for t in (comp.vendor, comp.manufacturer) if t}
    keys.update(squash(c["vendor"]) for c in component_cpes(comp))
    keys.discard("")
    return keys


def component_version(comp: Component) -> str:
    """The version field wins; the CPE version is the fallback."""
    if comp.version.strip():
        return comp.version.strip()
    for c in component_cpes(comp):
        if c["version"] not in _EMPTY:
            return with_cpe_update(c["version"], c.get("update", "*"))
    return ""


def _vendor_related(vendor: str, comp: Component) -> bool:
    v = squash(vendor)
    if len(v) < 3:
        return False
    return any(v == k or (len(k) >= 4 and (k in v or v in k)) for k in _vendor_keys(comp))


_ECOSYSTEM_REGISTRIES = {"python": ("pypi",), "cpython": ("pypi",), "nodejs": ("npmjs", "npm"),
                         "ruby": ("rubygems",), "php": ("packagist",)}


def _name_tokens(name: str) -> List[str]:
    return [t.lower() for t in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", name or "") if t]


def built_on_product(name: str, comp: Component, target_sw: str = "") -> bool:
    """'msgpack-python', 'GitPython', 'jenkins:git' (plugin for Jenkins) -> True for Python / Git."""
    keys = {k for k in _name_keys(comp) if len(k) >= 3}
    if squash(name) in keys and not target_sw:
        return False                      # that is the product itself, not something built on it
    if target_sw and squash(target_sw) not in ("", "*", "-") and squash(name) in keys:
        return True                       # e.g. product 'git' with target_sw 'jenkins' = Jenkins plugin
    for tok in _name_tokens(name):
        if tok in keys:
            return True
        if any(len(k) >= 3 and (tok.startswith(k) or tok.endswith(k)) and tok != k for k in keys):
            return True
    return False


def _registry_hit(entry: Dict[str, Any], comp: Component) -> bool:
    url = (str(entry.get("collectionURL", "")) + " " + str(entry.get("packageName", ""))).lower()
    for key in _name_keys(comp):
        for reg in _ECOSYSTEM_REGISTRIES.get(key, ()):
            if reg in url:
                return True
    return False


# ---------------------------------------------------------------------------
# 1. NVD CPE configurations
# ---------------------------------------------------------------------------
def cpe_matches_component(crit: Dict[str, str], comp: Component) -> bool:
    real = component_cpes(comp)
    if real:
        for c in real:
            if crit["product"] == c["product"] and crit["vendor"] == c["vendor"] \
                    and (c["part"] in ("*", crit["part"])):
                return True
        return False
    # No CPE: product name equality, or vendor match + product name containing a term.
    prod = squash(crit["product"])
    keys = _name_keys(comp)
    if prod in keys:
        return True
    if _vendor_related(crit["vendor"], comp):
        return any(len(k) >= 4 and k in prod for k in keys)
    return False


def evaluate_configurations(configurations: List[Dict[str, Any]], comp: Component
                            ) -> Tuple[str, str, List[str], List[str]]:
    """Check NVD applicability statements -> (status, detail, other products, products built on ours)."""
    if not configurations:
        return NO_CONFIGURATION, "CVE not yet analysed by NVD (no CPE configuration)", [], []
    result, detail = PRODUCT_NOT_LISTED, "NVD configuration lists other products only"
    rank = {PRODUCT_NOT_LISTED: 0, PLATFORM_ONLY: 1, NOT_AFFECTED: 2, VERSION_UNKNOWN: 3, AFFECTED: 4}
    others = []  # type: List[str]
    built_on = []  # type: List[str]
    version = component_version(comp)

    def consider(status: str, text: str) -> None:
        nonlocal result, detail
        if rank[status] > rank[result]:
            result, detail = status, text

    for config in configurations:
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = parse_cpe(m.get("criteria", ""))
                if not crit:
                    continue
                name = "{}:{}".format(crit["vendor"], crit["product"])
                if not cpe_matches_component(crit, comp):
                    if m.get("vulnerable", True) and name not in others:
                        others.append(name)
                        if built_on_product(crit["product"], comp, crit.get("target_sw", "")):
                            built_on.append(name + (" (for {})".format(crit["target_sw"])
                                                    if crit.get("target_sw", "*") not in _EMPTY else ""))
                    continue
                is_hw = crit["part"] == "h"
                if not m.get("vulnerable", True) and not is_hw:
                    consider(PLATFORM_ONLY, "{} is listed only as the platform the vulnerable product runs on".format(name))
                    continue
                crit_ver = crit["version"]
                ranges = {k: m.get(k, "") for k in _RANGE_KEYS if m.get(k)}
                try:
                    if crit_ver not in _EMPTY:
                        listed = with_cpe_update(crit_ver, crit.get("update", "*"))
                        if not version:
                            consider(VERSION_UNKNOWN, "NVD lists {} {}; component version unknown".format(name, listed))
                        elif compare_versions(version, listed) == 0 or (
                                listed == crit_ver and compare_versions(version, crit_ver) == 0):
                            consider(AFFECTED, "NVD CPE exact version match {} {}".format(name, listed))
                        else:
                            consider(NOT_AFFECTED, "version {} not listed by NVD for {}".format(version, name))
                    elif ranges:
                        rng = ", ".join("{} {}".format(
                            {"versionStartIncluding": ">=", "versionStartExcluding": ">",
                             "versionEndIncluding": "<=", "versionEndExcluding": "<"}[k], v)
                            for k, v in ranges.items())
                        if not version:
                            consider(VERSION_UNKNOWN, "NVD: {} affected ({}); component version unknown".format(name, rng))
                        elif version_in_range(version,
                                              ranges.get("versionStartIncluding", ""),
                                              ranges.get("versionStartExcluding", ""),
                                              ranges.get("versionEndIncluding", ""),
                                              ranges.get("versionEndExcluding", "")):
                            consider(AFFECTED, "NVD CPE range match: {} {} is in [{}]".format(name, version, rng))
                        else:
                            consider(NOT_AFFECTED, "{} {} is outside the NVD affected range [{}]".format(name, version, rng))
                    elif is_hw:
                        consider(AFFECTED, "NVD hardware model match {}".format(name))
                    elif crit_ver == "*":
                        consider(AFFECTED, "NVD: all versions of {} affected".format(name))
                    else:
                        consider(VERSION_UNKNOWN, "NVD lists {} without a version".format(name))
                except ValueError:
                    consider(VERSION_UNKNOWN, "version of {} could not be compared".format(name))
    if result == PRODUCT_NOT_LISTED and others:
        detail = "NVD analysed this CVE for other product(s): " + ", ".join(others[:4])
    return result, detail, others, built_on


# ---------------------------------------------------------------------------
# 2. CVE.org CNA affected data
# ---------------------------------------------------------------------------
def _na(value: str) -> bool:
    return squash(value) in ("", "na", "unknown", "unspecified", "none", "various", "multiple")


def cna_product_matches(entry: Dict[str, Any], comp: Component) -> bool:
    for cpe in entry.get("cpes", []) or []:
        crit = parse_cpe(cpe)
        if crit and cpe_matches_component(crit, comp):
            return True
    keys = _name_keys(comp)
    prod, vendor = squash(entry.get("product", "")), squash(entry.get("vendor", ""))
    pkg = squash(entry.get("packageName", ""))
    if prod in keys or (pkg and pkg in keys):
        return True
    if vendor and prod.startswith(vendor) and prod[len(vendor):] in keys and _vendor_related(entry.get("vendor", ""), comp):
        return True     # "SEGGER J-Link" -> "jlink" (only for the component's own vendor)
    if _vendor_related(entry.get("vendor", ""), comp):
        return bool(mentions(entry.get("product", ""), product_terms(comp)))
    return False


def _cna_range(v: Dict[str, Any]) -> Optional[Dict[str, str]]:
    base = str(v.get("version", "") or "").strip()
    lower = "" if base.lower() in ("0", "*", "", "n/a", "unspecified", "all") else base
    if v.get("lessThan"):
        lt = str(v["lessThan"]).strip()
        rng = {"start_incl": lower} if lower else {}
        if lt not in ("*", ""):
            rng["end_excl"] = lt
        return rng if all(is_version(x) for x in rng.values()) else None
    if v.get("lessThanOrEqual"):
        le = str(v["lessThanOrEqual"]).strip()
        rng = {"start_incl": lower} if lower else {}
        if le not in ("*", ""):
            rng["end_incl"] = le
        return rng if all(is_version(x) for x in rng.values()) else None
    parsed = parse_constraint(base)
    if parsed is not None and parsed and all(is_version(x) for x in parsed.values()):
        return parsed
    if is_version(base):
        return {"exact": base}
    return None


def assess_cna(affected: Optional[List[Dict[str, Any]]], comp: Component) -> Tuple[str, str, List[str]]:
    """-> (status, detail, products). For OTHER_PRODUCT, products lists only those built on/for ours."""
    if not affected:
        return NO_INFO, "", []
    relevant = [a for a in affected if not _na(a.get("product", ""))]
    products = ["{} {}".format(a.get("vendor", ""), a.get("product", "")).strip() for a in relevant]
    if not relevant:
        return NO_INFO, "", []
    mine = [a for a in relevant if cna_product_matches(a, comp)]
    if not mine:
        built = ["{} {}".format(a.get("vendor", ""), a.get("product", "")).strip() for a in relevant
                 if built_on_product(a.get("product", ""), comp) or built_on_product(a.get("packageName", ""), comp)
                 or _registry_hit(a, comp)]
        return OTHER_PRODUCT, "CVE.org (CNA) lists only other product(s): " + ", ".join(products[:4]), built
    version = component_version(comp)
    label = "{} {}".format(mine[0].get("vendor", ""), mine[0].get("product", "")).strip()
    if not version:
        return VERSION_UNKNOWN, "CVE.org (CNA) lists {}; component version unknown".format(label), products
    affected_ranges, unaffected_hit, unparsed = [], False, False
    default_affected = default_unaffected = has_range = False
    for a in mine:
        default_affected = default_affected or str(a.get("defaultStatus", "")).lower() == "affected"
        default_unaffected = default_unaffected or str(a.get("defaultStatus", "")).lower() == "unaffected"
        for v in a.get("versions", []) or []:
            if str(v.get("versionType", "")).lower() == "git":
                unparsed = True
                continue
            rng = _cna_range(v)
            if rng is None:
                unparsed = True
                continue
            status = str(v.get("status", "affected")).lower()
            if "exact" not in rng:
                has_range = True
            try:
                inside = in_constraint(version, rng)
            except ValueError:
                unparsed = True
                continue
            if status == "affected":
                affected_ranges.append(describe_constraint(rng))
                if inside:
                    return AFFECTED, "CVE.org (CNA): {} {} is in affected range [{}]".format(
                        label, version, describe_constraint(rng)), products
            elif status == "unaffected" and inside:
                unaffected_hit = True
    if unaffected_hit:
        return NOT_AFFECTED, "CVE.org (CNA): {} {} is listed as unaffected".format(label, version), products
    if affected_ranges and (has_range or default_unaffected):
        return NOT_AFFECTED, "CVE.org (CNA): {} {} is outside the affected range(s) [{}]".format(
            label, version, "; ".join(affected_ranges[:4])), products
    if affected_ranges:
        # Only individual tested versions are listed and other versions are 'unknown'.
        return VERSION_UNKNOWN, "CVE.org (CNA) lists only individual affected versions of {} ({}); {} is not " \
            "covered either way".format(label, ", ".join(r.replace("= ", "") for r in affected_ranges[:5]),
                                        version), products
    if default_affected and not unparsed:
        return AFFECTED, "CVE.org (CNA): {} - all versions affected by default".format(label), products
    return VERSION_UNKNOWN, "CVE.org (CNA) lists {} but its version data cannot be compared".format(label), products


# ---------------------------------------------------------------------------
# 3. Description text
# ---------------------------------------------------------------------------
_ECO_NOUN = (r"(?:package|packages|library|libraries|module|framework|plugin|plug-in|extension|add-?on|SDK|"
             r"wrapper|bindings?|client|connector|integration|gem|crate|toolkit|API|action|provider|driver)")
_ECO_NOUN_AFTER = (r"(?:package|packages|library|libraries|framework|plugin|plug-in|extension|add-?on|SDK|"
                   r"wrapper|bindings?|connector|integration|gem|crate|toolkit|action|provider|driver)")
_NOT_ECO_WORD = r"(?!standard\b|core\b|built-?in\b|internal\b|bundled\b|source\b|interpreter\b|shell\b)"
_ECO_MARKERS = [
    (r"\bPyPI\b", "PyPI"), (r"\bnpm\b", "npm"), (r"\bRubyGems\b", "RubyGems"), (r"\bcrates\.io\b", "crates.io"),
    (r"\bNuGet\b", "NuGet"), (r"\bPackagist\b", "Packagist"), (r"\bpip install\b", "pip"),
    (r"\bJenkins\b[^.]{0,60}\bplugin\b", "Jenkins"), (r"\bWordPress\b", "WordPress"),
    (r"\b(?:Visual Studio Code|VS ?Code)\b", "VS Code"), (r"\bGitHub Actions?\b", "GitHub Action"),
    (r"\bMaven\b", "Maven"), (r"\bGo module\b", "Go module"),
]
_STOP_SUBJECTS = {"a", "an", "the", "this", "that", "issue", "vulnerability", "flaw", "bug", "support", "code",
                  "data", "use", "used", "written", "exists", "fix", "patch", "update", "version", "versions",
                  "it", "is", "was", "and", "or", "in", "of", "cve", "attack", "attacker", "attackers", "x"}
_SUBJECT_RE = re.compile(
    r"^\s*([A-Z0-9@][\w.@/+-]*(?:\s+[\w.@/+-]+){0,3}?)\s+(?:is|are)\s+(?:an?|the)\s+(?:[\w.,/+-]+\s+){0,10}?"
    r"(?:library|framework|package|plugin|plug-in|module|extension|tool|application|app|platform|software|"
    r"client|server|service|system|SDK|implementation|wrapper|CMS|manager|utility|engine|toolkit|bindings?|"
    r"interface|program|project|solution|suite)\b", re.IGNORECASE)


_LEAD_SUBJECT_RE = re.compile(r"^\s*(?:The\s+)?([\w.+-]+(?:\s+[\w.+-]+){0,2}?)\s+(?:is|are)\s+(?:an?|the)\b", re.I)


def subject_is_product(desc: str, comp: Component) -> str:
    """'Git is a revision control system. ...' -> 'Git' when the opening subject is the product."""
    m = _LEAD_SUBJECT_RE.match(desc or "")
    if not m:
        return ""
    subject = squash(m.group(1))
    keys = _name_keys(comp)
    if subject in keys:
        return m.group(1)
    for v in _vendor_keys(comp):
        if subject.startswith(v) and subject[len(v):] in keys:
            return m.group(1)
    return ""


def text_scope(desc: str, comp: Component, hits: Sequence[str]) -> Tuple[str, str]:
    """Does the description talk about the product itself or about its ecosystem?"""
    terms = list(hits) or product_terms(comp)
    keys = _name_keys(comp)
    eco, core, strong_eco, range_core = [], [], False, False
    own_subject = subject_is_product(desc, comp)
    if own_subject:
        core.append("description is about '{}' itself".format(own_subject))
        range_core = True
    for rx, label in _ECO_MARKERS:
        if squash(label) not in keys and re.search(rx, desc, flags=re.IGNORECASE):
            eco.append("mentions {}".format(label))
            strong_eco = True
    m = None if own_subject else _SUBJECT_RE.search(desc)
    if m and re.match(r"(?:the|this|these|a|an|there|it|in|multiple|several|some)\b", m.group(1), re.I):
        m = None
    other_subject = ""
    if m and not mentions(m.group(1), product_terms(comp)) and not mentions(m.group(1), vendor_terms(comp)):
        first_sentence = re.split(r"\.\s+(?=[A-Z])", desc, maxsplit=1)[0]
        if mentions(first_sentence, product_terms(comp)):
            # "virtualenv is a tool for ... python environments" - another product built for ours
            eco.append("describes '{}', a {} item".format(m.group(1).strip(), comp.name))
            strong_eco = True
        else:
            other_subject = m.group(1).strip()      # "Argo CD is a ... tool for Kubernetes"
    for t in terms:
        T = re.escape(t)
        rx_list = [
            (r"\b" + _ECO_NOUN + r"(?:\s+[\w-]+){0,2}\s+(?:for|in|written in|built (?:on|with)|based on|on top of|"
             r"wrapping|around|that wraps)\s+(?:the\s+)?" + T + r"(?![\w-])", "a {} for/in " + t),
            (r"(?<![\w-])" + T + r"(?:[ -]" + _NOT_ECO_WORD + r"[\w-]+)?\s+" + _ECO_NOUN_AFTER + r"\b", t + " {}"),
            (r"(?<![\w.-])" + T + r"[-_](?!\d)(?!(?:before|through|prior)\b)[A-Za-z][\w-]*", "compound name"),
            (r"(?<![\w-])[A-Za-z][\w]*[-_]" + T + r"(?![\w-])", "compound name"),
        ]
        # "<OtherProduct> [before 1.2] for <T>" - e.g. "Flask before 2.2.5 for Python"
        for mm in re.finditer(r"\b([A-Z][\w.+-]+)(?:\s+(?:before|through|prior to|up to|<=?)\s*v?\d[\w.]*)?"
                              r"\s+(?:for|on top of)\s+(?:the\s+)?" + T + r"(?![\w-])", desc):
            word = mm.group(1)
            if word.lower() not in _STOP_SUBJECTS and not mentions(word, product_terms(comp) + vendor_terms(comp)):
                eco.append("'{}'".format(mm.group(0)))
                strong_eco = True
                break
        for rx, label in rx_list:
            mm = re.search(rx, desc, flags=re.IGNORECASE)
            if mm and not mentions(mm.group(0), [x for x in product_terms(comp) if x.lower() != t.lower()
                                                 and len(x) > len(t)]):
                eco.append("'{}'".format(mm.group(0).strip()))
                break
        if re.search(r"(?<![\w-])" + T + r"\s+(?:v(?:ersion)?s?\s*)?(?:before|through|prior to|up to|until|"
                     r"earlier than|<=?)\s*v?\d", desc, flags=re.IGNORECASE) or \
                re.search(r"(?<![\w-])" + T + r"\s+v?\d+(?:\.\d+)+[a-z]?\d*\s+(?:and|or)\s+(?:earlier|prior|below|older)",
                          desc, flags=re.IGNORECASE):
            core.append("'{}' with affected version range".format(t))
            range_core = True
        elif re.search(r"(?<![\w-])" + T + r"\s+(?:versions?\s+)?v?\d+\.\d+", desc, flags=re.IGNORECASE):
            core.append("'{}' with version number".format(t))
    for p in _profiles(comp):
        for rx in p["core"]:
            mm = re.search(rx, desc, flags=re.IGNORECASE)
            if mm:
                core.append("'{}'".format(mm.group(0)))
                range_core = True
                break
    vend = mentions(desc, vendor_terms(comp))
    if vend:
        core.append("vendor '{}'".format(vend[0]))
    if eco and not core:
        return SCOPE_RELATED, "; ".join(eco[:2])
    if core and not eco:
        return SCOPE_CORE, "; ".join(core[:2])
    if eco and core:
        if strong_eco and not range_core:
            return SCOPE_RELATED, "; ".join(eco[:2])
        if range_core and not strong_eco:
            return SCOPE_CORE, "; ".join(core[:2])
        return SCOPE_UNKNOWN, "mixed evidence: {} vs. {}".format(eco[0], core[0])
    if other_subject:
        return SCOPE_OTHER, "the description is about another product ('{}')".format(other_subject)
    return SCOPE_UNKNOWN, ""


_VER = r"v?(\d+(?:\.\d+)*(?:[a-z]+\d*)?)"
_VER_NC = r"v?\d+(?:\.\d+)*(?:[a-z]+\d*)?"
_VER_LIST = _VER_NC + r"(?:\s*(?:,\s*(?:and|or)?|and|or)\s*" + _VER_NC + r")*"


def _collect_bounds(text: str, label: str) -> List[Tuple[str, bool, str, bool, str]]:
    bounds = []  # type: List[Tuple[str, bool, str, bool, str]]
    for r in re.finditer(r"(?:versions?\s+)?" + _VER + r"\s*(?:through|to|until|-)\s*" + _VER, text):
        bounds.append((r.group(1), True, r.group(2), True, (label + " " + r.group(0)).strip()))
    rest = re.sub(_VER + r"\s*(?:through|to|until|-)\s*" + _VER, " ", text)
    for r in re.finditer(r"(before|prior to|earlier than|below|through|up to|until|and including|<=|<)\s*"
                         r"(?:versions?\s*)?(" + _VER_LIST + r")", rest, flags=re.IGNORECASE):
        incl = r.group(1).lower() in ("through", "up to", "until", "and including", "<=")
        snippet = (label + " " + r.group(0)).strip()
        for ver in re.findall(_VER, r.group(2)):
            bounds.append(("", True, ver, incl, snippet))
    for r in re.finditer(_VER + r"\s+(?:and|or)\s+(?:earlier|prior|below|older|before)", rest, re.IGNORECASE):
        bounds.append(("", True, r.group(1), True, (label + " " + r.group(0)).strip()))
    return bounds


def text_version(desc: str, terms: Sequence[str], version: str, whole_text: bool = False
                 ) -> Tuple[Optional[str], str]:
    """Version ranges stated for the product: 'Bash before 5.1.8', 'Git 2.39.1 and earlier'.

    whole_text=True (the description is about the product itself) also reads ranges that
    are not directly next to the product name ('Git is ... Prior to versions 2.43.1, ...').
    """
    if not version or not is_version(version):
        return None, ""
    bounds = []  # type: List[Tuple[str, bool, str, bool, str]]
    for t in terms:
        for m in re.finditer(r"(?<![\w-])" + re.escape(t) + r"(?![\w-])", desc, flags=re.IGNORECASE):
            window = desc[m.end(): m.end() + 200]
            cut = re.search(r"\.\s+(?=[A-Z])|;\s|\n", window)
            if cut:
                window = window[:cut.start()]
            bounds.extend(_collect_bounds(window, t))
    if whole_text and not bounds:
        bounds.extend(_collect_bounds(desc[:600], ""))
    bounds = [b for b in bounds if is_version(b[2]) and (not b[0] or is_version(b[0]))]
    if not bounds:
        return None, ""

    def inside(b: Tuple[str, bool, str, bool, str]) -> bool:
        lo, lo_incl, hi, hi_incl, _ = b
        if lo and compare_versions(version, lo) < (0 if lo_incl else 1):
            return False
        c = compare_versions(version, hi)
        return c < 0 or (hi_incl and c == 0)

    try:
        branch = [b for b in bounds if same_branch(version, b[2])]
        candidates = branch or bounds
        hit = [b for b in candidates if inside(b)]
        if hit:
            return "affected", "description states '{}'".format(hit[0][4])
        if branch:
            return "not_affected", "description states '{}' - {} is outside".format(branch[0][4], version)
        highest = max(bounds, key=lambda b: _Key(b[2]))
        if compare_versions(version, highest[2]) >= 0:
            return "not_affected", "description states '{}' - {} is newer".format(highest[4], version)
        if all(compare_versions(version, b[0] or "0") < 0 for b in bounds):
            return "not_affected", "description states '{}' - {} is older".format(bounds[0][4], version)
    except ValueError:
        return None, ""
    return None, ""


class _Key:
    def __init__(self, v: str) -> None:
        self.v = v

    def __lt__(self, other: "_Key") -> bool:
        return compare_versions(self.v, other.v) < 0


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------
def _evidence(method: str, search_term: str, hits: Sequence[str]) -> str:
    if method == "cpe":
        return "NVD CPE search '{}'".format(search_term) if search_term else "NVD CPE search"
    quoted = ", ".join("'{}'".format(h) for h in hits)
    if not search_term:
        return "NVD keyword search; description contains {}".format(quoted or "no exact term")
    if hits:
        return "NVD keyword search '{}'; description contains {}".format(search_term, quoted)
    return "NVD keyword search '{}'; no whole-word hit in description".format(search_term)


def assess_nvd(parsed: Dict[str, Any], comp: Component, method: str, search_term: str = "",
               strict: bool = True, cna: Optional[CnaLookup] = None) -> Assessment:
    """Decide applicability + scope of an NVD CVE for a component. method: 'cpe' | 'keyword'."""
    desc = parsed.get("description", "")
    terms = product_terms(comp)
    hits = mentions(desc, terms)
    ev = _evidence(method, search_term, hits)

    def result(app: Optional[str], reason: str, scope: str = SCOPE_UNKNOWN, extra: str = "") -> Assessment:
        return Assessment(app, reason, scope, ev + ("; " + extra if extra else ""))

    if parsed.get("nvd_status", "").lower() == "rejected" or desc.startswith("** REJECT **"):
        return result(None, "rejected CVE")
    excluded = mentions(desc, comp.exclude_keywords)
    if excluded:
        return result(None, "exclude keyword '{}' found in description".format(excluded[0]),
                      extra="exclude keyword '{}'".format(excluded[0]))
    if method == "keyword" and not hits:
        return result(None, "'{}' does not occur as a whole word in the description (NVD matched it inside "
                            "another word, e.g. a longer product name)".format(search_term or comp.name))

    vendor_hit = mentions(desc, vendor_terms(comp))
    status, detail, _others, built_on = evaluate_configurations(parsed.get("configurations", []), comp)
    if status == AFFECTED:
        if component_cpes(comp) or vendor_hit:
            return result("HIGH", detail, SCOPE_CORE, "confirmed by NVD configuration")
        return result("MEDIUM", detail + " (product name match, vendor not confirmed)", SCOPE_CORE,
                      "confirmed by NVD configuration")
    if status == VERSION_UNKNOWN:
        return result("MEDIUM", detail, SCOPE_CORE, "product confirmed by NVD configuration")
    if status == NOT_AFFECTED:
        return result(None, detail, SCOPE_CORE)
    if status == PLATFORM_ONLY:
        return result("LOW", detail, SCOPE_RELATED)
    if status == PRODUCT_NOT_LISTED:
        return _other_product(result, desc, comp, hits, detail, built_on)

    # ---- not analysed by NVD: CVE.org CNA data ----------------------------
    if cna is not None:
        cstat, cdetail, _cprods = assess_cna(cna(parsed.get("id", "")), comp)
        if cstat == AFFECTED:
            return result("HIGH", cdetail, SCOPE_CORE, "confirmed by CVE.org CNA data")
        if cstat == VERSION_UNKNOWN:
            return result("MEDIUM", cdetail, SCOPE_CORE, "product confirmed by CVE.org CNA data")
        if cstat == NOT_AFFECTED:
            return result(None, cdetail, SCOPE_CORE)
        if cstat == OTHER_PRODUCT:
            return _other_product(result, desc, comp, hits, cdetail, _cprods)

    # ---- text only ------------------------------------------------------
    scope, why = text_scope(desc, comp, hits)
    verdict, vdetail = text_version(desc, hits or terms, component_version(comp),
                                    whole_text=bool(subject_is_product(desc, comp)))
    if scope == SCOPE_OTHER and vendor_hit:
        scope = SCOPE_UNKNOWN
    if scope == SCOPE_RELATED:
        return result("LOW", "not analysed by NVD; text indicates an ecosystem item, not the product "
                             "itself ({})".format(why), SCOPE_RELATED)
    if scope == SCOPE_OTHER and not vendor_hit:
        return result(None, "not analysed by NVD; {} that only mentions '{}'".format(
            why, (list(hits) or [comp.name])[0]), SCOPE_RELATED)
    if verdict == "not_affected":
        return result(None, "not analysed by NVD; " + vdetail, SCOPE_CORE if scope == SCOPE_CORE else scope)
    if verdict == "affected":
        return result("MEDIUM", "not analysed by NVD; {}{}".format(
            vdetail, "; vendor '{}' named".format(vendor_hit[0]) if vendor_hit else ""), SCOPE_CORE)
    if vendor_hit or scope == SCOPE_CORE:
        return result("MEDIUM", "not analysed by NVD; '{}' named ({}) - version not verifiable".format(
            (hits or terms)[0], why or "vendor '{}'".format(vendor_hit[0])), SCOPE_CORE)
    if strict:
        return result(None, "keyword '{}' only - no vendor, version or product evidence (strict mode)".format(
            (hits or terms)[0]), scope)
    return result("LOW", "not analysed by NVD; keyword '{}' in description only".format((hits or terms)[0]), scope)


def _other_product(result: Callable[..., Assessment], desc: str, comp: Component, hits: Sequence[str],
                   detail: str, built_on: List[str]) -> Assessment:
    """The CVE is about another product: ecosystem item only with evidence, else not applicable."""
    if built_on:
        return result("LOW", "{}; built on / for {}: {}".format(detail, comp.name, ", ".join(built_on[:3])),
                      SCOPE_RELATED)
    scope, why = text_scope(desc, comp, hits)
    if scope == SCOPE_RELATED:
        return result("LOW", "{}; {}".format(detail, why), SCOPE_RELATED)
    return result(None, "{} - a different product that only mentions '{}'".format(
        detail, (list(hits) or [comp.name])[0]), SCOPE_RELATED)


def assess_osv(comp: Component, version_used: str, query: str = "") -> Assessment:
    ev = "OSV.dev package query '{}'".format(query) if query else "OSV.dev package query"
    if version_used:
        return Assessment("HIGH", "OSV.dev: package {} version {} is affected".format(
            query.split("@")[0] or comp.name, version_used), SCOPE_CORE, ev)
    return Assessment("MEDIUM", "OSV.dev package match, no version given", SCOPE_CORE, ev)
