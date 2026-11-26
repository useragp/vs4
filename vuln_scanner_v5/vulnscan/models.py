"""Data model: components (input) and vulnerabilities (output)."""

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

LIST_FIELDS = ("keywords", "aliases", "cpe", "projects", "exclude_keywords")
STR_FIELDS = ("name", "version", "description", "vendor", "manufacturer", "type",
              "purl", "osv_ecosystem", "osv_package", "id", "category")

# ---- component categories ---------------------------------------------------
# Categories are technology-neutral: the same taxonomy covers runtimes, compilers,
# libraries, frameworks, build tools, firmware and hardware across automotive stacks.
CAT_CORE_COMPONENT = "Core Component"
CAT_PACKAGE = "Package / Library"
RUNTIME_CPES = {("python", "python"): CAT_CORE_COMPONENT,
                ("python", "cpython"): CAT_CORE_COMPONENT}
PACKAGE_ECOSYSTEMS = {k: CAT_PACKAGE for k in (
    "pypi", "npm", "maven", "cargo", "crates.io", "golang", "go", "nuget",
    "gem", "rubygems", "deb", "debian", "ubuntu", "rpm", "alpine", "apk")}
TYPE_CATEGORIES = {"hardware": "Hardware", "firmware": "Firmware", "tool": "Tool",
                   "library": CAT_PACKAGE, "os": "Operating System", "software": "Software"}
SUGGESTED_CATEGORIES = [CAT_CORE_COMPONENT, CAT_PACKAGE, "Operating System", "Firmware",
                        "Hardware", "Tool", "Software"]


def derive_category(comp: "Component") -> str:
    """Explicit category, else purl/OSV ecosystem, else runtime CPE, else component type."""
    if comp.category.strip():
        return comp.category.strip()
    if comp.purl.lower().startswith("pkg:"):
        ptype = comp.purl[4:].split("/", 1)[0].lower()
        if ptype in PACKAGE_ECOSYSTEMS:
            return PACKAGE_ECOSYSTEMS[ptype]
    if comp.osv_ecosystem:
        eco = comp.osv_ecosystem.split(":", 1)[0].strip().lower()
        if eco in PACKAGE_ECOSYSTEMS:
            return PACKAGE_ECOSYSTEMS[eco]
    for cpe in comp.cpe:
        parts = cpe.split(":")
        if len(parts) > 4 and (parts[3].lower(), parts[4].lower()) in RUNTIME_CPES:
            return RUNTIME_CPES[(parts[3].lower(), parts[4].lower())]
    return TYPE_CATEGORIES.get((comp.type or "software").lower(), "Software")

NOT_APPLICABLE = "NOT APPLICABLE"
APPLICABILITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, NOT_APPLICABLE: 0}
APPLICABILITY_CHOICES = ["HIGH", "MEDIUM", "LOW", "ALL"]   # minimum applicability filter
SCOPE_CORE = "core"            # the component itself (runtime, compiler, tool, firmware, etc.)
SCOPE_RELATED = "ecosystem"    # libraries, plugins, frameworks, APIs built on / for the product
SCOPE_UNKNOWN = "unknown"
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
CVSS_VERSION_PREFERENCE = {"3.1": 4, "3.0": 3, "4.0": 2, "2.0": 1, "": 0}


SCOPE_LABELS = {SCOPE_CORE: "core component", SCOPE_RELATED: "ecosystem", SCOPE_UNKNOWN: "scope unconfirmed"}
SCOPE_RANK = {SCOPE_UNKNOWN: 0, SCOPE_RELATED: 1, SCOPE_CORE: 2}


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


@dataclass
class Component:
    name: str
    version: str = ""
    description: str = ""
    vendor: str = ""
    manufacturer: str = ""
    type: str = "software"          # software | hardware | firmware | tool | library
    keywords: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    cpe: List[str] = field(default_factory=list)
    projects: List[str] = field(default_factory=list)
    exclude_keywords: List[str] = field(default_factory=list)
    purl: str = ""                  # e.g. pkg:pypi/requests@2.25.1 (OSV.dev)
    osv_ecosystem: str = ""         # alternative to purl, e.g. "PyPI", "Debian"
    osv_package: str = ""
    category: str = ""              # e.g. "Core Component", "Package / Library"; empty = derived
    enabled: bool = True
    id: str = field(default_factory=_new_id)

    @property
    def label(self) -> str:
        return "{} {}".format(self.name, self.version).strip()

    @property
    def effective_category(self) -> str:
        return derive_category(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Component":
        known = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        data = {k: v for k, v in raw.items() if k in known}
        if not str(data.get("name", "")).strip():
            raise ValueError("Every component needs a non-empty 'name': {!r}".format(raw))
        for key in LIST_FIELDS:
            value = data.get(key)
            if value is None:
                data[key] = []
            elif isinstance(value, str):
                sep = "\n" if key == "cpe" else ","
                data[key] = [x.strip() for x in value.replace(";", sep).split(sep) if x.strip()]
            else:
                data[key] = [str(x).strip() for x in value if str(x).strip()]
        for key in STR_FIELDS:
            if key in data and data[key] is not None:
                data[key] = str(data[key]).strip()
        if not data.get("id"):
            data.pop("id", None)
        data["enabled"] = bool(data.get("enabled", True))
        return cls(**data)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_components(path: str) -> List[Component]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("components", []) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError("JSON must be a list of components or {'components': [...]}")
    comps = [Component.from_dict(item) for item in items]
    seen = set()  # type: Set[str]
    for comp in comps:
        while comp.id in seen:
            comp.id = _new_id()
        seen.add(comp.id)
    return comps


def save_components(path: str, components: List[Component]) -> None:
    data = {"schema_version": 1, "components": [c.to_dict() for c in components]}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


@dataclass
class ComponentMatch:
    component_id: str
    component_label: str
    applicability: str
    category: str = ""
    reasons: List[str] = field(default_factory=list)
    methods: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    scope: str = SCOPE_UNKNOWN
    evidence: List[str] = field(default_factory=list)   # exact search term / matched words

    def describe(self) -> str:
        return "{}: {} [{}] ({})".format(self.component_label, self.applicability,
                                        SCOPE_LABELS.get(self.scope, self.scope), "; ".join(self.reasons))


@dataclass
class Vulnerability:
    id: str
    aliases: Set[str] = field(default_factory=set)
    description: str = ""
    description_source: str = ""
    published: str = ""
    last_modified: str = ""
    nvd_status: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cvss_version: str = ""
    severity_hint: str = ""        # textual severity when no score is available
    cwes: Set[str] = field(default_factory=set)
    references: List[str] = field(default_factory=list)
    kev: bool = False
    kev_date_added: str = ""
    sources: Set[str] = field(default_factory=set)
    matches: Dict[str, ComponentMatch] = field(default_factory=dict)
    projects: Set[str] = field(default_factory=set)
    status: str = "NEW"
    first_seen: str = ""

    # ----- classification ---------------------------------------------
    @property
    def applicability(self) -> str:
        if not self.matches:
            return NOT_APPLICABLE
        return max((m.applicability for m in self.matches.values()),
                   key=lambda a: APPLICABILITY_ORDER.get(a, 0))

    @property
    def criticality(self) -> str:
        from .cvss import severity_from_score
        if self.cvss_score is not None:
            return severity_from_score(self.cvss_score)
        hint = (self.severity_hint or "").upper()
        if hint == "MODERATE":
            hint = "MEDIUM"
        return hint if hint in SEVERITY_ORDER else "UNKNOWN"

    @property
    def risk_rank(self) -> float:
        """Sort key combining applicability, criticality and KEV."""
        return (APPLICABILITY_ORDER.get(self.applicability, 0) * 100
                + SEVERITY_ORDER.get(self.criticality, 0) * 10
                + (5 if self.kev else 0) + (self.cvss_score or 0) / 10.0)

    # ----- merging ------------------------------------------------------
    def add_match(self, component: "Component", applicability: str, reason: str,
                  method: str, source: str, scope: str = SCOPE_UNKNOWN, evidence: str = "") -> None:
        match = self.matches.get(component.id)
        if match is None:
            match = ComponentMatch(component.id, component.label, applicability,
                                   component.effective_category, scope=scope)
            self.matches[component.id] = match
        else:
            if APPLICABILITY_ORDER[applicability] > APPLICABILITY_ORDER[match.applicability]:
                match.applicability = applicability
                match.reasons = [r for r in match.reasons if not r.startswith("not applicable:")]
            if SCOPE_RANK.get(scope, 0) > SCOPE_RANK.get(match.scope, 0):
                match.scope = scope
        if applicability == NOT_APPLICABLE and match.applicability != NOT_APPLICABLE:
            reason = ""   # a stronger match exists; keep the report focused on it
        elif applicability == NOT_APPLICABLE:
            reason = "not applicable: " + reason if reason else ""
        if reason and reason not in match.reasons:
            match.reasons.append(reason)
        if evidence and evidence not in match.evidence:
            match.evidence.append(evidence)
        match.methods.add(method)
        match.sources.add(source)
        self.sources.add(source)
        self.projects.update(component.projects)

    def keep_matches(self, min_rank: int) -> None:
        """Drop component matches below the minimum applicability rank."""
        self.matches = {k: m for k, m in self.matches.items()
                        if APPLICABILITY_ORDER.get(m.applicability, 0) >= min_rank}

    def update_cvss(self, score: Optional[float], vector: str, version: str) -> None:
        if score is None and not vector:
            return
        current = CVSS_VERSION_PREFERENCE.get(self.cvss_version, 0) if self.cvss_score is not None else -1
        new = CVSS_VERSION_PREFERENCE.get(version, 0) if score is not None else -1
        if new > current or (self.cvss_score is None and not self.cvss_vector):
            self.cvss_score, self.cvss_vector, self.cvss_version = score, vector, version

    def update_text(self, description: str, source: str, published: str, modified: str) -> None:
        # NVD descriptions are preferred over other sources.
        if description and (not self.description or (source == "NVD" and self.description_source != "NVD")):
            self.description, self.description_source = description, source
        if published and (not self.published or published < self.published):
            self.published = published
        if modified and modified > self.last_modified:
            self.last_modified = modified

    def absorb(self, other: "Vulnerability") -> None:
        """Merge another record describing the same vulnerability into this one."""
        self.aliases.update(other.aliases)
        if other.id != self.id:
            self.aliases.add(other.id)
        self.aliases.discard(self.id)
        self.update_text(other.description, other.description_source, other.published, other.last_modified)
        self.update_cvss(other.cvss_score, other.cvss_vector, other.cvss_version)
        self.severity_hint = self.severity_hint or other.severity_hint
        self.nvd_status = self.nvd_status or other.nvd_status
        self.cwes.update(other.cwes)
        for ref in other.references:
            if ref not in self.references:
                self.references.append(ref)
        self.kev = self.kev or other.kev
        self.kev_date_added = self.kev_date_added or other.kev_date_added
        self.sources.update(other.sources)
        self.projects.update(other.projects)
        for cid, match in other.matches.items():
            mine = self.matches.get(cid)
            if mine is None:
                self.matches[cid] = match
                continue
            if APPLICABILITY_ORDER[match.applicability] > APPLICABILITY_ORDER[mine.applicability]:
                mine.applicability = match.applicability
            if SCOPE_RANK.get(match.scope, 0) > SCOPE_RANK.get(mine.scope, 0):
                mine.scope = match.scope
            for e in match.evidence:
                if e not in mine.evidence:
                    mine.evidence.append(e)
            for r in match.reasons:
                if r not in mine.reasons:
                    mine.reasons.append(r)
            mine.methods.update(match.methods)
            mine.sources.update(match.sources)

    # ----- export -------------------------------------------------------
    def to_record(self) -> Dict[str, Any]:
        matches = sorted(self.matches.values(),
                         key=lambda m: (-APPLICABILITY_ORDER.get(m.applicability, 0), m.component_label))
        methods = []  # type: List[str]
        for m in matches:
            for e in (m.evidence or sorted(m.methods)):
                text = "{}: {}".format(m.component_label, e) if len(matches) > 1 else e
                if text not in methods:
                    methods.append(text)
        return {
            "status": self.status,
            "id": self.id,
            "aliases": sorted(self.aliases),
            "criticality": self.criticality,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "applicability": self.applicability,
            "applicability_details": [m.describe() for m in matches],
            "component_name": [m.component_label.rsplit(" ", 1)[0] if " " in m.component_label else m.component_label for m in matches],
            "version": [m.component_label.rsplit(" ", 1)[1] if " " in m.component_label else "" for m in matches],
            "components": [m.component_label for m in matches],
            "component_count": len(matches),
            "categories": sorted({m.category for m in matches if m.category}),
            "projects": sorted(self.projects),
            "sources": sorted(self.sources),
            "match_methods": methods,
            "kev": "YES" if self.kev else "NO",
            "kev_date_added": self.kev_date_added,
            "cwes": sorted(self.cwes),
            "published": self.published[:10],
            "last_modified": self.last_modified[:10],
            "nvd_status": self.nvd_status,
            "description": self.description,
            "first_seen": self.first_seen,
        }


# Column definitions shared by all report writers: (key, label, type)
REPORT_COLUMNS = [
    ("component_name", "Component name", "list"),
    ("version", "Version", "list"),
    ("id", "Vulnerability ID", "text"),
    ("criticality", "Criticality", "severity"),
    ("status", "Status", "enum"),
    ("cvss_score", "CVSS Score", "number"),
    ("cvss_version", "CVSS Version", "enum"),
    ("applicability", "Applicability", "applicability"),
    ("components", "Components", "list"),
    ("projects", "Projects", "list"),
    ("sources", "Sources", "list"),
    ("match_methods", "Match Method", "list"),
    ("kev", "Known Exploited (CISA KEV)", "enum"),
    ("cwes", "CWE", "list"),
    ("published", "Published", "date"),
    ("last_modified", "Last Modified", "date"),
    ("nvd_status", "NVD Status", "enum"),
    ("description", "Description", "text"),
    ("applicability_details", "Applicability Details", "list"),
    ("cvss_vector", "CVSS Vector", "text"),
]
