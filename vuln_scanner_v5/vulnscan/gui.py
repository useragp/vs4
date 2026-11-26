"""tkinter GUI for the vulnerability scanner."""

import datetime as dt
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from typing import Callable, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .credentials import get_nvd_api_key, set_nvd_api_key
from .models import SUGGESTED_CATEGORIES, Component, load_components, save_components
from .scanner import DEFAULT_REPORTS_DIR, LOOKBACK_CHOICES, ScanOptions, Scanner, parse_date_range
from .sources import NVDClient, ScanCancelled
from .versions import validate_cpe

TABLE_COLUMNS = [
    ("enabled", "Scan", 45), ("name", "Name", 140), ("version", "Version", 75),
    ("type", "Type", 75), ("effective_category", "Category", 120), ("vendor", "Vendor", 110), ("manufacturer", "Manufacturer", 110),
    ("description", "Description", 220), ("keywords", "Keywords", 160), ("aliases", "Aliases", 120),
    ("cpe", "CPE", 300), ("projects", "Projects", 150), ("purl", "purl (OSV)", 150),
    ("exclude_keywords", "Exclude keywords", 120),
]
COMPONENT_TYPES = ["software", "hardware", "firmware", "tool", "library", "os"]
LOOKBACK_LABELS = ["{} day{}".format(d, "" if d == 1 else "s") for d in LOOKBACK_CHOICES]
MIN_APP_LABELS = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
                  "ALL (incl. not applicable)": "ALL"}


def _fmt(value) -> str:
    if isinstance(value, list):
        return ", ".join(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def open_path(path: str) -> None:
    if sys.platform.startswith("win"):
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# ---------------------------------------------------------------------------
class CpeLookupDialog(tk.Toplevel):
    """Search the NVD CPE dictionary and pick CPE names (reduces false positives)."""

    def __init__(self, master: tk.Misc, initial: str, api_key: str,
                 on_pick: Callable[[str], None]) -> None:
        super().__init__(master)
        self.title("NVD CPE dictionary lookup")
        self.geometry("760x420")
        self.on_pick, self.api_key = on_pick, api_key
        self.q = queue.Queue()  # type: queue.Queue
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Keyword:").pack(side="left")
        self.var = tk.StringVar(value=initial)
        entry = ttk.Entry(top, textvariable=self.var, width=50)
        entry.pack(side="left", padx=4)
        entry.bind("<Return>", lambda e: self._search())
        self.btn = ttk.Button(top, text="Search", command=self._search)
        self.btn.pack(side="left")
        self.status = ttk.Label(top, text="")
        self.status.pack(side="left", padx=8)
        self.tree = ttk.Treeview(self, columns=("cpe", "title"), show="headings", selectmode="extended")
        self.tree.heading("cpe", text="CPE name")
        self.tree.heading("title", text="Title")
        self.tree.column("cpe", width=420)
        self.tree.column("title", width=300)
        self.tree.pack(fill="both", expand=True, padx=6)
        self.tree.bind("<Double-1>", lambda e: self._use())
        bottom = ttk.Frame(self, padding=6)
        bottom.pack(fill="x")
        ttk.Label(bottom, text="Tip: pick the exact version CPE, or edit the version field afterwards.").pack(side="left")
        ttk.Button(bottom, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(bottom, text="Add selected", command=self._use).pack(side="right", padx=4)
        self.transient(master)
        self.after(100, self._poll)

    def _search(self) -> None:
        keyword = self.var.get().strip()
        if len(keyword) < 3:
            return
        self.btn.state(["disabled"])
        self.status.config(text="Searching...")

        def work() -> None:
            try:
                self.q.put(("ok", NVDClient(self.api_key, log=lambda m: None).search_cpe_dictionary(keyword)))
            except Exception as exc:  # noqa: BLE001 - shown to the user
                self.q.put(("err", str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self) -> None:
        try:
            kind, payload = self.q.get_nowait()
        except queue.Empty:
            if self.winfo_exists():
                self.after(150, self._poll)
            return
        self.btn.state(["!disabled"])
        if kind == "err":
            self.status.config(text="Error")
            messagebox.showerror("CPE lookup failed", payload, parent=self)
        else:
            self.tree.delete(*self.tree.get_children())
            for cpe, title in payload:
                self.tree.insert("", "end", values=(cpe, title))
            self.status.config(text="{} results".format(len(payload)))
        self.after(150, self._poll)

    def _use(self) -> None:
        for item in self.tree.selection():
            self.on_pick(self.tree.item(item, "values")[0])


# ---------------------------------------------------------------------------
class ComponentDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc, component: Optional[Component], api_key_getter: Callable[[], str]) -> None:
        super().__init__(master)
        self.title("Edit component" if component else "Add component")
        self.resizable(True, True)
        self.result = None  # type: Optional[Component]
        self.component = component
        self.api_key_getter = api_key_getter
        c = component or Component(name="")
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        self.vars = {}
        row = 0

        def add_entry(key: str, label: str, value: str, hint: str = "") -> None:
            nonlocal row
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w", pady=2)
            var = tk.StringVar(value=value)
            ttk.Entry(frm, textvariable=var, width=60).grid(row=row, column=1, sticky="ew", pady=2)
            if hint:
                ttk.Label(frm, text=hint, foreground="#666").grid(row=row, column=2, sticky="w", padx=4)
            self.vars[key] = var
            row += 1

        add_entry("name", "Name *", c.name)
        add_entry("version", "Version", c.version, "used for version-range matching")
        ttk.Label(frm, text="Type").grid(row=row, column=0, sticky="w")
        self.vars["type"] = tk.StringVar(value=c.type or "software")
        ttk.Combobox(frm, textvariable=self.vars["type"], values=COMPONENT_TYPES).grid(row=row, column=1, sticky="w")
        row += 1
        ttk.Label(frm, text="Category").grid(row=row, column=0, sticky="w")
        self.vars["category"] = tk.StringVar(value=c.category)
        ttk.Combobox(frm, textvariable=self.vars["category"], values=SUGGESTED_CATEGORIES,
                     width=25).grid(row=row, column=1, sticky="w")
        ttk.Label(frm, text="empty = automatic (package URL / ecosystem / CPE / component type)",
                  foreground="#666").grid(row=row, column=2, sticky="w", padx=4)
        row += 1
        add_entry("vendor", "Vendor", c.vendor)
        add_entry("manufacturer", "Manufacturer", c.manufacturer)
        add_entry("keywords", "Keywords", ", ".join(c.keywords), "comma separated, exact phrases")
        add_entry("aliases", "Aliases", ", ".join(c.aliases), "comma separated")
        add_entry("projects", "Projects", ", ".join(c.projects), "comma separated")
        add_entry("exclude_keywords", "Exclude keywords", ", ".join(c.exclude_keywords), "drop CVEs mentioning these")
        add_entry("purl", "Package URL (purl)", c.purl, "e.g. pkg:pypi/requests@2.31.0 (OSV.dev)")
        add_entry("osv_ecosystem", "OSV ecosystem", c.osv_ecosystem, "alternative to purl, e.g. PyPI, Debian")
        add_entry("osv_package", "OSV package", c.osv_package)

        ttk.Label(frm, text="Description").grid(row=row, column=0, sticky="nw")
        self.desc = tk.Text(frm, height=3, width=60, wrap="word")
        self.desc.insert("1.0", c.description)
        self.desc.grid(row=row, column=1, sticky="ew", pady=2)
        row += 1
        ttk.Label(frm, text="CPE 2.3 (one per line)").grid(row=row, column=0, sticky="nw")
        self.cpe = tk.Text(frm, height=4, width=60, wrap="none")
        self.cpe.insert("1.0", "\n".join(c.cpe))
        self.cpe.grid(row=row, column=1, sticky="ew", pady=2)
        ttk.Button(frm, text="Look up in NVD...", command=self._lookup).grid(row=row, column=2, sticky="nw", padx=4)
        row += 1
        self.enabled = tk.BooleanVar(value=c.enabled)
        ttk.Checkbutton(frm, text="Include in scan", variable=self.enabled).grid(row=row, column=1, sticky="w")
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right", padx=4)
        self.bind("<Escape>", lambda e: self.destroy())
        self.transient(master)
        self.grab_set()

    def _lookup(self) -> None:
        name = self.vars["name"].get().strip()
        initial = " ".join(x for x in (self.vars["vendor"].get().strip(), name) if x)

        def pick(cpe: str) -> None:
            existing = self.cpe.get("1.0", "end").strip()
            if cpe not in existing.splitlines():
                self.cpe.insert("end", ("\n" if existing else "") + cpe)
        CpeLookupDialog(self, initial, self.api_key_getter(), pick)

    def _ok(self) -> None:
        name = self.vars["name"].get().strip()
        if not name:
            messagebox.showerror("Missing name", "The component name is required.", parent=self)
            return
        cpes = [x.strip() for x in self.cpe.get("1.0", "end").splitlines() if x.strip()]
        for cpe in cpes:
            ok, why = validate_cpe(cpe)
            if not ok:
                messagebox.showerror("Invalid CPE", "{}\n\n{}".format(cpe, why), parent=self)
                return
        split = lambda key: [x.strip() for x in self.vars[key].get().split(",") if x.strip()]  # noqa: E731
        data = {k: v.get().strip() for k, v in self.vars.items()}
        for key in ("keywords", "aliases", "projects", "exclude_keywords"):
            data[key] = split(key)
        data.update(description=self.desc.get("1.0", "end").strip(), cpe=cpes, enabled=self.enabled.get())
        if self.component:
            data["id"] = self.component.id
        self.result = Component.from_dict(data)
        self.destroy()


# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self, components_path: Optional[str] = None) -> None:
        super().__init__()
        self.title("Automotive Component Vulnerability Scanner")
        self.geometry("1450x900")
        self.minsize(1000, 650)
        try:
            self.state("zoomed")
        except tk.TclError:
            pass
        self.components = []  # type: List[Component]
        self.path = None  # type: Optional[str]
        self.dirty = False
        self.baseline_component_ids = set()
        self.queue = queue.Queue()  # type: queue.Queue
        self.cancel_event = threading.Event()
        self.worker = None  # type: Optional[threading.Thread]
        self.last_reports = {}
        self.last_report_dir = ""
        self._last_html_pointer = os.path.join(DEFAULT_REPORTS_DIR, ".last_html_report.txt")
        self._find_latest_html_report()
        self.sort_state = ("name", False)
        try:
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("Treeview", rowheight=27, font=("Segoe UI", 9), background="#ffffff", fieldbackground="#ffffff", borderwidth=1, relief="solid")
            style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=(7, 7), background="#e8edf3", borderwidth=1, relief="solid")
            style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#172554")])
            style.configure("Treeview", bordercolor="#cbd5e1")
            style.configure("TButton", padding=(9, 5), font=("Segoe UI", 9))
            style.configure("TLabelframe.Label", font=("Segoe UI", 9, "bold"))
            style.configure("TCheckbutton", padding=(2, 3))
            style.configure("TRadiobutton", padding=(2, 3))
            style.configure("TLabel", padding=(1, 1))
        except tk.TclError:
            pass
        self._build_menu()
        self._build_ui()
        if components_path and os.path.exists(components_path):
            self._load(components_path)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)

    # ----- layout ----------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        fm = tk.Menu(menubar, tearoff=False)
        fm.add_command(label="New component list", command=self._new)
        fm.add_command(label="Open components JSON...", command=self._open, accelerator="Ctrl+O")
        fm.add_command(label="Save", command=self._save, accelerator="Ctrl+S")
        fm.add_command(label="Save as...", command=self._save_as)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=fm)
        hm = tk.Menu(menubar, tearoff=False)
        hm.add_command(label="About applicability levels", command=self._about)
        menubar.add_cascade(label="Help", menu=hm)
        self.config(menu=menubar)
        self.bind("<Control-o>", lambda e: self._open())
        self.bind("<Control-s>", lambda e: self._save())

    def _build_ui(self) -> None:
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=6)

        # Components table
        comp_frame = ttk.LabelFrame(paned, text="Components", padding=4)
        paned.add(comp_frame, weight=3)
        bar = ttk.Frame(comp_frame)
        bar.pack(fill="x")
        for text, cmd in (("Add", self._add), ("Edit", self._edit), ("Duplicate", self._duplicate),
                          ("Remove", self._remove), ("Toggle scan", self._toggle)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=2)
        ttk.Label(bar, text="   Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._refresh_table())
        ttk.Entry(bar, textvariable=self.search_var, width=25).pack(side="left", padx=2)
        ttk.Label(bar, text="  Project:").pack(side="left")
        self.project_var = tk.StringVar(value="(all)")
        self.project_cb = ttk.Combobox(bar, textvariable=self.project_var, width=22, state="readonly")
        self.project_cb.pack(side="left", padx=2)
        self.project_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())
        ttk.Label(bar, text="  Category:").pack(side="left")
        self.category_var = tk.StringVar(value="(all)")
        self.category_cb = ttk.Combobox(bar, textvariable=self.category_var, width=20, state="readonly")
        self.category_cb.pack(side="left", padx=2)
        self.category_cb.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())
        self.count_label = ttk.Label(bar, text="")
        self.count_label.pack(side="right")

        table_wrap = ttk.Frame(comp_frame)
        table_wrap.pack(fill="both", expand=True, pady=(4, 0))
        self.tree = ttk.Treeview(table_wrap, columns=[c[0] for c in TABLE_COLUMNS if c[0] != "enabled"],
                                 show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Scan", command=lambda: self._sort_by("enabled"))
        self.tree.column("#0", width=58, minwidth=58, stretch=False, anchor="center")
        for key, label, width in TABLE_COLUMNS:
            if key == "enabled":
                continue
            self.tree.heading(key, text=label, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, minwidth=40, stretch=False)
        ysb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)
        self.tree.tag_configure("disabled", foreground="#9e9e9e")
        self.tree.tag_configure("stripe", background="#f6f8fb")
        self.tree.tag_configure("disabled_stripe", background="#f1f3f5", foreground="#9e9e9e")
        self.tree.bind("<Double-1>", lambda e: self._edit())
        self.tree.bind("<Button-1>", self._scan_checkbox_click, add="+")
        self.tree.bind("<Delete>", lambda e: self._remove())

        # Settings
        bottom = ttk.Frame(paned)
        paned.add(bottom, weight=2)
        settings = ttk.LabelFrame(bottom, text="Scan settings", padding=(10, 8))
        settings.pack(fill="x", padx=4, pady=(4, 8))
        for col in range(3):
            settings.columnconfigure(col, weight=1, uniform="settings")
        pad = dict(padx=6, pady=4, sticky="nsew")

        # --- 1. Scan period ------------------------------------------------------
        period = ttk.LabelFrame(settings, text="Scan period", padding=(10, 6))
        period.grid(row=0, column=0, **pad)
        self.period_mode = tk.StringVar(value="lookback")
        ttk.Radiobutton(period, text="Last", value="lookback", variable=self.period_mode,
                        command=self._update_period_widgets).grid(row=0, column=0, sticky="w", pady=2)
        self.lookback_var = tk.StringVar(value=LOOKBACK_LABELS[1])
        self.lookback_cb = ttk.Combobox(period, textvariable=self.lookback_var, values=LOOKBACK_LABELS, width=9,
                                        state="readonly")
        self.lookback_cb.grid(row=0, column=1, columnspan=2, sticky="w", padx=4, pady=2)
        ttk.Radiobutton(period, text="Date range", value="range", variable=self.period_mode,
                        command=self._update_period_widgets).grid(row=1, column=0, sticky="w", pady=2)
        today = dt.date.today()
        self.start_var = tk.StringVar(value=(today - dt.timedelta(days=30)).isoformat())
        self.end_var = tk.StringVar(value=today.isoformat())
        rng = ttk.Frame(period)
        rng.grid(row=1, column=1, columnspan=2, sticky="w", padx=4, pady=2)
        self.start_entry = ttk.Entry(rng, textvariable=self.start_var, width=11)
        self.start_entry.pack(side="left")
        ttk.Label(rng, text=" to ").pack(side="left")
        self.end_entry = ttk.Entry(rng, textvariable=self.end_var, width=11)
        self.end_entry.pack(side="left")
        ttk.Label(period, text="dates as YYYY-MM-DD (UTC, whole days)", foreground="#757575").grid(
            row=2, column=1, columnspan=2, sticky="w", padx=4)
        ttk.Separator(period).grid(row=3, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Label(period, text="Apply period to:").grid(row=4, column=0, columnspan=3, sticky="w")
        self.date_pub = tk.BooleanVar(value=True)
        self.date_mod = tk.BooleanVar(value=True)
        ttk.Checkbutton(period, text="Published date", variable=self.date_pub).grid(row=5, column=0, columnspan=2,
                                                                                   sticky="w", pady=2)
        ttk.Checkbutton(period, text="Last modified date", variable=self.date_mod).grid(row=5, column=2,
                                                                                       sticky="w", pady=2)
        self._update_period_widgets()

        # --- 2. Sources & matching ---------------------------------------------------
        match = ttk.LabelFrame(settings, text="Sources & matching", padding=(10, 6))
        match.grid(row=0, column=1, **pad)
        match.columnconfigure(0, weight=1, uniform="src")
        match.columnconfigure(1, weight=1, uniform="src")
        self.use_cpe = tk.BooleanVar(value=True)
        self.use_kw = tk.BooleanVar(value=True)
        self.use_osv = tk.BooleanVar(value=True)
        self.use_kev = tk.BooleanVar(value=True)
        self.use_cna = tk.BooleanVar(value=True)
        self.strict = tk.BooleanVar(value=True)
        for i, (text, var) in enumerate(((("NVD (CPE)", self.use_cpe)), ("NVD (keywords)", self.use_kw),
                                         ("CVE.org (CNA versions)", self.use_cna), ("OSV.dev", self.use_osv),
                                         ("CISA KEV", self.use_kev))):
            ttk.Checkbutton(match, text=text, variable=var).grid(row=i // 2, column=i % 2, sticky="w", pady=2)
        ttk.Separator(match).grid(row=3, column=0, columnspan=2, sticky="ew", pady=6)
        ttk.Checkbutton(match, text="Strict mode (minimise false positives)", variable=self.strict).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=2)
        ma = ttk.Frame(match)
        ma.grid(row=5, column=0, columnspan=2, sticky="w", pady=2)
        ttk.Label(ma, text="Minimum applicability:").pack(side="left")
        self.min_app = tk.StringVar(value="LOW")
        ttk.Combobox(ma, textvariable=self.min_app, values=list(MIN_APP_LABELS), width=21,
                     state="readonly").pack(side="left", padx=4)
        self.include_deferred = tk.BooleanVar(value=False)
        ttk.Checkbutton(match, text="Include deferred (NVD status \"Deferred\")", variable=self.include_deferred).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=2)

        # --- 3. What to scan ----------------------------------------------------------
        what = ttk.LabelFrame(settings, text="What to scan", padding=(10, 6))
        what.grid(row=0, column=2, **pad)
        ttk.Label(what, text="Components:").grid(row=0, column=0, sticky="w")
        self.scope_var = tk.StringVar(value="enabled")
        cf = ttk.Frame(what)
        cf.grid(row=1, column=0, sticky="w", pady=(0, 2))
        for text, val in (("all enabled", "enabled"), ("selected rows", "selected"), ("visible rows", "visible")):
            ttk.Radiobutton(cf, text=text, value=val, variable=self.scope_var).pack(side="left", padx=(0, 8))
        ttk.Separator(what).grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Label(what, text="Product scope:").grid(row=3, column=0, sticky="w")
        self.prod_scope = tk.StringVar(value="core")
        ttk.Radiobutton(what, text="Core component only (runtime, tool, firmware)",
                        value="core", variable=self.prod_scope).grid(row=4, column=0, sticky="w", pady=1)
        ttk.Radiobutton(what, text="Core + ecosystem (libraries, plugins, APIs)",
                        value="ecosystem", variable=self.prod_scope).grid(row=5, column=0, sticky="w", pady=1)
        ttk.Separator(what).grid(row=6, column=0, sticky="ew", pady=6)
        rc = ttk.Frame(what)
        rc.grid(row=7, column=0, sticky="w")
        ttk.Label(rc, text="Report categories:").pack(side="left")
        self.scan_cat_vars = {}  # type: Dict[str, tk.BooleanVar]
        self.scan_cat_btn = ttk.Menubutton(rc, text="(all)", width=18)
        self.scan_cat_menu = tk.Menu(self.scan_cat_btn, tearoff=False)
        self.scan_cat_btn["menu"] = self.scan_cat_menu
        self.scan_cat_btn.pack(side="left", padx=4)
        ttk.Label(what, text="none ticked = all categories", foreground="#757575").grid(row=8, column=0, sticky="w")

        # Spread each group's rows over the shared row height so the three boxes look balanced.
        for box in (period, match, what):
            rows = box.grid_size()[1]
            for r in range(rows):
                box.rowconfigure(r, weight=1)

        # --- 4. Output & access (full width) ------------------------------------------
        out = ttk.LabelFrame(settings, text="Output & access", padding=(10, 6))
        out.grid(row=1, column=0, columnspan=3, **pad)
        out.columnconfigure(1, weight=1)
        out.columnconfigure(4, weight=1)
        ttk.Label(out, text="Reports folder:").grid(row=0, column=0, sticky="w", pady=3)
        self.out_var = tk.StringVar(value=DEFAULT_REPORTS_DIR)
        ttk.Entry(out, textvariable=self.out_var).grid(row=0, column=1, sticky="ew", padx=4, pady=3)
        ttk.Button(out, text="Browse...", command=self._browse_out).grid(row=0, column=2, sticky="w", pady=3)
        ttk.Label(out, text="Formats:").grid(row=0, column=3, sticky="e", padx=(18, 4), pady=3)
        ff = ttk.Frame(out)
        ff.grid(row=0, column=4, sticky="w", pady=3)
        self.fmt_vars = {f: tk.BooleanVar(value=True) for f in ("csv", "xlsx", "html", "json")}
        for f, var in self.fmt_vars.items():
            ttk.Checkbutton(ff, text=f.upper(), variable=var).pack(side="left", padx=(0, 8))
        ttk.Label(ff, text="  CSV separator:").pack(side="left")
        self.csv_sep = tk.StringVar(value="; (Excel PL/EU)")
        ttk.Combobox(ff, textvariable=self.csv_sep, values=["; (Excel PL/EU)", ", (international)"], width=16,
                     state="readonly").pack(side="left", padx=4)
        ttk.Label(out, text="NVD API key:").grid(row=1, column=0, sticky="w", pady=3)
        self.api_var = tk.StringVar(value=get_nvd_api_key())
        ttk.Entry(out, textvariable=self.api_var, show="*").grid(row=1, column=1, sticky="ew", padx=4, pady=3)
        ttk.Button(out, text="Save securely", command=self._save_api_key).grid(row=1, column=2, sticky="w", pady=3)
        ttk.Label(out, text="stored in the OS credential vault; NVD_API_KEY is also accepted; one sub-folder per scan",
                  foreground="#757575").grid(row=1, column=3, columnspan=2, sticky="w", padx=(18, 0), pady=3)

        r3 = ttk.Frame(bottom, padding=(0, 6))
        r3.pack(fill="x")
        self.scan_btn = ttk.Button(r3, text="Start scan", command=self._start_scan)
        self.scan_btn.pack(side="left")
        self.cancel_btn = ttk.Button(r3, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=4)
        self.html_btn = ttk.Button(r3, text="Open HTML report", command=self._open_html, state=("normal" if self.last_reports.get("html") else "disabled"))
        self.html_btn.pack(side="left", padx=4)
        ttk.Button(r3, text="Open output folder", command=self._open_out).pack(side="left")
        self.progress = ttk.Progressbar(r3, mode="determinate", length=300)
        self.progress.pack(side="left", padx=10)
        self.status = ttk.Label(r3, text="Ready")
        self.status.pack(side="left")

        log_frame = ttk.LabelFrame(bottom, text="Log", padding=2)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=10, wrap="word", state="disabled", font=("Consolas", 9))
        lsb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=lsb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

    # ----- component table -------------------------------------------------
    def _scan_checkbox_click(self, event):
        if self.tree.identify_region(event.x, event.y) == "tree" and self.tree.identify_column(event.x) == "#0":
            item = self.tree.identify_row(event.y)
            comp = next((c for c in self.components if c.id == item), None)
            if comp is not None:
                comp.enabled = not comp.enabled
                self._refresh_table()
                return "break"

    def _visible_components(self) -> List[Component]:
        term = self.search_var.get().strip().lower()
        project = self.project_var.get()
        category = self.category_var.get()
        out = []
        for c in self.components:
            if project not in ("", "(all)") and project not in c.projects:
                continue
            if category not in ("", "(all)") and c.effective_category != category:
                continue
            if term:
                blob = " ".join(_fmt(v) for v in c.to_dict().values()).lower()
                if term not in blob:
                    continue
            out.append(c)
        key, reverse = self.sort_state
        out.sort(key=lambda c: _fmt(getattr(c, key)).lower(), reverse=reverse)
        return out

    def _refresh_table(self) -> None:
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        visible = self._visible_components()
        for row_index, c in enumerate(visible):
            values = [_fmt(getattr(c, key)) for key, _, _ in TABLE_COLUMNS if key != "enabled"]
            tags = ("disabled_stripe",) if not c.enabled and row_index % 2 else (("disabled",) if not c.enabled else (("stripe",) if row_index % 2 else ()))
            self.tree.insert("", "end", iid=c.id, text="☑" if c.enabled else "☐", values=values, tags=tags)
        keep = [i for i in selected if self.tree.exists(i)]
        if keep:
            self.tree.selection_set(keep)
        projects = sorted({p for c in self.components for p in c.projects})
        self.project_cb["values"] = ["(all)"] + projects
        categories = sorted({c.effective_category for c in self.components})
        self.category_cb["values"] = ["(all)"] + categories
        self._refresh_scan_categories(categories)
        self.count_label.config(text="{} shown / {} total / {} enabled".format(
            len(visible), len(self.components), sum(1 for c in self.components if c.enabled)))
        title = os.path.basename(self.path) if self.path else "untitled"
        self.title("Automotive Component Vulnerability Scanner - {}{}".format(title, " *" if self.dirty else ""))

    def _refresh_scan_categories(self, categories: List[str]) -> None:
        for cat in categories:
            if cat not in self.scan_cat_vars:
                self.scan_cat_vars[cat] = tk.BooleanVar(value=False)
        self.scan_cat_menu.delete(0, "end")
        for cat in categories:
            self.scan_cat_menu.add_checkbutton(label=cat, variable=self.scan_cat_vars[cat],
                                               command=self._update_scan_cat_label)
        self.scan_cat_menu.add_separator()
        self.scan_cat_menu.add_command(label="Clear (all categories)", command=self._clear_scan_categories)
        self._update_scan_cat_label()

    def _selected_scan_categories(self) -> List[str]:
        present = {c.effective_category for c in self.components}
        return [c for c, v in self.scan_cat_vars.items() if v.get() and c in present]

    def _update_scan_cat_label(self) -> None:
        chosen = self._selected_scan_categories()
        self.scan_cat_btn.config(text=", ".join(chosen) if chosen else "(all)")

    def _clear_scan_categories(self) -> None:
        for v in self.scan_cat_vars.values():
            v.set(False)
        self._update_scan_cat_label()

    def _sort_by(self, key: str) -> None:
        cur, rev = self.sort_state
        self.sort_state = (key, not rev if cur == key else False)
        self._refresh_table()

    def _selected(self) -> List[Component]:
        ids = set(self.tree.selection())
        return [c for c in self.components if c.id in ids]

    def _mark_dirty(self) -> None:
        self.dirty = True
        self._refresh_table()

    def _add(self) -> None:
        dlg = ComponentDialog(self, None, self.api_var.get)
        self.wait_window(dlg)
        if dlg.result:
            self.components.append(dlg.result)
            self._mark_dirty()

    def _edit(self) -> None:
        sel = self._selected()
        if not sel:
            return
        dlg = ComponentDialog(self, sel[0], self.api_var.get)
        self.wait_window(dlg)
        if dlg.result:
            idx = self.components.index(sel[0])
            self.components[idx] = dlg.result
            self._mark_dirty()

    def _duplicate(self) -> None:
        for c in self._selected():
            data = c.to_dict()
            data.pop("id")
            data["name"] = c.name + " (copy)"
            self.components.append(Component.from_dict(data))
        self._mark_dirty()

    def _remove(self) -> None:
        sel = self._selected()
        if not sel:
            return
        if messagebox.askyesno("Remove components", "Remove {} component(s)?\n{}".format(
                len(sel), "\n".join(c.label for c in sel[:15]))):
            self.components = [c for c in self.components if c not in sel]
            self._mark_dirty()

    def _toggle(self) -> None:
        for c in self._selected():
            c.enabled = not c.enabled
        self._mark_dirty()

    # ----- file handling ------------------------------------------------------
    def _confirm_discard(self) -> bool:
        if not self.dirty:
            return True
        answer = messagebox.askyesnocancel("Unsaved changes", "Save changes to the component list first?")
        if answer is None:
            return False
        return self._save() if answer else True

    def _new(self) -> None:
        if self._confirm_discard():
            self.components, self.path, self.dirty = [], None, False
            self.baseline_component_ids = set()
            self._refresh_table()

    def _open(self) -> None:
        if not self._confirm_discard():
            return
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if path:
            self._load(path)

    def _load(self, path: str) -> None:
        try:
            self.components = load_components(path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Cannot load components", str(exc))
            return
        self.path, self.dirty = path, False
        self.baseline_component_ids = {c.id for c in self.components}
        self._refresh_table()
        self._log("Loaded {} components from {}".format(len(self.components), path))

    def _save(self) -> bool:
        if not self.path:
            return self._save_as()
        try:
            save_components(self.path, self.components)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))
            return False
        self.dirty = False
        self._refresh_table()
        return True

    def _save_as(self) -> bool:
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return False
        self.path = path
        return self._save()

    def _browse_out(self) -> None:
        path = filedialog.askdirectory(initialdir=self.out_var.get())
        if path:
            self.out_var.set(path)

    def _update_period_widgets(self) -> None:
        custom = self.period_mode.get() == "range"
        self.lookback_cb.configure(state="disabled" if custom else "readonly")
        for w in (self.start_entry, self.end_entry):
            w.configure(state="normal" if custom else "disabled")

    # ----- scanning -------------------------------------------------------------
    def _save_api_key(self) -> None:
        try:
            set_nvd_api_key(self.api_var.get())
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror("NVD API key", str(exc))
            return
        messagebox.showinfo("NVD API key", "API key saved in the operating-system credential vault.")

    def _start_scan(self) -> None:
        days = LOOKBACK_CHOICES[LOOKBACK_LABELS.index(self.lookback_var.get())] \
            if self.lookback_var.get() in LOOKBACK_LABELS else 7
        start_date = end_date = None
        if self.period_mode.get() == "range":
            try:
                start_date, end_date = parse_date_range(self.start_var.get(), self.end_var.get())
            except ValueError as exc:
                messagebox.showwarning("Date range", str(exc))
                return
            if (end_date - start_date).days > 366:
                if not messagebox.askyesno("Long date range",
                                           "The range covers {} days. Keyword searches over long periods "
                                           "can take a long time without an NVD API key. Continue?"
                                           .format((end_date - start_date).days + 1)):
                    return
        scope = self.scope_var.get()
        if scope == "selected":
            comps = [c for c in self._selected() if c.enabled]
        elif scope == "visible":
            comps = [c for c in self._visible_components() if c.enabled]
        else:
            comps = [c for c in self.components if c.enabled]
        categories = tuple(self._selected_scan_categories())
        if categories:
            comps = [c for c in comps if c.effective_category in categories]
        if not comps:
            messagebox.showwarning("Nothing to scan", "No enabled components in the chosen scope"
                                   + (" and categories." if categories else "."))
            return
        formats = tuple(f for f, v in self.fmt_vars.items() if v.get())
        if not formats:
            messagebox.showwarning("No format", "Select at least one report format.")
            return
        if not (self.date_pub.get() or self.date_mod.get()):
            messagebox.showwarning("Date fields", "Tick \"Published date\", \"Last modified date\" or both.")
            return
        if not any(v.get() for v in (self.use_cpe, self.use_kw, self.use_osv)):
            messagebox.showwarning("No source", "Select at least one vulnerability source.")
            return
        api_key = self.api_var.get().strip()
        if api_key:
            try:
                set_nvd_api_key(api_key)
            except RuntimeError:
                # Scanning can still proceed with the key for this session only.
                pass
        opts = ScanOptions(lookback_days=days, start_date=start_date, end_date=end_date, output_dir=self.out_var.get().strip() or DEFAULT_REPORTS_DIR,
                           nvd_api_key=api_key, use_nvd_cpe=self.use_cpe.get(),
                           use_nvd_keywords=self.use_kw.get(), use_osv=self.use_osv.get(),
                           use_kev=self.use_kev.get(), use_cve_org=self.use_cna.get(), strict=self.strict.get(),
                           min_applicability=MIN_APP_LABELS.get(self.min_app.get(), "LOW"),
                           scope=self.prod_scope.get(), categories=categories, formats=formats,
                           csv_delimiter=self.csv_sep.get()[0],
                           include_rejected_candidates=MIN_APP_LABELS.get(self.min_app.get()) == "ALL",
                           date_published=self.date_pub.get(), date_modified=self.date_mod.get(),
                           include_deferred=self.include_deferred.get())
        snapshot = [Component.from_dict(c.to_dict()) for c in comps]
        self.cancel_event.clear()
        self.scan_btn.state(["disabled"])
        self.cancel_btn.state(["!disabled"])
        self.progress.configure(value=0, maximum=len(snapshot))
        self._log("-" * 70)

        def work() -> None:
            scanner = Scanner(snapshot, opts,
                              log=lambda m: self.queue.put(("log", m)),
                              progress=lambda a, b, t: self.queue.put(("progress", (a, b, t))),
                              cancel_event=self.cancel_event)
            try:
                self.queue.put(("done", scanner.run()))
            except ScanCancelled:
                self.queue.put(("cancelled", None))
            except Exception as exc:  # noqa: BLE001
                self.queue.put(("error", "{}: {}".format(exc.__class__.__name__, exc)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _cancel(self) -> None:
        self.cancel_event.set()
        self.status.config(text="Cancelling...")

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "progress":
                    cur, total, text = payload
                    self.progress.configure(value=cur, maximum=total)
                    self.status.config(text=text)
                else:
                    self._scan_finished(kind, payload)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _scan_finished(self, kind: str, payload) -> None:
        self.scan_btn.state(["!disabled"])
        self.cancel_btn.state(["disabled"])
        if kind == "done":
            self.last_reports = payload.reports
            self.last_report_dir = payload.report_dir
            if self.last_reports.get("html"):
                try:
                    os.makedirs(DEFAULT_REPORTS_DIR, exist_ok=True)
                    with open(self._last_html_pointer, "w", encoding="utf-8") as pointer:
                        pointer.write(os.path.abspath(self.last_reports["html"]))
                except OSError:
                    pass
            s = payload.stats
            self.status.config(text="Done: {} applicable ({} new), {} not applicable listed".format(
                s["applicable"], s["new"], s["not_applicable"]))
            if "html" in self.last_reports:
                self.html_btn.state(["!disabled"])
                self._open_html()
            messagebox.showinfo("Scan complete",
                                "{applicable} applicable vulnerabilities ({new} new, {old} old)\n"
                                "{not_applicable} not applicable listed (ALL mode)\n"
                                "{filtered_false_positives} candidates rejected as false positives\n\n".format(**s)
                                + "Reports folder:\n" + payload.report_dir + "\n\n"
                                + "\n".join(os.path.basename(p) for p in self.last_reports.values()))
        elif kind == "cancelled":
            self.status.config(text="Cancelled")
        else:
            self.status.config(text="Error")
            self._log("ERROR: " + payload)
            messagebox.showerror("Scan failed", payload)

    def _log(self, msg: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", "{}  {}\n".format(dt.datetime.now().strftime("%H:%M:%S"), msg))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _find_latest_html_report(self) -> None:
        # Prefer the last HTML report from any output directory (including custom paths).
        pointer = getattr(self, "_last_html_pointer", os.path.join(DEFAULT_REPORTS_DIR, ".last_html_report.txt"))
        try:
            with open(pointer, "r", encoding="utf-8") as fh:
                remembered = fh.read().strip()
            if remembered and os.path.isfile(remembered):
                self.last_reports = {"html": remembered}
                self.last_report_dir = os.path.dirname(remembered)
                return
        except OSError:
            pass
        root = DEFAULT_REPORTS_DIR
        candidates = []
        if os.path.isdir(root):
            for base, _dirs, files in os.walk(root):
                for filename in files:
                    if filename.lower().endswith(".html"):
                        full = os.path.join(base, filename)
                        try:
                            candidates.append((os.path.getmtime(full), full))
                        except OSError:
                            pass
        if candidates:
            latest = max(candidates)[1]
            self.last_reports = {"html": latest}
            self.last_report_dir = os.path.dirname(latest)
            if hasattr(self, "html_btn"):
                self.html_btn.state(["!disabled"])

    def _open_html(self) -> None:
        path = self.last_reports.get("html")
        if path and os.path.isfile(path):
            webbrowser.open("file://" + os.path.abspath(path))

    def _open_out(self) -> None:
        path = getattr(self, "last_report_dir", "") or self.out_var.get()
        os.makedirs(path, exist_ok=True)
        open_path(path)

    def _about(self) -> None:
        messagebox.showinfo("Applicability levels",
                            "HIGH: product and version inside an affected range confirmed by NVD (CPE), the "
                            "CVE.org record of the vendor/CNA, or OSV.dev (package + version).\n"
                            "MEDIUM: product confirmed, version not verifiable - or CVE not yet analysed "
                            "and the description names the product with vendor or an affected version range.\n"
                            "LOW: weak evidence (keyword only) or an ecosystem item (library/plugin) when the "
                            "scope 'Product + ecosystem' is selected.\n"
                            "NOT APPLICABLE: version outside the affected range, other product, keyword only "
                            "inside another word, exclude keyword... Listed only with minimum 'ALL'.\n\n"
                            "Product scope 'Core component only' keeps vulnerabilities of the component itself "
                            "(e.g. a runtime, compiler, build tool, Git, Bash) and drops libraries, plugins, frameworks "
                            "and APIs that merely use it.\n\n"
                            "Criticality is derived from the CVSS base score (v3.1 preferred): "
                            "CRITICAL >= 9.0, HIGH >= 7.0, MEDIUM >= 4.0, LOW > 0.\n"
                            "Candidates whose version is outside the affected range are rejected.")

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Scan running", "A scan is running. Cancel it and quit?"):
                return
            self.cancel_event.set()
        added = [c for c in self.components if c.id not in self.baseline_component_ids]
        if added:
            if not messagebox.askyesno("Save new components", "Add {} newly created component(s) to the components JSON file before closing?".format(len(added))):
                self.destroy()
                return
            if not self.path:
                messagebox.showwarning("Component list not saved", "Open or save a components JSON file first; new components were not persisted.")
                self.destroy()
                return
            try:
                original = load_components(self.path)
                known = {c.id for c in original}
                original.extend(c for c in added if c.id not in known)
                save_components(self.path, original)
            except Exception as exc:
                messagebox.showerror("Save failed", str(exc))
                return
        self.destroy()


def run_gui(components_path: Optional[str] = None) -> None:
    App(components_path).mainloop()
