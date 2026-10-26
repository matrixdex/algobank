"""Package-level structural Merkle analysis.

Improvements over merkle_code.py / release_reuse.py:
  * whole-package call graph: follows imports across modules (absolute, relative, aliased)
  * module-level ("import time") code is a node and runs when its module is imported
  * unresolved attribute calls are over-approximated by class-hierarchy analysis (CHA)
  * dynamic constructs are detected, flagged, and made conservative:
      - non-literal import / getattr / eval / exec / monkey-patching  -> capability TOP
      - non-literal import                                            -> edge to EVERY module in the package
  * capabilities come from a table keyed by the import origin, not only from bare names
"""
import ast, copy, hashlib, sys

TOP = "TOP"
DIGEST_LEN = 64      # full SHA-256 in hex

def H(s):
    if isinstance(s, str): s = s.encode()
    return hashlib.sha256(s).hexdigest()

MOD_CAPS = {"socket": "network", "ssl": "network", "urllib": "network", "http": "network", "requests": "network",
            "httpx": "network", "aiohttp": "network", "ftplib": "network", "smtplib": "network",
            "websockets": "network", "subprocess": "process", "multiprocessing": "process",
            "shutil": "file", "tempfile": "file", "glob": "file", "ctypes": "native", "cffi": "native"}
OS_ATTR = {"system": "process", "popen": "process", "execv": "process", "execl": "process", "execvp": "process",
           "spawnl": "process", "fork": "process", "kill": "process", "remove": "file", "unlink": "file",
           "rmdir": "file", "rename": "file", "replace": "file", "makedirs": "file", "mkdir": "file",
           "listdir": "file", "scandir": "file", "walk": "file", "chmod": "file",
           "environ": "env", "getenv": "env", "putenv": "env"}
DESER_MODS = {"pickle", "marshal", "dill", "shelve", "cloudpickle"}
FILE_ATTRS = {"write_text", "read_text", "write_bytes", "read_bytes", "unlink", "rmtree", "mkdir", "touch"}
DYN_NAMES = {"eval": "dyn-exec", "exec": "dyn-exec", "compile": "dyn-exec", "globals": "dyn-attr",
             "locals": "dyn-attr", "vars": "dyn-attr"}

def size(n): return sum(1 for _ in ast.walk(n))

def strip_doc(fn):
    b = getattr(fn, "body", None)
    if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) and isinstance(b[0].value.value, str):
        fn.body = b[1:] or [ast.Pass()]

class Canon(ast.NodeTransformer):
    def __init__(self, m): self.m = m
    def visit_arg(self, n):
        n.arg = self.m.get(n.arg, n.arg); n.annotation = None; return n
    def visit_Name(self, n):
        if n.id in self.m: n.id = self.m[n.id]
        return n

def local_map(fn):
    order = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
    if fn.args.vararg: order.append(fn.args.vararg.arg)
    if fn.args.kwarg: order.append(fn.args.kwarg.arg)
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id not in order: order.append(n.id)
    return {nm: f"_{i}" for i, nm in enumerate(order)}

def canon_fn(fn):
    c = copy.deepcopy(fn); strip_doc(c); c.name = "_"
    return ast.dump(Canon(local_map(fn)).visit(c), annotate_fields=False)

def dotted(e):
    parts = []
    while isinstance(e, ast.Attribute): parts.append(e.attr); e = e.value
    if isinstance(e, ast.Name): parts.append(e.id); return parts[::-1]
    return None

def modname_of(path):
    m = path[:-3].replace("/", ".")
    return m[:-9] if m.endswith(".__init__") else m

class Package:
    def __init__(self, files, pins=None):
        self.pins = pins or {}
        self.trees = {}
        for path, src in files.items():
            if path.endswith(".py"):
                try: self.trees[modname_of(path)] = (path, ast.parse(src))
                except SyntaxError: pass
        self.funcs = {}      # node id -> (fnnode, modname, clsqual)
        self.classes = {}    # modname -> {clsqual}
        self.top = {}        # modname -> {name: ('fn'|'cls', qual)}
        for mod, (path, tree) in self.trees.items():
            self.classes[mod], self.top[mod] = set(), {}
            self._collect(mod, tree.body, None)
        self.by_method = {}
        for nid in self.funcs:
            self.by_method.setdefault(nid.split(":", 1)[1].split(".")[-1], []).append(nid)
        self.nodes = {}
        self._analyze()

    def _collect(self, mod, body, cls):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = (cls + "." if cls else "") + n.name
                self.funcs[f"{mod}:{q}"] = (n, mod, cls)
                if cls is None: self.top[mod][n.name] = ("fn", q)
            elif isinstance(n, ast.ClassDef):
                q = (cls + "." if cls else "") + n.name
                self.classes[mod].add(q)
                if cls is None: self.top[mod][n.name] = ("cls", q)
                self._collect(mod, n.body, q)

    # ---- import resolution -------------------------------------------------
    def _bind_imports(self, mod, root):
        names = {}
        pkg = mod if self._is_pkg(mod) else mod.rsplit(".", 1)[0] if "." in mod else ""
        for n in ast.walk(root):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname: names[a.asname] = self._target(a.name)
                    else: names[a.name.split(".")[0]] = self._target(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom):
                base = n.module or ""
                if n.level:
                    parts = pkg.split(".") if pkg else []
                    parts = parts[: len(parts) - (n.level - 1)] if n.level > 1 else parts
                    base = ".".join(parts + ([n.module] if n.module else []))
                for a in n.names:
                    if a.name == "*": names["*" + base] = ("star", base); continue
                    full = f"{base}.{a.name}" if base else a.name
                    if full in self.trees: names[a.asname or a.name] = ("mod", full)
                    elif base in self.trees: names[a.asname or a.name] = ("sym", base, a.name)
                    else: names[a.asname or a.name] = ("ext", full.split("."))
        return names

    def _is_pkg(self, mod): return self.trees[mod][0].endswith("__init__.py")
    def _target(self, dotted_name):
        return ("mod", dotted_name) if dotted_name in self.trees else ("ext", dotted_name.split("."))

    def _sym_nodes(self, mod, name):
        ent = self.top.get(mod, {}).get(name)
        if not ent: return []
        kind, q = ent
        if kind == "fn": return [f"{mod}:{q}"]
        init = f"{mod}:{q}.__init__"
        return [init] if init in self.funcs else []

    # ---- scanning ----------------------------------------------------------
    def _scan(self, root, mod, cls, names, skeleton=False):
        """-> (edges, caps, flags, ext_roots, stats)"""
        edges, caps, flags, ext_roots = set(), set(), set(), set()
        stats = {"cross": 0, "cha": 0}
        mod_skel = lambda m: f"{m}:<module>"
        for n in ast.walk(root):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in names and names[n.id][0] == "ext":
                ext_roots.add(names[n.id][1][0])
            if isinstance(n, (ast.Import, ast.ImportFrom)) and skeleton:
                for nm, b in self._bind_imports(mod, n).items():
                    if b[0] == "mod": edges.add(mod_skel(b[1])); stats["cross"] += 1
                    if b[0] == "sym": edges.add(mod_skel(b[1])); stats["cross"] += 1
                    if b[0] == "star": flags.add("star-import"); edges.add(mod_skel(b[1]))
            if isinstance(n, ast.Attribute):
                ch = dotted(n)
                if ch and ch[0] in names and names[ch[0]][0] == "ext":
                    full = names[ch[0]][1] + ch[1:]
                    if full[0] == "os" and full[-1] in OS_ATTR: caps.add(OS_ATTR[full[-1]])
                    if full[:2] == ["sys", "modules"]: pass
                if n.attr in FILE_ATTRS: caps.add("file")
            if isinstance(n, (ast.Assign, ast.AugAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Attribute):
                        ch = dotted(t)
                        if ch and ch[0] in names and names[ch[0]][0] in ("mod", "ext"): flags.add("dyn-patch")
                    if isinstance(t, ast.Subscript):
                        ch = dotted(t.value)
                        if ch == ["sys", "modules"]: flags.add("dyn-patch")
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__getattr__":
                flags.add("dyn-getattr-def")
            if not isinstance(n, ast.Call): continue
            f = n.func
            ch = dotted(f)
            first_const = n.args[0].value if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) else None
            # builtins
            if isinstance(f, ast.Name) and f.id not in names and f.id not in self.top.get(mod, {}):
                if f.id == "open": caps.add("file"); continue
                if f.id in DYN_NAMES: flags.add(DYN_NAMES[f.id]); continue
                if f.id in ("getattr", "setattr", "delattr"):
                    if len(n.args) < 2 or not (isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)):
                        flags.add("dyn-attr")
                    continue
                if f.id == "__import__":
                    self._dyn_import(first_const, edges, flags); continue
            if not ch: continue
            # resolve chain through import bindings
            targets, ext = [], None
            p0 = ch[0]
            if p0 in ("self", "cls") and cls and len(ch) == 2:
                t = f"{mod}:{cls}.{ch[1]}"
                targets = [t] if t in self.funcs else self.by_method.get(ch[1], [])
                if t not in self.funcs and targets: stats["cha"] += len(targets)
            elif len(ch) == 1 and p0 in self.top.get(mod, {}) and p0 not in names:
                targets = self._sym_nodes(mod, p0)
            elif p0 in names:
                b = names[p0]
                if b[0] == "sym":
                    ent = self.top.get(b[1], {}).get(b[2])
                    if len(ch) == 1: targets = self._sym_nodes(b[1], b[2])
                    elif ent and ent[0] == "cls":
                        t = f"{b[1]}:{ent[1]}.{ch[1]}"; targets = [t] if t in self.funcs else []
                    if targets: stats["cross"] += 1
                elif b[0] == "mod":
                    m, rest = b[1], ch[1:]
                    while rest and f"{m}.{rest[0]}" in self.trees: m, rest = f"{m}.{rest[0]}", rest[1:]
                    if len(rest) == 1: targets = self._sym_nodes(m, rest[0])
                    elif len(rest) == 2:
                        ent = self.top.get(m, {}).get(rest[0])
                        if ent and ent[0] == "cls":
                            t = f"{m}:{ent[1]}.{rest[1]}"; targets = [t] if t in self.funcs else []
                    if targets: stats["cross"] += 1
                elif b[0] == "ext":
                    ext = b[1] + ch[1:]
            elif len(ch) >= 2:
                targets = self.by_method.get(ch[-1], [])      # unknown receiver: CHA over-approximation
                stats["cha"] += len(targets)
            for t in targets: edges.add(t)
            if ext:
                if ext[0] in MOD_CAPS: caps.add(MOD_CAPS[ext[0]])
                if ext[0] == "os" and ext[-1] in OS_ATTR: caps.add(OS_ATTR[ext[-1]])
                if ext[0] in DESER_MODS and ext[-1] in ("load", "loads", "open", "Unpickler"): flags.add("dyn-exec")
                if ext[0] == "importlib" and ext[-1] in ("import_module", "__import__"): self._dyn_import(first_const, edges, flags)
                if ext[:3] == ["importlib", "metadata", "entry_points"] or ext[-1] == "entry_points": flags.add("dyn-import")
        return edges, caps, flags, ext_roots, stats

    def _dyn_import(self, literal, edges, flags):
        if literal and literal in self.trees: edges.add(f"{literal}:<module>")
        elif literal: pass
        else:
            flags.add("dyn-import")
            for m in self.trees: edges.add(f"{m}:<module>")      # over-approximate: could load any module

    # ---- analysis ----------------------------------------------------------
    def _analyze(self):
        raw = {}
        for mod, (path, tree) in self.trees.items():
            names_mod = self._bind_imports(mod, tree)
            skel = copy.deepcopy(tree)
            class Drop(ast.NodeTransformer):
                def visit_FunctionDef(self, n): return None
                def visit_AsyncFunctionDef(self, n): return None
            skel = ast.fix_missing_locations(Drop().visit(skel))
            e, c, fl, er, st = self._scan(skel, mod, None, names_mod, skeleton=True)
            raw[f"{mod}:<module>"] = dict(own=H(ast.dump(skel, annotate_fields=False)), size=size(skel), edges=e, caps=c, flags=fl, ext=er, stats=st)
        for nid, (fn, mod, cls) in self.funcs.items():
            names = dict(self._bind_imports(mod, self.trees[mod][1]))
            names.update(self._bind_imports(mod, fn))
            e, c, fl, er, st = self._scan(fn, mod, cls, names)
            raw[nid] = dict(own=H(canon_fn(fn)), size=size(fn), edges=e, caps=c, flags=fl, ext=er, stats=st)
        for r in raw.values():
            r["calls"] = set(r["edges"])      # code that runs: calls, imports, import-time calls
        for nid, (fn, mod, cls) in self.funcs.items():
            # a function reads its module's constants, class attributes and imported names
            raw[nid]["edges"].add(f"{mod}:<module>")
            # module state written through `global` is read by every function in the module
            if any(isinstance(n, ast.Global) for n in ast.walk(fn)):
                raw[f"{mod}:<module>"]["edges"].add(nid)
        for r in raw.values():
            r["edges"] = {x for x in r["edges"] if x in raw}
            r["calls"] = {x for x in r["calls"] if x in raw}
            r["pins"] = {f"{x}={self.pins.get(x.lower(), 'stdlib/unpinned')}" for x in r["ext"]}
        self.facts = raw
        out, self.comps = backend(raw)
        check_backend(raw, out, self.comps)
        for k, r in raw.items():
            self.nodes[k] = dict(own=r["own"], merkle=out[k]["merkle"], size=r["size"], caps=out[k]["caps"],
                                 flags=out[k]["flags"], direct_flags=r["flags"], direct_caps=r["caps"], stats=r["stats"])

    # ---- package root: one package is one Merkle tree ----------------------
    def leaves(self):
        """One leaf per node. The leaf commits to the node id (the public name) and the node's Merkle hash.
        Leaf inputs start with 0x00 and interior inputs with 0x01, so the two can never be confused."""
        return sorted(H(f"\x00{nid}={n['merkle']}") for nid, n in self.nodes.items())

    def root(self):
        """Binary Merkle root over the sorted leaves."""
        level = self.leaves() or [H("empty")]
        if any(len(d) != DIGEST_LEN for d in level):
            raise ValueError("every digest in a tree must have the same length")
        while len(level) > 1:
            if len(level) % 2: level = level + [level[-1]]
            level = [H("\x01" + level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    def scope(self):
        """The union of all scopes (capabilities) in the package. TOP means unknown."""
        return sorted(set().union(*[n["caps"] for n in self.nodes.values()])) if self.nodes else []

    def scope_root(self):
        return H(",".join(self.scope()) or "none")


# ---- back end: everything after parsing --------------------------------------
# Input: per-node facts from the front end. For each node id:
#   own   - hash of the node's normalized code
#   edges - node ids it depends on (calls, its module's top-level code, ...); used for hashing
#   calls - the subset of edges whose code runs when this node runs; used for scope roll-up
#   pins  - "name=pin" strings for the outside packages it uses
#   caps, flags - its direct scopes and dynamic-code flags
# The proof in proofs/MerkleSound.v covers any output that check_backend accepts.

def sccs(graph):
    """Tarjan's algorithm. Returns components with every component listed after the components it depends on."""
    idx, low, st, on, out, i = {}, {}, [], set(), [], [0]
    sys.setrecursionlimit(20000)
    def go(v):
        idx[v] = low[v] = i[0]; i[0] += 1; st.append(v); on.add(v)
        for w in graph[v]:
            if w not in idx: go(w); low[v] = min(low[v], low[w])
            elif w in on: low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = st.pop(); on.discard(w); comp.append(w)
                if w == v: break
            out.append(comp)
    for v in graph:
        if v not in idx: go(v)
    return out


def comp_base(comp, own, merk):
    """The component hash: member own hashes (sorted), external dependencies' Merkle hashes, hashed pins."""
    return H("|".join(sorted(own[q] for q in comp["members"])) + "#"
             + "|".join(merk[d] for d in comp["ext"]) + "#"
             + "|".join(H(p) for p in comp["pins"]))

def backend(facts):
    graph = {k: sorted(v["edges"]) for k, v in facts.items()}
    own = {k: v["own"] for k, v in facts.items()}
    out, comps, merk = {}, [], {}
    for members in sccs(graph):
        cs = set(members)
        comp = dict(members=sorted(members),
                    ext=sorted({d for q in members for d in graph[q] if d not in cs}),
                    pins=sorted(set().union(*[facts[q]["pins"] for q in members])))
        base = comp_base(comp, own, merk)
        for q in members:
            merk[q] = H(base + own[q])
            out[q] = dict(merkle=merk[q], comp=len(comps))
        comps.append(comp)
    caps, flags = rollup(facts)
    for q in out:
        out[q]["caps"], out[q]["flags"] = caps[q], flags[q]
    return out, comps

def rollup(facts):
    """Scope and flags of a node: its own plus those of everything that runs when it runs (calls only)."""
    calls = {k: sorted(v.get("calls", v["edges"])) for k, v in facts.items()}
    caps, flags = {}, {}
    for members in sccs(calls):
        cs = set(members)
        below = {d for q in members for d in calls[q] if d not in cs}
        ccaps = set().union(*[facts[q]["caps"] for q in members], *[caps[d] for d in below])
        cflags = set().union(*[facts[q]["flags"] for q in members], *[flags[d] for d in below])
        if cflags & {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch"}: ccaps = ccaps | {TOP}
        for q in members:
            caps[q], flags[q] = ccaps, cflags
    return caps, flags

def _reaches_all(start, targets, graph):
    """True if every node in targets is reachable from start through nodes in targets."""
    seen, todo = {start}, [start]
    while todo:
        for w in graph[todo.pop()]:
            if w in targets and w not in seen: seen.add(w); todo.append(w)
    return targets <= seen

def check_backend(facts, out, comps):
    """Checks the back end's output against the conditions of the Merkle soundness proof.
    Raises ValueError if any condition fails; the theorem then does not apply."""
    def fail(msg): raise ValueError("back end check failed: " + msg)
    graph = {k: v["edges"] for k, v in facts.items()}
    rgraph = {k: set() for k in facts}
    for k, es in graph.items():
        for e in es: rgraph[e].add(k)
    merk = {k: o["merkle"] for k, o in out.items()}
    own = {k: v["own"] for k, v in facts.items()}
    hexd = set("0123456789abcdef")
    for k in facts:                                           # own hashes are digests
        if len(own[k]) != DIGEST_LEN or not set(own[k]) <= hexd: fail(f"own hash of {k}")
    sets = [(set(c["members"]), set(c["ext"])) for c in comps]
    for i, c in enumerate(comps):
        members = sets[i][0]
        for m in members:                                     # Mem, Comp
            if out[m]["comp"] != i: fail(f"{m} is not assigned to component {i}")
        for x in c["ext"]:                                    # X: every external entry is used by a member
            if not any(x in graph[m] for m in members): fail(f"external {x} of component {i} is unused")
        first = c["members"][0]                               # R: members are mutually reachable
        if not _reaches_all(first, members, graph) or not _reaches_all(first, members, rgraph):
            fail(f"component {i} is not strongly connected")
    for k in facts:
        c = comps[out[k]["comp"]]
        members, ext = sets[out[k]["comp"]]
        if k not in members: fail(f"{k} is missing from its component")
        for x in graph[k]:                                    # E: every edge stays inside or is listed as external
            if x not in members and x not in ext: fail(f"edge {k} -> {x} is not covered")
        base = comp_base(c, own, merk)                        # M: the Merkle equation
        if merk[k] != H(base + own[k]): fail(f"Merkle hash of {k}")
