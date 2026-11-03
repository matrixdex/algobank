"""Package-level structural Merkle analysis.

Improvements over merkle_code.py / release_reuse.py:
  * whole-package call graph: follows imports across modules (absolute, relative, aliased)
  * module-level ("import time") code is a node and runs when its module is imported
  * unresolved attribute calls are over-approximated by class-hierarchy analysis (CHA)
  * dynamic constructs are detected, flagged, and made conservative:
      - non-literal import / getattr / eval / exec / monkey-patching  -> capability TOP
      - non-literal import                                            -> edge to EVERY module in the package
  * getattr with a name drawn from a fixed list in the code is resolved like a plain call by name (see _names)
  * capabilities come from a table keyed by the import origin, not only from bare names
"""
import ast, builtins, copy, hashlib, sys

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
# names that are dangerous whatever object holds them: reached by a call, a getattr or as a value, each is flagged
NAME_FLAGS = dict(DYN_NAMES, __import__="dyn-import", import_module="dyn-import", entry_points="dyn-import",
                  load="dyn-exec", loads="dyn-exec", Unpickler="dyn-exec", breakpoint="dyn-exec",
                  getattr="dyn-attr", setattr="dyn-attr", delattr="dyn-attr", attrgetter="dyn-attr",
                  methodcaller="dyn-attr", getattr_static="dyn-attr")
# attributes that escape any sandbox: frames, globals, builtins, code objects, every subclass of a type
ESCAPE_ATTRS = {"__subclasses__", "__globals__", "__builtins__", "__code__", "__closure__", "__reduce__", "__reduce_ex__",
                "f_globals", "f_locals", "f_builtins", "f_back", "gi_frame", "cr_frame", "ag_frame", "tb_frame",
                "_getframe", "currentframe", "stack", "func_globals"}
# builtins that only inspect an object: passing a module to them is not passing it on
INSPECT_ONLY = {"hasattr", "isinstance", "issubclass", "type", "id", "callable", "len", "dir", "repr", "str", "bool"}
# attribute names that give write access to an object, or answer every read with code
WRITE_ACCESS = {"__dict__", "__setattr__", "__delattr__", "__getattribute__", "__getattr__"}
# a module used as a value (passed, stored, returned) brings everything it can do
MODULE_VALUE = {"os": ("caps", {"env", "file", "process"}), "importlib": ("flag", "dyn-import"), "builtins": ("flag", "dyn-exec"),
                "sys": ("flag", "dyn-patch"), "inspect": ("flag", "dyn-attr"), "operator": ("flag", "dyn-attr"),
                "gc": ("flag", "dyn-attr"), "types": ("flag", "dyn-exec")}

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

# ---- module values: top-level statements grouped by the names they bind or change ------

def _root_name(e):
    while isinstance(e, (ast.Attribute, ast.Subscript, ast.Call, ast.Starred)):
        e = e.func if isinstance(e, ast.Call) else e.value
    return e.id if isinstance(e, ast.Name) else None

def _walk_shallow(node):
    """ast.walk that yields nested function and lambda definitions but does not enter them."""
    todo = [node]
    while todo:
        n = todo.pop()
        yield n
        if n is not node and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        todo.extend(ast.iter_child_nodes(n))

def bound_names(st):
    """Module-level names a top-level statement binds or may change."""
    if isinstance(st, ast.ClassDef): return {st.name}
    if isinstance(st, (ast.Import, ast.ImportFrom)):
        return {"*" if a.name == "*" else (a.asname or a.name.split(".")[0]) for a in st.names}
    out = set()
    for n in _walk_shallow(st):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)): out.add(n.id)
        elif isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(n.ctx, (ast.Store, ast.Del)):
            r = _root_name(n); r and out.add(r)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            r = _root_name(n.func); r and out.add(r)          # a method call may change its receiver
        elif n is not st and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)                                   # conditional definitions
        elif n is not st and isinstance(n, (ast.Import, ast.ImportFrom)):
            out |= bound_names(n)
    return out

def class_skeleton(cdef):
    """A class definition without its methods, which are nodes of their own."""
    c = copy.deepcopy(cdef)
    def strip(k):
        k.body = [b for b in k.body if not isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))] or [ast.Pass()]
        for b in k.body:
            if isinstance(b, ast.ClassDef): strip(b)
    strip(c); strip_doc(c)
    return c

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
        self.values, self.effects = {}, {}
        for mod, (path, tree) in self.trees.items():
            groups, effects = {}, []
            for st in tree.body:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
                if isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant): continue   # docstring
                names = bound_names(st)
                if not names: effects.append(st)
                for nm in names: groups.setdefault(nm, []).append(st)
            self.values[mod], self.effects[mod] = groups, effects
        self.by_method = {}
        for nid in self.funcs:
            self.by_method.setdefault(nid.split(":", 1)[1].split(".")[-1], []).append(nid)

        self._name_tables()
        self.nodes = {}
        self._analyze()
        if self.lists and any(n["direct_flags"] & {"dyn-exec", "dyn-patch", "dyn-import", "dyn-attr"} for n in self.nodes.values()):
            # Something else in the package is dynamic, and it could rewrite a list at run time: analyze again
            # without the lists read from classes. Literal names and literal tuples stay resolved: nothing can change them.
            self.lists, self.taint = {}, None
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

    def _name_refs(self, mod, name):
        """Nodes a read of module-level `name` in `mod` depends on."""
        out = []
        ent = self.top.get(mod, {}).get(name)
        if ent and ent[0] == "fn": out.append(f"{mod}:{ent[1]}")
        if name in self.values.get(mod, {}): out.append(f"{mod}:={name}")
        elif not out and "*" in self.values.get(mod, {}) and not hasattr(builtins, name):
            out.append(f"{mod}:=*")                           # may come from an `import *`
        return out

    def _attr_refs(self, mod, name):
        """Nodes a read of `mod.name` depends on, from outside the module."""
        out = self._name_refs(mod, name)
        if not out and not f"{mod}.{name}" in self.trees: out.append(f"{mod}:<module>")
        return out

    # ---- names drawn from fixed lists ---------------------------------------
    # getattr(x, name) is TOP unless every value `name` can take is fixed by the code: a string literal, a loop
    # over a literal collection, a literal tuple, or a tuple the package fixes on its classes (__slots__, dataclass
    # fields, a class-level tuple of strings). A resolved name is never weaker than writing x.<name> by hand: the
    # same tables apply, and escape names stay TOP. A tuple read from a class counts only if nothing can change
    # it at run time; if anything else in the package is dynamic, Package analyzes again without these tuples.
    # Assumption (closed world): classes outside the package do not subclass package classes.
    def _name_tables(self):
        cdefs = {}                                            # class name -> ClassDef nodes (by name: over-approximate)
        for mod, (path, tree) in self.trees.items():
            for n in ast.walk(tree):
                if isinstance(n, ast.ClassDef): cdefs.setdefault(n.name, []).append(n)
        lit = lambda v: isinstance(v, ast.Tuple) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in v.elts)
        strs = lambda v: isinstance(v, (ast.Tuple, ast.List)) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in v.elts)
        self.lists, bad = {}, set()                           # class-level list name -> union of its literal values
        bases, slotted = {}, {}
        for name, defs in cdefs.items():
            for c in defs:
                bases.setdefault(name, set()).update(b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else "?" for b in c.bases)
                own = None
                for st in c.body:
                    if isinstance(st, (ast.Assign, ast.AnnAssign)):
                        tg = st.targets if isinstance(st, ast.Assign) else [st.target]
                        for t in tg:
                            if not isinstance(t, ast.Name) or st.value is None: continue
                            if len(tg) == 1 and lit(st.value): self.lists.setdefault(t.id, set()).update(e.value for e in st.value.elts)
                            else: bad.add(t.id)
                            if t.id == "__slots__": own = {e.value for e in st.value.elts} if strs(st.value) else {"__dict__"}
                    elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        bad.add(st.name)                      # a method or property by that name hides the list
                slotted[name] = slotted.get(name, True) and own is not None and "__dict__" not in own
                deco = [d.func if isinstance(d, ast.Call) else d for d in c.decorator_list]
                if any((d.id if isinstance(d, ast.Name) else d.attr if isinstance(d, ast.Attribute) else "") == "dataclass" for d in deco):
                    self.lists.setdefault("__dataclass_fields__", set()).update(
                        st.target.id for st in c.body if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name))
        # any other write to a list's name, anywhere, disqualifies it
        writes = []                                           # computed-name attribute writes: (kind, class name)
        for mod, (path, tree) in self.trees.items():
            parent = {ch: nd for nd in ast.walk(tree) for ch in ast.iter_child_nodes(nd)}
            def owner(n):                                     # the class whose method holds n, and the method
                fn = None
                while n in parent:
                    n = parent[n]
                    if fn is None and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)): fn = n
                    if isinstance(n, ast.ClassDef) and fn is not None and parent.get(fn) is n: return n.name, fn
                return None, fn
            for n in ast.walk(tree):
                if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                    bad.add(n.attr)
                    if n.attr in ("__class__", "__bases__", "__dict__"): writes.append(("any", None))   # an object changes class
                if isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)) and isinstance(n.value, ast.Attribute):
                    bad.add(n.value.attr)                     # x.__dataclass_fields__[k] = v
                    if n.value.attr == "__annotations__": bad.add("__dataclass_fields__")
                if isinstance(n, ast.Attribute) and n.attr in ("__dataclass_fields__", "__dict__") and isinstance(n.ctx, ast.Load):
                    p = parent.get(n)                         # only read in place; an alias could be written
                    gp = parent.get(p)
                    safe = (isinstance(p, (ast.For, ast.AsyncFor, ast.comprehension)) and p.iter is n) \
                        or (isinstance(p, ast.Subscript) and p.value is n and isinstance(p.ctx, ast.Load)) \
                        or (isinstance(p, ast.Attribute) and p.attr in ("keys", "items", "values", "get") and isinstance(gp, ast.Call) and gp.func is p) \
                        or (isinstance(p, ast.Compare) and n in p.comparators)
                    if not safe:
                        if n.attr == "__dict__": writes.append(("any", None))
                        else: bad.add("__dataclass_fields__")
                if isinstance(n, ast.Name) and n.id == "make_dataclass" or isinstance(n, ast.Attribute) and n.attr == "make_dataclass":
                    bad.add("__dataclass_fields__")
                if isinstance(n, ast.Call) and (isinstance(n.func, ast.Name) and n.func.id == "dataclass" or isinstance(n.func, ast.Attribute) and n.func.attr == "dataclass") \
                        and n.args and not isinstance(parent.get(n), ast.ClassDef):
                    bad.add("__dataclass_fields__")           # dataclass(cls) applied at run time
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "type" and len(n.args) >= 3:
                    writes.append(("any", None))              # a class made at run time
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__getattribute__":
                    writes.append(("any", None))              # every attribute read can be answered by code
                if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name): bad.add(n.target.id)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("append", "extend", "insert", "remove", "pop", "clear", "update", "add", "discard") \
                        and isinstance(n.func.value, ast.Attribute):
                    bad.add(n.func.value.attr)                # e.g. self._fields.append(...)
                recv, name = None, None
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("setattr", "delattr") and len(n.args) >= 2:
                    recv, name = n.args[0], n.args[1]
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("__setattr__", "__delattr__") and n.args:
                    recv, name = n.func.value, n.args[0]
                elif isinstance(n, (ast.Subscript, ast.Call)):    # vars(x)[k] = v, x.__dict__[k] = v, x.__dict__.update(...)
                    tgt = n.value if isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store) else \
                          n.func.value if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("update", "setdefault", "__setitem__") else None
                    if isinstance(tgt, ast.Attribute) and tgt.attr == "__dict__": recv, name = tgt.value, None
                    elif isinstance(tgt, ast.Call) and isinstance(tgt.func, ast.Name) and tgt.func.id == "vars" and tgt.args: recv, name = tgt.args[0], None
                    else: continue
                else: continue
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    bad.add(name.value); continue
                cls, fn = owner(n)
                first = fn.args.args[0].arg if fn and fn.args.args else None
                is_cm = fn is not None and any(isinstance(d, ast.Name) and d.id == "classmethod" for d in fn.decorator_list)
                r = recv.func if isinstance(recv, ast.Call) else recv
                if cls and isinstance(r, ast.Name) and r.id == "super": writes.append(("cls" if is_cm else "inst", cls))
                elif cls and isinstance(recv, ast.Name) and recv.id == first: writes.append(("cls" if is_cm else "inst", cls))
                elif isinstance(recv, ast.Name) and recv.id in cdefs: writes.append(("cls", recv.id))
                else: writes.append(("any", None))
        for x in bad: self.lists.pop(x, None)
        # the class hierarchy inside the package, by class name
        down = {c: {c} for c in bases}
        changed = True
        while changed:
            changed = False
            for c, bs in bases.items():
                for b in bs:
                    if b in down and not down[c] <= down[b]: down[b] |= down[c]; changed = True
        up = {c: {a for a in down if c in down[a]} for c in down}
        def nodict(c):                                        # every class of c's line is slotted, and all bases are known
            line = up.get(c, {c})
            return all(slotted.get(a, False) and all(b in down or b == "object" for b in bases.get(a, ())) for a in line)
        self.slotted = {c for c in down if all(nodict(d) for d in down[c])}   # c and all its subclasses have no __dict__
        self.taint = set()                                    # classes whose instances may hold a replaced list; None: all
        for kind, c in writes:
            if kind == "any": self.taint = None; break
            fam = {x for d in down.get(c, {c}) for x in up.get(d, {d})} | {x for u in up.get(c, {c}) for x in down.get(u, {u})}
            if kind == "cls" or not all(nodict(d) for d in down.get(c, {c})): self.taint |= fam

    def _slotted_self(self, recv, ctx):
        """Whether `recv` is the instance (self, or super()) of a class whose whole family is slotted."""
        r = recv.func if isinstance(recv, ast.Call) else recv
        if not (ctx and ctx["cls"] and isinstance(r, ast.Name)): return False
        is_self = r.id == "super" or r.id == ctx["first"] and ctx["binds"].get(r.id) == [("arg", None)]
        return is_self and ctx["cls"] in self.slotted

    def _elems(self, e, ctx, depth=0):
        """The strings iterating `e` can yield, if the code fixes them; otherwise None."""
        if depth > 8: return None
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)) and all(isinstance(x, ast.Constant) and isinstance(x.value, str) for x in e.elts):
            return {x.value for x in e.elts}
        if isinstance(e, ast.Subscript) and isinstance(e.slice, ast.Slice):
            return self._elems(e.value, ctx, depth + 1)       # a slice yields a subset
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "keys" and not e.args:
            return self._elems(e.func.value, ctx, depth + 1)
        if isinstance(e, ast.Attribute) and e.attr in self.lists:
            if self.taint is None: return None
            r = e.value.func if isinstance(e.value, ast.Call) else e.value
            mine = ctx["cls"] and isinstance(r, ast.Name) and (r.id == "super" or r.id == ctx["first"] and ctx["binds"].get(r.id) == [("arg", None)])
            if (ctx["cls"] in self.taint) if mine else self.taint: return None
            return set(self.lists[e.attr])
        if isinstance(e, ast.Name):                           # a local name assigned only from fixed lists
            binds = ctx["binds"].get(e.id)
            if not binds or any(k != "assign" for k, _ in binds): return None
            out = set()
            for _, v in binds:
                if isinstance(v, (ast.List, ast.Set, ast.Dict)): return None   # a list can be changed through an alias
                s = self._elems(v, ctx, depth + 1)
                if s is None: return None
                out |= s
            return out
        return None

    def _names(self, e, ctx):
        """The strings `e` can evaluate to, if the code fixes them; otherwise None."""
        if isinstance(e, ast.Constant) and isinstance(e.value, str): return {e.value}
        if isinstance(e, ast.Subscript) and not isinstance(e.slice, ast.Slice):
            return self._elems(e.value, ctx)                  # one element of a fixed list
        if isinstance(e, ast.Name):
            binds = ctx["binds"].get(e.id)
            if not binds or any(k != "loop" for k, _ in binds): return None
            out = set()
            for _, it in binds:
                s = self._elems(it, ctx)
                if s is None: return None
                out |= s
            return out
        return None

    def _bindings(self, root):
        """Every binding of a name in `root`: ('loop', iterable), ('assign', value) or ('other', None)."""
        parent = {ch: nd for nd in ast.walk(root) for ch in ast.iter_child_nodes(nd)}
        out = {}
        add = lambda k, kind, v: out.setdefault(k, []).append((kind, v))
        for n in ast.walk(root):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                p = parent.get(n)
                if isinstance(p, (ast.For, ast.AsyncFor, ast.comprehension)) and p.target is n: add(n.id, "loop", p.iter)
                elif isinstance(p, ast.Assign) and p.targets == [n]: add(n.id, "assign", p.value)
                else: add(n.id, "other", None)
            elif isinstance(n, ast.arg): add(n.arg, "arg", None)
            elif isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)) and isinstance(n.value, ast.Name):
                add(n.value.id, "other", None)                # names[0] = x changes a list in place
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                    and n.func.attr in ("append", "extend", "insert", "remove", "pop", "clear", "update", "add", "discard", "__setitem__"):
                add(n.func.value.id, "other", None)           # names.append(x) too
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                for g in n.names: add(g, "other", None)
            elif isinstance(n, ast.alias): add((n.asname or n.name).split(".")[0], "other", None)
            elif isinstance(n, ast.ExceptHandler) and n.name: add(n.name, "other", None)
            elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name: add(n.name, "other", None)
            elif isinstance(n, ast.MatchMapping) and n.rest: add(n.rest, "other", None)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not root: add(n.name, "other", None)
        return out

    # ---- scanning ----------------------------------------------------------
    def _scan(self, root, mod, cls, names, skeleton=False, local=None):
        """-> (edges, caps, flags, ext_roots, stats, reads). Reads are collected when `local` is given:
        the names that are local to the scanned code and so are not module-level reads."""
        edges, caps, flags, ext_roots, reads = set(), set(), set(), set(), set()
        stats = {"cross": 0, "cha": 0}
        ctx = None                                            # name bindings, built on the first getattr
        mod_skel = lambda m: f"{m}:<module>"
        parent = {ch: nd for nd in ast.walk(root) for ch in ast.iter_child_nodes(nd)}
        for n in ast.walk(root):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                p = parent.get(n)
                inspected = isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id not in names and (
                    p.func.id in INSPECT_ONLY and n in p.args                              # hasattr(os, x): look, never call
                    or p.func.id in ("getattr", "setattr", "delattr") and p.args and p.args[0] is n)   # the getattr rule decides
                used = (isinstance(p, ast.Attribute) and p.value is n) or (isinstance(p, ast.Call) and p.func is n) or inspected
                if n.id in names and names[n.id][0] == "ext" and not used:
                    self._ext_effects(names[n.id][1], caps, flags, edges, value=True)    # an outside module or function, passed on
                elif n.id not in names and n.id not in self.top.get(mod, {}) and (local is None or n.id not in local):
                    if n.id == "__builtins__": flags.add("dyn-exec")
                    elif not used and n.id in NAME_FLAGS: flags.add(NAME_FLAGS[n.id])     # f = getattr; f(os, "system")
                    elif not used and n.id == "open": caps.add("file")
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in names and names[n.id][0] == "ext":
                ext_roots.add(names[n.id][1][0])
            if local is not None and isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in local:
                reads.update(self._name_refs(mod, n.id))
            if local is not None and isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
                ch = dotted(n)
                if ch and ch[0] in names and names[ch[0]][0] == "mod" and ch[0] not in local:
                    m, rest = names[ch[0]][1], ch[1:]
                    while rest and f"{m}.{rest[0]}" in self.trees: m, rest = f"{m}.{rest[0]}", rest[1:]
                    if rest: reads.update(self._attr_refs(m, rest[0]))
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
                if n.attr in ESCAPE_ATTRS: flags.add("dyn-attr")
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
                    if ctx is None:
                        fn = root if isinstance(root, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
                        static = fn is not None and any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
                        ctx = dict(binds=self._bindings(root), cls=cls.split(".")[-1] if cls else None,
                                   first=fn.args.args[0].arg if fn is not None and fn.args.args and not static else None)
                    names_ = self._names(n.args[1], ctx) if len(n.args) >= 2 else None
                    if names_ is not None and names_ & (ESCAPE_ATTRS | WRITE_ACCESS):
                        names_ = None                         # escapes and write access stay TOP
                    if names_ is None:
                        if not (f.id != "getattr" and self._slotted_self(n.args[0], ctx)):
                            flags.add("dyn-attr")             # a slotted instance accepts only its slot names: a data write
                    elif f.id == "getattr":                   # like x.<name>(): everything a hand-written x.<name>() would get
                        rc = dotted(n.args[0])
                        for nm in sorted(names_):
                            targets = self.by_method.get(nm, []); stats["cha"] += len(targets)
                            edges.update(targets)
                            if nm in NAME_FLAGS: flags.add(NAME_FLAGS[nm])
                            if nm in OS_ATTR: caps.add(OS_ATTR[nm])          # the receiver may be os
                            if nm in FILE_ATTRS or nm == "open": caps.add("file")
                            if rc and rc[0] in names and names[rc[0]][0] == "ext":
                                self._ext_effects(names[rc[0]][1] + rc[1:] + [nm], caps, flags, edges, value=True)
                            elif rc and rc[0] in names and names[rc[0]][0] == "mod":
                                m = names[rc[0]][1]
                                if nm in self.top.get(m, {}): edges.update(self._sym_nodes(m, nm))
                                else: flags.add("dyn-attr")   # may be a module the other module imported
                            elif rc and rc[0] in ("builtins", "__builtins__"):
                                flags.add("dyn-exec")
                    else:                                     # a write by a fixed name is like x.<name> = v
                        ch0 = dotted(n.args[0])
                        if ch0 and ch0[0] in names and names[ch0[0]][0] in ("mod", "ext"): flags.add("dyn-patch")
                    continue
                if f.id == "__import__":
                    self._dyn_import(first_const, edges, flags, caps); continue
            if isinstance(f, ast.Attribute) and f.attr in ("__setattr__", "__delattr__", "__getattribute__", "__getattr__"):
                if ctx is None:
                    fn = root if isinstance(root, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
                    static = fn is not None and any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.decorator_list)
                    ctx = dict(binds=self._bindings(root), cls=cls.split(".")[-1] if cls else None,
                               first=fn.args.args[0].arg if fn is not None and fn.args.args and not static else None)
                unbound = isinstance(f.value, ast.Name) and f.value.id in ("object", "type") or isinstance(f.value, ast.Name) and f.value.id in self.top.get(mod, {})
                recv, arg = (n.args[0] if n.args else None, n.args[1] if len(n.args) > 1 else None) if unbound else (f.value, n.args[0] if n.args else None)
                nm = self._names(arg, ctx) if arg is not None else None
                if nm is None or nm & (ESCAPE_ATTRS | WRITE_ACCESS):
                    write = f.attr in ("__setattr__", "__delattr__")
                    if not (write and nm is None and recv is not None and self._slotted_self(recv, ctx)):
                        flags.add("dyn-attr")
            if not ch:
                if isinstance(f, ast.Attribute):          # receiver is an expression (super(), a call result, ...)
                    targets = self.by_method.get(f.attr, []); stats["cha"] += len(targets)
                    edges.update(targets)
                continue
            # resolve chain through import bindings
            targets, ext = [], None
            p0 = ch[0]
            if p0 in ("self", "cls") and cls and len(ch) == 2:
                targets = self.by_method.get(ch[1], [])   # the instance may be a subclass that overrides it
                stats["cha"] += len(targets)
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
                self._ext_effects(ext, caps, flags, edges, call=n)
        return edges, caps, flags, ext_roots, stats, reads

    def _ext_effects(self, ext, caps, flags, edges, value=False, call=None):
        """Scope and flags of the external name `ext` (a dotted path), when called or, with value=True, used as a value."""
        root, last = ext[0], ext[-1]
        if root in MOD_CAPS: caps.add(MOD_CAPS[root])
        if root == "os" and last in OS_ATTR: caps.add(OS_ATTR[last])
        if root in DESER_MODS and (value or last in ("load", "loads", "open", "Unpickler")): flags.add("dyn-exec")
        if root == "builtins" and len(ext) > 1:
            if last == "open": caps.add("file")
            elif last in NAME_FLAGS: flags.add(NAME_FLAGS[last])
        if last in ESCAPE_ATTRS: flags.add("dyn-attr")
        if ext[:2] == ["sys", "modules"]: flags.add("dyn-patch")
        if ext[:3] == ["importlib", "metadata", "entry_points"] or last == "entry_points": flags.add("dyn-import")
        if root == "importlib" and last in ("import_module", "__import__"):
            lit = call.args[0].value if call is not None and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str) else None
            self._dyn_import(lit, edges, flags, caps)
        if root in ("operator", "inspect") and last in ("attrgetter", "methodcaller", "getattr_static"):
            args = (call.args[1:2] if last == "getattr_static" else call.args[:1] if last == "methodcaller" else call.args) if call is not None else []
            lits = [a.value for a in args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if call is None or not args or len(lits) != len(args):
                flags.add("dyn-attr")                         # getattr by another name, with a computed name
            else:                                             # literal names: the same checks as a literal getattr
                for nm in {x for l in lits for x in l.split(".")}:
                    if nm in ESCAPE_ATTRS or nm in WRITE_ACCESS: flags.add("dyn-attr")
                    if nm in NAME_FLAGS: flags.add(NAME_FLAGS[nm])
                    if nm in OS_ATTR: caps.add(OS_ATTR[nm])
                    if nm in FILE_ATTRS or nm == "open": caps.add("file")
                    edges.update(self.by_method.get(nm, []))
        if value and len(ext) == 1 and root in MODULE_VALUE:   # the module itself, as a value
            kind, v = MODULE_VALUE[root]
            if kind == "caps": caps.update(v)
            else: flags.add(v)
        if value and len(ext) > 1 and last in NAME_FLAGS: flags.add(NAME_FLAGS[last])

    def _dyn_import(self, literal, edges, flags, caps=None):
        if literal and literal in self.trees: edges.add(f"{literal}:<module>")
        elif literal:                                         # an outside module, returned as a value
            self._ext_effects(literal.split("."), caps if caps is not None else set(), flags, edges, value=True)
        else:
            flags.add("dyn-import")
            for m in self.trees: edges.add(f"{m}:<module>")      # over-approximate: could load any module

    # ---- analysis ----------------------------------------------------------
    def _analyze(self):
        raw = {}
        mod_names = {mod: self._bind_imports(mod, tree) for mod, (path, tree) in self.trees.items()}
        for mod, (path, tree) in self.trees.items():
            names_mod = mod_names[mod]
            skel = copy.deepcopy(tree)
            class Drop(ast.NodeTransformer):
                def visit_FunctionDef(self, n): return None
                def visit_AsyncFunctionDef(self, n): return None
            skel = ast.fix_missing_locations(Drop().visit(skel))
            e, c, fl, er, st, _ = self._scan(skel, mod, None, names_mod, skeleton=True)
            raw[f"{mod}:<module>"] = dict(own=H(ast.dump(skel, annotate_fields=False)), size=size(skel), edges=e,
                                          calls=set(e), caps=c, flags=fl, ext=er, stats=st)
            # module values: hashing only; their import-time effects are part of <module>
            groups = dict(self.values[mod])
            if self.effects[mod]: groups["<effects>"] = self.effects[mod]
            for name, stmts in groups.items():
                body = [class_skeleton(x) if isinstance(x, ast.ClassDef) else x for x in stmts]
                block = ast.Module(body=body, type_ignores=[])
                e, c, fl, er, st, rd = self._scan(block, mod, None, names_mod, local=set())
                for x in stmts:
                    if isinstance(x, ast.ImportFrom):
                        for nm, b in self._bind_imports(mod, x).items():
                            if b[0] == "sym": rd.update(self._attr_refs(b[1], b[2]))
                            if b[0] == "star": rd.add(f"{b[1]}:<module>")
                rd.discard(f"{mod}:={name}")
                raw[f"{mod}:={name}"] = dict(own=H(ast.dump(block, annotate_fields=False)), size=size(block),
                                             edges=e | rd, calls=set(), caps=set(), flags=set(), ext=er,
                                             stats=st)
        for nid, (fn, mod, cls) in self.funcs.items():
            names = dict(mod_names[mod])
            names.update(self._bind_imports(mod, fn))
            declared_global = {g for n in ast.walk(fn) if isinstance(n, ast.Global) for g in n.names}
            local = set(local_map(fn)) - declared_global
            e, c, fl, er, st, rd = self._scan(fn, mod, cls, names, local=local)
            if cls is not None:
                rd.add(f"{mod}:={cls.split('.')[0]}")             # a method reads its class's attributes
            if self.effects[mod]:
                rd.add(f"{mod}:=<effects>")
            raw[nid] = dict(own=H(canon_fn(fn)), size=size(fn), edges=e | rd, calls=set(e), caps=c, flags=fl,
                            ext=er, stats=st)
        for nid, (fn, mod, cls) in self.funcs.items():
            # module state written through `global` depends on the function that writes it
            for g in {g for n in ast.walk(fn) if isinstance(n, ast.Global) for g in n.names}:
                key = f"{mod}:={g}"
                if key not in raw:
                    raw[key] = dict(own=H(""), size=0, edges=set(), calls=set(), caps=set(), flags=set(),
                                    ext=set(), stats={"cross": 0, "cha": 0})
                raw[key]["edges"].add(nid)
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
