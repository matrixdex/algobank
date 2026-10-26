"""algobank diff: what changed in a Python package between two versions, and what it can do now.

Usage:
  python3.14 algobank_diff.py diff NAME OLD NEW [--json]
  python3.14 algobank_diff.py scope NAME VERSION [--json]

OLD, NEW and VERSION are PyPI versions or paths to local wheel or sdist files.

PyPI artifacts are downloaded, checked against PyPI's SHA-256, and read in memory.
Nothing from the package is installed, imported or run.

Exit status: 0 no high-severity findings, 1 high-severity findings, 2 error.
"""
import argparse, hashlib, io, json, os, re, sys, tarfile, urllib.request, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgmerkle import Package, TOP

CACHE = os.path.join(os.path.expanduser("~"), ".cache", "algobank")
MAX_FILE = 50 * 2**20          # skip larger members
MAX_TOTAL = 500 * 2**20        # stop reading an archive beyond this much uncompressed data
HIGH_SCOPES = {"network", "process", "env", "native", TOP}
NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll")
DYN_FLAGS = {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch", "dyn-getattr-def", "star-import"}
FLAG_TEXT = {"dyn-import": "import with a computed name", "dyn-attr": "attribute access with a computed name",
             "dyn-exec": "eval, exec or deserialization", "dyn-patch": "changes another module at run time",
             "dyn-getattr-def": "__getattr__ (attributes resolved at run time)", "star-import": "import *"}

# ---- fetching -----------------------------------------------------------------

class Artifact:
    def __init__(self, label, filename, data):
        self.label, self.filename, self.data = label, filename, data
        self.sha256 = hashlib.sha256(data).hexdigest()

def _pick(files):
    wheels = [f for f in files if f["packagetype"] == "bdist_wheel"]
    pure = [f for f in wheels if f["filename"].endswith("-none-any.whl")]
    if pure: return pure[0]
    if wheels:
        linux = [f for f in wheels if "manylinux" in f["filename"] and "x86_64" in f["filename"]]
        return (linux or sorted(wheels, key=lambda f: f["filename"]))[0]
    sdists = [f for f in files if f["packagetype"] == "sdist"]
    if sdists: return sdists[0]
    raise SystemExit(f"error: no wheel or sdist published")

def fetch(name, version):
    if os.path.exists(version):
        with open(version, "rb") as fh:
            return Artifact(version, os.path.basename(version), fh.read())
    if os.sep in version or version.endswith((".whl", ".tar.gz", ".zip")):
        raise SystemExit(f"error: file not found: {version}")
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            meta = json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"error: {name} {version} not found on PyPI ({e.code})")
    f = _pick(meta["urls"])
    want = f["digests"]["sha256"]
    path = os.path.join(CACHE, want + "-" + f["filename"])
    data = None
    if os.path.exists(path):
        with open(path, "rb") as fh: data = fh.read()
        if hashlib.sha256(data).hexdigest() != want: data = None
    if data is None:
        with urllib.request.urlopen(f["url"], timeout=120) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != want:
            raise SystemExit(f"error: {f['filename']} does not match PyPI's SHA-256")
        os.makedirs(CACHE, exist_ok=True)
        with open(path, "wb") as fh: fh.write(data)
    return Artifact(f"{name} {version}", f["filename"], data)

# ---- reading ------------------------------------------------------------------

def read_members(art):
    """{path: bytes} for regular files, plus notes about anything skipped. Nothing is extracted to disk."""
    out, notes, total = {}, [], 0
    buf = io.BytesIO(art.data)
    if art.filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(buf) as z:
            for i in z.infolist():
                if i.is_dir(): continue
                if i.file_size > MAX_FILE or total + i.file_size > MAX_TOTAL:
                    notes.append(f"skipped large file {i.filename}"); continue
                total += i.file_size
                out[i.filename] = z.read(i)
    elif art.filename.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(fileobj=buf) as t:
            for m in t.getmembers():
                if not m.isfile(): continue
                if m.size > MAX_FILE or total + m.size > MAX_TOTAL:
                    notes.append(f"skipped large file {m.name}"); continue
                total += m.size
                name = m.name.split("/", 1)[1] if "/" in m.name else m.name   # drop "name-version/"
                out[name] = t.extractfile(m).read()
    else:
        raise SystemExit(f"error: unsupported file type {art.filename}")
    return out, notes

def requires(members):
    meta = next((v for k, v in members.items() if k.endswith((".dist-info/METADATA", "PKG-INFO"))), b"")
    deps = {}
    for m in re.finditer(r"^Requires-Dist:[ \t]*([A-Za-z0-9_.\-]+)[ \t]*(.*)$", meta.decode("utf-8", "replace"), re.M):
        spec = m.group(2).strip()
        if spec.startswith("("):                      # older metadata wraps the version range in parentheses
            spec = re.sub(r"^\(([^)]*)\)", r"\1", spec)
        spec = re.sub(r"\s+", " ", spec).strip()
        deps[m.group(1).lower().replace("-", "_")] = spec or "any version"
    return deps

def hooks(members, is_wheel):
    """Code that runs without the package being imported."""
    found = {}
    for path in members:
        base = path.rsplit("/", 1)[-1]
        top_level = "/" not in path or re.match(r"[^/]+\.data/(purelib|platlib)/[^/]+$", path)
        if base.endswith(".pth") and top_level:
            found[path] = "runs on every Python start (.pth file)"
        elif base in ("sitecustomize.py", "usercustomize.py") and top_level:
            found[path] = "runs on every Python start"
        elif re.match(r"[^/]+\.data/scripts/", path):
            found[path] = "script installed on PATH"
        elif not is_wheel and path in ("setup.py",):
            found[path] = "runs when the package is built from source"
    return found

def entry_points(members):
    ep = next((v for k, v in members.items() if k.endswith(".dist-info/entry_points.txt")), b"")
    lines = [l.strip() for l in ep.decode("utf-8", "replace").splitlines()]
    out, section = set(), ""
    for l in lines:
        if l.startswith("["): section = l
        elif l and not l.startswith("#"): out.add(f"{section} {l}")
    return out

def analyze(art):
    members, notes = read_members(art)
    is_wheel = art.filename.endswith(".whl")
    sources, unparsed = {}, []
    for path, data in members.items():
        if path.endswith(".py") and ".dist-info/" not in path:
            try:
                src = data.decode("utf-8")
                compile(src, path, "exec", flags=0x400, dont_inherit=True)   # ast.PyCF_ONLY_AST: parse only
                sources[path] = src
            except (UnicodeDecodeError, SyntaxError, ValueError):
                unparsed.append(path)
    deps = requires(members)
    pins = dict(deps)
    if "beautifulsoup4" in pins: pins["bs4"] = pins["beautifulsoup4"]
    pkg = Package(sources, pins)
    natives = {p: hashlib.sha256(d).hexdigest() for p, d in members.items() if p.endswith(NATIVE_EXT)}
    other = {p: hashlib.sha256(d).hexdigest() for p, d in members.items()
             if not p.endswith(".py") and p not in natives and ".dist-info/" not in p}
    return dict(art=art, pkg=pkg, deps=deps, hooks=hooks(members, is_wheel), entry_points=entry_points(members),
                natives=natives, other=other, unparsed=unparsed, notes=notes, is_wheel=is_wheel)

# ---- reporting ----------------------------------------------------------------

def module_of(nid): return nid.split(":", 1)[0]

def module_scopes(pkg):
    out = {}
    for nid, n in pkg.nodes.items():
        out.setdefault(module_of(nid), set()).update(n["direct_caps"])
        if TOP in n["caps"] and n["direct_flags"] & DYN_FLAGS: out[module_of(nid)].add(TOP)
    return {m: sorted(s) for m, s in sorted(out.items())}

def finding(sev, kind, text, nodes=()):
    nodes = list(nodes)
    return dict(severity=sev, kind=kind, text=text, nodes=nodes[:10], more=max(0, len(nodes) - 10))

def scope_report(a):
    pkg = a["pkg"]
    f = []
    for path, why in sorted(a["hooks"].items()):
        sev = "high" if "Python start" in why else "medium"
        f.append(finding(sev, "hook", f"{path}: {why}"))
    for s in sorted(set().union(*[n["direct_caps"] for n in pkg.nodes.values()]) if pkg.nodes else []):
        users = [k for k, n in pkg.nodes.items() if s in n["direct_caps"]]
        f.append(finding("info", "scope", f"uses {s}", users))
    for flag in sorted(DYN_FLAGS):
        users = [k for k, n in pkg.nodes.items() if flag in n["direct_flags"]]
        if users: f.append(finding("info", "dynamic", FLAG_TEXT[flag], users))
    if a["natives"]:
        f.append(finding("info", "native", f"{len(a['natives'])} native binaries, not analyzed", list(a["natives"])))
    return dict(artifact=a["art"].filename, sha256=a["art"].sha256, code_root=pkg.root(),
                nodes=len(pkg.nodes), scope=pkg.scope(), modules=module_scopes(pkg),
                dependencies=a["deps"], findings=f, coverage=coverage(a))

def coverage(a):
    c = []
    if not a["is_wheel"]: c.append("no wheel published; analyzed the sdist")
    if a["unparsed"]: c.append(f"{len(a['unparsed'])} Python files could not be parsed")
    if a["natives"]: c.append(f"{len(a['natives'])} native binaries are not analyzed")
    c.extend(a["notes"])
    return c

def diff_report(a, b):
    p, q = a["pkg"], b["pkg"]
    f = []
    # code
    same = [k for k in q.nodes if k in p.nodes and p.nodes[k]["merkle"] == q.nodes[k]["merkle"]]
    code = [k for k in q.nodes if k in p.nodes and p.nodes[k]["own"] != q.nodes[k]["own"]]
    deps_only = [k for k in q.nodes if k in p.nodes and p.nodes[k]["own"] == q.nodes[k]["own"]
                 and p.nodes[k]["merkle"] != q.nodes[k]["merkle"]]
    added = [k for k in q.nodes if k not in p.nodes]
    removed = [k for k in p.nodes if k not in q.nodes]
    # hooks
    for path, why in sorted(b["hooks"].items()):
        if path not in a["hooks"]:
            sev = "high" if "Python start" in why else "medium"
            f.append(finding(sev, "hook", f"new {path}: {why}"))
    # scope: where a power newly enters, and what existing code can now reach it
    old_scope, new_scope = set(p.scope()), set(q.scope())
    def entered(k, s):
        n = q.nodes[k]
        if s == TOP:
            had = p.nodes[k]["direct_flags"] if k in p.nodes else set()
            return bool((n["direct_flags"] - had) & {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch"})
        return s in n["direct_caps"] and (k not in p.nodes or s not in p.nodes[k]["direct_caps"])
    for s in sorted(new_scope | old_scope):
        origin = [k for k in q.nodes if entered(k, s)]
        reach = [k for k, n in q.nodes.items() if k in p.nodes and s in n["caps"] and s not in p.nodes[k]["caps"]]
        if not origin and not reach and s in old_scope:
            continue
        funcs = [k for k in reach if not k.endswith(":<module>")]
        mods = [k for k in reach if k.endswith(":<module>")]
        if s not in old_scope:
            sev, text = ("high" if s in HIGH_SCOPES else "medium"), f"package can now use {s} (it could not before)"
        elif reach:
            sev, text = ("high" if s in HIGH_SCOPES else "medium"), f"{s} is now reachable from more code"
        else:
            sev, text = ("medium" if s in HIGH_SCOPES else "low"), f"new code that uses {s}"
        parts = []
        if origin: parts.append(f"enters at {len(origin)} node(s)")
        if funcs: parts.append(f"{len(funcs)} existing function(s) can now reach it")
        if mods: parts.append(f"importing {len(mods)} module(s) now reaches it at import time")
        f.append(finding(sev, "scope", text + ": " + "; ".join(parts), list(dict.fromkeys(origin + funcs + mods))))
    # dynamic code
    for flag in sorted(DYN_FLAGS):
        new = [k for k, n in q.nodes.items() if flag in n["direct_flags"]
               and (k not in p.nodes or flag not in p.nodes[k]["direct_flags"])]
        if new:
            f.append(finding("high" if flag in ("dyn-exec", "dyn-patch") else "medium", "dynamic",
                             f"new {FLAG_TEXT[flag]}", new))
    # binaries, dependencies, entry points
    nb = [x for x in b["natives"] if x not in a["natives"]]
    cb = [x for x in b["natives"] if x in a["natives"] and a["natives"][x] != b["natives"][x]]
    if nb: f.append(finding("high", "native", "new native binaries (not analyzed)", nb))
    if cb: f.append(finding("medium", "native", "changed native binaries (not analyzed)", cb))
    for d in sorted(set(b["deps"]) - set(a["deps"])):
        f.append(finding("medium", "dependency", f"new dependency {d} ({b['deps'][d]})"))
    for d in sorted(set(a["deps"]) - set(b["deps"])):
        f.append(finding("low", "dependency", f"removed dependency {d}"))
    for d in sorted(set(a["deps"]) & set(b["deps"])):
        if a["deps"][d] != b["deps"][d]:
            f.append(finding("low", "dependency", f"{d}: {a['deps'][d]} -> {b['deps'][d]}"))
    for e in sorted(b["entry_points"] - a["entry_points"]):
        f.append(finding("medium", "entry point", f"new entry point {e}"))
    changed_files = [x for x in b["other"] if x in a["other"] and a["other"][x] != b["other"][x]]
    new_files = [x for x in b["other"] if x not in a["other"]]
    if new_files: f.append(finding("low", "file", "new non-Python files", new_files))
    if changed_files: f.append(finding("low", "file", "changed non-Python files", changed_files))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    f.sort(key=lambda x: order[x["severity"]])
    return dict(old=dict(artifact=a["art"].filename, sha256=a["art"].sha256, code_root=p.root()),
                new=dict(artifact=b["art"].filename, sha256=b["art"].sha256, code_root=q.root()),
                nodes=dict(total=len(q.nodes), unchanged=len(same), code_changed=len(code),
                           dependency_changed=len(deps_only), added=len(added), removed=len(removed)),
                code_changed=sorted(code), added=sorted(added), removed=sorted(removed),
                scope=dict(old=sorted(old_scope), new=sorted(new_scope)),
                findings=f, coverage=coverage(a) + [c for c in coverage(b) if c not in coverage(a)])

def show_findings(fs):
    for x in fs:
        nodes = ", ".join(x["nodes"]) + (f", and {x['more']} more" if x["more"] else "")
        print(f"  [{x['severity']}] {x['text']}" + (f"\n         {nodes}" if nodes else ""))

def print_diff(name, r):
    n = r["nodes"]
    print(f"{name}: {r['old']['artifact']} -> {r['new']['artifact']}")
    print(f"  functions and modules: {n['total']} ({n['unchanged']} unchanged, {n['code_changed']} code changed, "
          f"{n['dependency_changed']} affected by a changed dependency, {n['added']} added, {n['removed']} removed)")
    print(f"  scope: {', '.join(r['scope']['old']) or 'none'} -> {', '.join(r['scope']['new']) or 'none'}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    else:
        print("findings: none")
    for c in r["coverage"]: print(f"  note: {c}")

def print_scope(name, r):
    print(f"{name}: {r['artifact']}  ({r['nodes']} functions and modules)")
    print(f"  scope: {', '.join(r['scope']) or 'none'}")
    for m, s in r["modules"].items():
        if s: print(f"    {m}: {', '.join(s)}")
    if r["dependencies"]: print(f"  dependencies: {', '.join(sorted(r['dependencies']))}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    for c in r["coverage"]: print(f"  note: {c}")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="algobank_diff", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff"); d.add_argument("name"); d.add_argument("old"); d.add_argument("new")
    s = sub.add_parser("scope"); s.add_argument("name"); s.add_argument("version")
    for x in (d, s): x.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    sys.setrecursionlimit(20000)
    try:
        if args.cmd == "diff":
            r = diff_report(analyze(fetch(args.name, args.old)), analyze(fetch(args.name, args.new)))
            print(json.dumps(r, indent=2)) if args.json else print_diff(args.name, r)
        else:
            r = scope_report(analyze(fetch(args.name, args.version)))
            print(json.dumps(r, indent=2)) if args.json else print_scope(args.name, r)
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr); return 2
        raise
    return 1 if any(x["severity"] == "high" for x in r["findings"]) else 0

if __name__ == "__main__":
    sys.exit(main())
