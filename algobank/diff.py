"""algobank diff: what changed in a Python package between two versions, and what it can do now.

Usage:
  algobank diff OLD NEW [--json]
  algobank scope FILE [--json]
  algobank lookup SHA256 [--json]

OLD, NEW and FILE are paths to wheel or sdist files, for example from
  pip download --only-binary :all: -d wheels/ NAME==VERSION

Algobank reads the files you give it, in memory. It has no network access and writes no files.
Nothing from the package is installed, imported or run.

Every result is checked against the known-bad data shipped in this package: malicious releases,
releases with known vulnerabilities, and known malicious files. lookup gives the stored report of a
popular package's file by its SHA-256, for when you have a hash (from a lockfile) but not the file.

Exit status: 0 no high-severity findings, 1 high-severity findings, 2 error.
"""
import argparse, ast, gzip, hashlib, io, json, os, re, sys, tarfile, zipfile

from .pkgmerkle import Package, TOP

MAX_FILE = 50 * 2**20          # skip larger members
MAX_TOTAL = 500 * 2**20        # stop reading an archive beyond this much uncompressed data
HIGH_SCOPES = {"network", "process", "env", "native", TOP}
SDIST_TEXT = ("source distribution: installing it runs its build backend and any setup.py, code not analyzed "
              "here (TOP); pip runs that code to read the metadata even during pip download, so download "
              "with --only-binary :all:")
NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll")
DYN_FLAGS = {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch", "dyn-getattr-def", "star-import"}
FLAG_TEXT = {"dyn-import": "import with a computed name", "dyn-attr": "attribute access with a computed name",
             "dyn-exec": "eval, exec or deserialization", "dyn-patch": "changes another module at run time",
             "dyn-getattr-def": "__getattr__ (attributes resolved at run time)", "star-import": "import *"}

# ---- reading ------------------------------------------------------------------

class Artifact:
    def __init__(self, filename, data):
        self.filename, self.data = filename, data
        self.sha256 = hashlib.sha256(data).hexdigest()

def load(path):
    """Reads the one file it is given. Algobank reads no other files except its own package (known())."""
    if not os.path.isfile(path):
        raise SystemExit(f"error: file not found: {path}")
    with open(path, "rb") as fh:
        return Artifact(os.path.basename(path), fh.read())

# ---- known data ---------------------------------------------------------------
# Shipped in this package, built by v0.1/build_cache.py. Known-bad entries are only ever added.
# A report is facts about one file, never a verdict that the file is safe.

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known.json.gz")
_known = None

def known():
    global _known
    if _known is None:
        _known = dict(date=None, analyzer=None, sources=[], reports={}, bad_releases={}, bad_files={})
        if os.path.isfile(DATA):
            with gzip.open(DATA, "rt", encoding="utf-8") as fh:
                _known = json.load(fh)
    return _known

def analyzer_root():
    """Code root of this analyzer. A stored report is valid only for the analyzer that produced it."""
    here, files = os.path.dirname(os.path.abspath(__file__)), {}
    for f in sorted(os.listdir(here)):
        if f.endswith(".py"):
            with open(os.path.join(here, f), encoding="utf-8") as fh:
                files["algobank/" + f] = fh.read()
    return Package(files).root()

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def known_findings(release, sha256, digests, which=""):
    k, f = known(), []
    if release:
        for e in k["bad_releases"].get(f"{release[0]}=={release[1]}", []):
            f.append(finding("high", "known " + e["kind"], f"{which}{release[0]} {release[1]}: {e['id']}: {e['summary']}"))
    for e in k["bad_files"].get(sha256, []):
        f.append(finding("high", "known malicious", f"{which}this file is known malicious ({e['id']}): {e['note']}"))
    for path, d in sorted(digests.items()):
        for e in k["bad_files"].get(d, []):
            f.append(finding("high", "known malicious", f"{which}{path} is a known malicious file ({e['id']}): {e['note']}"))
    return f

def known_note():
    k = known()
    if not k["date"]:
        return "no known-bad data is shipped with this copy of algobank"
    return (f"known-bad data as of {k['date']} ({'; '.join(k['sources'])}); "
            "anything reported after that date is not included: update algobank")

def with_known(r, *arts):
    """Add known-bad findings to a report. Kept apart from the report itself, which is pure analysis."""
    labels = ("old: ", "new: ") if len(arts) == 2 else ("",)
    for a, which in zip(arts, labels):
        r["findings"] = known_findings(a["release"], a["art"].sha256, a["digests"], which) + r["findings"]
    r["coverage"] = r["coverage"] + [known_note()]
    return r

def lookup(sha256):
    k = known()
    e = k["reports"].get(sha256)
    if e and k["analyzer"] != analyzer_root():
        e, stale = None, "stored reports were made by a different analyzer and are not used"
    else:
        stale = None
    if e:
        r = dict(e["report"])
        r["findings"] = known_findings((e["name"], e["version"]), sha256, {}) + r["findings"]
        r["coverage"] = r["coverage"] + [f"stored report for {e['name']} {e['version']}, made by this analyzer from "
                                         f"{r['artifact']}; to check it, download the file and run algobank scope",
                                         "files inside the archive were not checked against known malicious files",
                                         known_note()]
        return r
    f = [finding("high", "unknown", "not in the stored reports for popular packages, so its scope is unknown (TOP): "
                                    "download the file and run algobank scope")]
    return dict(artifact=None, sha256=sha256, code_root=None, nodes=0, scope=[TOP], modules={}, dependencies={},
                findings=known_findings(None, sha256, {}) + f, coverage=[c for c in (stale, known_note()) if c])

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

def release(members):
    meta = next((v for k, v in members.items() if k.endswith((".dist-info/METADATA", "PKG-INFO"))), b"")
    text = meta.decode("utf-8", "replace")
    name, version = re.search(r"^Name:[ \t]*(\S+)", text, re.M), re.search(r"^Version:[ \t]*(\S+)", text, re.M)
    return (norm(name.group(1)), version.group(1)) if name and version else None

def hooks(members):
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
                ast.parse(src, path)                                       # parse only, never run
                sources[path] = src
            except (UnicodeDecodeError, SyntaxError, ValueError):
                unparsed.append(path)
    deps = requires(members)
    pins = dict(deps)
    if "beautifulsoup4" in pins: pins["bs4"] = pins["beautifulsoup4"]
    pkg = Package(sources, pins)
    digests = {p: hashlib.sha256(d).hexdigest() for p, d in members.items()}
    natives = {p: d for p, d in digests.items() if p.endswith(NATIVE_EXT)}
    other = {p: d for p, d in digests.items()
             if not p.endswith(".py") and p not in natives and ".dist-info/" not in p}
    return dict(art=art, pkg=pkg, deps=deps, hooks=hooks(members), entry_points=entry_points(members),
                natives=natives, other=other, unparsed=unparsed, notes=notes, is_wheel=is_wheel,
                digests=digests, release=release(members))

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
    if not a["is_wheel"]:
        f.append(finding("high", "sdist", SDIST_TEXT))
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
    if not b["is_wheel"]:
        f.append(finding("high", "sdist", SDIST_TEXT))
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
        f.append(finding("high", "dependency", f"new dependency {d} ({b['deps'][d]}): not analyzed here, "
                                               "so its scope is unknown (TOP), including test-only and optional ones"))
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

def print_diff(r):
    n = r["nodes"]
    print(f"{r['old']['artifact']} -> {r['new']['artifact']}")
    print(f"  nodes (functions, classes, module values): {n['total']} ({n['unchanged']} unchanged, {n['code_changed']} code changed, "
          f"{n['dependency_changed']} affected by a changed dependency, {n['added']} added, {n['removed']} removed)")
    print(f"  scope: {', '.join(r['scope']['old']) or 'none'} -> {', '.join(r['scope']['new']) or 'none'}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    else:
        print("findings: none")
    for c in r["coverage"]: print(f"  note: {c}")

def print_scope(r):
    print(f"{r['artifact'] or r['sha256']}  ({r['nodes']} nodes)")
    print(f"  scope: {', '.join(r['scope']) or 'none'}")
    for m, s in r["modules"].items():
        if s: print(f"    {m}: {', '.join(s)}")
    if r["dependencies"]:
        print(f"  dependencies (not analyzed here, scope unknown): {', '.join(sorted(r['dependencies']))}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    for c in r["coverage"]: print(f"  note: {c}")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="algobank", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff"); d.add_argument("old"); d.add_argument("new")
    s = sub.add_parser("scope"); s.add_argument("file")
    l = sub.add_parser("lookup"); l.add_argument("sha256")
    for x in (d, s, l): x.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    sys.setrecursionlimit(20000)
    try:
        if args.cmd == "diff":
            a, b = analyze(load(args.old)), analyze(load(args.new))
            r = with_known(diff_report(a, b), a, b)
            print(json.dumps(r, indent=2)) if args.json else print_diff(r)
        elif args.cmd == "scope":
            a = analyze(load(args.file))
            r = with_known(scope_report(a), a)
            print(json.dumps(r, indent=2)) if args.json else print_scope(r)
        else:
            if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
                raise SystemExit("error: expected a SHA-256 digest (64 lowercase hex characters)")
            r = lookup(args.sha256)
            print(json.dumps(r, indent=2)) if args.json else print_scope(r)
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr); return 2
        raise
    return 1 if any(x["severity"] == "high" for x in r["findings"]) else 0

if __name__ == "__main__":
    sys.exit(main())
