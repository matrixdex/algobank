"""algobank diff: what changed in a Python package between two versions, and what it can do now.

Usage:
  algobank diff OLD NEW [--json]
  algobank scope FILE [--json]

OLD, NEW and FILE are paths to wheel or sdist files, for example from
  pip download --only-binary :all: -d wheels/ NAME==VERSION

Algobank reads the files you give it, in memory. It has no network access and writes no files.
Nothing from the package is installed, imported or run.

Every result is checked against the advisories shipped in this package (algobank/known.json):
malicious releases, releases with known vulnerabilities, and known malicious files.

Native binaries (.so, .pyd, .dylib, .dll) are not checked: each is a high finding, "native binary
detected. not checked", to be checked separately. With --ignore-native they are still reported, marked
ignored, and do not affect the exit status, so a package with native code can still be algobanked.

Exit status: 0 no high-severity findings, 1 high-severity findings, 2 error.
"""
import argparse, ast, hashlib, io, json, os, re, sys, tarfile, zipfile

from .pkgmerkle import Package, TOP

MAX_FILE = 50 * 2**20          # skip larger members
MAX_TOTAL = 500 * 2**20        # stop reading an archive beyond this much uncompressed data
HIGH_SCOPES = {"network", "process", "env", "native", TOP}
SDIST_TEXT = ("source distribution: installing it runs its build backend and any setup.py, code not analyzed "
              "here (TOP); pip runs that code to read the metadata even during pip download, so download "
              "with --only-binary :all:")
NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll")
NATIVE_TEXT = "native binary detected. not checked"
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
    """Reads the one file it is given. The only other file Algobank reads is its own known.json."""
    if not os.path.isfile(path):
        raise SystemExit(f"error: file not found: {path}")
    with open(path, "rb") as fh:
        return Artifact(os.path.basename(path), fh.read())

# ---- known data ---------------------------------------------------------------
# known.json, shipped in this package and built by v0.1/build_cache.py, holds the published advisory records
# (OSV format) for popular packages, unchanged, so anyone can read them. This code decides what they mean,
# on the machine that runs it. A catch is kept: records are only ever added. A pass is never stored: every
# file is analyzed every time it is checked.

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known.json")
_known = None

def known():
    """The records, indexed by package name and by the digests of known malicious files."""
    global _known
    if _known is None:
        data = dict(date=None, sources=[], advisories=[])
        if os.path.isfile(DATA):
            with open(DATA, encoding="utf-8") as fh:
                data = json.load(fh)
        by_name, by_digest = {}, {}
        for e in data["advisories"]:
            for a in e.get("affected", []):
                if a.get("package", {}).get("ecosystem") == "PyPI":
                    by_name.setdefault(norm(a["package"]["name"]), []).append((e, a))
            for f in e.get("database_specific", {}).get("iocs", {}).get("files", []):
                if f.get("digests", {}).get("sha256"):
                    by_digest.setdefault(f["digests"]["sha256"], []).append(e)
        _known = dict(data, by_name=by_name, by_digest=by_digest)
    return _known

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

def vkey(v):
    """Sort key for a PEP 440 version, or None if it is not one. Local labels (+...) are ignored: PyPI rejects them."""
    m = re.fullmatch(r"v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
                     r"(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*))?"
                     r"(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?"
                     r"(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?", v.strip().lower())
    if not m:
        return None
    epoch, rel, pre_l, pre_n, post_a, post_l, post_n, dev_l, dev_n = m.groups()
    rel = [int(x) for x in rel.split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    post = int(post_a) if post_a else int(post_n or 0) if post_l else -1
    dev = int(dev_n or 0) if dev_l else float("inf")
    if pre_l: pre = (PRE[pre_l], int(pre_n or 0))
    elif post == -1 and dev_l: pre = (-1, 0)                   # 1.0.dev1 sorts before 1.0a1
    else: pre = (9, 0)                                         # a final release sorts after its pre-releases
    return (int(epoch or 0), tuple(rel), pre, post, dev)

def affects(a, version):
    """Whether an advisory's `affected` block covers this version: True, False, or None if it cannot tell."""
    if version in a.get("versions", []):
        return True
    rngs = [r for r in a.get("ranges", []) if r.get("type") == "ECOSYSTEM"]
    if not rngs:
        return not a.get("versions")                           # no versions and no ranges: every version
    k = vkey(version)
    hit = False
    for r in rngs:
        events = []
        for ev in r.get("events", []):
            (kind, v), = ev.items()
            ek = (-1,) if v == "0" else vkey(v)
            if ek is None or k is None:
                return None
            events.append((ek, kind))
        affected = False
        for ek, kind in sorted(events, key=lambda x: x[0]):
            if kind == "introduced" and (ek == (-1,) or k >= ek): affected = True
            elif kind in ("fixed", "limit") and k >= ek: affected = False
            elif kind == "last_affected" and k > ek: affected = False
        hit = hit or affected
    return hit

def known_findings(release, sha256, digests, which=""):
    k, f = known(), []
    if release:
        name, version = release
        for e, a in k["by_name"].get(name, []):
            hit = affects(a, version)
            if hit is False:
                continue
            kind = "malicious" if e["id"].startswith("MAL-") else "vulnerability"
            maybe = "" if hit else "; its version could not be compared with the advisory's ranges, so it may apply"
            f.append(finding("high", "known " + kind, f"{which}{name} {version}: {e['id']}{maybe} (algobank/known.json)"))
    for path, d in [("this file", sha256)] + sorted(digests.items()):
        for e in k["by_digest"].get(d, []):
            f.append(finding("high", "known malicious", f"{which}{path} is a known malicious file: {e['id']} (algobank/known.json)"))
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

def scope_of(a):
    """The package's scope, with `native` when it ships binaries Algobank cannot see into."""
    return sorted(set(a["pkg"].scope()) | ({"native"} if a["natives"] else set()))

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
        f.append(finding("high", "native", NATIVE_TEXT, list(a["natives"])))
    return dict(artifact=a["art"].filename, sha256=a["art"].sha256, code_root=pkg.root(),
                nodes=len(pkg.nodes), scope=scope_of(a), modules=module_scopes(pkg),
                dependencies=a["deps"], findings=f, coverage=coverage(a))

def coverage(a):
    c = []
    if a["unparsed"]: c.append(f"{len(a['unparsed'])} Python files could not be parsed")
    if a["natives"]: c.append(f"{len(a['natives'])} native binaries are not checked: check them separately")
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
    old_scope, new_scope = set(scope_of(a)), set(scope_of(b))
    def entered(k, s):
        n = q.nodes[k]
        if s == TOP:
            had = p.nodes[k]["direct_flags"] if k in p.nodes else set()
            return bool((n["direct_flags"] - had) & {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch"})
        return s in n["direct_caps"] and (k not in p.nodes or s not in p.nodes[k]["direct_caps"])
    for s in sorted((new_scope | old_scope) - {"native"}):          # native binaries are reported below
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
    if nb: f.append(finding("high", "native", "new " + NATIVE_TEXT, nb))
    if cb: f.append(finding("high", "native", "changed " + NATIVE_TEXT, cb))
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
        sev = x["severity"] + (", ignored" if x.get("ignored") else "")
        print(f"  [{sev}] {x['text']}" + (f"\n         {nodes}" if nodes else ""))

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
    for x in (d, s):
        x.add_argument("--json", action="store_true")
        x.add_argument("--ignore-native", action="store_true",
                       help="report native binaries but do not fail on them; check them separately")
    args = ap.parse_args(argv)
    sys.setrecursionlimit(20000)
    try:
        if args.cmd == "diff":
            a, b = analyze(load(args.old)), analyze(load(args.new))
            r = with_known(diff_report(a, b), a, b)
        elif args.cmd == "scope":
            a = analyze(load(args.file))
            r = with_known(scope_report(a), a)
        if args.ignore_native:
            for x in r["findings"]:
                if x["kind"] == "native": x["ignored"] = True
        if args.json: print(json.dumps(r, indent=2))
        elif args.cmd == "diff": print_diff(r)
        else: print_scope(r)
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr); return 2
        raise
    return 1 if any(x["severity"] == "high" and not x.get("ignored") for x in r["findings"]) else 0

if __name__ == "__main__":
    sys.exit(main())
