"""algobank diff: what changed in a Python package between two versions, and what it can do now.

Usage:
  algobank diff OLD NEW [--json]
  algobank scope FILE [FILE ...] [--json]

OLD, NEW and FILE are paths to wheel or sdist files, for example from
  pip download --only-binary :all: -d wheels/ NAME==VERSION

Algobank reads the files you give it, in memory. It has no network access and writes no files.
Nothing from the package is installed, imported or run.

Every result is checked against the advisories shipped in this package (algobank/known.json):
malicious releases, releases with known vulnerabilities, and known malicious files.

Native binaries (.so, .pyd, .dylib, .dll, and any file whose first bytes are machine code) and compiled
Python (.pyc) are not checked: each is a high finding, "native binary detected. not checked", to be checked
separately. So is every Python file Algobank cannot decode or parse. With --ignore-native they are still reported, marked
ignored, and do not affect the exit status, so a package with native code can still be algobanked.

Every package a package calls (its Requires-Dist dependencies) should be algobanked too. Give scope all
the files of a dependency closure (pip download without --no-deps); a called package that is not among
them gets a warning. A warning never changes the exit status.

Exit status: 0 no high-severity findings, 1 high-severity findings, 2 error.
"""
import argparse, ast, hashlib, io, json, os, re, sys, tarfile, tokenize, unicodedata, zipfile

from .pkgmerkle import Package, TOP, modname_of

MAX_FILE = 50 * 2**20          # skip larger members
MAX_TOTAL = 500 * 2**20        # stop reading an archive beyond this much uncompressed data
HIGH_SCOPES = {"network", "process", "env", "native", TOP}
SDIST_TEXT = ("source distribution: installing it runs its build backend and any setup.py, code not analyzed "
              "here (TOP); pip runs that code to read the metadata even during pip download, so download "
              "with --only-binary :all:")
NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll")
NATIVE_RE = re.compile(r"\.(so|pyd|dylib|dll)(\.[0-9]+)*$", re.I)   # libx.so.1 too
# machine code by its first bytes, whatever the file is called: ELF, Windows PE, Mach-O, WebAssembly
NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\x00asm")
SOURCE_EXT = (".py", ".pyw")                                   # Python imports both
COMPILED_EXT = (".pyc", ".pyo")
# entry point groups that tools load by themselves: installing the package is enough for its code to run
AUTO_ENTRY_POINTS = {"pytest11", "distutils.commands", "distutils.setup_keywords", "egg_info.writers", "setuptools.file_finders",
                     "setuptools.finalize_distribution_options", "flake8.extension", "flake8.report", "jupyter_server.extension",
                     "sphinx.builders", "pylint.plugins", "coverage.plugins", "mypy.plugins", "nose.plugins.0.10"}
COMPILED_TEXT = "compiled Python detected (.pyc): Python can run it in place of the source. not checked"
# characters that change how code looks without changing what it does (Trojan Source, CVE-2021-42574)
HIDDEN_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2028\u2029\u00ad\u2060-\u2064\ufeff]")
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
            if e.get("withdrawn"):                             # retracted by its publisher: kept in the file, never matched
                continue
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
    k0 = vkey(version)
    if version in a.get("versions", []) or (k0 and any(vkey(v) == k0 for v in a.get("versions", []))):
        return True                                           # 1.0 and 1.0.0 are one version (PEP 440)
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
        found = known_findings(a["release"], a["art"].sha256, a["digests"], which)
        if a.get("named") and a["named"] != a["release"]:      # match the name in the file name too
            texts = {x["text"] for x in found}
            found += [x for x in known_findings(a["named"], a["art"].sha256, {}, which) if x["text"] not in texts]
        r["findings"] = found + r["findings"]
    r["coverage"] = r["coverage"] + [known_note()]
    return r

def read_members(art):
    """{path: bytes} for regular files, plus notes about anything skipped. Nothing is extracted to disk.
    A skipped file, a name stored twice and a path outside the package are listed in art.issues."""
    out, notes, total = {}, [], 0
    issues = art.issues = []
    def add(name, data):
        if name in out:
            issues.append(("high", "duplicate", f"{name} is stored twice in the archive: the copy analyzed may not be the copy installed"))
        out[name] = data
    buf = io.BytesIO(art.data)
    if art.filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(buf) as z:
            for i in z.infolist():
                if i.is_dir(): continue
                if i.file_size > MAX_FILE or total + i.file_size > MAX_TOTAL:
                    issues.append(("high", "not read", f"{i.filename} is too large to read ({i.file_size} bytes): not analyzed (TOP)")); continue
                total += i.file_size
                add(i.filename, z.read(i))
    elif art.filename.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(fileobj=buf) as t:
            for m in t.getmembers():
                if not m.isfile(): continue
                if m.size > MAX_FILE or total + m.size > MAX_TOTAL:
                    issues.append(("high", "not read", f"{m.name} is too large to read ({m.size} bytes): not analyzed (TOP)")); continue
                total += m.size
                name = m.name.split("/", 1)[1] if "/" in m.name else m.name   # drop "name-version/"
                add(name, t.extractfile(m).read())
    else:
        raise SystemExit(f"error: unsupported file type {art.filename}")
    folded = {}
    for name in out:
        parts = name.replace("\\", "/").split("/")
        if name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name) or "\\" in name:
            issues.append(("high", "path", f"{name} points outside the package or uses a backslash: an installer may write it elsewhere"))
        key = unicodedata.normalize("NFC", name).casefold()       # Mod.py and mod.py are one file on many systems
        if key in folded and folded[key] != name:
            issues.append(("high", "duplicate", f"{folded[key]} and {name} differ only in case or Unicode form: which one is used depends on the system"))
        folded.setdefault(key, name)
    return out, notes

def metadata(members):
    """The package's own metadata: METADATA in a .dist-info folder at the top of a wheel, or PKG-INFO at the top of
    an sdist. A vendored copy deeper in the archive (flit_core ships tomli's) is not the package's."""
    found = sorted(k for k in members if re.fullmatch(r"[^/]+\.dist-info/METADATA|PKG-INFO", k))
    return members[found[0]] if found else b"", found

def requires(members):
    meta = metadata(members)[0]
    deps = {}
    for m in re.finditer(r"^Requires-Dist:[ \t]*([A-Za-z0-9_.\-]+)[ \t]*(.*)$", meta.decode("utf-8", "replace"), re.M):
        spec = m.group(2).strip()
        if spec.startswith("("):                      # older metadata wraps the version range in parentheses
            spec = re.sub(r"^\(([^)]*)\)", r"\1", spec)
        spec = re.sub(r"\s+", " ", spec).strip().lstrip("; ")          # "; extra == 'x'" has no version range
        deps[m.group(1).lower().replace("-", "_")] = spec or "any version"
    return deps

def release(members):
    meta = metadata(members)[0]
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
        elif re.match(r"[^/]+\.data/(data|headers)/", path):  # installed under the Python prefix, outside the package
            if base.endswith(".pth") or base in ("sitecustomize.py", "usercustomize.py"):
                found[path] = "installed outside the package; runs on every Python start"
            elif re.search(r"/(site|dist)-packages/|/bin/|/Scripts/", path):
                found[path] = "installed outside the package, into site-packages or a bin folder: it can replace other code"
            else:
                found[path] = "installed outside the package, under the Python prefix"
    return found

def entry_points(members):
    ep = b"\n".join(v for k, v in sorted(members.items()) if re.fullmatch(r"[^/]+\.dist-info/entry_points\.txt", k))   # the package's own
    lines = [l.strip() for l in ep.decode("utf-8", "replace").splitlines()]
    out, section = set(), ""
    for l in lines:
        if l.startswith("["): section = l
        elif l and not l.startswith("#"): out.add(f"{section} {l}")
    return out

def decode_source(data):
    """The text Python reads from these bytes: the encoding comes from the BOM or the coding line (PEP 263)."""
    enc, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    return data.decode(enc), enc

def analyze(art):
    members, notes = read_members(art)
    is_wheel = art.filename.endswith(".whl")
    sources, unparsed, encodings, hidden = {}, [], {}, []
    for path, data in members.items():
        if path.endswith(SOURCE_EXT):
            try:
                src, enc = decode_source(data)
                ast.parse(src, path)                                       # parse only, never run
                sources[path] = src
                if enc not in ("utf-8", "utf-8-sig"): encodings[path] = enc
                if HIDDEN_CHARS.search(src.lstrip("\ufeff")): hidden.append(path)
            except (UnicodeDecodeError, SyntaxError, ValueError, LookupError, RecursionError, MemoryError):
                unparsed.append(path)
    deps = requires(members)
    pins = dict(deps)
    if "beautifulsoup4" in pins: pins["bs4"] = pins["beautifulsoup4"]
    pkg = Package(sources, pins)
    digests = {p: hashlib.sha256(d).hexdigest() for p, d in members.items()}
    natives = {p: d for p, d in digests.items()
               if NATIVE_RE.search(p) or (not p.endswith(SOURCE_EXT) and members[p][:4].startswith(NATIVE_MAGIC))}
    compiled = {p: d for p, d in digests.items() if p.endswith(COMPILED_EXT)}
    other = {p: d for p, d in digests.items()
             if not p.endswith(SOURCE_EXT) and p not in natives and p not in compiled and ".dist-info/" not in p}
    return dict(art=art, pkg=pkg, deps=deps, hooks=hooks(members), entry_points=entry_points(members),
                natives=natives, other=other, unparsed=unparsed, notes=notes, is_wheel=is_wheel,
                digests=digests, release=release(members), sources=sources, compiled=compiled, issues=art.issues,
                encodings=encodings, hidden=hidden, named=name_in_filename(art.filename), metadata_files=metadata(members)[1])

def name_in_filename(fn):
    """(name, version) from a wheel or sdist file name."""
    m = re.match(r"^([^-]+)-([^-]+)(?:-[^-]+)?-[^-]+-[^-]+-[^-]+\.whl$", fn) or re.match(r"^(.+)-([^-]+)\.(?:tar\.gz|tgz|tar|zip)$", fn)
    return (norm(m.group(1)), m.group(2)) if m else None

def reading_findings(a):
    """What the archive itself shows: code Algobank could not read or check, and names that disagree."""
    f = [finding(sev, kind, text) for sev, kind, text in a["issues"]]
    if a["unparsed"]:
        f.append(finding("high", "not analyzed", "Python files that cannot be decoded or parsed: not analyzed (TOP)", a["unparsed"]))
    if a["compiled"]:
        f.append(finding("high", "compiled", COMPILED_TEXT, list(a["compiled"])))
    for path, enc in sorted(a["encodings"].items()):
        f.append(finding("medium", "encoding", f"{path} declares the source encoding {enc}: a known way to hide code from readers"))
    if a["hidden"]:
        f.append(finding("medium", "hidden characters", "invisible or direction-changing characters in source code: the code may not do what it looks like", a["hidden"]))
    if len(a["metadata_files"]) > 1:
        f.append(finding("high", "metadata", "more than one top-level metadata file: which name and version apply is unclear", a["metadata_files"]))
    for e in sorted(a["entry_points"]):                       # "[group] name = target"
        g = re.match(r"^\[([^\]]+)\]", e)
        if g and g.group(1).strip() in AUTO_ENTRY_POINTS:
            f.append(finding("high", "entry point", f"entry point {e}: a tool loads it by itself, so installing the package runs its code"))
    tops = {p.split("/", 1)[0].removesuffix(".py").removesuffix(".pyw") for p in a["sources"]
            if "/" not in p.split(".data/", 1)[-1] or p.count("/") >= 1 and not p.split("/", 1)[0].endswith((".dist-info", ".data"))}
    shadow = sorted(t for t in tops if t in sys.stdlib_module_names and t not in ("test", "tests"))
    if shadow:
        f.append(finding("high", "shadowing", "the package ships modules named like standard library modules: every program that "
                                              "imports them may run this code instead", shadow))
    rel, named = a["release"], a["named"]
    if rel is None:
        f.append(finding("high", "metadata", "no package metadata (METADATA or PKG-INFO): name and version are unknown"))
    elif named and (rel[0] != named[0] or vkey(rel[1]) != vkey(named[1])):
        f.append(finding("high", "metadata", f"the file name says {named[0]} {named[1]}, the metadata says {rel[0]} {rel[1]}: "
                                             "an installer may use either"))
    return f

def closure_report(arts):
    """Every wheel's code in one graph: calls into a dependency follow its code. Sdists stay outside."""
    sources, owner, f = {}, {}, []
    for a in arts:
        if not a["is_wheel"]: continue
        for path, src in sorted(a["sources"].items()):
            m = re.match(r"[^/]+\.data/(?:purelib|platlib)/(.+)$", path)
            key = m.group(1) if m else path
            if key in sources and sources[key] != src:
                f.append(finding("high", "conflict", f"{key} is in {owner[key]} and in {a['art'].filename}: "
                                 "which one Python runs depends on the order of installation"))
                continue
            sources[key], owner[key] = src, a["art"].filename
    inside = {a["release"][0] for a in arts if a["release"] and a["is_wheel"]}
    pins = {}
    for a in arts:
        for d, spec in a["deps"].items():
            if norm(d) not in inside: pins.setdefault(d.lower(), set()).add(spec)
    pkg = Package(sources, {d: "; ".join(sorted(v)) for d, v in pins.items()})
    mod_owner = {modname_of(p): o for p, o in owner.items()}
    byart = {}
    for nid, n in pkg.nodes.items():
        byart.setdefault(mod_owner.get(nid.split(":", 1)[0], "?"), []).append(n)
    natives = {a["art"].filename for a in arts if a["natives"]}
    packages = [dict(artifact=a["art"].filename, sha256=a["art"].sha256,
                     scope=sorted(set().union(*[n["caps"] for n in byart.get(a["art"].filename, [])]) | ({"native"} if a["art"].filename in natives else set())))
                for a in arts if a["is_wheel"]]
    enters = {}                                               # where each scope enters: the packages whose own code uses it
    for nid, n in pkg.nodes.items():
        for c in n["direct_caps"] | ({"TOP"} if n["direct_flags"] & {"dyn-import", "dyn-attr", "dyn-exec", "dyn-patch"} else set()):
            enters.setdefault(c, set()).add(mod_owner.get(nid.split(":", 1)[0], "?"))
    for a in arts:
        if a["natives"]: enters.setdefault("native", set()).add(a["art"].filename)
    for a in arts:
        if not a["is_wheel"]:
            f.append(finding("high", "sdist", f"{a['art'].filename} is not in the closure graph: " + SDIST_TEXT))
    f += [x for x in design_findings(pkg) if x["kind"] == "effect under a shared name"]   # names shared across packages
    outside = sorted({d for a in arts for d in a["deps"] if norm(d) not in inside})
    for d in outside:
        f.append(finding("warning", "not algobanked", f"{d} is called but not in this closure: its code is not followed; run algobank on it too"))
    scope = sorted(set(pkg.scope()) | ({"native"} if natives else set()))
    return dict(closure=[a["art"].filename for a in arts], code_root=pkg.root(), nodes=len(pkg.nodes), scope=scope,
                packages=packages, enters={k: sorted(v) for k, v in sorted(enters.items())}, findings=f,
                coverage=["one graph: calls between these packages follow their code; "
                          "for a call into a package named in the scope table, that table also applies"])

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

ORDER = {"high": 0, "warning": 1, "medium": 2, "low": 3, "info": 4}

def finding(sev, kind, text, nodes=()):
    nodes = list(nodes)
    return dict(severity=sev, kind=kind, text=text, nodes=nodes[:10], more=max(0, len(nodes) - 10))

EFFECTS = {"file", "network", "process", "env", "native"}
PROPERTY = {"property", "cached_property", "setter", "getter", "deleter"}

def design_findings(pkg, only=None):
    """Two ways code makes its effects hard to place: an effect in a special method, which Python runs without
    a visible call, and an effect in a function whose name other functions share, so that calls matched by name
    reach it from unrelated code. `only`: report just these nodes (for diff, the new cases)."""
    names = {}
    for nid in pkg.funcs: names.setdefault(nid.split(":", 1)[1].split(".")[-1], []).append(nid)
    special, shared = [], []
    for nid, (fn, mod, cls) in sorted(pkg.funcs.items()):
        caps = sorted(pkg.nodes[nid]["direct_caps"] & EFFECTS) if nid in pkg.nodes else []
        if not caps or (only is not None and nid not in only): continue
        name = nid.split(":", 1)[1].split(".")[-1]
        deco = {(d.func if isinstance(d, ast.Call) else d) for d in fn.decorator_list}
        deco = {d.id if isinstance(d, ast.Name) else d.attr if isinstance(d, ast.Attribute) else "" for d in deco}
        if name.startswith("__") and name.endswith("__") and name != "__init__" or deco & PROPERTY or name in ("__get__", "__set__", "__delete__"):
            special.append(finding("medium", "effect in a special method",
                                   f"special method with {', '.join(caps)}: {nid} runs without a visible call; "
                                   "move the effect into a plain, uniquely named function", [nid]))
        elif len(names[name]) > 1 and not (name.startswith("__") and name.endswith("__")):   # K() finds __init__ by class
            shared.append(finding("medium", "effect under a shared name",
                                  f"effectful function with a shared name: {nid} ({', '.join(caps)}) shares its name with "
                                  f"{len(names[name]) - 1} other definition(s); a unique name keeps its scope from spreading "
                                  "to unrelated callers", [nid]))
    return special + shared

def scope_report(a):
    pkg = a["pkg"]
    f = []
    for path, why in sorted(a["hooks"].items()):
        sev = "high" if "Python start" in why or "replace other code" in why else "medium"
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
    f += design_findings(pkg)
    f = reading_findings(a) + f
    return dict(artifact=a["art"].filename, sha256=a["art"].sha256, code_root=pkg.root(),
                nodes=len(pkg.nodes), scope=scope_of(a), modules=module_scopes(pkg),
                dependencies=a["deps"], findings=f, coverage=coverage(a))

def coverage(a):
    c = []
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
    f += reading_findings(b)                                  # what the new file holds that Algobank cannot check
    # hooks
    for path, why in sorted(b["hooks"].items()):
        if path not in a["hooks"]:
            sev = "high" if "Python start" in why or "replace other code" in why else "medium"
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
    old_design = {x["text"] for x in design_findings(p)}
    f += [x for x in design_findings(q) if x["text"] not in old_design]     # new cases only
    for e in sorted(b["entry_points"] - a["entry_points"]):
        f.append(finding("medium", "entry point", f"new entry point {e}"))
    changed_files = [x for x in b["other"] if x in a["other"] and a["other"][x] != b["other"][x]]
    new_files = [x for x in b["other"] if x not in a["other"]]
    if new_files: f.append(finding("low", "file", "new non-Python files", new_files))
    if changed_files: f.append(finding("low", "file", "changed non-Python files", changed_files))
    f.sort(key=lambda x: ORDER[x["severity"]])
    return dict(old=dict(artifact=a["art"].filename, sha256=a["art"].sha256, code_root=p.root()),
                new=dict(artifact=b["art"].filename, sha256=b["art"].sha256, code_root=q.root()),
                nodes=dict(total=len(q.nodes), unchanged=len(same), code_changed=len(code),
                           dependency_changed=len(deps_only), added=len(added), removed=len(removed)),
                code_changed=sorted(code), added=sorted(added), removed=sorted(removed),
                scope=dict(old=sorted(old_scope), new=sorted(new_scope)),
                findings=f, coverage=coverage(a) + [c for c in coverage(b) if c not in coverage(a)])

def with_called(r, a, algobanked):
    """Warn about each called package that was not algobanked in this run. A warning is reported but never
    fails the run: algobanking every called package is the goal, and its absence is a soft condition."""
    w = [finding("warning", "not algobanked", f"calls {d} ({a['deps'][d]}), which was not algobanked in this run: "
                                               "run algobank on it too")
         for d in sorted(a["deps"]) if norm(d) not in algobanked]
    r["findings"] = sorted(r["findings"] + w, key=lambda x: ORDER[x["severity"]])
    return r

def safe(x):
    """Text from a package, made safe to print: control and direction characters are shown as escapes, so a
    file name cannot rewrite the terminal (erase a line, move the cursor, reorder text)."""
    return "".join(c if c == " " or c.isprintable() and not HIDDEN_CHARS.match(c) else f"\\u{ord(c):04x}" for c in str(x))

def show_findings(fs):
    for x in fs:
        nodes = ", ".join(x["nodes"]) + (f", and {x['more']} more" if x["more"] else "")
        sev = x["severity"] + (", ignored" if x.get("ignored") else "")
        print(f"  [{sev}] {safe(x['text'])}" + (f"\n         {safe(nodes)}" if nodes else ""))

def print_diff(r):
    n = r["nodes"]
    print(f"{safe(r['old']['artifact'])} -> {safe(r['new']['artifact'])}")
    print(f"  nodes (functions, classes, module values): {n['total']} ({n['unchanged']} unchanged, {n['code_changed']} code changed, "
          f"{n['dependency_changed']} affected by a changed dependency, {n['added']} added, {n['removed']} removed)")
    print(f"  scope: {', '.join(r['scope']['old']) or 'none'} -> {', '.join(r['scope']['new']) or 'none'}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    else:
        print("findings: none")
    for c in r["coverage"]: print(f"  note: {safe(c)}")

def print_closure(r):
    print(f"closure of {len(r['closure'])} files  ({r['nodes']} nodes)")
    print(f"  scope: {', '.join(r['scope']) or 'none'}")
    for p in r["packages"]:
        print(f"    {safe(p['artifact'])}: {', '.join(p['scope']) or 'none'}")
    if r["enters"]:
        print("  where each scope enters (the packages whose own code uses it):")
        for c, arts in r["enters"].items(): print(f"    {safe(c)}: {safe(', '.join(arts))}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    for c in r["coverage"]: print(f"  note: {safe(c)}")

def print_scope(r):
    print(f"{safe(r['artifact'] or r['sha256'])}  ({r['nodes']} nodes)")
    print(f"  scope: {', '.join(r['scope']) or 'none'}")
    for m, s in r["modules"].items():
        if s: print(f"    {safe(m)}: {safe(', '.join(s))}")
    if r["dependencies"]:
        print(f"  dependencies (not analyzed here, scope unknown): {safe(', '.join(sorted(r['dependencies'])))}")
    if r["findings"]:
        print("findings:"); show_findings(r["findings"])
    for c in r["coverage"]: print(f"  note: {safe(c)}")

def main(argv=None):
    ap = argparse.ArgumentParser(prog="algobank", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff"); d.add_argument("old"); d.add_argument("new")
    s = sub.add_parser("scope"); s.add_argument("files", nargs="+", metavar="file")
    s.add_argument("--closure", action="store_true", help="also analyze all the files as one graph: calls between them follow their code")
    for x in (d, s):
        x.add_argument("--json", action="store_true")
        x.add_argument("--ignore-native", action="store_true",
                       help="report native binaries but do not fail on them; check them separately")
    args = ap.parse_args(argv)
    sys.setrecursionlimit(20000)
    try:
        if args.cmd == "diff":
            a, b = analyze(load(args.old)), analyze(load(args.new))
            reports = [with_called(with_known(diff_report(a, b), a, b), b, {b["release"][0]} if b["release"] else set())]
        else:
            arts = [analyze(load(f)) for f in args.files]
            algobanked = {a["release"][0] for a in arts if a["release"]}
            reports = [with_called(with_known(scope_report(a), a), a, algobanked) for a in arts]
            if args.closure: reports.append(closure_report(arts))
        for r in reports:
            for x in r["findings"]:
                if args.ignore_native and x["kind"] == "native": x["ignored"] = True
        if args.json: print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
        else:
            for r in reports: print_diff(r) if args.cmd == "diff" else print_closure(r) if "closure" in r else print_scope(r)
    except SystemExit as e:
        if isinstance(e.code, str):
            print(safe(e.code), file=sys.stderr); return 2
        raise
    except Exception as e:                                    # fail closed: a file Algobank cannot analyze never passes
        print(f"error: could not analyze: {safe(type(e).__name__)}: {safe(e)}", file=sys.stderr); return 2
    return 1 if any(x["severity"] == "high" and not x.get("ignored") for r in reports for x in r["findings"]) else 0

if __name__ == "__main__":
    sys.exit(main())
