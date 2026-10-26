"""Regression tests for pkgmerkle.py. Run: python3.14 -I v0.1/test_pkgmerkle.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgmerkle import Package, DIGEST_LEN, H

def changed(a, b):
    return sorted(k for k in a.nodes if k in b.nodes and a.nodes[k]["merkle"] != b.nodes[k]["merkle"])

def test_full_digest():
    assert len(H("x")) == DIGEST_LEN == 64
    p = Package({"m.py": "def f():\n    return 1\n"})
    assert len(p.root()) == 64 and all(len(n["merkle"]) == 64 for n in p.nodes.values())

def test_module_constant():
    """G1: a function's hash covers the module-level values it reads."""
    a = Package({"m.py": "LIMIT = 10\n\ndef f(x):\n    return x < LIMIT\n"})
    b = Package({"m.py": "LIMIT = 1000\n\ndef f(x):\n    return x < LIMIT\n"})
    assert "m:f" in changed(a, b)

def test_constant_in_other_module():
    """A constant imported from another module of the package."""
    a = Package({"pkg/__init__.py": "", "pkg/config.py": "LIMIT = 10\n",
                 "pkg/check.py": "from .config import LIMIT\n\ndef f(x):\n    return x < LIMIT\n"})
    b = Package({"pkg/__init__.py": "", "pkg/config.py": "LIMIT = 1000\n",
                 "pkg/check.py": "from .config import LIMIT\n\ndef f(x):\n    return x < LIMIT\n"})
    assert "pkg.check:f" in changed(a, b)

def test_class_attribute():
    a = Package({"m.py": "class C:\n    k = 1\n    def f(self):\n        return self.k\n"})
    b = Package({"m.py": "class C:\n    k = 2\n    def f(self):\n        return self.k\n"})
    assert "m:C.f" in changed(a, b)

def test_global_writer():
    """A function that writes module state through `global` affects every reader."""
    a = Package({"m.py": "x = 0\n\ndef w():\n    global x\n    x = 1\n\ndef r():\n    return x\n"})
    b = Package({"m.py": "x = 0\n\ndef w():\n    global x\n    x = 2\n\ndef r():\n    return x\n"})
    assert "m:r" in changed(a, b)

def test_unrelated_body_edit():
    """Editing one function's body does not change a function that neither calls nor reads it."""
    a = Package({"m.py": "def f():\n    return 1\n\ndef g():\n    return 2\n"})
    b = Package({"m.py": "def f():\n    return 1\n\ndef g():\n    return 3\n"})
    assert changed(a, b) == ["m:g"]

def test_prefixes():
    """Leaves and interior nodes use different prefixes."""
    p = Package({"m.py": "def f():\n    return 1\n"})
    leaf = H("\x00" + "m:f=" + p.nodes["m:f"]["merkle"])
    assert leaf in p.leaves()

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} tests passed")
