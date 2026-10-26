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

# ---- check_backend must reject every output that breaks a condition of the Merkle soundness proof

import copy
from pkgmerkle import backend, check_backend, comp_base

# Two modules, a mutual recursion (a component with two members), and a cross-module call.
CYCLE = {"pkg/__init__.py": "",
         "pkg/a.py": "from .b import g\n\ndef f(n):\n    return g(n - 1) if n else 0\n",
         "pkg/b.py": "def g(n):\n    from .a import f\n    return f(n) + 1\n\ndef h():\n    return g(3)\n"}

def rejected(facts, out, comps):
    """The checker's failure message, or None if it accepts."""
    try:
        check_backend(facts, out, comps)
    except ValueError as e:
        return str(e)
    return None

def rehash(facts, out, comps):
    """Recompute every Merkle hash from the (possibly altered) components, so the Merkle
    equation holds and only the structural condition under test can fail."""
    own = {k: v["own"] for k, v in facts.items()}
    merk = {}
    for c in comps:
        base = comp_base(c, own, merk)
        for q in c["members"]:
            merk[q] = H(base + own[q])
    for k in out:
        out[k]["merkle"] = merk[k]

def test_checker_accepts_real_output():
    p = Package(CYCLE)
    assert any(len(c["members"]) > 1 for c in p.comps)
    out, comps = backend(p.facts)
    assert not rejected(p.facts, out, comps)

def mutated(change, rehash_after=False):
    p = Package(CYCLE)
    out, comps = backend(p.facts)
    out, comps = copy.deepcopy(out), copy.deepcopy(comps)
    change(p.facts, out, comps)
    if rehash_after:
        rehash(p.facts, out, comps)
    return rejected(p.facts, out, comps) or ""

def test_checker_rejects_wrong_merkle():                      # wf_merk
    def change(facts, out, comps):
        k = next(iter(out)); out[k]["merkle"] = H("forged")
    assert "Merkle hash of" in mutated(change)

def test_checker_rejects_wrong_component():                   # wf_mem, wf_comp
    def change(facts, out, comps):
        k = next(iter(out)); out[k]["comp"] = (out[k]["comp"] + 1) % len(comps)
    assert "is not assigned to component" in mutated(change)

def test_checker_rejects_missing_external():                  # wf_edge
    def change(facts, out, comps):
        c = next(c for c in comps if c["ext"]); c["ext"] = c["ext"][1:]
    assert "is not covered" in mutated(change, rehash_after=True)

def test_checker_rejects_unused_external():                   # wf_ext
    def change(facts, out, comps):
        i = next(i for i, c in enumerate(comps) if i > 0)   # an earlier component exists to point at
        earlier = comps[0]["members"][0]
        if earlier not in comps[i]["ext"]:
            comps[i]["ext"] = sorted(comps[i]["ext"] + [earlier])
        else:
            raise AssertionError("pick another component")
    assert "is unused" in mutated(change, rehash_after=True)

def test_checker_rejects_own_not_digest():                    # wf_own
    def change(facts, out, comps):
        k = next(iter(facts)); facts[k]["own"] = "not a digest"
    assert "own hash of" in mutated(change)

def test_checker_rejects_unconnected_component():             # wf_scc
    """Two unrelated nodes in one component, with Merkle hashes computed consistently,
    so only the strong-connectivity condition can catch it."""
    facts = {n: dict(own=H(n), edges=set(), pins=set(), caps=set(), flags=set()) for n in ("x", "y")}
    comps = [dict(members=["x", "y"], ext=[], pins=[])]
    own = {n: facts[n]["own"] for n in facts}
    base = comp_base(comps[0], own, {})
    out = {n: dict(merkle=H(base + own[n]), caps=set(), flags=set(), comp=0) for n in facts}
    assert "not strongly connected" in rejected(facts, out, comps)

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"{len(tests)} tests passed")
