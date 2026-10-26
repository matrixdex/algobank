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

def test_unrelated_constant_does_not_spread():
    """G14: a function depends only on the module-level names it reads."""
    a = Package({"m.py": "A = 1\nB = 2\n\ndef f():\n    return A\n"})
    b = Package({"m.py": "A = 1\nB = 3\n\ndef f():\n    return A\n"})
    assert "m:f" not in changed(a, b)

def test_unrelated_module_does_not_spread():
    """G14: changing one module's top-level code does not change functions in modules that import it
    but do not read the changed name."""
    cfg = "LIMIT = 10\nOTHER = {}\n"
    use = "from . import config\n\ndef f(x):\n    return x < config.LIMIT\n"
    a = Package({"pkg/__init__.py": "", "pkg/config.py": cfg, "pkg/use.py": use})
    b = Package({"pkg/__init__.py": "", "pkg/config.py": cfg.replace("{}", "{1: 2}"), "pkg/use.py": use})
    c = Package({"pkg/__init__.py": "", "pkg/config.py": cfg.replace("10", "20"), "pkg/use.py": use})
    assert "pkg.use:f" not in changed(a, b)
    assert "pkg.use:f" in changed(a, c)

def test_function_reference():
    """A function passed as a value, not called, is still a dependency."""
    src = "def helper(x):\n    return x + {n}\n\ndef g(xs):\n    return list(map(helper, xs))\n"
    assert "m:g" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_registry_mutation():
    """Module-level statements that change a name (REG["a"] = ...) belong to that name."""
    src = "REG = {{}}\nREG['a'] = {n}\n\ndef f():\n    return REG\n"
    assert "m:f" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_conditional_import():
    src = "try:\n    import json\nexcept ImportError:\n    json = {v}\n\ndef f(s):\n    return json.loads(s)\n"
    assert "m:f" in changed(Package({"m.py": src.format(v="None")}), Package({"m.py": src.format(v="0")}))

def test_star_import():
    use = "from .x import *\n\ndef f():\n    return LIMIT\n"
    a = Package({"pkg/__init__.py": "", "pkg/x.py": "LIMIT = 1\n", "pkg/use.py": use})
    b = Package({"pkg/__init__.py": "", "pkg/x.py": "LIMIT = 2\n", "pkg/use.py": use})
    assert "pkg.use:f" in changed(a, b)

# ---- receivers of method calls (G7): link by method name, never narrow

TWO = "class Text:\n    def append(self, x):\n        return {t}\n\nclass Other:\n    def append(self, x):\n        return {o}\n\n"

def with_classes(body, t=1, o=1):
    return Package({"m.py": TWO.format(t=t, o=o) + body})

def test_parameter_receiver_stays_conservative():
    body = "def f(t):\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_annotation_is_not_trusted():
    """An annotation does not narrow the receiver: the caller may pass any object."""
    body = "def f(t: Text):\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_rebinding_disqualifies():
    body = "def make():\n    return Other()\n\ndef f():\n    t = Text()\n    for t in [make()]:\n        pass\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_rebound_class_name_disqualifies():
    body = "Text = Other\n\ndef f():\n    t = Text()\n    t.append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, o=2))

def test_self_call_includes_subclass_override():
    """A.run calls self.step(); B(A) overrides step, so A.run can run B.step."""
    src = "class A:\n    def run(self):\n        return self.step()\n    def step(self):\n        return 1\n\n" \
          "class B(A):\n    def step(self):\n        return {n}\n"
    assert "m:A.run" in changed(Package({"m.py": src.format(n=2)}), Package({"m.py": src.format(n=3)}))

def test_super_call():
    src = "class A:\n    def step(self):\n        return {n}\n\nclass B(A):\n    def step(self):\n        return super().step() + 1\n"
    assert "m:B.step" in changed(Package({"m.py": src.format(n=1)}), Package({"m.py": src.format(n=2)}))

def test_call_on_call_result():
    """A method called on the result of another call is linked by name."""
    body = "def get():\n    return Text()\n\ndef f():\n    return get().append(1)\n"
    assert "m:f" in changed(with_classes(body), with_classes(body, t=2))

def test_unresolved_base_stays_conservative():
    src = "from somewhere import Base\n\nclass C(Base):\n    pass\n\nclass Other:\n    def append(self, x):\n        return {o}\n\n" \
          "def f():\n    c = C()\n    c.append(1)\n"
    assert "m:f" in changed(Package({"m.py": src.format(o=1)}), Package({"m.py": src.format(o=2)}))

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
